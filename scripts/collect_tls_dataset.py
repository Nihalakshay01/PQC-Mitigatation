import csv
import socket
import subprocess
import time
from pathlib import Path

ROOT = Path.home() / "pqc-project"
CERT = ROOT / "certs/server.crt"
KEY = ROOT / "certs/server.key"
LOGS = ROOT / "logs"
RESULTS = ROOT / "results"
OUT = RESULTS / "tls_dataset.csv"

HOST = "127.0.0.1"
PORT = 4433
REPEATS = 5

SCENARIOS = [
    ("hybrid_success", "X25519MLKEM768", "X25519MLKEM768",
     "HYBRID_SUCCESS"),
    ("classical_fallback", "X25519", "X25519MLKEM768:X25519",
     "CLASSICAL_FALLBACK"),
    ("incompatible_groups", "X25519", "X25519MLKEM768",
     "HANDSHAKE_FAILURE"),
]

LOGS.mkdir(exist_ok=True)
RESULTS.mkdir(exist_ok=True)

def wait_for_port(timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((HOST, PORT), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.1)
    return False

def run_one(name, server_groups, client_groups, run_no):
    server_log = LOGS / f"dataset_{name}_{run_no}_server.log"
    client_log = LOGS / f"dataset_{name}_{run_no}_client.log"

    server_cmd = [
        "openssl", "s_server",
        "-accept", str(PORT),
        "-cert", str(CERT),
        "-key", str(KEY),
        "-groups", server_groups,
        "-tls1_3", "-www",
    ]

    with server_log.open("w") as sf:
        server = subprocess.Popen(
            server_cmd, stdout=sf, stderr=subprocess.STDOUT
        )

    try:
        if not wait_for_port():
            return "SERVER_ERROR", "UNKNOWN", "Server failed to listen"

        client_cmd = [
            "openssl", "s_client",
            "-connect", f"{HOST}:{PORT}",
            "-groups", client_groups,
            "-tls1_3", "-state", "-msg",
        ]

        try:
            result = subprocess.run(
                client_cmd,
                input="",
                text=True,
                capture_output=True,
                timeout=8,
            )
            output = result.stdout + result.stderr
        except subprocess.TimeoutExpired as e:
            output = (e.stdout or "") + (e.stderr or "")
            if isinstance(output, bytes):
                output = output.decode(errors="replace")

        client_log.write_text(output, errors="replace")
        low = output.lower()

        if "negotiated tls1.3 group: x25519mlkem768" in low:
            return "HYBRID_SUCCESS", "X25519MLKEM768", "Hybrid group explicitly reported"

        if "negotiated tls1.3 group: x25519" in low:
            return "CLASSICAL_FALLBACK", "X25519", "Classical group explicitly reported"

        if "peer temp key: x25519, 253 bits" in low:
            return "CLASSICAL_FALLBACK", "X25519", "Verbose TLS output reports classical X25519 key exchange"

        if "protocol version: tlsv1.3" in low and "connection established" in low:
            return "TLS_SUCCESS_GROUP_UNKNOWN", "UNKNOWN", "TLS succeeded but group was not reported"

        if any(x in low for x in (
            "handshake failure", "no suitable key share", "no shared group"
        )):
            return "HANDSHAKE_FAILURE", "UNKNOWN", "TLS negotiation failed"

        return "UNKNOWN", "UNKNOWN", "Insufficient client evidence"

    finally:
        server.terminate()
        try:
            server.wait(timeout=2)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
        time.sleep(0.15)

rows = []

for name, server_groups, client_groups, expected in SCENARIOS:
    print(f"\nScenario: {name}")
    for run_no in range(1, REPEATS + 1):
        detected, group, details = run_one(
            name, server_groups, client_groups, run_no
        )
        status = "MATCH" if detected == expected else "REVIEW"

        rows.append({
            "scenario": name,
            "run": run_no,
            "server_groups": server_groups,
            "client_groups": client_groups,
            "detected_label": detected,
            "negotiated_group": group,
            "expected_label": expected,
            "status": status,
            "details": details,
        })

        print(f"  {run_no}/{REPEATS}: {detected} group={group} [{status}]")

with OUT.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)

print(f"\nSaved {len(rows)} records to {OUT}")
print("Review any UNKNOWN or REVIEW rows; do not relabel them by assumption.")
