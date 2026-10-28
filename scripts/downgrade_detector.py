import csv
import subprocess
from pathlib import Path

ROOT = Path.home() / "pqc-project"
LOGS = ROOT / "logs"
RESULTS = ROOT / "results"
PCAP = RESULTS / "downgrade_baseline.pcapng"

def read_log(name):
    path = LOGS / name
    return path.read_text(errors="replace").lower() if path.exists() else ""

def packet_groups():
    if not PCAP.exists():
        return []

    result = subprocess.run(
        [
            "tshark", "-r", str(PCAP),
            "-Y", "tls.handshake.type == 2",
            "-T", "fields",
            "-e", "tls.handshake.extensions_key_share_group",
        ],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        print("Warning: tshark could not read the capture.")
        return []

    return [
        line.strip().lower()
        for line in result.stdout.splitlines()
        if line.strip()
    ]

hybrid_fail_log = read_log("hybrid_only_vs_classical_client.log")
fallback_log = read_log("permitted_fallback_baseline_client.log")
groups = packet_groups()

fallback_in_capture = any(
    "29" in item.split(",") for item in groups
)

tests = []

if any(marker in hybrid_fail_log for marker in (
    "handshake failure", "no suitable key share", "no shared group"
)):
    tests.append([
        "hybrid_only_vs_classical",
        "HANDSHAKE_FAILURE",
        "HANDSHAKE_FAILURE",
        "MATCH",
        "Client log records a TLS negotiation failure",
    ])
else:
    tests.append([
        "hybrid_only_vs_classical",
        "UNKNOWN",
        "HANDSHAKE_FAILURE",
        "REVIEW",
        "Client log does not confirm the expected failure",
    ])

if fallback_in_capture:
    tests.append([
        "permitted_fallback_baseline",
        "CLASSICAL_FALLBACK",
        "CLASSICAL_FALLBACK",
        "MATCH",
        "Packet capture contains ServerHello selecting X25519 (group 29)",
    ])
else:
    tests.append([
        "permitted_fallback_baseline",
        "UNKNOWN",
        "CLASSICAL_FALLBACK",
        "REVIEW",
        "No confirmed X25519 selection found in the capture",
    ])

output = RESULTS / "downgrade_detection.csv"
with output.open("w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "test", "detected_label", "expected_label", "status", "details"
    ])
    writer.writerows(tests)

for row in tests:
    print(f"{row[0]}: {row[1]} | {row[3]}")
    print(f"  {row[4]}")

print(f"\nUpdated CSV: {output}")
