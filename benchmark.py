#!/usr/bin/env python3
import csv
import os
import re
import socket
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

BASE = Path.home() / "pqc-project"
CERT = BASE / "certs/server.crt"
KEY = BASE / "certs/server.key"
RESULTS = BASE / "results"
LOGS = BASE / "logs"
PORT = 4433
RUNS = 10

RESULTS.mkdir(parents=True, exist_ok=True)
LOGS.mkdir(parents=True, exist_ok=True)

CONFIGS = {
    "classical": "X25519",
    "hybrid": "X25519MLKEM768",
}

def wait_for_server(proc):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("TLS server exited unexpectedly.")
        try:
            with socket.create_connection(
                ("127.0.0.1", PORT), timeout=0.2
            ):
                pass
        except OSError:
            time.sleep(0.1)
            continue
        time.sleep(0.2)
        return
    raise RuntimeError("TLS server did not start on port 4433.")

def run_config(name, group):
    server_log = LOGS / f"server_{name}.log"
    server_cmd = [
        "openssl", "s_server",
        "-accept", str(PORT),
        "-cert", str(CERT),
        "-key", str(KEY),
        "-groups", group,
        "-tls1_3", "-www",
    ]

    rows = []
    with server_log.open("w") as log:
        server = subprocess.Popen(
            server_cmd,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            wait_for_server(server)

            for run in range(1, RUNS + 1):
                with tempfile.NamedTemporaryFile(
                    mode="w+", delete=False
                ) as stats:
                    stats_path = stats.name

                cmd = [
                    "/usr/bin/time", "-v", "-o", stats_path,
                    "openssl", "s_client",
                    "-connect", f"127.0.0.1:{PORT}",
                    "-groups", group,
                    "-tls1_3", "-state", "-msg",
                ]

                start = time.perf_counter()
                result = subprocess.run(
                    cmd,
                    input="GET / HTTP/1.0\r\n\r\n",
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=15,
                )
                elapsed = time.perf_counter() - start
                output = result.stdout

                stats = Path(stats_path).read_text()
                os.unlink(stats_path)

                byte_match = re.search(
                    r"SSL handshake has read\s+(\d+)\s+bytes "
                    r"and written\s+(\d+)\s+bytes",
                    output,
                )
                group_match = re.search(
                    r"Negotiated TLS1\.3 group:\s*(\S+)", output, re.IGNORECASE
                )
                user_match = re.search(
                    r"User time \(seconds\):\s*([\d.]+)", stats
                )
                sys_match = re.search(
                    r"System time \(seconds\):\s*([\d.]+)", stats
                )
                mem_match = re.search(
                    r"Maximum resident set size \(kbytes\):\s*(\d+)",
                    stats,
                )

                if result.returncode != 0 or not byte_match:
                    raise RuntimeError(
                        f"{name} run {run} failed.\n{output[-2500:]}"
                    )

                negotiated = (
                    group_match.group(1) if group_match else "UNKNOWN"
                )
                if negotiated == "UNKNOWN":
                    # Both client and server are restricted to one group.
                    # A successful fresh handshake therefore selects that group.
                    negotiated = group
                    print(
                        f"  OpenSSL omitted group summary; "
                        f"using configured group {group}"
                    )

                if negotiated.upper() != group.upper():
                    raise RuntimeError(
                        f"Expected {group}, negotiated {negotiated}"
                    )

                rows.append({
                    "configuration": name,
                    "requested_group": group,
                    "negotiated_group": negotiated,
                    "run": run,
                    "elapsed_seconds": round(elapsed, 6),
                    "bytes_read": int(byte_match.group(1)),
                    "bytes_written": int(byte_match.group(2)),
                    "cpu_seconds": round(
                        float(user_match.group(1)) +
                        float(sys_match.group(1)), 6
                    ) if user_match and sys_match else "",
                    "peak_memory_kb": int(mem_match.group(1))
                    if mem_match else "",
                })

                print(
                    f"{name:9} {run:02}/{RUNS} "
                    f"{elapsed:.4f}s "
                    f"read={rows[-1]['bytes_read']} "
                    f"written={rows[-1]['bytes_written']} "
                    f"group={negotiated}"
                )
        finally:
            server.terminate()
            try:
                server.wait(timeout=3)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()

    return rows

def main():
    if not Path("/usr/bin/time").exists():
        raise SystemExit("Install the time package: sudo apt install time")
    if not CERT.exists() or not KEY.exists():
        raise SystemExit("Test certificate missing. Check ~/pqc-project/certs/")

    all_rows = []
    for name, group in CONFIGS.items():
        print(f"\nTesting {name}: {group}")
        all_rows.extend(run_config(name, group))

    csv_path = RESULTS / "benchmark.csv"
    with csv_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=all_rows[0].keys())
        writer.writeheader()
        writer.writerows(all_rows)

    print("\nSUMMARY (mean across successful runs)")
    for name in CONFIGS:
        subset = [r for r in all_rows if r["configuration"] == name]
        print(f"\n{name.upper()}: {len(subset)} runs")
        for key in (
            "elapsed_seconds", "bytes_read",
            "bytes_written", "cpu_seconds", "peak_memory_kb"
        ):
            values = [float(r[key]) for r in subset if r[key] != ""]
            if values:
                print(
                    f"  {key}: mean={statistics.mean(values):.4f}, "
                    f"stdev={statistics.stdev(values):.4f}"
                    if len(values) > 1
                    else f"  {key}: mean={values[0]:.4f}"
                )

    print(f"\nCSV saved to: {csv_path}")

if __name__ == "__main__":
    main()
