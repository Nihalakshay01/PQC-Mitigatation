import csv
from pathlib import Path
from statistics import mean, stdev
import matplotlib.pyplot as plt

root = Path.home() / "pqc-project"
results = root / "results"

with open(results / "benchmark.csv", newline="") as f:
    rows = list(csv.DictReader(f))

configs = ["classical", "hybrid"]
metrics = [
    "elapsed_seconds",
    "cpu_seconds",
    "peak_memory_kb",
    "bytes_read",
    "bytes_written",
]

summary = {}
for config in configs:
    subset = [r for r in rows if r["configuration"] == config]
    summary[config] = {}
    for metric in metrics:
        values = [float(r[metric]) for r in subset]
        summary[config][metric] = (
            mean(values), stdev(values) if len(values) > 1 else 0
        )

with open(results / "benchmark_summary.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["configuration", "metric", "runs", "mean", "stdev"])
    for config in configs:
        for metric in metrics:
            avg, sd = summary[config][metric]
            writer.writerow([config, metric, 10, f"{avg:.6f}", f"{sd:.6f}"])

fig, axes = plt.subplots(1, 3, figsize=(12, 4))
for ax, metric, title in zip(
    axes,
    ["elapsed_seconds", "cpu_seconds", "peak_memory_kb"],
    ["Handshake elapsed time (s)", "CPU time (s)", "Peak memory (KB)"]
):
    averages = [summary[c][metric][0] for c in configs]
    errors = [summary[c][metric][1] for c in configs]
    ax.bar(configs, averages, yerr=errors, capsize=4)
    ax.set_title(title)
    ax.grid(axis="y", alpha=0.25)

fig.suptitle("PQCSentry: Classical vs Hybrid TLS")
fig.tight_layout()
fig.savefig(results / "benchmark_performance.png", dpi=180)
plt.close(fig)

fig, ax = plt.subplots(figsize=(7, 4))
x = range(2)
width = 0.35
ax.bar(
    [i - width/2 for i in x],
    [summary[c]["bytes_read"][0] for c in configs],
    width, label="Bytes read"
)
ax.bar(
    [i + width/2 for i in x],
    [summary[c]["bytes_written"][0] for c in configs],
    width, label="Bytes written"
)
ax.set_xticks(list(x), configs)
ax.set_ylabel("Bytes")
ax.set_title("TLS Handshake Data Exchange")
ax.legend()
ax.grid(axis="y", alpha=0.25)
fig.tight_layout()
fig.savefig(results / "benchmark_bytes.png", dpi=180)
plt.close(fig)

print("Files created:")
for name in [
    "benchmark_summary.csv",
    "benchmark_performance.png",
    "benchmark_bytes.png",
]:
    print(results / name)

print("\nMean results:")
for config in configs:
    print(f"\n{config.upper()}")
    for metric in metrics:
        avg, sd = summary[config][metric]
        print(f"{metric}: {avg:.6f} (SD {sd:.6f})")
