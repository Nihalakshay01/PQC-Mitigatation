import csv
from pathlib import Path

root = Path.home() / "pqc-project"
results = root / "results"

source = results / "downgrade_detection.csv"
output = results / "pqc_labeled_dataset.csv"

with source.open(newline="") as f:
    rows = list(csv.DictReader(f))

with output.open("w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "test",
        "detected_label",
        "status",
        "evidence",
        "malicious_downgrade_confirmed",
    ])

    for row in rows:
        label = row["detected_label"]
        evidence = row["details"]

        # The current tests establish negotiation behavior only.
        writer.writerow([
            row["test"],
            label,
            row["status"],
            evidence,
            "NO",
        ])

print(f"Dataset saved: {output}")
print(f"Rows: {len(rows)}")
for row in rows:
    print(f"{row['test']}: {row['detected_label']}")
