import json
import csv
from collections import defaultdict

# Input JSONL file path
jsonl_file = "trackers_results.jsonl"

# List of reference apps
reference_apps = [
    #app1, app2, app3, ..., appn
]

# Data structure to store counts per app per tracker type
app_tracker_counts = defaultdict(lambda: defaultdict(int))
all_tracker_types = set()

# Read JSONL and count tracker types
with open(jsonl_file, "r", encoding="utf-8") as f:
    for line in f:
        data = json.loads(line)
        app = data.get("package")
        if not app:
            continue

        for tracker in data.get("trackers", []):
            ttypes = tracker.get("type")
            if not ttypes:
                ttypes = ["other"]
            elif isinstance(ttypes, str):
                ttypes = [ttypes]

            for ttype in ttypes:
                app_tracker_counts[app][ttype] += 1
                all_tracker_types.add(ttype)

# Sort tracker types for consistent column order
sorted_tracker_types = sorted(all_tracker_types)

# Write CSV
csv_file = "tracker_counts.csv"
with open(csv_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    header = ["app"] + sorted_tracker_types
    writer.writerow(header)

    for app in reference_apps:
        row = [app] + [
            app_tracker_counts[app].get(t, "") for t in sorted_tracker_types
        ]
        writer.writerow(row)

print(f"Done: tracker counts written to {csv_file}")