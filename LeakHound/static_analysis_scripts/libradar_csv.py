#!/usr/bin/env python3
import os
import glob
import json
import csv
import argparse
from pathlib import Path

def main(lib_dir: str, output_csv: str):
    # Prepare CSV file
    with open(output_csv, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["app", "package", "type"])

        # Iterate over all *_libradar.json files in lib_dir
        pattern = os.path.join(lib_dir, "*_libradar.json")
        for json_path in glob.glob(pattern):
            # Derive app name from filename: {package_name}_libradar.json
            filename = Path(json_path).name
            if not filename.endswith("_libradar.json"):
                continue
            app_name = filename[: -len("_libradar.json")]

            # Load and parse JSON array
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    entries = json.load(f)
            except Exception as e:
                print(f"Failed to parse {json_path}: {e}")
                continue

            # For each entry, extract "Package" and "Type"
            for entry in entries:
                pkg = entry.get("Package")
                if not isinstance(pkg, str) or pkg.strip() == "":
                    # Skip if "Package" is missing or empty
                    continue

                type_name = entry.get("Type") or "Unknown"
                if not isinstance(type_name, str) or type_name.strip() == "":
                    type_name = "Unknown"

                writer.writerow([app_name, pkg, type_name])

    print(f"CSV written to: {output_csv}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert libRadar JSON files to a CSV of app, package, type")
    parser.add_argument(
        "--lib_dir",
        required=False,
        default="libRadar",
        help="Directory containing {package_name}_libradar.json files (default: libRadar)",
    )
    parser.add_argument(
        "--output_csv",
        required=False,
        default="libradar_summary.csv",
        help="Output CSV file path (default: libradar_summary.csv)",
    )
    args = parser.parse_args()
    main(args.lib_dir, args.output_csv)