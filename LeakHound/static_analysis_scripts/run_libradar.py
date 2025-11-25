import os
import argparse
import subprocess

def run_libradar_on_apks(input_dir, output_dir, libradar_script):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    apk_files = [f for f in os.listdir(input_dir) if f.endswith(".apk")]

    for apk in apk_files:
        apk_path = os.path.abspath(os.path.join(input_dir, apk))
        output_file = os.path.abspath(os.path.join(output_dir, f"{os.path.splitext(apk)[0]}_libradar.json"))

        if os.path.exists(output_file):
            print(f"Skipping (already processed): {apk}")
            continue

        print(f"Processing: {apk}")
        libradar_dir = os.path.dirname(libradar_script)
        cmd = ["python2.7", libradar_script, apk_path]
        print(f"Running: {' '.join(cmd)} on {libradar_dir}")

        try:
            with open(output_file, "w") as outfile:
                subprocess.run(cmd, check=True, cwd=libradar_dir, stdout=outfile, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            print(f"Error processing {apk}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Input directory with APK files")
    parser.add_argument("--output", required=True, help="Output directory for LibRadar results")
    parser.add_argument("--libradar", required=True, help="Path to libradar.py")

    args = parser.parse_args()
    run_libradar_on_apks(args.input, args.output, args.libradar)