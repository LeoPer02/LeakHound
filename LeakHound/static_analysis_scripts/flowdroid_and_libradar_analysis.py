#!/usr/bin/env python3
import os
import sys
import subprocess
import logging

# Configuration paths (adjust these to your installation)
# Download this file from the FlowDroid repo: https://github.com/secure-software-engineering/FlowDroid
FLOWDROID_JAR = "/path/to/soot-infoflow-cmd-jar-with-dependencies.jar"

ANDROID_PLATFORMS = "/path/to/android/sdk/platforms"

# Provide as well
SOURCES_SINKS = "/path/to/customSourcesAndSinks.txt"

# Clone the LibRadar repo https://github.com/pkumza/LibRadar
LIBRADAR_SCRIPT = "/path/to/LibRadar/LibRadar/libradar.py"

# Clone the LiteRadar repo: https://github.com/pkumza/LiteRadar
LITERADAR_SCRIPT = "/path/to/LiteRadar/literadar.py"

# FlowDroid analysis options
FLOWDROID_PATHALGO = "contextsensitive"  # path reconstruction mode
FLOWDROID_CALLBACK_TIMEOUT = 60         # callback collection timeout (seconds)
FLOWDROID_DF_TIMEOUT = 300              # data-flow analysis timeout (seconds)
FLOWDROID_RESULT_TIMEOUT = 60           # result collection timeout (seconds)

# Setup logging: only critical errors will be logged
logging.basicConfig(filename='analysis.log', level=logging.CRITICAL,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Determine APK directory from argument (or use current directory)
if len(sys.argv) > 1:
    apk_folder = sys.argv[1]
else:
    apk_folder = os.getcwd()
apk_folder = os.path.abspath(apk_folder)
if not os.path.isdir(apk_folder):
    logging.critical(f"APK directory not found: {apk_folder}")
    sys.exit(1)

# List all APK files in the directory
apk_files = [f for f in os.listdir(apk_folder) if f.lower().endswith('.apk')]

for apk_name in apk_files:
    apk_path = os.path.join(apk_folder, apk_name)
    base_name = os.path.splitext(apk_name)[0]
    result_folder = os.path.join(apk_folder, base_name)

    # Skip APKs that were already processed
    if os.path.exists(result_folder):
        continue

    # Create results directory
    try:
        os.makedirs(result_folder, exist_ok=True)
    except Exception as e:
        logging.critical(f"Failed to create folder for {apk_name}: {e}")
        continue

    # ---- Run FlowDroid ----
    flowdroid_output = os.path.join(result_folder, "flowdroid_output.txt")
    flowdroid_error = os.path.join(result_folder, "flowdroid_error.txt")
    try:
        cmd = [
            "java", "-jar", FLOWDROID_JAR,
            "-a", apk_path,
            "-p", ANDROID_PLATFORMS,
            "-s", SOURCES_SINKS,
            "--pathalgo", FLOWDROID_PATHALGO,
            "-ct", str(FLOWDROID_CALLBACK_TIMEOUT),
            "-dt", str(FLOWDROID_DF_TIMEOUT),
            "-rt", str(FLOWDROID_RESULT_TIMEOUT)
        ]
        with open(flowdroid_output, 'w') as out_file:
            proc = subprocess.run(cmd, stdout=out_file, stderr=out_file)
        if proc.returncode != 0:
            with open(flowdroid_error, 'w') as err_file:
                err_file.write(f"FlowDroid failed with return code {proc.returncode}\n")
            logging.critical(f"FlowDroid failed for {apk_name}")
    except Exception as e:
        with open(flowdroid_error, 'w') as err_file:
            err_file.write(f"FlowDroid exception: {e}\n")
        logging.critical(f"FlowDroid exception for {apk_name}: {e}")

    # ---- Run LibRadar ----
    libradar_output = os.path.join(result_folder, "libradar_output.txt")
    libradar_error = os.path.join(result_folder, "libradar_error.txt")
    try:
        cmd = ["python3", LIBRADAR_SCRIPT, apk_path]
        with open(libradar_output, 'w') as out_file:
            proc = subprocess.run(cmd, stdout=out_file, stderr=out_file)
        if proc.returncode != 0:
            with open(libradar_error, 'w') as err_file:
                err_file.write(f"LibRadar failed with return code {proc.returncode}\n")
            logging.critical(f"LibRadar failed for {apk_name}")
    except Exception as e:
        with open(libradar_error, 'w') as err_file:
            err_file.write(f"LibRadar exception: {e}\n")
        logging.critical(f"LibRadar exception for {apk_name}: {e}")

    # ---- Run LiteRadar ----
    literadar_output = os.path.join(result_folder, "literadar_output.txt")
    literadar_error = os.path.join(result_folder, "literadar_error.txt")
    try:
        cmd = ["python3", LITERADAR_SCRIPT, apk_path]
        with open(literadar_output, 'w') as out_file:
            proc = subprocess.run(cmd, stdout=out_file, stderr=out_file)
        if proc.returncode != 0:
            with open(literadar_error, 'w') as err_file:
                err_file.write(f"LiteRadar failed with return code {proc.returncode}\n")
            logging.critical(f"LiteRadar failed for {apk_name}")
    except Exception as e:
        with open(literadar_error, 'w') as err_file:
            err_file.write(f"LiteRadar exception: {e}\n")
        logging.critical(f"LiteRadar exception for {apk_name}: {e}")