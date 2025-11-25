import logging
import os
import re
import subprocess
import xml.etree.ElementTree as ET

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


def file_exists(file_path):
    if os.path.exists(file_path):
        return True
    return False


def retrieve_xml(file_path):
    if not file_exists(file_path):
        logger.error(f"XML file <{file_path}> does not exist, exiting...")
        return
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.read()  # Return the raw XML text
    except FileNotFoundError:
        logger.error(f"Error: The file {file_path} was not found.")
        return None
    except Exception as e:
        logger.error(f"Error reading XML file: {e}")
        return None


def is_valid_xml(file_path):
    # Check if file exists
    if not os.path.exists(file_path):
        return False

    # Check if file is empty
    if os.path.getsize(file_path) == 0:
        logger.error(f"Error: The file '{file_path}' is empty.")
        return False

    # Check if the file is a valid XML
    try:
        ET.parse(file_path)
        logger.info(f"The file '{file_path}' is a valid XML.")
        return True
    except ET.ParseError as e:
        logger.error(f"Error: The file '{file_path}' is not a valid XML. {e}")
        return False


def get_directories(path):
    try:
        # Get a list of all items in the path and filter only directories
        directories = [name for name in os.listdir(path) if os.path.isdir(os.path.join(path, name))]
        return directories
    except FileNotFoundError:
        print(f"The path '{path}' does not exist.")
        return []
    except PermissionError:
        print(f"Permission denied for accessing the path '{path}'.")
        return []
    except Exception as e:
        print(f"An error occurred: {e}")
        return []


def get_files_in_directory(directory):
    try:
        # Get the list of all files and directories in the given directory
        all_files_and_dirs = os.listdir(directory)

        # Filter out the directories, only keep files
        files = [file for file in all_files_and_dirs if os.path.isfile(os.path.join(directory, file))]

        return files

    except FileNotFoundError:
        logger.error(f"Error: The directory '{directory}' does not exist.")
        return []
    except PermissionError:
        logger.error(f"Error: Permission denied to access '{directory}'.")
        return []


def get_package_name(apk_path):
    logger.debug(
        f"AAPT2 command: {" ".join([os.getenv("AAPT2PATH"), 'dump', 'badging', apk_path, '|', 'findstr', 'package'])}")

    try:
        # Run the aapt2 command to dump the badging information
        result = subprocess.run(
            [os.getenv("AAPT2PATH"), 'dump', 'badging', apk_path, '|', 'findstr', 'package'],
            capture_output=True,
            text=True,
            check=True,
            shell=True
        )
        result = result.stdout
        match = re.search(r"package: name='([^']+)'", result)
        if match:
            return match.group(1)
        logger.error("Failed to retrieve package name. No match in command output")
        return None
    except subprocess.SubprocessError as e:
        logger.error(f"Failed to retrieve package name due to: {e}")
        return None



def get_f_droid_description(package_name):
    # URL of the app page on F-Droid
    url = f"https://f-droid.org/packages/{package_name}/"

    # Send a GET request to fetch the HTML content
    response = requests.get(url)

    if response.status_code == 200:
        # Parse the HTML response with BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find the description within the package-description div
        description_div = soup.find('div', class_='package-description')

        if description_div:
            # Extract the raw text content, removing extra HTML tags
            description = description_div.get_text(separator="\n", strip=True)
            return description
        else:
            return "NOT FOUND"
    else:
        logger.error(f"Error: Unable to fetch the page (status code {response.status_code})")
        return "NOT FOUND"


def get_play_store_description(package_name) -> str :
    url = f"https://play.google.com/store/apps/details?id={package_name}&hl=en"

    # Send a GET request to fetch the page content
    response = requests.get(url)

    if response.status_code == 200:
        # Parse the HTML response
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find the div with the class bARER, which contains the description
        description_div = soup.find('div', {'class': 'bARER'})

        if description_div:
            # Extract and clean the text, removing unwanted tags
            description = description_div.get_text(separator="\n", strip=True)
            return description
        else:
            return "NOT FOUND"
    else:
        logger.error(f"Error: Unable to fetch the page (status code {response.status_code})")
        return "NOT FOUND"


def get_app_description(apk_path) -> str | None:
    package_name = get_package_name(apk_path)
    if not package_name:
        return None

    # Try first in fdroid
    f_droid_description = get_f_droid_description(package_name)
    if f_droid_description != "NOT FOUND":
        return f_droid_description

    play_store_description = get_play_store_description(package_name)
    if play_store_description != "NOT FOUND":
        return play_store_description

    return None
