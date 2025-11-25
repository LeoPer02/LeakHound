import logging
import os
import subprocess
import re
import sys
import xml.etree.ElementTree as ET


DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BODY_SENSORS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
}


logger = logging.getLogger(__name__)

def extract_permissions(manifest_output):

    permissions = []
    # Regular expression to match the permission lines in the manifest output
    permission_pattern = r'android.permission\.[\w\._-]+'

    # Find all occurrences of permissions in the output
    permissions = re.findall(permission_pattern, manifest_output)

    return permissions


def add_permissions_to_xml(xml_file, new_xml, permissions):
    # Parse the XML file
    tree = ET.parse(xml_file)
    root = tree.getroot()
    permissionSection = ET.SubElement(root, "DeclaredPermissions")
    for permission in permissions:
        new_permission = ET.SubElement(permissionSection, "permission")
        new_permission.text = permission

    # Write the modified XML to a file
    tree.write(new_xml)


def get_permissions_from_apk(apk_path, leak_path, extended_leak):
    try:
        logger.debug(f"Print new xml: {extended_leak} exists? {os.path.exists(extended_leak)}")
        with open(extended_leak, 'a'):
            pass
        logger.debug(f"AAPT2 command: {[os.getenv("AAPT2PATH"), 'd', 'xmltree', apk_path, '--file', 'AndroidManifest.xml']}")
        # Run the aapt2 command to dump the badging information
        result = subprocess.run(
            [os.getenv("AAPT2PATH"), 'd', 'xmltree', apk_path, '--file', 'AndroidManifest.xml'],
            capture_output=True,
            text=True,
            check=True
        )

        # Extract the permissions from the command output
        manifest_output = result.stdout
        temp_permissions = extract_permissions(manifest_output)
        permissions = []
        for permission in temp_permissions:
            if permission in DANGEROUS_PERMISSIONS:
                permissions.append(permission)
        permissions = list(set(permissions))
        add_permissions_to_xml(leak_path, extended_leak, permissions)
        return permissions
    except subprocess.CalledProcessError as e:
        print(f"Error executing aapt2: {e}")
        return []
    except FileNotFoundError as e:
        print(f"aapt2 command not found. Please ensure that aapt2 is installed and accessible.: {e}")
        return []

