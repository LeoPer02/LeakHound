import json
import logging
import re
import subprocess

from sqlalchemy.testing.config import ident

logger = logging.getLogger(__name__)


class DeviceInfo:


    def __init__(self, device: str):
        """
        The only information needed to initialize this class is the device name (as presented in adb devices). The class will itself fetch the data from
        adb.
        :param device: AVD device name (as per shown with "adb devices")
        """

        self.device = device
        self.sim_operator = None
        self.sim_operator_country = None
        self.timezone = None
        self.hardware = None
        self.build_fingerprint = None
        self.build_flavor = None
        self.build_host = None
        self.build_id = None
        self.build_product = None
        self.build_tags = None
        self.build_type = None
        self.build_user = None
        self.build_description = None
        self.min_sdk = None
        self.android_version = None
        self.version_sdk = None
        self.model = None
        self.manufacturer = None
        self.brand = None
        self.abi = None
        self.locale = None
        self.pixel_density = None
        self.screen_size = None

        self.get_device_info()


    def to_json(self):
        return json.dumps(self.__dict__, indent=4)

    def to_dict(self):
        return self.__dict__

    def get_device_info(self):
        """Retrieves detailed information about a specific device."""
        device_id = self.device

        self.sim_operator = self.run_adb_command(["adb", "-s", device_id, "shell", "getprop", "gsm.operator.alpha"])
        self.sim_operator_country = self.run_adb_command(
            ["adb", "-s", device_id, "shell", "getprop", "gsm.operator.iso-country"])
        self.timezone = self.run_adb_command(["adb", "-s", device_id, "shell", "getprop", "persist.sys.timezone"])
        self.build_fingerprint = self.run_adb_command(
            ["adb", "-s", device_id, "shell", "getprop", "ro.bootimage.build.fingerprint"])
        self.build_description = self.run_adb_command(
            ["adb", "-s", device_id, "shell", "getprop", "ro.build.description"])
        self.build_flavor = self.run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.build.flavor"])
        self.build_host = self.run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.build.host"])
        self.build_id = self.run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.build.id"])
        self.build_product = self.run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.build.product"])
        self.build_tags = self.run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.build.tags"])
        self.build_type = self.run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.build.type"])
        self.build_user = self.run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.build.user"])
        self.min_sdk = self.run_adb_command(
            ["adb", "-s", device_id, "shell", "getprop", "ro.build.version.min_supported_target_sdk"])
        self.android_version = self.run_adb_command(
            ["adb", "-s", device_id, "shell", "getprop", "ro.build.version.release"])
        self.version_sdk = self.run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.build.version.sdk"])
        self.model = self.run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.product.model"])
        self.manufacturer = self.run_adb_command(
            ["adb", "-s", device_id, "shell", "getprop", "ro.product.manufacturer"])
        self.brand = self.run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.product.brand"])
        self.hardware = self.run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.hardware"])
        self.abi = self.run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.product.cpu.abi"])
        self.locale = self.run_adb_command(["adb", "-s", device_id, "shell", "getprop", "ro.product.locale"])

        # Get pixel density
        density_output = self.run_adb_command(["adb", "-s", device_id, "shell", "wm", "density"])
        if density_output:
            match = re.search(r"Physical density:\s*(\d+)", density_output)
            self.pixel_density = int(match.group(1)) if match else None

        # Get screen size
        size_output = self.run_adb_command(["adb", "-s", device_id,  "shell", "wm", "size"])
        if size_output:
            match = re.search(r"Physical size:\s*(\d+x\d+)", size_output)
            self.screen_size = match.group(1) if match else None

    @staticmethod
    def run_adb_command(command):
        """Runs an ADB shell command and returns the output, or None if it fails."""
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout.strip() if result.stdout.strip() else None
            else:
                logger.warning(f"Error running command {' '.join(command)}: {result.stderr.strip()}")
                return None
        except subprocess.SubprocessError as e:
            logger.warning(f"Exception running command {' '.join(command)}: {str(e)}")
            return None

# TEST ZONE
# device_info = DeviceInfo("emulator-5554")
# print(device_info.to_json())