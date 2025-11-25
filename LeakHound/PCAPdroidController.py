import logging
import re
import subprocess

logger = logging.getLogger(__name__)

class PCAPdroidController:
    def __init__(self, socks5_ip, socks5_port, package_name=None, pcap_dump_mode="vpn", device: str = ""):
        """
        Initialize the PCAPDroidCapture class with SOCKS5 proxy details and optional parameters.
        This assumes that you are using the modified version of PCAPdroid provided (which removes consent and remote server checks).

        This modified version could be deprecated/old at the time you're using this. If you wish to modify the app, tend your attention
        to the CaptureCtrl.java file, namely, for checks of the callingApp and remoteServer values passed and bypass those validations.

        :param socks5_ip: The IP address of the SOCKS5 proxy (mandatory)
        :param socks5_port: The port number of the SOCKS5 proxy (mandatory)
        :param package_name: The package name of the app to monitor (default: None, monitors all traffic)
        :param pcap_dump_mode: Capture mode (default: "vpn")
        """
        self.socks5_ip = socks5_ip
        self.socks5_port = socks5_port
        self.package_name = package_name
        self.pcap_dump_mode = pcap_dump_mode
        self.device = device

    def __run_adb_command(self, command1, check=True, stdout=None, stderr=None, text=True, capture_output=False):
        """Run a specified ADB command."""
        logger.info(f"[{self.device}] PCAP starting in port:{self.socks5_port}")

        try:


            command = ["adb"] + command1
            # If there's a specified device, use it, otherwise it's assumed only one device is available
            if self.device != "":
                command = ["adb", "-s", self.device] + command1

            result = subprocess.run(command, check=check, stdout=stdout, stderr=stderr, text=text, capture_output=capture_output)
            logger.info(f"Command '{command}' executed successfully.")
            return result
        except subprocess.CalledProcessError as e:
            logger.error(f"Error executing command '{command1}': {e}")
            return None

    def start_capture(self):
        """
        Start PCAPdroid capture with the specified configuration.
        """
        try:
            logger.debug("Starting capture...")
            # if the VPN app is running, stop it
            if self.__is_app_running("com.emanuelef.remote_capture"):
                self.__close_app("com.emanuelef.remote_capture")

            command = [
                "shell", "am", "start",
                "-e", "action", "start",
                "-e", "pcap_dump_mode", self.pcap_dump_mode,
                "-e", "socks5_enabled", "true",
                "-e", "socks5_proxy_ip_address", self.socks5_ip,
                "-e", "socks5_proxy_port", str(self.socks5_port),
                "-e", "app_filter", self.package_name,
                "-n", "com.emanuelef.remote_capture/.activities.CaptureCtrl"
            ]
            logger.debug(f"Starting with command: {" ".join(command)}")
            result = self.__run_adb_command(command)
            logger.info(f"Capture started for {self.package_name or 'all apps'} with SOCKS5 proxy at {self.socks5_ip}:{self.socks5_port}")

        except subprocess.CalledProcessError as e:
            logger.error(f"Error executing ADB command: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")

    def stop_capture(self):
        """
        Stop the PCAPdroid capture.
        """
        try:
            command = [
                "shell", "am", "start",
                "-e", "action", "stop",
                "-n", "com.emanuelef.remote_capture/.activities.CaptureCtrl"
            ]
            logger.debug(f"Stopping with command: {" ".join(command)}")
            result = self.__run_adb_command(command)
            self.__close_app("com.emanuelef.remote_capture")


        except subprocess.CalledProcessError as e:
            logger.error(f"Error executing ADB command: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")


    # Currently not working
    def __get_status(self):
        """
        Get the status of the proxy
        :return:
        """
        try:
            command = [
                "shell", "am", "start",
                "-e", "action", "get_status",
                "-n", "com.emanuelef.remote_capture/.activities.CaptureCtrl"
            ]
            results = self.__run_adb_command(command, capture_output=True, text=True)

            # Check if the command was successful
            if results.returncode != 0:
                print(f"Error running ADB command: {results.stderr}")
                return None

            # Extract the output
            output = results.stdout
            if output is None:
                return None

            print(output)
            # Look for the running status in the output using a regular expression
            match = re.search(r'running\s*=\s*(true|false)', output)
            if match:
                running_status = match.group(1) == "true"
                return running_status
            else:
                print("Failed to find the running status in the output.")
                return None

        except subprocess.CalledProcessError as e:
            logger.error(f"Error executing ADB command: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")

        return None


    def __is_app_running(self, package_name):
        """Checks if the app is running on the Android device."""
        try:
            # Check if the app is running by querying the list of processes
            result = self.__run_adb_command(["shell", "ps"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            # If the app's package name is in the result, the app is running
            if package_name in result.stdout:
                return True
            return False
        except subprocess.CalledProcessError as e:
            print(f"Error checking app status: {e}")
            return False

    def __close_app(self, package_name):
        """Closes the app on the Android device."""
        try:
            # Force stop the app if it's running
            self.__run_adb_command(
                ["shell", "am", "force-stop", package_name],
                check=True
            )
            logger.info(f"App {package_name} has been closed.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to stop the app: {e}")



# Example usage
# droid_capture = PCAPdroidCapture("192.168.1.246", "8087", "com.leonpk.testingfrida")
# print(f"Get Status: {droid_capture.get_status()}")
# print(f"Is PCAP open?: {droid_capture.is_app_running("com.emanuelef.remote_capture")}")
# print(f"Closing PCAP")
# droid_capture.close_app("com.emanuelef.remote_capture")
# print(f"Is PCAP open?: {droid_capture.is_app_running("com.emanuelef.remote_capture")}")
# droid_capture.start_capture()
# print(f"Is PCAP open?: {droid_capture.is_app_running("com.emanuelef.remote_capture")}")
# print(f"Status: {droid_capture.get_status()}")
# time.sleep(15)
# droid_capture.stop_capture()
# print("Stopped")
# print(f"Status: {droid_capture.get_status()}")
