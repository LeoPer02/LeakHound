import glob
import ipaddress
import json
import os.path
import platform
import queue
import random
import socket
import statistics
import subprocess
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from LeakHound.DeviceCommand import HelpCommand, StopDroidBot, StartDroidBot, StatusCommand, StopAnalysis
from LeakHound.DeviceController import DeviceController
from LeakHound.DeviceInfo import DeviceInfo
from LeakHound.NetTraceLogger import setup_logger
from LeakHound.TrafficInterceptor import CapturedTraffic
import traceback

global_lock = threading.Lock()  # lock used to access shared files

logger = setup_logger(os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs"), "netTraceCollector.log")

def exception_handler(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        # Call default handler for keyboard interrupts
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    print("Uncaught Exception:", "".join(traceback.format_exception(exc_type, exc_value, exc_traceback)))

sys.excepthook = exception_handler


class HoundEngine:
    """
    Class responsible for automating the network trace collection process from a list of apps.
    Things to keep in mind:
        - Run this class from withing the same directory in which it is declared.
        - The number of threads will be maxed at the number of AVD devices running at the time that __init__ is called. However, it's recommended to have 1 thread per avd. If you're feeling lazy, just put something crazy (Something bigger than ∞) and the __init__ will max it to the number of AVDs
        - This class will not take care of any setup from the AVD point-of-view and thus, expects it to be properly set up. In case of doubts, consult the README.md
        - The APKs for the apps must be provided in the format of a list containing their absolute path
        - The methods will expect the name of the file to be the package name of the app with _base or _{index} added. Since some applications (when downloaded from Play Store) are split into multiple apks, this tool was adapted to first look for {package_name}_base.apk, once it finds it, it will check for the existence of all split apks of format {package_name}_{index}.apk and then installs them together. If your app only has 1 apk, just name it {package_name}_base.apk
        - The analysis will try it's best to continue onto the next file even if an error occurs
        - A list of the apps already analyzed will be generated in the output folder with the name "__apps_analyzed.txt". If you notice that an app was not analyzed (no .json created) and it's also not present in "__apps_analyzed.txt" then it's likely that some crash/exception occurred during that analysis. To confirm, pass only that apk in the list and check the logs. Otherwise, the "__apps_analyzed.txt" will indicate "NO OUTPUT" for apps which did not generate traffic (common when the app has root/emulation/frida checks, SSL pinning, login wall, etc) "ERROR ..." when something bad happened and we were able to catch it (apk provided is not valid) and "" when the analysis was a success
        - The json generated will contain most of the information mitmproxy provides, as well as some statistics (is better to have it all from the get-go then not ;D) so expect the files to be chunky
        - This is not the class you should be using for pipelining the process for a single app. Use this to analyze apps in batches while you take your well deserved nap 😪
        - I know you don't make mistakes, but just to be extra sure, test the analysis on all AVDs with the :class:`DeviceController` directly to see if you get the results you expect. If it doesn't, it just saved you a night of a script logging errors.
    """

    def __init__(self, num_threads: int = 3, mitm_ip: str = "0.0.0.0",
                 output_folder: str = os.path.join(os.path.dirname(os.path.abspath(__file__)), "networkTracesJson"),
                 socks5_ip: str = "192.168.1.246", emulator_path: str = "emulator", frida: bool = False, frida_scripts: str = "",
                 persistent_frida: bool = False, timeout: int = 270, spawn_with_frida: bool = True, manual_control: bool = False):
        """
        Initializes the :class:`NetTraceCollector` class.
        :param num_threads: The number of threads to be used. It will be topped at the current number of adb devices online on the host
        :param mitm_ip: The interface in which to bind the mitm server(s) / Check also DeviceController "__start_mitm" as there are mitm configs there
        :param output_folder: The folder where the results will be stored
        :param socks5_ip: The ip address the SOCKS5 will communicate as the remote server (for most cases, use your host's private IP address)
        :param emulator_path: The path to the emulator binary to launch AVDs (if they disconnect during analysis)
        :param frida: Flag which activates and deactivates the use of Frida Scripts in the apps. Make sure you have the frida-server file withing the /data/local/tmp folder (use the file name frida-server)
        :param frida_scripts: Path to the folder with the frida scripts. Ignored if the frida bool flag is not set to True
        :param timeout: The maximum amount of time for which to run DroidBot (rare is the case where the timeout is not triggered).
        :param spawn_with_frida: When true, this will force DroidBot to launch the app in an attachable mode, inject the hooks and then resume the app. If False, a background thread will be created which will continuously check if the scripts were lost, in which case, it attempts to hook them again. NOTE: In development this flag only worked with one script at a time (you can simply place all scripts inside a single file), so we recommend you to do the same
        :param manual_control: This will disable DroidBot and instead, the user will be able to run the application manually. Once done, look into the terminal as it will provide you the steps to stop the analysis
        """

        # TODO
        # Change the way information is returned to the HoundEngine. Currently the threads migrate the information back. It would be more stable, and easier to
        # debug if we store the information for each application inside a file and then the HiveMaster class processes everything and combines them.
        # MITMPROXY apparently has a design issue where multiple mitmproxies overlap, and everything is sent to the same one. MIGHT have to do with the interfaces chosen for the listener
        # to fix this, maybe use a single mitmproxy, dump the requests in the filesystem of the device and later retrieve them
        # this also increase the efficiency of the tool given that only one mitm will be running at a time.

        if not self.__check_adb():
            logger.error(
                "No abd detected in the device. Make sure adb is added to the PATH. Try running it on the terminal \"adb --version\" to check if it's working")
            raise ValueError("No abd detected in your system")
        else:
            self.avd_devices = self.__get_avd_devices()
            # Make sure we have at most 1 thread per avd device
            if len(self.avd_devices) == 0:
                logger.error("You need at least one device online (reachable by adb). None were found...")
                raise ValueError("No devices detected with adb")
            self.num_threads = min(num_threads, len(self.avd_devices))

        if not self.__is_valid_ip(socks5_ip):
            logger.error(f"Invalid ip address provided for SOCKS5 client: {socks5_ip}")
            raise ValueError("Ip provided for socks5_ip is not a valid ip")

        if not self.__is_valid_ip(mitm_ip):
            logger.error(f"Invalid ip address provided for mitm server: {mitm_ip}")
            raise ValueError("Ip provided for mitm_ip is not a valid ip")

        self.ip = mitm_ip
        self.socks5_ip = socks5_ip
        self.output_folder = output_folder
        self.manual_control = manual_control
        self.timeout = 0
        if timeout > 0:
            self.timeout = timeout

        # Object which will hold the mapping between the device name and the corresponding avd name
        self.device_avd_mapping: dict[str, str] = {}
        self.__get_device_avd_names()

        self.frida: dict[str, bool] = {}
        self.spawn_with_frida = spawn_with_frida
        self.device_info: dict[str, DeviceInfo] = {}

        # Set the use of frida per device to the passed value
        # When performing the analysis of the device does not contain
        # frida-server in /data/local/tmp/ then make it False for that device
        for device in self.avd_devices:
            self.frida[device] = frida
            self.device_info[device] = DeviceInfo(device)
        self.frida_scripts: str
        self.persistent_frida = persistent_frida

        # Keep track of apps already analyzed to avoid repeating analysis
        self.apps_analyzed = os.path.join(output_folder, "__apps_analyzed.txt")

        # Create folder if it doesn't exist
        os.makedirs(self.output_folder, exist_ok=True)

        if not os.path.exists(self.apps_analyzed):
            with open(self.apps_analyzed, 'w'):
                logger.info(f"File {self.apps_analyzed} does not exist. Creating it...")

        if os.path.exists(frida_scripts) and self.frida:
            self.frida_scripts = frida_scripts

        self.emulator_path = emulator_path

        logger.info(f"Object created: {self}")

        logger.debug(f"AVD names:\n{self.device_avd_mapping}")
        for device in self.avd_devices:
            logger.debug(f"Does emulator detect {device}?: {self.__check_avd_exists(self.device_avd_mapping[device])}")

    def __str__(self):
        return (f"HoundEngine(\n"
                f"\tnum_threads={self.num_threads},\n"
                f"\tmitm_ip='{self.ip}',\n"
                f"\toutput_folder='{self.output_folder}',\n"
                f"\tsocks5_ip='{self.socks5_ip}',\n"
                f"\tavd_devices={self.avd_devices})\n"
                f"\temulator_path={self.emulator_path}\n"
                f"\tfrida={self.frida}\n"
                f"\tfrida_scripts={self.frida_scripts}\n"
                f"\tpersistent_frida={self.persistent_frida}")

    def run_analysis(self, file_path: str, device: str, cmd_queue: dict):
        """
        Main function for app analysis. This is the actual function executed per thread to each application provided.
        This will make some basic checks such as verifying files/folders exist, frida is available (if opted in), if file was already analyzed, etc.
        Then, this function will call :class:`DeviceController` to execute the actual analysis logic for the given device.

        Once the analysis is done, the function will gather the results, including some statistics calculated and performance metrics, store them in a dictionary,
        dump them as a json into the output folder and add the app to the "__apps_analyzed.txt".
        :param file_path: The path to the apk file. This function expects the file name to be {package_name}_base.apk (and possibly the split apks {package_name}_{index}.apk). More information in the :class:`HiveMaster` documentattion
        :param device: The name of the device (as per shown in adb with "adb devices") in which to run the analysis. This assumes the initial setup was manually performed. For more information about this setup, consult the README.md
        """

        logger.debug(f"Process file called for: {file_path}")
        package_name = self.__extract_package_name(file_path)

        if package_name is None or package_name == "":
            logger.error(f"Unable to extract package name from file: {file_path}, aborting...")
            return

        logger.debug(f"Package name extracted: {package_name}")

        if not os.path.exists(file_path):
            logger.error(f"File path provided {file_path} was not found, aborting...")
            with open(self.apps_analyzed, "r") as file:
                lines = file.readlines()
                cleaned_lines = [line.strip().split()[0] for line in lines if line.strip()]
                if package_name not in cleaned_lines:
                    self.__mark_file_as_analyzed(
                        package_name + f" ERROR :: File path provided {file_path} was not found")
            return

        if not self.__has_frida_server(device):
            logger.error("Frida server not found in the device. Make sure to add it as /data/local/tmp/frida-server")
            self.frida[device] = False

        if self.frida[device]:
            if not self.__frida_server_running(device):
                logger.warning("Frida server is not running (under the name \"frida-server\"). Attempting to start it...")
                self.__run_frida_server(device)
                if self.__frida_server_running(device):
                    logger.info("Frida server successfully started")
                else:
                    logger.warning(f"Failed to start frida for device {device}, proceeding without it...")
                    self.frida[device] = False

        with open(self.apps_analyzed, "r") as file:
            lines = file.readlines()
            cleaned_lines = [line.strip().split()[0] for line in lines if line.strip()]
            if package_name in cleaned_lines:
                logger.info(f"App {package_name} was already analyzed, skipping...")
                return
            else:
                logger.debug(f"App {package_name} not found in analyzed list, analyzing...")


        per_app_output_folder = os.path.join(self.output_folder, package_name.replace(".", "_"))
        os.makedirs(per_app_output_folder, exist_ok=True)

        mitm_controller = DeviceController(package_name, socks5_port=self.__get_available_port(),
                                              socks5_ip=self.socks5_ip,
                                              adb_device=device, apk_path=file_path,
                                              frida_flag=self.frida[device], frida_scripts=self.frida_scripts,
                                              persistent_frida=self.persistent_frida,
                                              timeout=self.timeout, output_folder=per_app_output_folder,
                                              spawn_with_frida=self.spawn_with_frida,
                                              manual_control=self.manual_control,
                                              command_queue=cmd_queue)

        ########################## PREPARATION ###########################
        self.__install_apk(file_path, package_name, device)
        self.__enable_wifi(device)
        ######################### RUN ANALYSIS ###########################
        start_time = time.perf_counter()
        traffic_results = mitm_controller.run()
        end_time = time.perf_counter()
        ########################### CLEAN UP #############################
        self.__uninstall_app(package_name, device)
        ##################################################################

        if len(traffic_results) == 0:
            logger.warning(f"App {package_name} did not return any network traces")
            # Add package to list of already analyzed apps even if no network traces were found
            self.__mark_file_as_analyzed(package_name + " NO OUTPUT")
            return
        else:
            logger.info(f"App {package_name} had a total of {len(traffic_results)} network traces")

        # Measure time taken to analyze the application
        execution_time = end_time - start_time

        # Get the file size
        apk_size = self.__get_apk_size(file_path)
        logger.debug(f"App size: {apk_size}")

        stats = self.__get_stats(traffic_results)
        logger.debug(f"Stats for app {package_name} has {len(stats)} entries")
        stats["execution_time"] = execution_time
        stats["apk_size"] = apk_size


        logger.debug("About to convert info to json:"
                     f"stats: {stats}"
                     f"device_info: {self.device_info[device].to_dict()}")

        device_info = {
            "device_info": self.device_info[device].to_dict()
        }

        traces = {
            "traces": [entry.to_dict() for entry in traffic_results]
        }

        # Save to a JSON file
        traces_path = os.path.join(per_app_output_folder, "network_traces.json")
        device_info_path = os.path.join(per_app_output_folder, "device_info.json")
        logger.debug(f"Saving json to {traces_path} and {device_info_path} for app: {package_name}")
        logger.info(f"Saving network traces for app {package_name} in {traces_path}")

        try:
            with open(traces_path, "w", encoding="utf-8") as f:
                json.dump(traces, f, indent=4, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to store network traces for app {package_name} with error: {e}")

        try:
            with open(device_info_path, "w", encoding="utf-8") as f:
                json.dump(device_info, f, indent=4, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to store device info for app {package_name} with error: {e}")


        self.__mark_file_as_analyzed(package_name)

    def __worker(self, device, file_queue, cmd_queue):
        """
        Worker function that processes files assigned to a specific device.
        This function is passed to the threads in the thread pool. It receives a device and the files associated to that device.
        With this, it iterates through each of the files, and once the analysis is done, pops the file out of the queue and moves to the next one.
        Since the files are pre-attributed to each thread, and therefore device, in the event that one of the devices goes down/crashes, the files mapped to that thread
        will not be analyzed. To solve that, this method will attempt to boot the AVD image once again. This is done by retrieving the AVD name from the adb device info and using
        that information, followed with the emulator binary (if passed, given that the user might not be working with emulators but actual devices) and so tries to boot the image again.

        :param device: Device on which to run the analysis
        :param file_queue: File queue holding the files which this device/thread will be responsible for analysing
        """
        while not file_queue.empty():
            file = file_queue.get()
            logger.info(f"About to start analysis of apk {file} inside the device {device}")

            # Checks if AVD is still on, if not, attempt to restart it
            if not self.__is_avd_running(device):
                logger.debug(f"Detected that device {device} with avd {self.device_avd_mapping[device]} is not running")
                self.__start_avd(self.device_avd_mapping[device])
                # Sleep for 10 seconds to give it time to start
                timeout = 20
                start_time = time.time()
                while not self.__is_avd_running(device):
                    time.sleep(1)
                    if time.time() - start_time > timeout:
                        logger.error("Failed to restart the device, stopping analysis in this device...")
                        return
                logger.debug(f"Elapsed time: {time.time() - start_time}s")
                logger.debug("Device is running once again")

            try:
                self.run_analysis(file, device, cmd_queue)
            except Exception as e:
                logger.error(f" ## ANALYSIS ERROR ##  An exception occurred while running analysis: {e}")

            logger.info("Task completed.")
            file_queue.task_done()

        logger.info(f"File queue depleted for device {device}, exiting...")

    def process_files_multithreaded(self, file_list):
        """
        Divides the files by the threads/devices available and creates a thread pool to run the analysis
        on each of the applications.

        :param file_list: List of the apk's absolute paths. (the expected naming convention for the files is explained in the :class:`HiveMaster` documentation)
        """

        ########################### DEBUG INFO #####################################
        logger.info("Starting multithread analysis with following environment:\n"
                    f"\t- Number of threads: {self.num_threads}\n"
                    f"\t- Devices found: {self.avd_devices}\n"
                    f"\t- Number of APKs to analyze: {len(file_list)}\n"
                    f"\t- MitM server: {self.ip} (port will be randomly assigned)\n"
                    f"\t- SOCKS5 server: {self.socks5_ip} (port will be randomly assigned)\n"
                    f"\t- Output Folder: {self.output_folder}\n"
                    f"\t- Apps analyzed folder: {self.apps_analyzed}")

        # Create a queue for each device
        device_queues = {device: queue.Queue() for device in self.avd_devices}
        device_cmd_queues = {device: queue.Queue() for device in self.avd_devices}
        stop_events      = {d: threading.Event() for d in self.avd_devices}


        # Distribute files (commands) across device queues in a round-robin fashion
        for index, command in enumerate(file_list):
            device = self.avd_devices[index % len(self.avd_devices)]  # Cycle through devices
            device_queues[device].put(command)


        # Start a thread for each device
        with ThreadPoolExecutor(max_workers=len(self.avd_devices)) as executor:
            for device, file_queue in device_queues.items():
                executor.submit(self.__worker, device, file_queue, device_cmd_queues)




        logger.debug("########## ABOUT TO EXIT MULTITHREADED ANALYSIS ##############")

    @staticmethod
    def __interactive_shell(ctx: dict):
        """
        ctx must contain:
          - 'stop_events': Dict[str, threading.Event]
          - we'll populate: 'commands' -> Dict[name,Command], 'should_exit'
        """
        # instantiate and register
        all_cmds = [
            StopAnalysis(),
            StatusCommand(),
            HelpCommand(),
            StartDroidBot(),
            StopDroidBot(),
        ]
        ctx["commands"] = {c.name: c for c in all_cmds}
        ctx["should_exit"] = False

        # show help on startup
        ctx["commands"]["help"].execute("", ctx)

        while not ctx["should_exit"]:
            text = input("Insert command >> ")

            text = text.strip()
            if not text:
                continue

            # split into command name + args
            parts = text.split(None, 1)
            name = parts[0]
            args = parts[1] if len(parts) > 1 else ""
            if name == "droidbot_start" and len(parts) > 2:
                args += parts[2]

            cmd = ctx["commands"].get(name)
            if cmd:
                try:
                    cmd.execute(args, ctx)
                except Exception as e:
                    print(f"error running `{name}`: {e}")
            else:
                print(f"unknown command: {name!r}.  Type `help`.")

        print("Exiting interactive console.")


    def __get_available_port(self, start=1024, end=65535) -> int:
        """
        Generate a random port within the given range and ensure it's available.
        The default values should be used since they represent the non-reserved port range

        :param start: Lowest port value
        :param end: Highes port value
        :return: Available port number
        """
        while True:
            port = random.randint(start, end)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                try:
                    s.bind((self.ip, port))  # Try binding to the port
                    return port  # If successful, return the port
                except OSError:
                    continue  # If binding fails, try another port


    @staticmethod
    def __is_valid_ip(ip: str) -> bool:
        """
        Check if the given string is a valid IPv4 or IPv6 address.

        :param ip: The IPv4/IPv6 address to be checked.
        :return: ``True`` if ``ip`` is a valid :class:`~ipaddress.IPv4Address` / :class:`~ipaddress.IPv4Address`, ```False``` otherwise.
        :rtype: bool
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    @staticmethod
    def __check_adb() -> bool:
        try:
            result = subprocess.run("adb --version", shell=True, check=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    text=True)
            if result.stderr:
                logger.error(f"Command Error: {result.stderr}")
                return False
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Command '{e.cmd}' failed with error {e.returncode}")
            logger.error(e.stderr)
            return False

    @staticmethod
    def __get_avd_devices() -> list[str]:
        # Run the adb command to get the list of devices attached

        # Make sure adb is running
        subprocess.run(["adb", "start-server"])

        result = subprocess.run(["adb", "devices"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check if the command was successful
        if result.returncode != 0:
            logger.error(f"Error: {result.stderr}")
            return []

        # Parse the output to get the list of devices
        device_lines = result.stdout.splitlines()

        # Filter out the header line and empty lines
        device_names = [line.split()[0] for line in device_lines[1:] if line.strip()]

        return device_names

    def __get_device_avd_names(self):
        for device_serial in self.avd_devices:
            try:
                # Retrieve the AVD name by sending a command to the emulator
                result = subprocess.run(
                    ['adb', '-s', device_serial, 'emu', 'avd', 'name'],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )
                avd_name = result.stdout.strip()
                if avd_name:
                    self.device_avd_mapping[device_serial] = avd_name.splitlines()[0]
                else:
                    self.device_avd_mapping[device_serial] = ''
            except subprocess.CalledProcessError:
                self.device_avd_mapping[device_serial] = ''

    def __check_avd_exists(self, avd_name):
        """
        Checks if the specified AVD exists.

        :param avd_name: Name of the AVD to check.
        :return: True if the AVD exists, False otherwise.
        """
        try:
            if self.emulator_path == "" or not avd_name or avd_name == "":
                logger.info("Emulator not provided, so will skip attempting to check AVD")
                return False
            result = subprocess.run(
                [self.emulator_path, '-list-avds'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            avd_list = result.stdout.splitlines()
            return avd_name in avd_list
        except Exception as e:
            print(f"Error checking AVD existence: {e}")
            return False

    def __start_avd(self, avd_name) -> bool:
        """
        Starts the specified AVD if it exists and detaches the process.

        :param avd_name: Name of the AVD to start.
        :return: True if the emulator is started successfully, False otherwise.
        """
        if self.__check_avd_exists(avd_name):
            try:
                # Prepare the command to start the emulator
                if self.emulator_path == "" or not avd_name or avd_name == "":
                    logger.info("Emulator or avd name not provided, so will skip attempting to start AVD")
                    return False
                command = [self.emulator_path, '-avd', avd_name]

                # Determine the platform to set appropriate startupinfo
                if platform.system() == 'Windows':
                    # On Windows, use CREATE_NEW_CONSOLE to detach the process
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    subprocess.Popen(command, startupinfo=startupinfo, creationflags=subprocess.CREATE_NEW_CONSOLE)
                else:
                    # On Unix-like systems, use setsid to start the process in a new session
                    subprocess.Popen(command, preexec_fn=os.setsid, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)

                print(f"Starting AVD '{avd_name}'...")
                return True
            except Exception as e:
                print(f"Error starting AVD: {e}")
                return False
        else:
            print(f"AVD '{avd_name}' does not exist.")
            return False

    @staticmethod
    def __is_avd_running(avd_name):
        """
        Checks if the specified AVD is currently running.

        :param avd_name: Name of the AVD to check.
        :return: True if the AVD is running, False otherwise.
        """
        try:
            if not avd_name or avd_name == "":
                logger.info("Avd name not provided, so will skip attempting to start AVD")
                return False
            result = subprocess.run(
                ['adb', 'devices'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            devices_output = result.stdout.splitlines()
            for line in devices_output:
                if avd_name in line and 'device' in line:
                    return True
            return False
        except Exception as e:
            print(f"Error checking if AVD is running: {e}")
            return False

    @staticmethod
    def __extract_package_name(file_path: str) -> str:
        """

        :param file_path:
        :return:
        """
        # Extract the filename (without the directory path)
        filename = os.path.basename(file_path).replace("_base", "")

        # Remove the file extension
        name_without_extension, _ = os.path.splitext(filename)

        return name_without_extension

    def __install_apk(self, apk_file: str, package_name: str, device: str) -> bool:
        try:
            # Run adb install command to install the APK
            if self.__is_app_installed(package_name, device):
                logger.info(f"APK {apk_file} already installed, skipping")
                return True

            logger.info(f"Installing apk: {apk_file}")
            split_apks = self.__get_split_apks(apk_file)
            if len(split_apks) == 0:
                subprocess.run(["adb", "-s", device, "install", apk_file], check=True)
                if self.__is_app_installed(package_name, device):
                    logger.info(f"App {package_name} installed")
                    return True
            else:
                command = ["adb", "-s", device, "install-multiple", apk_file, *split_apks]
                logger.debug(f"Multiple apks detected, running: {command}")
                subprocess.run(command, check=True)
                if self.__is_app_installed(package_name, device):
                    logger.info(f"App {package_name} installed")
                    return True
        except subprocess.CalledProcessError:
            # Try again but with the -t tag (for test packages)
            logger.debug("Failed to install package. Attempting with -t flag (for testing packages)")
            try:
                split_apks = self.__get_split_apks(apk_file)
                if len(split_apks) == 0:
                    subprocess.run(["adb", "-s", device, "install", "-t", apk_file], check=True)
                    if self.__is_app_installed(package_name, device):
                        logger.info(f"App {package_name} installed")
                        return True
                else:
                    command = ["adb", "-s", device, "install-multiple", "-t", apk_file, *split_apks]
                    logger.debug(f"Multiple apks detected, running: {command}")
                    subprocess.run(command, check=True)
                    if self.__is_app_installed(package_name, device):
                        logger.info(f"App {package_name} installed")
                        return True
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to install APK {apk_file}: {e}")
                return False

        return False

    def __uninstall_app(self, package_name: str, device: str) -> bool:
        try:
            # Run adb install command to uninstall the APK
            if not self.__is_app_installed(package_name, device):
                logger.info(f"APK {package_name} already uninstalled, skipping")
                return True

            logger.info(f"Uninstalling apk: {package_name}")
            subprocess.run(["adb", "-s", device, "shell", "pm", "uninstall", package_name], check=True)
            if not self.__is_app_installed(package_name, device):
                logger.info(f"App {package_name} uninstalled")
                return True
        except subprocess.CalledProcessError:
            logger.error(f"Failed to uninstall APK {package_name}.")

        logger.error(f"Failed to uninstall APK {package_name}")
        return False

    def __get_split_apks(self, apk_file: str) -> list:
        apk_list = []
        try:
            folder_path = os.path.dirname(apk_file)  # Correct way to get folder path
            package_name = self.__extract_package_name(apk_file)

            # Use glob to match files ending with {package_name}_*.apk
            pattern = os.path.join(folder_path, f"{package_name}_*.apk")
            apk_list = glob.glob(pattern)

            # Remove the base APK from the list, if it exists
            apk_list = [apk for apk in apk_list if os.path.abspath(apk) != os.path.abspath(apk_file)]

            logger.debug(f"Split files: {apk_list}")

        except Exception as e:
            logger.debug(f"Exception while trying to retrieve split apks: {e}")
        finally:
            return apk_list


    @staticmethod
    def __is_app_installed(package_name: str, device: str) -> bool:
        """
        As the name suggest, it checks if the package is installed in the device provided
        :param package_name: The name of package to check
        :param device: The avd device in which the check is to be performed
        :return: Boolean indicating if the app is installed or not
        """
        try:
            # Run adb command to check if the app is installed
            result = subprocess.run(
                ["adb", "-s", device, "shell", "pm", "list", "packages", package_name],
                check=True, capture_output=True, text=True
            )
            # If the result contains the package name, it means the app is installed
            if package_name in result.stdout:
                return True
            return False
        except subprocess.CalledProcessError:
            return False

    def __mark_file_as_analyzed(self, package_name: str):
        timeout = 5  # Wait a maximum of 5 seconds to acquire the lock. If it timeouts, simply move on
        lock_acquired = global_lock.acquire(timeout=timeout)

        if not lock_acquired:
            logger.warning(f"Failed to acquire lock for analyzed list for package {package_name}, skipping step...")
            return

        # Add package to list of already analyzed apps
        # Make sure to do this with a lock
        # The with is used here to make sure the lock is released even if it crashes
        try:
            with open(self.apps_analyzed, "a") as file:
                file.write(package_name + '\n')
        except FileNotFoundError as fnf_error:
            logger.error(f"File not found: {fnf_error}")
        except PermissionError as perm_error:
            logger.error(f"Permission denied: {perm_error}")
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")
        finally:
            global_lock.release()  # Ensure the lock is always released

    def __reset_analyzed_packages(self):
        """
        This function will reset the analyzed apps list.
        With "reset" we mean, removing the entries of the apps which failed for some reason. The reset is done by checking which apps have
        a .json and keep those in the list. Every other app is removed. If you only want to remove a select few, remove them manually
        """
        # Get a list of files in the folder
        try:
            files = os.listdir(self.output_folder)
            # Filter the files that end with .json and return just the filenames (without path or extension)
            json_files = [os.path.splitext(file)[0] for file in files if file.endswith('.json')]


            with open(self.apps_analyzed, "r") as f:
                initial_lines = len(f.readlines())
                logger.info(f"{initial_lines} packages were present in the list. New number will be {len(json_files)}")

            with open(self.apps_analyzed, "w") as analyzed_list:
                # Opening the file with "w" will delete everything inside
                for file in json_files:
                    package_name = self.__extract_package_name(file)
                    if package_name is not None and package_name != "":
                        analyzed_list.write(package_name + "\n")

        except FileNotFoundError:
            logger.error(f"The directory {self.output_folder} does not exist.")
        except PermissionError:
            logger.error(f"Permission denied to access {self.output_folder}.")

    def __get_apk_size(self, apk_file: str) -> int:
        split_apks = self.__get_split_apks(apk_file)
        final_size = os.path.getsize(apk_file)
        for apk in split_apks:
            final_size += os.path.getsize(apk)

        return final_size

    @staticmethod
    def __has_frida_server(device):
        try:
            result = subprocess.run(
                ["adb", "-s", device, "shell", "ls", "/data/local/tmp/frida-server"],
                check=True, capture_output=True, text=True
            )

            # Check if the output contains the file path
            if "/data/local/tmp/frida-server" in result.stdout.strip():
                return True
            return False

        except subprocess.CalledProcessError:
            # If the command fails, it means the file does not exist
            return False

    @staticmethod
    def __frida_server_running(device):
        try:
            # Properly quote and escape the command
            result = subprocess.run(
                ["adb", "-s", device, "shell", "ps", "|", "grep", "frida-server"],
                check=True, capture_output=True, text=True
            )

            # Check if ps contains frida-server
            if "frida-server" in result.stdout.strip():
                return True
            return False

        except subprocess.CalledProcessError as e:
            logger.error(f"Error while checking if frida server is running for command {' '.join(['adb', '-s', device, 'shell', 'ps', '|', 'grep', 'frida-server'])}: {e}")
            return False


    @staticmethod
    def __run_frida_server(device):
        try:
            # Run the frida-server using adb shell with su to gain root access
            subprocess.run(
                ["adb", "-s", device, "shell", "su", "-c", "nohup /data/local/tmp/frida-server 1>/dev/null 2>&1 &"],
                check=True
            )
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to start frida-server on the device {device}: {e}")


    @staticmethod
    def __enable_wifi(device: str):
        # Turn off Airplane mode
        subprocess.run(["adb", "-s", device, "shell", "settings", "put", "global", "airplane_mode_on", "0"])

        # Turn on Wi-Fi
        subprocess.run(["adb", "-s", device, "shell", "svc", "wifi", "enable"])

    ########################### STAT METHOD #######################################

    @staticmethod
    def __get_stats(results: list[CapturedTraffic]) -> dict[str, float]:
        hosts_collection = defaultdict(int)
        request_no_response = 0
        ok_response = 0
        get_method = 0
        post_method = 0
        put_method = 0
        delete_method = 0
        head_method = 0
        options_method = 0
        patch_method = 0
        trace_method = 0
        connect_method = 0
        other_methods = 0  # For any unexpected methods
        for result in results:

            # Count the number of occurrences of each host
            url = result.request.url
            try:
                parsed_url = urlparse(result.request.pretty_url)
                url = parsed_url.hostname  # Extracts the host (domain) part
            except Exception as e:
                # Handle the case where URL parsing fails
                logger.warning(f"Error extracting host from URL: {result.request.pretty_url}. Error: {e}")

            hosts_collection[url] += 1

            # Count the number of requests without responses
            if result.response is None:
                request_no_response += 1
            # Count the number of requests with status code 200
            elif result.response.status_code == 200:
                ok_response += 1

            # Checking HTTP method
            if result.request.method == "GET":
                get_method += 1
            elif result.request.method == "POST":
                post_method += 1
            elif result.request.method == "PUT":
                put_method += 1
            elif result.request.method == "DELETE":
                delete_method += 1
            elif result.request.method == "HEAD":
                head_method += 1
            elif result.request.method == "OPTIONS":
                options_method += 1
            elif result.request.method == "PATCH":
                patch_method += 1
            elif result.request.method == "TRACE":
                trace_method += 1
            elif result.request.method == "CONNECT":
                connect_method += 1
            else:
                other_methods += 1  # Catch any unknown HTTP methods

        try:
            # Convert the values (counts) from the hosts_collection to a list for statistics
            counts = list(hosts_collection.values())

            # Create stats dictionary
            stats = {
                "total_traces": sum(counts),
                "unique_strings": len(hosts_collection),
                "mean": statistics.mean(counts) if counts else 0,
                "max_count": max(counts, default=0),
                "min_count": min(counts, default=0),
                "median": statistics.median(counts) if counts else 0,
                "mode": statistics.mode(counts) if counts else 0,
                "stdev": statistics.stdev(counts) if len(counts) > 1 else 0,
                "variance": statistics.variance(counts) if len(counts) > 1 else 0,
                "no_response": request_no_response,
                "ok_response": ok_response,
                "get_method_count": get_method,
                "post_method_count": post_method,
                "put_method_count": put_method,
                "delete_method_count": delete_method,
                "head_method_count": head_method,
                "options_method_count": options_method,
                "patch_method_count": patch_method,
                "trace_method_count": trace_method,
                "connect_method_count": connect_method,
                "other_method_count": other_methods
            }
            return stats
        except Exception as e:
            logger.error(f"Exception while trying to build stat object: {e}")


def main():
    netTraceCollector = HoundEngine(100,
                                    emulator_path="path/to/emulator.exe", # You can find this
                                    frida=True, frida_scripts="path/to/scripts",
                                    timeout=180, spawn_with_frida=True, manual_control=False)

    apk_list = [os.path.abspath(
        os.path.join("/path/to/folder/with/apks", file))
        for file in os.listdir("/path/to/folder/with/apks")
        if file.endswith("base.apk")] # This expects the file to end with base.apk. Something like instagram_base.apk

    print(f"About to analyze {len(apk_list)} apks")
    time.sleep(2)
    netTraceCollector.process_files_multithreaded(apk_list)


# TEST ZONE
if __name__ == "__main__":
    main()
