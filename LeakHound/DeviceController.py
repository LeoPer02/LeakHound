import asyncio
import glob
import json
import logging
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time

import frida
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster
from spacy.tokens.doc import defaultdict

from LeakHound.FridaManager import FridaManager
from LeakHound.PCAPdroidController import PCAPdroidController
from LeakHound.TrafficInterceptor import TrafficInterceptor, CapturedTraffic

logger = logging.getLogger(__name__)
logging.getLogger("hpack").setLevel(logging.CRITICAL) # Remove DroidBot's logging to avoid spam

class DeviceController:
    """Manages mitmproxy execution and result retrieval."""

    def __init__(self, package_name: str, apk_path: str, output_folder: str, socks5_port: int, socks5_ip="192.168.1.246", adb_device: str = "",
                 frida_flag: bool = False, frida_scripts: str = None, persistent_frida: bool = False, timeout: int = 270, spawn_with_frida: bool = True,
                 manual_control: bool = False, command_queue: queue.Queue = None):
        self.pcap_thread = None
        self.mitm_thread = None
        self.manual_control = manual_control
        self.command_queue = command_queue
        self.port = socks5_port
        self.interceptor = TrafficInterceptor()
        self.timeout = 1
        if timeout > 0:
            self.timeout = timeout


        # Initialize the event loop
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        if not os.path.exists(output_folder):
            logger.error(f"Output folder provided {output_folder} does not exist")
            return
        self.output_folder = output_folder

        self.master = None
        self.package_name = package_name
        self.adb_device = adb_device
        # Initialize PCAPdroid
        self.pcap_capture = PCAPdroidController(socks5_port=self.port, socks5_ip=socks5_ip, package_name=package_name, device=adb_device)

        self.apk_path = apk_path
        if not os.path.exists(apk_path):
            raise ValueError(f"APK path provided does not exist: {apk_path}")

        self.frida = frida_flag
        self.spawn_with_frida = spawn_with_frida
        self.frida_scripts = []
        if self.frida and frida_scripts:
            self.frida_scripts = frida_scripts
        # Output list
        self.captured_traffic: list[CapturedTraffic] = []
        self.frida_results: dict[str, list[str]] = {}
        self.persistent_frida = persistent_frida

    async def __start_mitm(self):
        """Starts mitmproxy in an async function."""
        logger.info(f"[{self.adb_device}] mitmproxy listening on 0.0.0.0:{self.port}")

        # Forward port
        logger.debug(f"Forwarding port {self.port} with command: {" ".join(["forward", f"tcp:{self.port}", f"tcp:{self.port}"])}")
        self.__run_adb_command(["forward", f"tcp:{self.port}", f"tcp:{self.port}"])
        options = Options(listen_host="0.0.0.0", listen_port=self.port, mode=["socks5"])
        self.master = DumpMaster(options)
        self.master.addons.add(self.interceptor)

        # Run mitmproxy asynchronously
        await self.master.run()

    def __start_pcap(self):
        """Start the PCAPdroid capture in a separate process."""
        self.pcap_capture.start_capture()

    def __stop_pcap(self):
        """Stop the PCAPdroid capture in a separate process."""
        self.pcap_capture.stop_capture()

    def __stop_mitm(self):
        """Stops mitmproxy gracefully."""
        logger.info("Stopping mitmproxy...")
        self.__run_adb_command(["forward", "--remove", f"tcp:{self.port}"])

        # Once mitmproxy finishes, send results to main thread
        results = self.interceptor.get_results()
        self.captured_traffic = results
        if self.master:
            self.master.shutdown()

    def stop(self) -> list[CapturedTraffic]:
        """Stops both mitmproxy and PCAPdroid."""
        # Stop mitmproxy
        self.__stop_mitm()
        self.__stop_pcap()
        logger.debug(f"Traffic captured: {len(self.captured_traffic)}")
        return self.captured_traffic


    def run(self) -> list[CapturedTraffic]:
        """Runs both mitmproxy and PCAPdroid in separate threads."""

        # Start PCAPdroid capture in a separate thread
        self.pcap_thread = threading.Thread(target=self.__start_pcap, daemon=True)
        self.pcap_thread.start()

        # Start MitmProxy in a separate thread
        self.mitm_thread = threading.Thread(target=self.__run_mitm, daemon=True)
        self.mitm_thread.start()

        # TODO
        # Add a more robust check to see if mitm and PCAPdroid are currently up and running
        logger.debug(
            "############ Sleeping for 3 seconds to give time for PCAPdroid and MitM to initiate. A more robust check should be placed here #################")
        logger.debug(f"APK path = {self.apk_path}")
        time.sleep(3)
        start_time = time.time()

        try:

            frida_manager = None
            temp_dir = None

            # Here we have 2 options:
            #
            # - Run DroidBot as per usual and create a background thread (FridaManager) which will operate in an infinite loop checking if the scripts are still running
            # if not, try to attach them again. This is the more simple and stable approach, but it means that we run the risk of losing information (the time it takes for the
            # scripts to attach while the app is still running)
            #
            # - Use the modifications made on DroidBot to force it into launching the app in an attachable mode, inject the scripts and then run the app (Doing this for every app start).
            # This makes it lose less information from the app however, this approach is more volatile depending on the scripts and can only handle a single script (In developing using more than one script would break frida, so we simply joined every script into a single file). Feel free to experiment
            #
            # By default the second option will be used, but this can be changed with a flag in the main class

            if self.frida and not self.spawn_with_frida:
                frida_manager = FridaManager(self.package_name, self.frida_scripts, self.adb_device, self.output_folder, persistent_frida=self.persistent_frida)
                frida_manager.start_frida()
            else:
                temp_dir = tempfile.mkdtemp()
                logger.debug(f"Temp directory created at: {temp_dir}")


            # This allows the user to control the app himself
            # If set to True, the user can traverse the app, and send commands to the app
            # Otherwise, it just runs the app as per usual with droidbot
            if not self.manual_control:
                self.__run_droidbot(timeout=self.timeout, frida_scripts=self.frida_scripts, frida_output_folder=temp_dir, package_name=self.package_name)
            else:
                logger.debug("Entering manual control loop")
                DEVICE = frida.get_device(self.adb_device)
                # Spawn the app (gets you a pid)
                pid = DEVICE.spawn([self.package_name])

                # Attach to it
                session = DEVICE.attach(pid)

                def on_message(message, data=None):

                    """Handles messages from Frida scripts and writes output to files."""
                    print(f"Received message from frida: {message}")
                    if message is None:
                        return

                    if message["type"] == "send":
                        try:
                            if "payload" in message:
                                payload = message["payload"]

                                try:
                                    script_name = payload.get("script", "common")
                                    msg_content = payload.get("msg", None)

                                    if msg_content is not None:
                                        output_path = os.path.join(temp_dir, f"{script_name}.txt")

                                        with open(output_path, "a", encoding="utf-8") as frida_file:
                                            json.dump({"script": script_name, "msg": msg_content}, frida_file)
                                            frida_file.write("\n")

                                except Exception as e:
                                    print(f"Malformed payload, defaulting to 'common'. Error: {e}")
                                    output_path = os.path.join(temp_dir, "common.txt")
                                    with open(output_path, "a", encoding="utf-8") as frida_file:
                                        json.dump({"script": "common", "msg": payload}, frida_file)
                                        frida_file.write("\n")
                            else:
                                print(f"Payload missing in message: {message}")
                                pass
                        except Exception as e:
                            print(f"Message {message} raised an exception: {e}")
                            pass

                    else:
                        # logger.debug(f"Received error message: {message}")
                        pass

                # Optionally load & create your script
                frida_scripts = self.__list_js_files(self.frida_scripts)
                for script in frida_scripts:
                    with open(script) as f:
                        script = session.create_script(f.read())
                        script.on("message", on_message)
                    script.load()

                # Resume the process so it actually starts
                DEVICE.resume(pid)
                while True:
                    text = input("Type quit() to stop")
                    if text == "quit()":
                        break

                logger.debug("Exiting manual control loop")
                session.detach()  # stop your instrumentation
                # then either:
                DEVICE.kill(pid)  # kills the spawned process

            # Stop frida thread
            if self.frida and frida_manager is not None and not self.spawn_with_frida:
                self.frida_results = frida_manager.stop_frida()

            # Collect the frida output from the tempfolder and delete it
            else:
                self.frida_results = self.__parse_json_logs(temp_dir)
                shutil.rmtree(temp_dir)
                if self.frida_results != {}:
                    with open(os.path.join(self.output_folder, "frida_traces.json"), "w") as f:
                        json.dump(self.frida_results, f)

            logger.debug(f"Droibot finished with {int(time.time() - start_time)} seconds left")
        except Exception as e:
            logger.error(f"Exception raised while running DroidBot/Monkey: {e}")


        results = self.stop()

        self.pcap_thread.join()
        self.mitm_thread.join()

        return results


    def __run_mitm(self):
        """Runs the mitmproxy tool in the event loop."""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            # Start mitmproxy
            self.loop.run_until_complete(self.__start_mitm())
        except Exception as e:
            logger.error(f"Error running mitmproxy: {e}")
        finally:
            logger.debug("Stopping mitm server...")
            if self.loop.is_running():
                self.loop.stop()
            self.loop.close()

    def __run_monkey_test(self, timeout: int | None = None):
        monkey_command = [
            "shell", "monkey", "-p", self.package_name, "-v", "500",
            "--pct-touch", "80", "--pct-motion", "14", "--pct-trackball", "5",
            "--pct-nav", "1", "--throttle", "1500"
        ]

        logger.info(f"Running Monkey exerciser with command: {f"adb -s {self.adb_device} {monkey_command}"}")

        # Run the monkey test
        self.__run_adb_command(monkey_command, timeout=timeout)

    def __run_droidbot(self, timeout: int = 180, frida_scripts: str = None, frida_output_folder: str = None, package_name: str = None):
        working_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "droidbot")
        logger.debug(f"Running droidbot script at: {working_directory}")
        cmd = [sys.executable, "start.py", "-d", self.adb_device, "-is_emulator", "-a", self.apk_path,
               "-timeout", str(timeout), "-grant_perm", "-keep_env", "-keep_app", "-interval", "1"]

        if frida_output_folder:
            logger.debug("Forcing DroidBot to inject frida scripts")
            cmd.extend(['-frida_scripts', frida_scripts, '-frida_output_folder', frida_output_folder, '-package_name', package_name, '-device', self.adb_device])
            logger.debug(f"About to run: {cmd}")

        try:
            subprocess.run(
                cmd,
                cwd=working_directory,
            )
        except Exception as e:
            print(f"Error occurred while running the subprocess: {e}")


    def __run_adb_command(self, command1, check=True, stdout=None, stderr=None, text=True, capture_output=False, timeout=None):
        """Run a specified ADB command."""
        try:

            command = ["adb"] + command1
            # If there's a specified device, use it, otherwise it's assumed only one device is available
            if self.adb_device != "":
                command = ["adb", "-s", self.adb_device] + command1

            process_result = subprocess.run(command, check=check, stdout=stdout, stderr=stderr, text=text, capture_output=capture_output, timeout=timeout)
            logger.info(f"Command '{command}' executed successfully.")
            return process_result
        except subprocess.CalledProcessError as e:
            logger.error(f"Error executing command '{command1}': {e}")
            return None

    def __attach_with_timeout(self, timeout=5):
        """
        Try to attach to the target package within the given timeout period.
        If unsuccessful, return None.
        """
        device = frida.get_device(self.adb_device)
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                ses = device.attach(self.package_name)
                logger.info(f"Successfully attached to {self.package_name}")
                return ses  # Return the session if successful
            except frida.ProcessNotFoundError:
                logger.warning(f"Waiting for {self.package_name} to start...")
                time.sleep(0.3)  # Wait and retry

        logger.warning(f"Timeout reached. Could not attach to {self.package_name}. Proceeding...")
        return None  # Return None if the app never starts

    @staticmethod
    def __parse_json_logs(folder_path: str) -> dict[str, list[dict]]:
        """
        Parses a folder of JSON lines files, returning a dictionary of script_name to a list of messages.

        :param folder_path: Path to the folder containing the log files.
        :return: Dictionary with file base names (without extension) as keys, and list of parsed JSON messages as values.
        """
        result: dict[str, list[dict | str]] = {}

        if not os.path.isdir(folder_path):
            logger.error(f"Provided path is not a directory: {folder_path}")
            return result

        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)

            if not os.path.isfile(file_path):
                continue

            script_name = os.path.splitext(filename)[0]
            result[script_name] = []

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    for line_number, line in enumerate(f, 1):
                        try:
                            data = json.loads(line)
                            if isinstance(data, dict) and "script" in data and "msg" in data:
                                script_name = data.pop("script")  # Optionally use or discard this
                                msg = data.get("msg")

                                if isinstance(msg, dict) or isinstance(msg, str):
                                    result[script_name].append(msg)  # Store only the msg object
                                else:
                                    logger.warning(f"'msg' is not a dictionary in file '{filename}', line {line_number}. Skipping.")
                            else:
                                logger.debug(f"Line {line_number} in {filename} is missing 'script' or 'msg' key. Skipping.")
                        except json.JSONDecodeError as e:
                            logger.warning(f"JSON decode error in file '{filename}', line {line_number}: {e}. Skipping.")
                        except Exception as e:
                            logger.warning(f"Unexpected error reading line {line_number} in {filename}: {e}. Skipping.")
            except Exception as e:
                logger.error(f"Failed to read file '{filename}': {e}")

        return result

    @staticmethod
    def __list_js_files(dir_path):
        pattern = os.path.join(dir_path, '*.js')
        return glob.glob(pattern)

