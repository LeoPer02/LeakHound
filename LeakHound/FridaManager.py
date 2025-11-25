import json
import logging
import os.path
import subprocess
import threading
import time

import frida

logger = logging.getLogger(__name__)


class FridaManager:
    def __init__(self, package_name, scripts, device, output_folder: str, timeout=15, persistent_frida: bool = False):
        self.package_name = package_name
        self.scripts = scripts
        self.stop_event = threading.Event()
        self.frida_thread_obj = None
        self.device = None
        self.adb_device = device
        self.session = None
        self.timeout = timeout
        self.persistent_frida = persistent_frida

        if not os.path.exists(output_folder):
            logger.error("Failed to create Frida Manager, output folder does not exist")
            return
        self.output_folder = output_folder

        # This will hold the messages received per script
        # Create the default entry which will hold all the messages without script value
        self.results: dict[str, list[str]] = {"common": []}

    def get_app_pid(self):
        try:
            # Run the adb command to get the PID of the app
            result = subprocess.run(
                ["adb", "-s", self.adb_device, "shell", "pidof", self.package_name],
                check=True, capture_output=True, text=True
            )
            # If a PID is found, return it
            pid = result.stdout.strip()
            if pid:
                return pid
            else:
                return None  # No PID found
        except subprocess.CalledProcessError as e:
            logger.debug(f"Error getting PID. App must not be running, trying again...: {e}")
            return None

    def on_message(self, message, data):
        """Handles messages from Frida scripts."""

        # Example:

        # var script_name = "script2";
        #
        # send({script: script_name, msg: "Hello from script2"});
        #
        # Interceptor.attach(Module.findExportByName(null, "read"), {
        #     onEnter: function(args) {
        #         send({script: script_name, msg: "read() called"});
        #     }
        # });

        logger.debug(f"Received message from frida on app {self.package_name}: {message}")

        if message["type"] == "send":
            try:
                # Check if the payload exists and is a string
                if "payload" in message:
                    #logger.debug(f"Payload: {message['payload']}")
                    payload = message['payload']

                    try:
                        script_name = payload.get("script", "common")
                        #logger.debug(f"Got script_name: {script_name}")
                        msg_content = payload.get("msg", None)

                        if msg_content is not None:
                            if script_name not in self.results:
                                self.results[script_name] = []
                            self.results[script_name].append(msg_content)
                    except Exception:
                        # Most likely the message does not adhere to json format
                        self.results["common"].append(payload)
                else:
                    logger.debug(f"Payload missing in message: {message}")
            except Exception as e:
                logger.debug(f"Message {message} raised an exception: {e}")

        else:
            logger.debug(f"Received error message: {message}")
            pass

    def load_script(self, session, script_path):
        """Loads a single Frida script into the session."""
        try:
            with open(script_path, "r") as f:
                script_code = f.read()

            script = session.create_script(script_code)
            script.on("message", self.on_message)  # Attach message handler
            script.load()
            logger.debug(f"Loaded script: {script_path}")
            return script

        except Exception as e:
            logger.debug(f"Failed to load {script_path}: {e}")
            return None

    def frida_thread(self):
        """Function to run Frida in a separate thread."""
        try:
            # Attach to the target app
            self.device = frida.get_device(self.adb_device)
            if self.device is None:
                return

            start_time = time.time()
            attached = False
            while time.time() - start_time < self.timeout:
                time.sleep(0.15)
                try:
                    pid = self.get_app_pid()
                    if pid is None:
                        continue
                    pid = int(pid)
                    self.session = self.device.attach(pid)
                    attached = True
                    logger.info(f"Attached frida to {self.package_name}")

                    # Load all scripts
                    scripts = [self.load_script(self.session, script) for script in self.scripts]

                    while not self.stop_event.is_set():  # Loop until stop_event is set
                        time.sleep(0.15)
                        # If the connection was lost (for example, the app restarted) then raise the exception
                        if self.session.is_detached:
                            raise frida.ProcessNotFoundError

                    logger.info("Frida thread is terminating...")
                    break
                except frida.ProcessNotFoundError:
                    if attached and self.persistent_frida:
                        logger.info("App connection lost. Attempting again")
                        start_time = time.time()
                        attached = False
                    pass
            if not attached:
                logger.warning(
                    f"Failed to attach frida script to {self.package_name}, time passed: {time.time() - start_time}")
        except Exception as e:
            logger.error(f"Frida Error: {e}")

    def start_frida(self):
        """Start Frida in a separate thread."""
        self.frida_thread_obj = threading.Thread(target=self.frida_thread, daemon=True)
        self.frida_thread_obj.start()
        logger.info("Frida started in a separate thread.")

    def stop_frida(self):
        """Stop the Frida thread."""
        logger.info("Triggering Frida thread termination...")
        self.stop_event.set()
        logger.debug("############ DEBUG #############")
        logger.debug("ABOUT TO RETURN FRIDA TRACES:")
        for key in self.results:
            logger.debug(f"Key {key} has {len(self.results[key])} entries")

        try:
            # If nothing was caught, them do not save the file
            if self.results == {"common": []}:
                return
            with open(os.path.join(self.output_folder, "frida_traces.json"), "w") as f:
                json.dump(self.results, f)
        except Exception as e:
            logger.error(f"Failed to store frida traces inside of {os.path.join(self.output_folder, "frida_traces.json")} with error: {e}")
