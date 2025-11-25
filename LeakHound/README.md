# LeakHound

This tool was developed during my Master's Thesis for the purpose of automating the process of acquiring network traces as well
as hooking frida scripts and collecting the results. In the end, we saw that the tool could be useful for other researchers
and so decided to create this separate

## Instructions

For the configuration of the MitM, since it can differ from device to device we opted to leave
this as manual configuration.


## Root your device

If you're using an AVD, a possible tool to use is [rootAVD](https://gitlab.com/newbit/rootAVD). This
will install Magisk in your device, which will come in handy later

## Setting up the device

In order for you to get the certificate and installing it in the device is important that you follow
the tutorial below

https://docs.mitmproxy.org/stable/howto-install-system-trusted-ca-android/#instructions-when-using-magisk

Remember to copy the certificate and place it's absolute path inside the frida script used for ssl-bypass (if you're using one)

If you intend to do this in multiple devices (AVDs), consider doing the setup on 1, and then creating clones
to speed the process.

Make sure to install the `PCAPdroid` APK provided with this project. This is a custom version which strips the app from some of the privacy checks (such as making sure information is not leaving the device).
You prefer to compile it yourself, or if you believe the current version of the app is too old, here's the code https://github.com/emanuele-f/PCAPdroid


## Cloning DroidBot

This project uses DroidBot to explore the application. The current version was modified to make sure that DroidBot is the one injecting the Frida scripts. Not using this version can lead to the frida scripts not being injected properly.
The modified code is provided (not a compiled version), however, if you prefer to clone the repo from DroidBot yourself, you can find it in [DroidBot](https://github.com/honeynet/droidbot.git). Keep in mind that this will break the Frida hook injection which you will need to care of.

I recommend running some manual tests with DroidBot first to make sure all permission are provided and that it is working properly. For more information, refer to their repo.


## Frida

Frida will be used in this project, so make sure to install the frida-server in the device. To do so, follow the instructions provided in https://frida.re/docs/android/.
This project expects the frida-server to be placed in `/data/local/tmp/frida-server` within the device.

The used/created frida scripts are also provided within this project, as well as the `compacted` version (which is more stable to use with DroidBot). Keep in mind that the `compacted` version only includes the needed scripts, as some were then discarted.


## General Configuration

Before trying to run the project, do a first pass to look for hardcoded strings such as `path/to/emulator.exe`. These define paths, and there should not be that many to configure, however is still better to do an initial pass to check what needs to be changed.
Also, this project was only tested with AVDs from Android Studio. In theory, anything which can be controlled through the adb command line will work, but keep that in mind.


## How to run

First do an initial run through the files, as some files need to be configured to your setup. Most of these files will have the format of `path/to/...`, as mentioned previously.

Within the `HoundEngine` you can also configure the arguments/setting for the analysis, this includes:

- `num_threads`: Dictates the max number of threads to use (will be capped at the number of AVDs detected through the device)
- `mitm_ip`: The interface to use for the `MitM` proxy
- `output_folder`: The folder where the results will be placed
- `socks5_ip`: The IP address the `SOCKS5` proxy will communicate as the remote server (usually the computer's private IP address)
- `emulator_path`: The path to the `emulator.exe` (usually shipped with Android Studio). This is used to launch AVDs if they fail/crash
- `frida`: Boolean which dictates if frida is to be used or not
- `frida_scripts`: The path to the frida scripts to injected. It accepts multiple scripts, but if `spawn_with_frida` is used, it's recommended to compact all scripts into one file. This will be ignored if `frida` is set to `False`
- `timeout`: The maximum time DroidBot is ran for. There was never a case where DroidBot ended before the timeout, so keep that in mind.
- `spawn_with_frida`: If set to `True`, this project will use DroidBot (assuming that you're using the modified version of DroidBot provided) to spawn and inject the frida scripts it self. If set to `False` a seperate Thread will be created to ensure the scripts are injected.
- `manual_control`: If set to `True` DroidBot will be skipped and the user will be free to navigate the application them selves. A prompt in the terminal will show up so that the user can stop the analysis whenever preferred.

Before actually running the application, ensure the `AVDs` are up and running with the configurations mentioned previously. It's also recommended to test the analysis manually (leverage the `DeviceController` class) to check if everything is running smoothly.

Once all devices are up and running, the paths are configured and the parameters/arguments are set, simply run the `HoundEngine` class:

```Bash
python3 HoundEngine.py
```

Ensure you're doing so from the project directoty, as some paths are relative.

This will open of the `AVDs` detected, install the application, and run the analysis as configured by the user. In the end, all results obtained will be placed within the `output_folder` provided.

From here you can choose to run the `TraceParser` to compact all results, as well as perform some treatment, such as call stack reconstruction.

To do so, simply change the arguments inside the `main` function to represent your setup and run:

```Bash
python3 TraceParser.py
```

This will create a folder with `json` files for each of the applications, as well as a compiled version with all files (which is a simple concat of all `json` files). This will create your dataset, but keep in mind that some information can, and should, be later retrieved from the `HoundEngine` files, such as all call stack from threads for the `call stack` distance metric. Nonetheless, this provides all the results needed, minus the ones from the `LibRadar` and `FlowDroid` which should be executed independently from this project.