#!/usr/bin/python3
# -*- coding: utf-8 -*-

import logging
import os
import sys
import time

import droidsf.utils
from droidsf.subprocess import Subprocess, SubprocessShell

log = logging.getLogger(__name__)

# https://developer.android.com/studio/command-line/adb
class ADB(object):
    def __init__(self, args):
        self.args = args

    def list_devices(self):
        cmd = Subprocess(["adb", "devices"])
        if cmd.success:
            device_list = []
            for line in cmd.out.split('\n'):
                line = line.strip()
                if line.startswith("*"):
                    continue
                if line.startswith("List of devices attached"):
                    continue
                if line.endswith("device"):
                    device_list.append(line[:-6].strip())

            return device_list

    def select_device(self):
        try:
            devices = self.list_devices()
            if not devices:
                log.critical("Unable to find any device through ADB.")
                sys.exit(1)

            while True:

                if self.args.device_id == "*":
                    self.device_id = devices[0]
                    break

                if self.args.device_id in devices:
                    self.device_id = self.args.device_id
                    break

                print("Available devices found in ADB:")
                for idx, device in enumerate(devices):
                    print("{}. Device: {}".format(idx + 1, device))
                keyword = input("Select device: 1 .. {}\n".format(len(devices)))

                if not keyword:
                    self.device_id = devices[0]
                    break
                else:
                    try:
                        sel_idx = int(keyword) - 1
                        self.device_id = devices[sel_idx]
                        break
                    except (IndexError, ValueError) as e:
                        log.warning("Invalid device selection: %s", e)

            log.info("Using device ID: %s", self.device_id)

        except Exception as e:
            log.exception("Failed ADB device selection: %s", e)
            sys.exit(1)

    def launch_adb_server(self):
        cmd = Subprocess(["adb", "-s", self.device_id, "root"])
        time.sleep(0.5)

        return cmd.success

    def kill_adb_server(self):
        cmd = Subprocess(["adb", "kill-server"])
        time.sleep(0.5)

        return cmd.success

    def list_installed_packages(self):
        inputs = ["sh -c 'cmd package list packages -f'"]
        cmd = SubprocessShell(["adb", "-s", self.device_id, "shell"], inputs, parse=False)
        if cmd.success:
            package_list = [l.split("=")[-1] for l in cmd.out.split('\n')]
            return package_list

    def install_apk(self, app_package):
        try:
            packages = self.list_installed_packages()
            if app_package in packages:
                log.debug("Found application %s on device.", app_package)
                return

            log.info("Could not find %s on device, installing APK...", app_package)
            keyword = input("Proceed with APK install on device? [Yn]\n")
            if keyword == "n":
                log.debug("Skipped APK install on device.")
                return

            apk_name = os.path.basename(self.args.apk_file)
            cmd = Subprocess(["adb", "-s", self.device_id, "install", self.args.apk_file])
            if not cmd.success:
                log.critical("Failed to install APK %s on device.", apk_name)
                sys.exit(1)

            log.info("APK %s was installed on device.", apk_name)

        except Exception as e:
            log.exception("Failed to install APK on device: %s", e)
            sys.exit(1)

    def launch_frida_server(self):
        frida_server_path = os.path.join(self.args.download_path, self.args.frida_server_bin)

        if not os.path.isfile(frida_server_path):
            log.critical("Unable to find %s on workspace.")
            sys.exit(1)

        cmd = Subprocess(["adb", "-s", self.device_id, "push", frida_server_path, "/data/local/tmp/frida-server"])
        if cmd.success:
            log.info("Pushed frida-server to device.")
        else:
            log.critical("Unable to push frida-server to device.")
            sys.exit(1)

        time.sleep(0.5)
        inputs = [
            "chmod 755 /data/local/tmp/frida-server",
            "/data/local/tmp/frida-server &"
        ]
        cmd = SubprocessShell(["adb", "-s", self.device_id, "shell"], inputs, persists=True)

        if cmd.success:
            log.info("Launched frida-server on device.")
        else:
            log.critical("Unable to launch frida-server on device.")
            sys.exit(1)

    def kill_frida_server(self):
        inputs = ["killall -s SIGKILL frida-server frida-helper-32"]
        cmd = SubprocessShell(["adb", "-s", self.device_id, "shell"], inputs)
        if cmd.success:
            log.info("Killed frida-server on device.")
            return True

        return False
