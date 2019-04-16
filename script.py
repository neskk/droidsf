#!/usr/bin/python3
# -*- coding: utf-8 -*-

import logging
import os
import sys
import time

import frida

from droidsf.droidstatx import DroidStatX
from droidsf.subprocess import Subprocess, SubprocessShell
import droidsf.config
import droidsf.utils
import droidsf.apk

log = logging.getLogger('droidsf')


app_class_list = []
def parse_class_list(message, data):
    # {'type': 'send', 'payload': '[Ljava.io.FileDescriptor;'}
    # None
    if message['type'] == 'send':
        app_class_list.append(message['payload'])

def export_class_list(apk):
    filename = apk.output_name + "-class_list.txt"
    droidsf.utils.export_file(apk.output_path, filename, app_class_list)
    log.info("Exported class list: %s", filename)


def on_message(message, data):
    if message['type'] == 'error':
        log.error(message['stack'])
    elif message['type'] == 'send':
        log.info(message['payload'])
    else:
        log.warning(message)

on_message_handlers = {
    "class_list.js": parse_class_list,
}

on_resume_handlers = {
    "class_list.js": export_class_list,
}


def adb_launch_frida(args):
    frida_server_path = os.path.join(args.download_path, args.frida_server_bin)

    if not os.path.isfile(frida_server_path):
        log.critical("Unable to find %s on workspace. Run: python install.py")
        sys.exit(1)

    cmd = Subprocess(["adb", "root"])

    time.sleep(0.5)
    cmd = Subprocess(["adb", "push", frida_server_path, "/data/local/tmp/frida-server"])
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
    cmd = SubprocessShell(["adb", "shell"], inputs, persists=True)

    if cmd.success:
        log.info("Launched frida-server on device.")
    else:
        log.critical("Unable to launch frida-server on device.")
        sys.exit(1)


def adb_kill_frida():
    inputs = ["killall -s SIGKILL frida-server frida-helper-32"]
    cmd = SubprocessShell(["adb", "shell"], inputs)
    if cmd.success:
        log.info("Killed frida-server on device.")

def adb_list_installed_packages():
    inputs = ["sh -c 'cmd package list packages -f'"]
    cmd = SubprocessShell(["adb", "shell"], inputs)
    if cmd.success:
        package_list = [a.split("=")[-1] for a in cmd.out.split('\n')]
        return package_list

def adb_install_apk(apk_file):
    cmd = Subprocess(["adb", "install", apk_file])
    if cmd.success:
        log.info("APK %s was installed on device.", os.path.basename(apk_file))

if __name__ == '__main__':
    print(droidsf.utils.HEADER)
    args = droidsf.utils.get_args()

    try:
        droidsf.utils.setup_workspace(args)
        droidsf.utils.setup_logging(args, log)
    except Exception as e:
        log.exception("Unable to setup workspace environment: %s", e)
        sys.exit(1)

    if not os.path.isfile(args.apk_file):
        log.critical("Unable to open APK: %s", args.apk_file)
        sys.exit(1)

    droidsf.config.init(args)

    apk = droidsf.apk.APK(args)
    if not apk.process():
        log.critical("Failed to process APK: %s", args.apk_file)
        sys.exit(1)

    # DroidSF framework initialized -------------------------------------------

    app_package = apk.apk.get_package()

    keyword = input("Proceed with static analysis? [yN]\n")
    if keyword == "y":
        droidstatx = DroidStatX(args, apk)
        log.info("Analysed %s with DroidStat-X.", app_package)

    installed_packages = []
    try:
        installed_packages = adb_list_installed_packages()
        if len(installed_packages) < 3:
            log.critical("Failed to communicate with device using ADB.")
            sys.exit(1)
    except Exception as e:
        log.exception("Unable to fetch installed apps from device: %s", e)
        sys.exit(1)

    if app_package not in installed_packages:
        log.info("Could not find %s on device, installing APK...", app_package)
        keyword = input("Proceed with APK install on device? [Yn]\n")
        if keyword != "n":
            adb_install_apk(args.apk_file)

    keyword = input("Proceed with Frida dynamic analysis? [yN]\n")
    if keyword != "y":
        sys.exit(0)

    adb = adb_launch_frida(args)

    try:
        log.debug("Frida found devices: %s", frida.enumerate_devices())
        device = frida.get_usb_device(timeout=5)
        log.info("Frida found USB device!")

        found = False
        for app in device.enumerate_applications():
            if app.identifier == app_package:
                found = True
                log.debug("Frida found application: %s", app_package)
                break

        if not found:
            log.error("Frida could not find %s installed on device.", app_package)

        # TODO: Allow manual selection of device if multiple options are available

        pid = device.spawn([app_package], timeout=10)
        log.info("Frida spawned application: %s (PID: %s).", app_package, pid)
        session = device.attach(pid)
        log.info("Frida attached to %s (PID: %s).", app_package, pid)

        script_header = os.path.join(args.cwd, "frida-scripts", "_header.js")
        code = droidsf.utils.load_file(script_header)
        script_file = os.path.join(args.cwd, "frida-scripts", args.script)
        code += droidsf.utils.load_file(script_file)
        code = code.replace("%app%", app_package)
        code = code.replace("%script%", args.script)

        log.info("Loaded script: %s.", args.script)

        script = session.create_script(code)

        if args.script in on_message_handlers:
            script.on('message', on_message_handlers[args.script])
        else:
            script.on('message', on_message)
        script.load()

        time.sleep(1)
        device.resume(pid)
        time.sleep(1)  # Without it Java.perform silently fails

        # Prevent the python script from terminating
        # sys.stdin.read()
        keyword = input("Press 'X' + 'ENTER' to terminate.\n")
        while keyword != "x":
            keyword = input("Press 'X' + 'ENTER' to terminate.\n")

        if args.script in on_resume_handlers:
            on_resume_handlers[args.script](apk)
        # api = script.exports
        # print("api.hello() =>", api.hello())
        # api.fail_please()

        device.kill(pid)
        log.info("Killed application: %s (PID: %s).", app_package, pid)
        session.detach()
        log.debug("Detached from application.")
    except Exception as e:
        log.exception("Frida failed to execute: %s", e)

    adb_kill_frida()
