#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
import os
import subprocess
import sys
import time

import frida

import droidsf.utils

log = logging.getLogger('droidsf')

def on_message(message, data):
    # log.info("Received message: %s", message)
    # log.info("Received data: %s", data)

    if message['type'] == 'error':
        log.error(message['stack'])
    elif message['type'] == 'send':
        log.info(message['payload'])
    else:
        log.warning(message)

def adb_launch_frida(args):
    frida_server = "frida-server-" + args.frida_version + "-android-" + args.arch
    frida_server_path = os.path.join(args.download_path, frida_server)

    if not os.path.isfile(frida_server_path):
        log.critical("Unable to find %s on workspace. Run: python install.py")
        sys.exit(1)

    adb = subprocess.Popen(["adb", "root"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    out, err = adb.communicate()
    if err:
        log.info(err)
    if out:
        log.info(out)

    time.sleep(0.5)
    adb = subprocess.Popen(["adb", "push", frida_server_path, "/data/local/tmp/frida-server"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    out, err = adb.communicate()
    if err:
        log.error(err)
    elif "error" in out:
        log.critical("Unable to push frida-server to device:\n%s", out)
        sys.exit(1)
    else:
        log.info("Pushed frida-server to device:\n%s", out)

    time.sleep(0.5)
    adb = subprocess.Popen(["adb", "shell"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

    adb.stdin.write("chmod 755 /data/local/tmp/frida-server\n")
    adb.stdin.flush()
    time.sleep(0.3)

    adb.stdin.write("/data/local/tmp/frida-server &\n")
    adb.stdin.flush()
    time.sleep(0.3)

    # Popen.poll() returns None if process hasn't terminated yet
    if adb.poll() is None:
        log.info("Launched frida-server on device.")
        time.sleep(1)
        adb.kill()
        log.debug("Killed adb shell process.")
        time.sleep(2)
    else:
        log.critical("Unable to launch frida-server on device.")
        sys.exit(1)


def adb_kill_frida():
    adb = subprocess.Popen(["adb", "shell"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    out, err = adb.communicate("killall -s SIGKILL frida-server frida-helper-32", timeout=3)
    if err:
        log.info(err)
    if out:
        log.info(out)


if __name__ == '__main__':
    print(droidsf.utils.HEADER)
    args = droidsf.utils.get_args()

    droidsf.utils.setup_workspace(args)
    droidsf.utils.setup_logging(args, log)

    droidsf.utils.setup_frida(args.frida_version)

    adb = adb_launch_frida(args)

    try:
        log.debug("Frida found devices: %s", frida.enumerate_devices())
        cwd = os.path.dirname(os.path.realpath(__file__))
        device = frida.get_usb_device(timeout=5)
        log.info("Frida found USB device!")
        log.debug("Frida found applications: %s", device.enumerate_applications())
        pid = device.spawn([args.app])
        log.info("Frida spawned application: %s (PID: %s).", args.app, pid)
        session = device.attach(pid)
        log.info("Frida attached to %s (PID: %s).", args.app, pid)

        inject = droidsf.utils.load_file("frida-scripts/", args.script)
        inject = inject.format(app=args.app, name="xxx")
        log.info("Loaded script: %s.", args.script)
        script = session.create_script(inject)
        script.on('message', on_message)
        script.load()

        # with open("change_method.js") as f:
        # with open("instance.js") as f:
        # with open("brutal.js") as f:
        # with open("class_list.js") as f:
        # with open("security.js") as f:
        # with open("some_class.js") as f:
        # with open("debug.js") as f:
        # with open(args.script) as f:
        #     script = session.create_script(f.read())

        # script.on('message', on_message)
        # script.load()

        time.sleep(1)
        device.resume(pid)
        time.sleep(1)  # Without it Java.perform silently fails

        device.kill(pid)
        session.detach()
    except Exception as e:
        log.exception("Frida failed to execute: %s", e)

    adb_kill_frida()
    log.info("Killed frida-server on device.")

    # Prevent the python script from terminating
    # sys.stdin.read()
    keyword = input("Press 'X' + 'ENTER' to terminate.\n")
    while keyword != "x":
        keyword = input("Press 'X' + 'ENTER' to terminate.\n")
