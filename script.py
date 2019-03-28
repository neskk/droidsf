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
    log.info("Received message: %s", message)
    log.info("Received data: %s", data)


def adb_setup_frida(args):
    frida_server = "frida-server-" + args.frida_version + "-android-" + args.arch
    frida_server_path = os.path.join(args.download_path, frida_server)

    if not os.path.isfile(frida_server_path):
        log.critical("Unable to find %s on workspace. Run: python install.py")
        sys.exit(1)

    adb = subprocess.Popen(["adb", "root"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    out, err = adb.communicate()
    if err:
        log.debug(err)
    if out:
        log.debug(out)

    adb = subprocess.Popen(["adb", "push", frida_server_path, "/data/local/tmp/frida-server"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    out, err = adb.communicate()
    if err:
        log.error(err)
    else:
        log.info("Pushed frida-server to device.")

    adb = subprocess.Popen(["adb", "shell"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

    adb.stdin.write("chmod 755 /data/local/tmp/frida-server\n")
    adb.stdin.flush()
    time.sleep(0.1)

    adb.stdin.write("/data/local/tmp/frida-server &\n")
    adb.stdin.flush()
    time.sleep(0.1)

    # Popen.poll() returns None if process hasn't terminated yet
    if adb.poll() is None:
        log.info("Launched frida-server on device.")
        adb.kill()
        log.debug("Killed adb shell process.")
        return True
    else:
        log.critical("Unable to launch frida-server on device.")
        sys.exit(1)

    return False


if __name__ == '__main__':
    print(droidsf.utils.HEADER)
    args = droidsf.utils.get_args()

    droidsf.utils.setup_workspace(args)
    droidsf.utils.setup_logging(args, log)

    droidsf.utils.setup_frida(args.frida_version)

    adb = adb_setup_frida(args)

    cwd = os.path.dirname(os.path.realpath(__file__))
    device = frida.get_usb_device()
    log.info("Frida found USB device!")
    pid = device.spawn([args.app])
    device.resume(pid)
    time.sleep(1)  # Without it Java.perform silently fails
    session = device.attach(pid)

    log.info("Frida attached to %s (PID: %s).", args.app, pid)
    sys.exit(0)
    # with open("change_method.js") as f:
    # with open("instance.js") as f:
    # with open("brutal.js") as f:
    # with open("class_list.js") as f:
    # with open("security.js") as f:
    # with open("some_class.js") as f:
    # with open("debug.js") as f:
    with open(args.script) as f:
        script = session.create_script(f.read())

    script.on('message', on_message)
    script.load()

    # prevent the python script from terminating
    sys.stdin.read()
