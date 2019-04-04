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


app_class_list = []
def parse_class_list(message, data):
    # {'type': 'send', 'payload': '[Ljava.io.FileDescriptor;'}
    # None
    if message['type'] == 'send':
        app_class_list.append(message['payload'])

def export_class_list(args):
    filename = args.app + "-class_list.txt"
    droidsf.utils.export_file(args.report_path, filename, app_class_list)
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


def parse_subprocess_output(out, err):
    res = ""
    if err:
        res += "[stderr] " + err
    if out:
        if res:
            res += "\n"
        res += "[stdout] " + out

    if "error" in res:
        log.error(res)
        return False
    elif res:
        log.info(res)

    return True


def adb_launch_frida(args):
    frida_server = "frida-server-" + args.frida_version + "-android-" + args.arch
    frida_server_path = os.path.join(args.download_path, frida_server)

    if not os.path.isfile(frida_server_path):
        log.critical("Unable to find %s on workspace. Run: python install.py")
        sys.exit(1)

    adb = subprocess.Popen(["adb", "root"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    out, err = adb.communicate()
    parse_subprocess_output(out, err)

    time.sleep(0.5)
    adb = subprocess.Popen(["adb", "push", frida_server_path, "/data/local/tmp/frida-server"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    out, err = adb.communicate()
    if parse_subprocess_output(out, err):
        log.info("Pushed frida-server to device.")
    else:
        log.critical("Unable to push frida-server to device.")
        sys.exit(1)

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

    if parse_subprocess_output(out, err):
        log.info("Killed frida-server on device.")


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

        code = droidsf.utils.load_file("frida-scripts", "_header.js")
        code += droidsf.utils.load_file("frida-scripts", args.script)
        code = code.replace("%app%", args.app)
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
            on_resume_handlers[args.script](args)
        # api = script.exports
        # print("api.hello() =>", api.hello())
        # api.fail_please()

        device.kill(pid)
        log.info("Killed application: %s (PID: %s).", args.app, pid)
        session.detach()
        log.debug("Detached from application.")
    except Exception as e:
        log.exception("Frida failed to execute: %s", e)

    adb_kill_frida()
