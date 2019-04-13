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

log = logging.getLogger('droidsf')


app_class_list = []
def parse_class_list(message, data):
    # {'type': 'send', 'payload': '[Ljava.io.FileDescriptor;'}
    # None
    if message['type'] == 'send':
        app_class_list.append(message['payload'])

def export_class_list(args):
    filename = args.apk + "-class_list.txt"
    droidsf.utils.export_file(args.output_path, filename, app_class_list)
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


# def java_decompile(args):
#     if not args.decompiler:
#         log.debug("Skipped DEX to JAR decompilation.")
#         return

#     if args.decompiler == "cfr":
#         cfr_path = os.path.join(args.download_path, args.cfr_jar)
#         cmd = Subprocess(["java", "-Xms128m", "-Xmx1024m", "-jar", apktool_path, "d", "-b", "-f", "--frame-path", "/tmp/", args.apk_file, "-o", self.output_path])
#         cmd = Subprocess(['java', '-Xms512m', '-Xmx1024m', "-jar", cfr_path, 'org.benf.cfr.reader.Main', ext_path + '/' + jar_filename, '--outputdir', src_path, '--caseinsensitivefs', 'true', '--silent', 'true'])
#     elif (decompiler == 'procyon'):
#         subprocess.call(['java','-Xms512m', '-Xmx1024m', '-cp', lib_path, 'com.strobel.decompiler.DecompilerDriver', '-jar', ext_path + '/' + jar_filename, '--o', src_path], stdout=FNULL)
#     inputs = ["killall -s SIGKILL frida-server frida-helper-32"]
#     cmd = SubprocessShell(["adb", "shell"], inputs)
#     if cmd.success:
#         log.info("Killed frida-server on device.")


if __name__ == '__main__':
    print(droidsf.utils.HEADER)
    args = droidsf.utils.get_args()

    try:
        droidsf.utils.setup_workspace(args)
        droidsf.utils.setup_logging(args, log)
    except Exception as e:
        log.exception("Unable to setup workspace environment: %s", e)
        sys.exit(1)

    droidsf.config.init(args)

    # DroidSF framework initialized

    droidstatx = DroidStatX(args)
    app_package = droidstatx.apk.get_package()
    log.info("Analysed %s with DroidStatX.", app_package)

    sys.exit(0)
    adb = adb_launch_frida(args)

    try:
        log.debug("Frida found devices: %s", frida.enumerate_devices())
        cwd = os.path.dirname(os.path.realpath(__file__))
        device = frida.get_usb_device(timeout=5)
        log.info("Frida found USB device!")
        log.debug("Frida found applications: %s", device.enumerate_applications())
        pid = device.spawn([app_package])
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
            on_resume_handlers[args.script](args)
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
