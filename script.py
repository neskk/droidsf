#!/usr/bin/python3
# -*- coding: utf-8 -*-

import logging
import os
import sys
import time
from timeit import default_timer

import frida

from droidsf.droidstatx import DroidStatX
from droidsf.subprocess import Subprocess, SubprocessShell
import droidsf.config
import droidsf.utils
import droidsf.apk
import droidsf.adb

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

    if not args.no_static_analysis:
        droidstatx = DroidStatX(args, apk)
        log.info("Analysed %s with DroidStat-X.", app_package)

    if args.no_dynamic_analysis:
        log.info("Skipped Frida dynamic analysis.")
        sys.exit(0)

    adb = droidsf.adb.ADB(args)

    adb.select_device()
    adb.launch_adb_server()
    adb.install_apk(app_package)
    adb.launch_frida_server()

    try:
        found = False
        for device in frida.enumerate_devices():
            if device.id == adb.device_id:
                found = True
                log.debug("Frida found device: %s", device)
                break

        if not found:
            log.error("Frida could not find device: %s", adb.device_id)

        device = frida.get_device(id=adb.device_id)
        # device = frida.get_usb_device(timeout=5)

        found = False
        for app in device.enumerate_applications():
            if app.identifier == app_package:
                found = True
                log.debug("Frida found application: %s", app)
                break

        if not found:
            log.error("Frida could not find application: %s", app_package)

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
        try:
            timeout = 0
            if args.instrumentation_timeout > 0:
                timeout = default_timer() + args.instrumentation_timeout
                log.info("Instrumenting for %d seconds.", args.instrumentation_timeout)

            while True:
                if timeout > 0:
                    if timeout > default_timer():
                        time.sleep(0.5)
                    else:
                        break
                else:
                    keyword = input("Type 'x' to terminate instrumentation.\n")
                    if keyword.lower() == "x":
                        break

        except KeyboardInterrupt:
            log.warning("User forced instrumentation to stop.")

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

    adb.kill_frida_server()
    adb.kill_adb_server()
