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


if __name__ == '__main__':
    print(droidsf.utils.HEADER)
    args = droidsf.utils.get_args()

    droidsf.utils.setup_workspace(args)
    droidsf.utils.setup_logging(args, log)

    droidsf.utils.setup_frida(args.frida_version)

    device = frida.get_usb_device()
    pid = device.spawn([args.app])
    device.resume(pid)
    time.sleep(1)  # Without it Java.perform silently fails
    session = device.attach(pid)

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
