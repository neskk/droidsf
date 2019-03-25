#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import time

import frida

import droidsf.utils


def on_message(message, data):
    print(message)
    print(data)

print(droidsf.utils.HEADER)
args = droidsf.utils.get_args()

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
