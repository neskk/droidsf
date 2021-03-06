#!/usr/bin/python3
# -*- coding: utf-8 -*-

import json
import logging
import subprocess
import time

log = logging.getLogger(__name__)

class Subprocess(object):
    def __init__(self, cmd, parse=True):
        self.cmd = " ".join(cmd)
        self.parse = parse
        self.success = False
        try:
            self.p = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True)
            self.out, self.err = self.p.communicate()
            self.success = self.parse_output()
        except Exception as e:
            log.error("Process terminated unexpectedly: %s", e)
            self.success = False

    def parse_output(self):
        self.out = self.out.strip()
        self.err = self.err.strip()

        if not self.parse:
            return True

        res = ""
        if self.err:
            res += "[ stderr from: " + self.cmd + " ]\n" + self.err
        if self.out:
            if res:
                res += "\n"
            res += "[ stdout from: " + self.cmd + " ]\n" + self.out

        if "error" in res:
            log.error(res)
            return False
        elif res:
            log.info(res)

        return True


class SubprocessShell(Subprocess):
    def __init__(self, cmd, inputs=[], parse=False, persists=False):
        self.cmd = " ".join(cmd)
        self.parse = parse
        self.success = False
        try:
            self.p = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True)
            if not persists:
                inputs = "\n".join(inputs)
                self.out, self.err = self.p.communicate(inputs)
                self.success = self.parse_output()
            else:
                self.out, self.err = "", ""
                for shell_cmd in inputs:
                    self.p.stdin.write(shell_cmd + "\n")
                    self.p.stdin.flush()
                    time.sleep(0.3)

                # Popen.poll() returns None if process hasn't terminated yet
                if self.p.poll() is None:
                    log.debug("Shell is busy, process is running...")
                    time.sleep(1)
                    self.p.kill()
                    log.debug("Terminating shell process.")
                    time.sleep(2)
                    self.success = True
                else:
                    log.error("Shell process was unexpectedly terminated.")
                    self.success = False
        except Exception as e:
            log.error("Shell process terminated unexpectedly: %s", e)
            self.success = False
