#!/usr/bin/python3
# -*- coding: utf-8 -*-

import logging
import os
import sys
import time

import droidsf.utils
from droidsf.subprocess import Subprocess, SubprocessShell

from androguard.core.analysis import analysis
from androguard.core.bytecodes import apk, dvm
from androguard.misc import AnalyzeAPK

log = logging.getLogger(__name__)

class APK(object):
    def __init__(self, args):
        self.args = args
        self.apk_file = args.apk_file
        self.sha256 = droidsf.utils.sha256_checksum(args.apk_file)

    def process(self):
        log.info("Parsing APK: %s", self.apk_file)
        self.apk = apk.APK(self.apk_file)
        app_version = self.apk.get_androidversion_code() or self.apk.get_androidversion_name() or "1"
        self.output_name = self.apk.get_package() + "_" + app_version
        self.output_path = os.path.join(self.args.output_path, self.output_name)

        if not self.baksmali():
            return False

        if not self.args.decompile:
            log.debug("APK decompilation is disabled.")
        else:
            if not self.dex_convert():
                return False

            if not self.jar_decompile():
                return False

        return True

    def baksmali(self):
        if not self.args.force and os.path.isdir(self.output_path):

            for root, dirs, files in os.walk(self.output_path, topdown=False):
                self.smali_paths = [os.path.join(root, d) for d in dirs if "smali" in d]

            if self.smali_paths:
                log.info("Skipped Baksmali, found previous output.")
                return True

        log.info("Baksmaling DEX files")
        apktool_path = os.path.join(self.args.download_path, self.args.apktool_jar)
        cmd = Subprocess(["java", "-Xms128m", "-Xmx1024m", "-jar", apktool_path, "d", "-b", "-f", "--frame-path", self.args.cache_path, self.args.apk_file, "-o", self.output_path])

        if not cmd.success:
            log.error("Apktool failed to decompile APK: %s", self.apk_file)
            return False

        # Find result paths containing smali code
        self.smali_paths = []
        for root, dirs, files in os.walk(self.output_path, topdown=False):
            self.smali_paths = [os.path.join(root, d) for d in dirs if "smali" in d]

        if not self.smali_paths:
            log.error("Unable to find smali paths in: %s", self.output_path)
            return False

        return True

    def dex_convert(self):
        filename = self.output_name + "-" + self.args.dex_converter + ".jar"
        output_path = os.path.join(self.output_path, filename)

        if not self.args.force and os.path.isfile(output_path) and os.path.getsize(output_path) > 0:
            log.info("Skipped APK convertion to JAR, found previous output.")
            self.jar_file = output_path
            return True

        log.info("Converting APK to JAR...")
        if self.args.dex_converter == "enjarify":
            enjarify_path = os.path.join(self.args.download_path, self.args.enjarify_pex)
            # Execute Python through 'sys.executable' for cross-platform compatibility.
            cmd = Subprocess([sys.executable, enjarify_path, self.args.apk_file, "-o", output_path, "--force"])

            if cmd.success:
                self.jar_file = output_path
                return True

        elif self.args.dex_converter == "dex2jar":
            dex2jar_path = os.path.join(self.args.download_path, self.args.dex2jar_dir + "/*")
            cmd = Subprocess(["java", "-Xms128m", "-Xmx1024m", "-cp", dex2jar_path, "com.googlecode.dex2jar.tools.Dex2jarCmd", "-f", self.args.apk_file, "-o", output_path])
            if cmd.success:
                self.jar_file = output_path
                return True

        return False

    def jar_decompile(self):
        if not self.jar_file:
            log.error("Unable to find a JAR to decompile, make sure DEX converter is working.")
            return False

        output_path = os.path.join(self.output_path, "src-" + self.args.java_decompiler)

        if not self.args.force and os.path.isdir(output_path) and len(os.listdir(output_path)) > 0:
            log.info("Skipped JAR convertion to Java, found previous output.")
            self.src_path = output_path
            return True

        log.info("Converting JAR to Java...")
        if self.args.java_decompiler == "cfr":
            cfr_path = os.path.join(self.args.download_path, self.args.cfr_jar)
            cmd = Subprocess(["java", "-Xms128m", "-Xmx1024m", "-jar", cfr_path, "org.benf.cfr.reader.Main", self.jar_file, "--outputdir", output_path, "--caseinsensitivefs", "true", "--silent", "true"])
            if cmd.success:
                self.src_path = output_path
                return True

        elif self.args.java_decompiler == "procyon":
            procyon_path = os.path.join(self.args.download_path, self.args.procyon_jar)
            cmd = Subprocess(["java", "-Xms128m", "-Xmx1024m", "-jar", procyon_path, "com.strobel.decompiler.DecompilerDriver", self.jar_file, "--output-directory", output_path])
            if cmd.success:
                self.src_path = output_path
                return True

        return False
