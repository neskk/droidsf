#!/usr/bin/python3
# -*- coding: utf-8 -*-

import mmap
import os
import re

# https://stackoverflow.com/a/38918877/1546848
# Similar to grep.
class Grep(object):
    def __init__(self, pattern, dir_exclusions=[], file_exclusions=[]):
        self.regex = re.compile(bytes(pattern, "utf-8"))
        self.dir_exclusions = dir_exclusions
        self.file_exclusions = file_exclusions

    def is_excluded_file(self, filename):
        for pattern in self.file_exclusions:
            if pattern in filename:
                return True
        return False

    def is_excluded_dir(self, dirname):
        for pattern in self.dir_exclusions:
            if pattern in dirname:
                return True
        return False

    def check_directories(self, paths):
        result = []
        for path in paths:
            result.extend(self.check_directory(path))

        return result

    def check_directory(self, path):
        result = []

        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if not self.is_excluded_dir(d)]
            files[:] = [f for f in files if not self.is_excluded_file(f)]

            for name in files:
                file_path = os.path.join(root, name)
                with open(file_path, "r") as f:
                    content = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                    if re.search(self.regex, content):
                        result.append(file_path)

        return result

    def check_file(self, file_path):
        with open(file_path, "r") as f:
            content = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            if re.search(self.regex, content):
                return True

        return False
