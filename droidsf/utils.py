#!/usr/bin/python
# -*- coding: utf-8 -*-

import hashlib
import json
import logging
import lzma
import os
import socket
import struct
import sys
import time
import urllib.parse
import zipfile
from timeit import default_timer

import configargparse
import requests

log = logging.getLogger(__name__)

HEADER = """
     _           _     _      __
    | |         (_)   | |    / _|
  __| |_ __ ___  _  __| |___| |_
 / _` | '__/ _ \| |/ _` / __|  _|
| (_| | | | (_) | | (_| \__ \ |
 \__,_|_|  \___/|_|\__,_|___/_|

    Android Security Framework
    v0.1 by @neskk
"""


class LogFilter(logging.Filter):

    def __init__(self, level):
        self.level = level

    def filter(self, record):
        return record.levelno < self.level

# Decorator for memoization/result cache
# Alternative: functools.lru_cache(maxsize=128)
def memoize(f):
    memo = {}

    def helper(x):
        if x not in memo:
            memo[x] = f(x)
        return memo[x]
    return helper

# Decorator for time benchmarks
def timeit(f):
    def timed(*args, **kw):
        ts = default_timer()
        result = f(*args, **kw)
        td = default_timer() - ts
        print("%s  %.2fms" % (f.__name__, td * 1000))
        return result

    return timed

def get_args():
    cwd = os.path.dirname(os.path.realpath(__file__))
    default_config = []
    if "-cf" not in sys.argv and "--config" not in sys.argv:
        default_config = [os.path.join(cwd, "../config/config.ini")]

    p = configargparse.ArgParser(default_config_files=default_config)

    p.add_argument("-cf", "--config",
                   is_config_file=True,
                   help="Set configuration file.")
    p.add_argument("-v", "--verbose",
                   help="Run in the verbose mode.",
                   action="store_true")
    p.add_argument("-a", "--apk-file",
                   required=True,
                   help="Path to APK to analyse.")
    p.add_argument("-d", "--decompile",
                   help="Decompile APK DEX into Java source code.",
                   action="store_true")
    p.add_argument("--force",
                   help="Overrides previously generated files.",
                   action="store_true")
    p.add_argument("--force-download",
                   help="Overrides previously downloaded files.",
                   action="store_true")
    p.add_argument("--cache-path",
                   help="Directory where temporary files are saved.",
                   default="downloads/cache")
    p.add_argument("--download-path",
                   help="Directory where downloaded files are saved.",
                   default="downloads")
    p.add_argument("--log-path",
                   help="Directory where log files are saved.",
                   default="logs")
    p.add_argument("--output-path",
                   help="Directory where generated files are saved.",
                   default="output")
    p.add_argument("--arch",
                   help="Android device architecture. Default: x86",
                   default="x86",
                   choices=("arm", "arm64", "x86", "x86_64"))
    p.add_argument("--dex-converter",
                   help="DEX to JAR converter. Default: enjarify",
                   default="enjarify",
                   choices=("enjarify", "dex2jar"))
    p.add_argument("--java-decompiler",
                   help="JAR to Java decompiler. Default: procyon",
                   default="procyon",
                   choices=("cfr", "procyon"))
    p.add_argument("--frida-version",
                   help=("Specify which frida version to use."
                         "Note: must match python package version."),
                   default="12.4.4")
    p.add_argument("-s", "--script",
                   help="Script to execute.",
                   default="class_list.js")
    p.add_argument("--file-exclusions",
                   help="Ignore these paths/files on static analysis",
                   default=[".css", ".png", ".jpg", "jpeg", ".gif", "res/anim", "res/color", "res/drawable", "res/menu", "res/layout", "assets/fonts", "AndroidManifest.xml", "resources.arsc"],
                   action="append")
    p.add_argument("--directory-exclusions",
                   help="Ignore these directories on static analysis.",
                   default=[],
                   action="append")
    p.add_argument("--custom-checks",
                   help="Additional checks to smali code.",
                   default=[],
                   action="append")
    p.add_argument("--java_home",
                   help="Directory that contains Java executables.",
                   env_var="JAVA_HOME")
    p.add_argument("--android_sdk",
                   help="Directory that contains Android SDK executables.",
                   env_var="ANDROID_SDK")

    args = p.parse_args()

    # Helper attributes
    setattr(args, "cwd", os.path.realpath(os.path.join(cwd, "../")))
    setattr(args, "apk_file", os.path.abspath(args.apk_file))

    # Print configuration
    if args.verbose:
        d = vars(args)
        for k, v in d.items():
            print(k + ": " + str(v))

    return args

# Create necessary work directories
# Note: manipulates 'args' object
def setup_workspace(args):
    pathnames = ["cache_path", "download_path", "log_path", "output_path"]
    args_dict = vars(args)
    for pathname in pathnames:
        rel_path = args_dict[pathname]
        abs_path = os.path.realpath(os.path.join(args.cwd, rel_path))

        if not os.path.exists(abs_path):
            os.makedirs(abs_path)

        args_dict[pathname] = abs_path

def setup_logging(args, log):
    date = time.strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(args.log_path, "{}-droidsf.log".format(date))
    filelog = logging.FileHandler(filename)

    full_f = "%(asctime)s [%(threadName)12s][%(module)14s][%(levelname)8s] %(funcName)s: %(message)s"
    formatter_full = logging.Formatter(full_f)
    filelog.setFormatter(formatter_full)
    log.addHandler(filelog)

    if args.verbose:
        log.setLevel(logging.DEBUG)
        short_f = "[%(levelname)8s] %(funcName)s: %(message)s"
    else:
        log.setLevel(logging.INFO)
        short_f = "[%(levelname)8s] %(message)s"

    formatter_short = logging.Formatter(short_f)

    # Define log level for dependency modules
    logging.getLogger("requests").setLevel(logging.WARNING)

    # Redirect messages lower than WARNING to stdout
    stdout_hdlr = logging.StreamHandler(sys.stdout)
    stdout_hdlr.setFormatter(formatter_short)
    log_filter = LogFilter(logging.WARNING)
    stdout_hdlr.addFilter(log_filter)
    stdout_hdlr.setLevel(0)

    # Redirect messages equal or higher than WARNING to stderr
    stderr_hdlr = logging.StreamHandler(sys.stderr)
    stderr_hdlr.setFormatter(formatter_short)
    stderr_hdlr.setLevel(logging.WARNING)

    log.addHandler(stdout_hdlr)
    log.addHandler(stderr_hdlr)

def load_file(file_path, mode="r"):
    content = ""
    with open(file_path, mode) as f:
        content = f.read()

    return content

def export_file(output_path, filename, content, mode="w"):
    file_path = os.path.join(output_path, filename)

    if not os.path.exists(output_path):
        os.makedirs(output_path)

    with open(file_path, mode) as file:
        file.truncate()
        if isinstance(content, list):
            for line in content:
                file.write(line + "\n")
        else:
            file.write(content)

def download_file(url, output_path, override=False, chunk_size=16 * 1024):
    filename = url.split("/")[-1]
    file_path = os.path.join(output_path, filename)

    # Use stream=True parameter to enable chunked file download
    with requests.get(url, stream=True, timeout=3) as r:
        r.raise_for_status()
        # Download progress report
        total_bytes = int(r.headers["content-length"])
        downloaded_bytes = 0

        if os.path.isfile(file_path) and os.path.getsize(file_path) == total_bytes and not override:
            return filename

        with open(file_path, "wb") as f:
            f.truncate()
            for chunk in r.iter_content(chunk_size=chunk_size):
                if not chunk:
                    # Filter out keep-alive new chunks
                    continue

                f.write(chunk)
                downloaded_bytes += len(chunk)
                percent = float(downloaded_bytes) / total_bytes * 100
                # percent = round(percent * 100, 2)
                sys.stdout.write("Downloaded %d of %d bytes (%0.2f%%)\r" % (downloaded_bytes, total_bytes, percent))

                if downloaded_bytes >= total_bytes:
                    sys.stdout.write("\n")
                    break

    return filename

def get_html(url, cache_path, ttl=3600):
    file_url = url.replace("://", "_").replace("/", "_")
    file_url = urllib.parse.quote(file_url) + ".html"
    file_path = os.path.join(cache_path, file_url)

    if os.path.isfile(file_path):
        last_modified = os.path.getmtime(file_path)
        filesize = os.path.getsize(file_path)
        if filesize > 0 and time.time() < last_modified + ttl:
            return load_file(file_path)

    r = requests.get(url, timeout=3)
    data = r.text
    export_file(cache_path, file_url, data)
    return data

def get_json(url, cache_path, ttl=3600):
    file_url = url.replace("://", "_").replace("/", "_")
    file_url = urllib.parse.quote(file_url) + ".json"
    file_path = os.path.join(cache_path, file_url)

    if os.path.isfile(file_path):
        last_modified = os.path.getmtime(file_path)
        filesize = os.path.getsize(file_path)
        if filesize > 0 and time.time() < last_modified + ttl:
            data = load_file(file_path)
            return json.loads(data)

    r = requests.get(url, timeout=3)
    data = r.text
    export_file(cache_path, file_url, data)
    return json.loads(data)

def extract_xz(path, filename, override=False):
    input_path = os.path.join(path, filename)

    extracted_filename = os.path.splitext(filename)[0]
    output_path = os.path.join(path, extracted_filename)

    if os.path.isfile(output_path) and not override:
        return extracted_filename

    with lzma.open(input_path) as f, open(output_path, "wb") as fout:
        data = f.read()
        fout.write(data)

    return extracted_filename

def extract_zip(path, filename, override=False, includes=""):
    input_path = os.path.join(path, filename)

    zip_path = os.path.splitext(filename)[0]
    output_path = os.path.join(path, zip_path)

    if os.path.isdir(output_path) and not override:
        return zip_path

    with zipfile.ZipFile(input_path, 'r') as f:
        files = f.namelist()
        if includes:
            files = [n for n in files if includes in n]

        if files[0].startswith(zip_path):
            output_path = path

        f.extractall(output_path, files)

    return zip_path

# Return the SHA256 of the file.
def sha256_checksum(file_path):
    with open(file_path, "rb") as f:
        contents = f.read()
        return hashlib.sha256(contents).hexdigest()
