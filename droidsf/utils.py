#!/usr/bin/python
# -*- coding: utf-8 -*-

import json
import logging
import lzma
import os
import socket
import struct
import sys
import time

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


def get_args():
    default_config = []
    if "-cf" not in sys.argv and "--config" not in sys.argv:
        default_config = [os.path.join(
            os.path.dirname(__file__), "../config/config.ini")]
    parser = configargparse.ArgParser(default_config_files=default_config)

    parser.add_argument("-cf", "--config",
                        is_config_file=True,
                        help="Set configuration file.")
    parser.add_argument("-v", "--verbose",
                        help="Run in the verbose mode.",
                        action="store_true")
    parser.add_argument("--download-path",
                        help="Directory where downloaded files are saved.",
                        default="downloads")
    parser.add_argument("--log-path",
                        help="Directory where log files are saved.",
                        default="logs")
    parser.add_argument("--report-path",
                        help="Directory where report files are saved.",
                        default="reports")
    parser.add_argument('--arch',
                        help="Android device architecture. Default: x86",
                        default='x86',
                        choices=('arm', 'arm64', 'x86', 'x86_64'))
    parser.add_argument("-fv", "--frida-version",
                        help=("Specify which frida version to use."
                              "Note: must match python package version."),
                        default="12.4.4")
    parser.add_argument("-s", "--script",
                        help="Script to execute.",
                        default="open.js")
    parser.add_argument("-a", "--app",
                        help="App name to instrument.",
                        default="com.android.chrome")

    args = parser.parse_args()

    return args


def setup_workspace(args):
    cwd = os.getcwd()
    dirs = [args.download_path, args.log_path, args.report_path]

    # Create necessary work directories
    for directory in dirs:
        if not os.path.exists(directory):
            os.makedirs(directory)


def setup_logging(args, log):
    date = time.strftime("%Y%m%d_%H%M")
    filename = os.path.join(args.log_path, "{}-droidsf.log".format(date))
    filelog = logging.FileHandler(filename)
    formatter_full = logging.Formatter(
        "%(asctime)s [%(threadName)12s][%(module)16s][%(levelname)8s] %(message)s")
    formatter_short = logging.Formatter(
        "[%(levelname)8s] %(message)s")
    filelog.setFormatter(formatter_full)
    log.addHandler(filelog)

    if args.verbose:
        log.setLevel(logging.DEBUG)
        log.debug("Running in verbose mode (-v).")
    else:
        log.setLevel(logging.INFO)

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

def setup_frida(target_version):
    try:
        import frida
        frida_version = frida.__version__
        log.debug("Found frida python package installed: %s", frida_version)
        if frida_version != target_version:
            log.critical("Found conflicting frida versions: "
                         "%s (python package), %s (frida-server).",
                         frida_version, target_version)
            log.critical("Run: pip install -r requirements.txt --upgrade")
            sys.exit(1)
    except ImportError as e:
        log.critical("Unable to find frida python package installed.")
        log.critical("Run: pip install -r requirements.txt --upgrade")
        sys.exit(1)


def load_file(path, filename):
    file_path = os.path.join(path, filename)

    with open(file_path, "r") as f:
        return f.read()


def export_file(output_path, filename, content):
    file_path = os.path.join(output_path, filename)

    with open(file_path, "w") as file:
        file.truncate()
        if isinstance(content, list):
            for line in content:
                file.write(line + "\n")
        else:
            file.write(content)


def download_file(url, output_path, chunk_size=8192):
    filename = url.split("/")[-1]
    file_path = os.path.join(output_path, filename)

    if os.path.isfile(file_path):
        return filename

    # Use stream=True parameter to enable chunked file download
    with requests.get(url, stream=True) as r:
        r.raise_for_status()
        # Download progress report
        total_bytes = int(r.headers["content-length"])
        downloaded_bytes = 0

        with open(file_path, "wb") as f:
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

    return filename


def get_json(url):
    r = requests.get(url)
    return r.json()

def extract_xz(path, filename):
    input_path = os.path.join(path, filename)

    extracted_filename = os.path.splitext(filename)[0]
    output_path = os.path.join(path, extracted_filename)

    if os.path.isfile(output_path):
        return extracted_filename

    with lzma.open(input_path) as f, open(output_path, "wb") as fout:
        data = f.read()
        fout.write(data)

    return extracted_filename
