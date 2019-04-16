#!/usr/bin/python

import logging
import re
import sys
import shutil

import droidsf.utils

log = logging.getLogger('droidsf')

URL_APKTOOL_LATEST = "https://api.github.com/repos/iBotPeaches/Apktool/releases/latest"
URL_FRIDA_RELEASES = "https://api.github.com/repos/frida/frida/releases"

URL_CFR = "http://www.benf.org/other/cfr/"
URL_CFR_PATTERN = r"https\:\/\/www.benf.org\/other\/cfr\/cfr-([\d\.]+)\.jar"

URL_PROCYON = "https://api.bitbucket.org/2.0/repositories/mstrobel/procyon/downloads/"

URL_ENJARIFY_LATEST = "https://api.github.com/repos/neskk/enjarify/releases/latest"

URL_DEX2JAR_RELEASES = "https://api.github.com/repos/pxb1988/dex2jar/releases"
URL_DEX2JAR_PATTERN = r"\[(dex-tools-.*)\]\((.*)\)"

URL_JADX_RELEASES = "https://api.github.com/repos/skylot/jadx/releases"
URL_JADX_PATTERN = r"jadx-([\d\.]+)\.zip"

def init(args):
    log.info("Initializing required tools.")

    if shutil.which("java") is None:
        log.critical("Unable to find 'java' executable on environment.")
        sys.exit(1)

    if shutil.which("adb") is None:
        log.critical("Unable to find 'adb' executable on environment.")
        sys.exit(1)

    # Helper attributes
    filename = download_apktool(args)
    setattr(args, "apktool_jar", filename)

    filename = download_enjarify(args)
    setattr(args, "enjarify_pex", filename)

    output_path = download_dex2jar(args)
    setattr(args, "dex2jar_dir", output_path)

    output_path = download_jadx(args)
    setattr(args, "jadx_dir", output_path)

    filename = download_cfr(args)
    setattr(args, "cfr_jar", filename)

    filename = download_procyon(args)
    setattr(args, "procyon_jar", filename)

    filename = download_frida_server(args)
    setattr(args, "frida_server_bin", filename)

    setup_frida(args.frida_version)

def download_apktool(args):
    log.debug("Downloading latest Apktool...")
    try:
        data = droidsf.utils.get_json(URL_APKTOOL_LATEST, args.cache_path)
        url = data["assets"][0]["browser_download_url"]
        filename = droidsf.utils.download_file(
            url, args.download_path, args.force_download)
        log.debug("Downloaded: %s", filename)
        return filename

    except Exception as e:
        log.exception("Unable to download Apktool: %s", e)
        sys.exit(1)

def download_enjarify(args):
    log.debug("Downloading latest Enjarify...")
    try:
        data = droidsf.utils.get_json(URL_ENJARIFY_LATEST, args.cache_path)
        url = data["assets"][0]["browser_download_url"]
        filename = droidsf.utils.download_file(
            url, args.download_path, args.force_download)
        log.debug("Downloaded: %s", filename)
        return filename

    except Exception as e:
        log.exception("Unable to download Enjarify: %s", e)
        sys.exit(1)

def download_dex2jar(args):
    log.debug("Downloading latest DEX2JAR...")
    try:
        data = droidsf.utils.get_json(URL_DEX2JAR_RELEASES, args.cache_path)
        release = data[0]
        tag_name = release["tag_name"]
        match = re.search(URL_DEX2JAR_PATTERN, release["body"])

        if not match:
            log.critical("Unable to find DEX2JAR download link.")
            sys.exit(1)

        filename = match.group(1)
        url = match.group(2)

        filename = droidsf.utils.download_file(
            url, args.download_path, args.force_download)
        log.debug("Downloaded: %s", filename)

        # Note: use 'includes="/lib/"' to filter out other files.
        output_path = droidsf.utils.extract_zip(
            args.download_path, filename, args.force_download)
        log.debug("Extracted: %s", output_path)
        return output_path + "/lib"

    except Exception as e:
        log.exception("Unable to download DEX2JAR: %s", e)
        sys.exit(1)

def download_jadx(args):
    log.debug("Downloading latest JADX...")
    try:
        data = droidsf.utils.get_json(URL_JADX_RELEASES, args.cache_path)
        release = data[0]
        tag_name = release["tag_name"]
        regex = re.compile(URL_JADX_PATTERN)

        url = ""
        for asset in release["assets"]:
            if re.search(regex, asset["name"]):
                url = asset["browser_download_url"]
                break

        if not url:
            log.critical("Unable to find JADX download link.")
            sys.exit(1)

        filename = droidsf.utils.download_file(
            url, args.download_path, args.force_download)
        log.debug("Downloaded: %s", filename)

        # Note: use 'includes="/lib/"' to filter out other files.
        output_path = droidsf.utils.extract_zip(
            args.download_path, filename, args.force_download)
        log.debug("Extracted: %s", output_path)
        return output_path + "/lib"

    except Exception as e:
        log.exception("Unable to download DEX2JAR: %s", e)
        sys.exit(1)

def download_cfr(args):
    log.debug("Downloading latest CFR...")
    try:
        html_data = droidsf.utils.get_html(URL_CFR, args.cache_path)
        match = re.search(URL_CFR_PATTERN, html_data)

        if not match:
            log.critical("Unable to find CFR download link.")
            sys.exit(1)

        url = match.group(0)
        version = match.group(1)
        filename = droidsf.utils.download_file(
            url, args.download_path, args.force_download)
        log.debug("Downloaded: %s", filename)
        return filename

    except Exception as e:
        log.exception("Unable to download CFR: %s", e)
        sys.exit(1)

def download_procyon(args):
    log.debug("Downloading latest Procyon...")
    try:
        data = droidsf.utils.get_json(URL_PROCYON, args.cache_path)
        url = data["values"][0]["links"]["self"]["href"]
        filename = droidsf.utils.download_file(
            url, args.download_path, args.force_download)
        log.debug("Downloaded: %s", filename)
        return filename

    except Exception as e:
        log.exception("Unable to download Procyon: %s", e)
        sys.exit(1)

def download_frida_server(args):
    log.debug("Downloading frida-server v.%s for Android...", args.frida_version)

    try:
        data = droidsf.utils.get_json(URL_FRIDA_RELEASES, args.cache_path)
        release = None
        for item in data:
            if item["tag_name"] == args.frida_version:
                release = item
                break
        if not release:
            log.critical("Unable to find frida-server v.%s", args.frida_version)
            sys.exit(1)

        target_name = "frida-server-" + release["tag_name"] + "-android"
        target_fullname = target_name + "-" + args.arch

        target_filename = None
        for asset in release["assets"]:
            if asset["name"].startswith(target_name):
                url = asset["browser_download_url"]
                filename = droidsf.utils.download_file(
                    url, args.download_path, args.force_download)
                log.debug("Downloaded: %s", filename)

                filename = droidsf.utils.extract_xz(
                    args.download_path, filename, args.force_download)
                if target_fullname == filename:
                    target_filename = filename

                log.debug("Extracted: %s", filename)

        if not target_filename:
            log.critical("Unable to find frida-server v.%s for %s", args.frida_version, args.arch)
            sys.exit(1)

        return target_filename

    except Exception as e:
        log.exception("Unable to download frida-server: %s", e)
        sys.exit(1)

def setup_frida(target_version):
    try:
        import frida
        frida_version = frida.__version__
        log.debug("Found frida python package installed: %s", frida_version)
        if frida_version != target_version:
            log.critical("Found conflicting frida versions: "
                         "%s (python package), %s (frida-server).",
                         frida_version, target_version)
            log.critical("Run: pip3 install -r requirements.txt --upgrade")
            sys.exit(1)
    except ImportError as e:
        log.critical("Unable to find frida python package installed.")
        log.critical("Run: pip3 install -r requirements.txt --upgrade")
        sys.exit(1)
