#!/usr/bin/python

import logging
import sys

import droidsf.utils

log = logging.getLogger('droidsf')

URL_APKTOOL_LATEST = "https://api.github.com/repos/iBotPeaches/Apktool/releases/latest"
URL_FRIDA_RELEASES = "https://api.github.com/repos/frida/frida/releases"


if __name__ == '__main__':
    print(droidsf.utils.HEADER)
    args = droidsf.utils.get_args()

    droidsf.utils.setup_workspace(args)
    droidsf.utils.setup_logging(args, log)
    droidsf.utils.setup_frida(args.frida_version)

    log.info("Downloading latest Apktool...")
    try:
        data = droidsf.utils.get_json(URL_APKTOOL_LATEST)
        url = data["assets"][0]["browser_download_url"]
    except Exception as e:
        log.exception("Unable to download Apktool: %s", e)

    filename = droidsf.utils.download_file(url, args.download_path)
    log.info("Downloaded: %s", filename)

    log.info("Downloading frida-server v.%s for Android...", args.frida_version)
    try:
        data = droidsf.utils.get_json(URL_FRIDA_RELEASES)
        release = None
        for item in data:
            if item["tag_name"] == args.frida_version:
                release = item
                break
        if not release:
            log.critical("Unable to find frida-server v.%s", args.frida_version)
            sys.exit(1)

        target_name = "frida-server-" + release["tag_name"] + "-android"

        for asset in release["assets"]:
            if asset["name"].startswith(target_name):
                url = asset["browser_download_url"]
                filename = droidsf.utils.download_file(url, args.download_path)
                log.info("Downloaded: %s", filename)

                filename = droidsf.utils.extract_xz(args.download_path, filename)
                log.info("Extracted: %s", filename)

    except Exception as e:
        log.exception("Unable to download frida-server: %s", e)
