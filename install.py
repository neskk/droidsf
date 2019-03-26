#!/usr/bin/python

import logging

import droidsf.utils

log = logging.getLogger('droidsf')

URL_APKTOOL = "https://api.github.com/repos/iBotPeaches/Apktool/releases/latest"
URL_FRIDA = "https://api.github.com/repos/frida/frida/releases/latest"


if __name__ == '__main__':
    print(droidsf.utils.HEADER)
    args = droidsf.utils.get_args()

    droidsf.utils.setup_workspace(args)
    droidsf.utils.setup_logging(args, log)
    droidsf.utils.setup_frida(args.frida_version)

    log.info("Downloading latest Apktool...")
    try:
        data = droidsf.utils.get_json(URL_APKTOOL)
        url = data["assets"][0]["browser_download_url"]
    except Exception as e:
        log.exception("Unable to download Apktool: %s", e)

    filename = droidsf.utils.download_file(url, args.download_path)
    log.info("Downloaded: %s", filename)

    log.info("Downloading latest frida-server for Android...")
    try:
        data = droidsf.utils.get_json(URL_FRIDA)
        target_name = "frida-server-" + data["tag_name"] + "-android"
        for asset in data["assets"]:
            name = asset["name"]
            if name.startswith(target_name):
                url = asset["browser_download_url"]
                filename = droidsf.utils.download_file(url, args.download_path)
                log.info("Downloaded: %s", filename)

                filename = droidsf.utils.extract_xz(args.download_path, filename)
                log.info("Extracted: %s", filename)

    except Exception as e:
        log.exception("Unable to download frida-server: %s", e)
