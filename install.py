#!/usr/bin/python

import hashlib
import json
import logging
import os
import sys

import droidsf.utils

log = logging.getLogger()

URL_APKTOOL = "https://api.github.com/repos/iBotPeaches/Apktool/releases/latest"


if __name__ == '__main__':
    print(droidsf.utils.HEADER)
    args = droidsf.utils.get_args()

    droidsf.utils.setup_workspace(args)
    droidsf.utils.setup_logging(args, log)

    log.info("Downloading latest Apktool version...")
    try:
        apktool_json = droidsf.utils.download_json(URL_APKTOOL)
        url = apktool_json["assets"][0]["browser_download_url"]
    except Exception as e:
        log.exception("Unable to parse URL %s: %s", url, e)

    filename = droidsf.utils.download_file(url, args.download_path)
    log.info("Finished download: %s", filename)
