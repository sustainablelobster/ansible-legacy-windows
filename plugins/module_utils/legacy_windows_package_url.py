# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Acquire a package into an owned temporary directory before provider checks."""

import os
import time
import uuid
from email.message import Message
from urllib.parse import urlsplit

import legacy_windows_get_url as web  # pylint: disable=import-error


class PackageDownloadError(ValueError):
    """Retain the released unhandled download exception result boundary."""


def _filename(response):
    filename = urlsplit(response.url).path.rsplit("/", 1)[-1]
    disposition = response.header(65535, "Content-Disposition")
    if disposition:
        header = Message()
        header["Content-Disposition"] = disposition
        parsed = header.get_param("filename", header="content-disposition")
        if isinstance(parsed, str) and parsed:
            filename = uuid.uuid4().hex[:8] + ".tmp-" + parsed
    return filename


def acquire(url, options, result, directory):
    """Stream one response to the temporary package path used by native providers.

    :param str url: Public HTTP or HTTPS package URL.
    :param dict options: Validated released request parameters.
    :param dict result: Public response metadata updated by the web request.
    :param str directory: Caller-owned temporary directory, removed on exit.
    :returns: Downloaded local package path, preserving its response filename.
    :rtype: str
    :raises PackageDownloadError: Request, response or file creation fails.
    """
    started, response, warnings = time.time(), None, []
    try:
        response = web.open_resource(url, options, warnings)
        result["msg"], result["status_code"] = response.message, response.status
        if response.status >= 400:
            raise OSError(
                "The remote server returned an error: ({0}) {1}.".format(
                    response.status, response.message
                )
            )
        path = os.path.join(directory, _filename(response))
        with open(path, "wb") as stream:
            for block in iter(lambda: response.read(65536), b""):
                stream.write(block)
            stream.flush()
        return path
    except (OSError, ValueError) as error:
        raise PackageDownloadError(str(error)) from error
    finally:
        if response is not None:
            response.close()
        result["elapsed"] = time.time() - started
        if warnings:
            result["warnings"] = warnings
