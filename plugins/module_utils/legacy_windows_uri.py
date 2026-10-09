# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Preserve the released URI response contract using native Windows requests."""

import datetime
import hashlib
import json
import os
import re
import time
from collections import OrderedDict
from urllib.parse import urlsplit

import legacy_windows_get_url as web  # pylint: disable=import-error
from legacy_windows_module import as_string  # pylint: disable=import-error

# HttpWebResponse promotes its optimized headers after ordinary wire headers.
# This order is observable in the released module's public Headers collection.
_COMMON_HEADERS = (
    "Accept-Ranges",
    "Content-Length",
    "Cache-Control",
    "Content-Type",
    "Date",
    "Expires",
    "ETag",
    "Last-Modified",
    "Location",
    "Proxy-Authenticate",
    "P3P",
    "Set-Cookie2",
    "Set-Cookie",
    "Server",
    "Via",
    "WWW-Authenticate",
    "X-AspNet-Version",
    "X-Powered-By",
)


def _snake_case(name):
    plural = re.search(r"[A-Z]{3,}s", name)
    if plural:
        before = name[: plural.start()]
        name = (
            before
            + ("_" if before else "")
            + plural.group().lower()
            + name[plural.end() :]
        )
    name = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()


def _headers(raw):
    ordinary, common = OrderedDict(), {}
    known = {name.lower(): name for name in _COMMON_HEADERS}
    for line in raw.split("\r\n")[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = name.lower()
        destination = common if key in known else ordinary
        if key in destination:
            original_name, original_value = destination[key]
            destination[key] = (original_name, original_value + "," + value.strip())
        else:
            destination[key] = (known.get(key, name), value.strip())
    result = list(ordinary.values())
    result.extend(
        common[name.lower()] for name in _COMMON_HEADERS if name.lower() in common
    )
    return OrderedDict(result)


def _character_set(content_type):
    if not content_type:
        return None
    value = "ISO-8859-1" if content_type.lower().strip().startswith("text/") else ""
    match = re.search(r"[; ]charset *=([^;]+)", content_type, re.IGNORECASE)
    return match.group(1).strip() if match else value


def _body(value):
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    else:
        text = as_string(value, "body")
    return text.encode("utf-8")


def _json_is_true(value):
    if isinstance(value, dict):
        return True
    if isinstance(value, list):
        return _json_is_true(value[0]) if len(value) == 1 else bool(value)
    return bool(value)


def _current_local_timestamp():
    value = datetime.datetime.now()
    local = time.localtime()
    offset = -(time.altzone if local.tm_isdst > 0 else time.timezone) // 60
    return "{0}.{1:06d}0{2}{3:02d}:{4:02d}".format(
        value.strftime("%Y-%m-%dT%H:%M:%S"),
        value.microsecond,
        "+" if offset >= 0 else "-",
        abs(offset) // 60,
        abs(offset) % 60,
    )


def _http_properties(response, options):
    raw = response.header(22)
    headers = _headers(raw)
    lookup = {name.lower(): value for name, value in headers.items()}
    content_type = lookup.get("content-type", "")
    version = raw.split(" ", 1)[0].split("/", 1)[1]
    major, minor = map(int, version.split(".", 1))
    properties = {
        "character_set": _character_set(content_type),
        "content_encoding": lookup.get("content-encoding", ""),
        "content_length": int(lookup.get("content-length", -1)),
        "content_type": content_type,
        "cookies": [],
        "headers": list(headers),
        "is_from_cache": False,
        "is_mutually_authenticated": False,
        "last_modified": lookup.get("last-modified") or _current_local_timestamp(),
        "method": getattr(response, "method", options["url_method"]),
        "protocol_version": {
            "Major": major,
            "Minor": minor,
            "Build": -1,
            "Revision": -1,
            "MajorRevision": -1,
            "MinorRevision": -1,
        },
        "response_uri": getattr(response, "url", options["url"]),
        "server": lookup.get("server", ""),
        "status_code": response.status,
        "status_description": response.message,
        "supports_headers": True,
    }
    for name, value in headers.items():
        properties[_snake_case(name.replace("-", ""))] = value
    return properties


def _file_properties(response, options):
    length = (
        response.content_length
        if hasattr(response, "content_length")
        else os.path.getsize(response.path)
    )
    return {
        "content_length": str(length),
        "content_type": "application/octet-stream",
        "headers": ["Content-Length", "Content-Type"],
        "is_from_cache": False,
        "is_mutually_authenticated": False,
        "response_uri": options["url"],
        "supports_headers": True,
    }


def _ftp_last_modified(timestamp):
    if timestamp is None:
        return "0001-01-01T00:00:00.0000000"
    local = datetime.datetime.fromtimestamp(timestamp)
    offset = (
        int((local - datetime.datetime.utcfromtimestamp(timestamp)).total_seconds())
        // 60
    )
    return "{0}.{1:06d}0{2}{3:02d}:{4:02d}".format(
        local.strftime("%Y-%m-%dT%H:%M:%S"),
        local.microsecond,
        "+" if offset >= 0 else "-",
        abs(offset) // 60,
        abs(offset) % 60,
    )


def _ftp_properties(response, options):
    return {
        "banner_message": (
            response.banner_message.replace("\n", "\r\n") + "\r\n"
            if response.banner_message
            else ""
        ),
        "welcome_message": (
            response.welcome_message.replace("\n", "\r\n") + "\r\n"
            if response.welcome_message
            else ""
        ),
        "exit_message": "",
        "content_length": response.content_length,
        "content_type": None,
        "headers": [],
        "is_from_cache": False,
        "is_mutually_authenticated": False,
        "last_modified": _ftp_last_modified(response.timestamp),
        "response_uri": options["url"],
        "status_code": response.status,
        "status_description": response.message,
        "supports_headers": True,
    }


def _ftp_status_name(status):
    # FtpStatusCode is a distinct enum: 226 is ClosingData, not an HTTP code.
    return {
        0: "Undefined",
        110: "RestartMarker",
        120: "ServiceTemporarilyNotAvailable",
        125: "DataAlreadyOpen",
        150: "OpeningData",
        200: "CommandOK",
        202: "CommandExtraneous",
        212: "DirectoryStatus",
        213: "FileStatus",
        215: "SystemType",
        220: "SendUserCommand",
        221: "ClosingControl",
        226: "ClosingData",
        227: "EnteringPassive",
        230: "LoggedInProceed",
        234: "ServerWantsSecureSession",
        250: "FileActionOK",
        257: "PathnameCreated",
        331: "SendPasswordCommand",
        332: "NeedLoginAccount",
        350: "FileCommandPending",
        421: "ServiceNotAvailable",
        425: "CantOpenData",
        426: "ConnectionClosed",
        450: "ActionNotTakenFileUnavailableOrBusy",
        451: "ActionAbortedLocalProcessingError",
        452: "ActionNotTakenInsufficientSpace",
        500: "CommandSyntaxError",
        501: "ArgumentSyntaxError",
        502: "CommandNotImplemented",
        503: "BadCommandSequence",
        530: "NotLoggedIn",
        532: "AccountNeeded",
        550: "ActionNotTakenFileUnavailable",
        551: "ActionAbortedUnknownPageType",
        552: "FileActionAborted",
        553: "ActionNotTakenFilenameNotAllowed",
    }.get(status, str(status))


def _destination_changed(path, data):
    expected = hashlib.sha256(data).hexdigest()
    return not os.path.exists(path) or web.checksum_file(path, "sha256") != expected


def _status_name(status):
    # Invalid-status messages use the released framework enum, not the wire
    # reason phrase. Unknown numeric values must remain numeric strings.
    return {
        0: "",
        100: "Continue",
        101: "SwitchingProtocols",
        200: "OK",
        201: "Created",
        202: "Accepted",
        203: "NonAuthoritativeInformation",
        204: "NoContent",
        205: "ResetContent",
        206: "PartialContent",
        300: "MultipleChoices",
        301: "MovedPermanently",
        302: "Redirect",
        303: "SeeOther",
        304: "NotModified",
        305: "UseProxy",
        306: "Unused",
        307: "TemporaryRedirect",
        400: "BadRequest",
        401: "Unauthorized",
        402: "PaymentRequired",
        403: "Forbidden",
        404: "NotFound",
        405: "MethodNotAllowed",
        406: "NotAcceptable",
        407: "ProxyAuthenticationRequired",
        408: "RequestTimeout",
        409: "Conflict",
        410: "Gone",
        411: "LengthRequired",
        412: "PreconditionFailed",
        413: "RequestEntityTooLarge",
        414: "RequestUriTooLong",
        415: "UnsupportedMediaType",
        416: "RequestedRangeNotSatisfiable",
        417: "ExpectationFailed",
        426: "UpgradeRequired",
        500: "InternalServerError",
        501: "NotImplemented",
        502: "BadGateway",
        503: "ServiceUnavailable",
        504: "GatewayTimeout",
        505: "HttpVersionNotSupported",
    }.get(status, str(status))


def _read_content(response, options, result, check_mode):
    if not options["return_content"] and not options["dest"]:
        return
    data = b"".join(iter(response.read, b""))
    if options["return_content"]:
        result["content"] = data.decode("utf-8", "replace")
        if result["content_type"] and re.search(
            r"text|json|javascript", result["content_type"], re.IGNORECASE
        ):
            try:
                value = json.loads(result["content"])
            except ValueError:
                pass
            else:
                if _json_is_true(value):
                    result["json"] = value
    if options["dest"]:
        result["changed"] = _destination_changed(options["dest"], data)
        if result["changed"] and not check_mode:
            with open(options["dest"], "wb") as stream:
                stream.write(data)


def _consume_response(response, options, result, check_mode):
    result.update(msg=response.message, status_code=response.status)
    scheme = urlsplit(options["url"]).scheme.lower()
    file_response = scheme == "file"
    if file_response:
        properties = _file_properties(response, options)
    elif scheme == "ftp":
        properties = _ftp_properties(response, options)
    else:
        properties = _http_properties(response, options)
    result.update(properties)
    _read_content(response, options, result, check_mode)
    # FileWebResponse has no StatusCode. Membership tests use null, although
    # the source's formatted failure displays zero and its wrapper exposes 200.
    status = None if file_response else response.status
    if status not in options["status_code"]:
        result.update(
            failed=True,
            msg=(
                "Status code of request '{0}' is not in list of valid "
                "status codes {1} : {2}'."
            ).format(
                0 if status is None else status,
                " ".join(map(str, options["status_code"])),
                (
                    _ftp_status_name(status)
                    if scheme == "ftp"
                    else _status_name(0 if status is None else status)
                ),
            ),
        )


def _skip_request(options, result):
    for name, should_exist in (("creates", False), ("removes", True)):
        path = options[name]
        if path and os.path.exists(path) != should_exist:
            result.update(
                skipped=True,
                msg="The '{0}' file or directory ({1}) {2}.".format(
                    name,
                    path,
                    "already exists" if name == "creates" else "does not exist",
                ),
            )
            return True
    return False


def _open_response(options, warnings, body):
    try:
        return (
            web.open_resource(options["url"], options, warnings)
            if body is None
            else web.open_resource(options["url"], options, warnings, body=body)
        )
    except OSError as error:
        # IgnoreBadResponse requires an actual FTP response; ordinary request
        # errors still reach the public request's existing failure handler.
        response = getattr(error, "response", None)
        if response is not None and urlsplit(options["url"]).scheme.lower() == "ftp":
            return response
        raise


def request(options, check_mode=False):
    """Execute a public URI request, retaining response and partial file effects.

    :param dict options: Bound public URI and common web-request options.
    :param bool check_mode: Predict destination writes without changing files.
    :returns: Complete module result, including HTTP and FTP error responses.
    :rtype: dict
    """
    result = {"changed": False, "elapsed": 0, "url": options["url"]}
    method = options["url_method"].upper()
    if re.match(r"^[A-Z]+$", method) is None:
        result.update(
            failed=True,
            msg="Parameter 'method' needs to be a single word in uppercase, like GET or POST.",
        )
        return result
    if _skip_request(options, result):
        return result
    request_options = dict(options, url_method=method)
    if options["content_type"] is not None:
        headers = {
            name: value
            for name, value in (options["headers"] or {}).items()
            if name.lower() != "content-type"
        }
        headers["Content-Type"] = options["content_type"]
        request_options["headers"] = headers
    warnings, response = [], None
    body = _body(options["body"])
    if body is not None and urlsplit(options["url"]).scheme.lower() == "file":
        result.update(
            failed=True,
            msg="file:// requests with a body are not supported; use win_copy to write files.",
        )
        return result
    if body is not None and method in ("GET", "HEAD", "CONNECT"):
        result.update(
            failed=True,
            msg="Unhandled exception occurred when sending web request. Exception: "
            'Exception calling "GetRequestStream" with "0" argument(s): '
            '"Cannot send a content-body with this verb-type."',
        )
        return result
    started = time.time()
    try:
        response = _open_response(request_options, warnings, body)
        _consume_response(response, request_options, result, check_mode)
        if not result.get("failed", False):
            result["elapsed"] = time.time() - started
    except (OSError, ValueError, NotImplementedError) as error:
        result.setdefault("status_code", getattr(error, "status_code", None))
        result.update(
            failed=True,
            msg="Unhandled exception occurred when sending web request. Exception: "
            + (
                error.strerror
                if isinstance(error, OSError) and error.strerror
                else str(error)
            ),
        )
        result["elapsed"] = time.time() - started
    finally:
        if response is not None:
            response.close()
    if warnings:
        result["warnings"] = warnings
    return result
