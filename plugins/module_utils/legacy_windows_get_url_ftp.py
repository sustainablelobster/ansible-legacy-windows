# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Own FTP control replies and data streams using Python 3.4.4's library."""

import datetime
import ftplib
import io
from urllib.parse import unquote, urlsplit


class RequestSetupError(ValueError):
    """Preserve the source's minimal unhandled request-setup failure result."""


class _FtpClient(ftplib.FTP):
    """Retain the exact protocol reply exposed by FTP's response object."""

    response = None

    def getresp(self):
        """Read and retain one reply using the standard-library parser.

        :returns: Full decoded server reply.
        :rtype: str
        :raises ftplib.Error: If the server reports a protocol failure.
        """
        try:
            self.response = super().getresp()
        except ftplib.Error as error:
            self.response = str(error)
            raise
        return self.response


def _ftp_method(options):
    method = (options["url_method"] or "RETR").upper()
    if method not in (
        "APPE",
        "DELE",
        "LIST",
        "MDTM",
        "MKD",
        "NLST",
        "PWD",
        "RENAME",
        "RETR",
        "RMD",
        "SIZE",
        "STOR",
        "STOU",
    ):
        raise RequestSetupError(
            "Unhandled exception while executing module: Exception setting "
            '"Method": "This method is not supported.\r\nParameter name: value"'
        )
    return method


def _ftp_error(error):
    text = str(error)
    status = int(text[:3]) if text[:3].isdigit() else None
    description = {
        530: "Not logged in",
        550: "File unavailable (e.g., file not found, no access)",
    }.get(status)
    failure = OSError(
        "The remote server returned an error: ({0}) {1}.".format(status, description)
        if description
        else text
    )
    failure.status_code = status
    return failure


def _credentials(options, parts):
    if options["url_username"]:
        return options["url_username"], options["url_password"] or ""
    return unquote(parts.username or "anonymous"), unquote(parts.password or "")


def _preliminary_length(reply):
    opening, ending = reply.rfind("("), reply.find(" bytes).")
    if opening < 0 or ending <= opening:
        return -1
    digits = reply[opening + 1 : ending].strip(" \t\r\n\v\f")
    if not digits or any(character < "0" or character > "9" for character in digits):
        return -1
    length = int(digits, 10)
    return length if length <= 0x7FFFFFFFFFFFFFFF else -1


# The control/data handles, transfer state and original server replies belong
# to this one owned response; splitting them would hide its cleanup lifetime.
class FtpResponse:  # pylint: disable=too-many-instance-attributes
    """Own one FTP control connection and optional binary data connection."""

    def __init__(self, url, options, timestamp=False, body=None):
        """Acquire one FTP resource with source-compatible reply fields.

        :param str url: Absolute FTP URL.
        :param dict options: Bound module request options.
        :param bool timestamp: Request MDTM instead of a data resource.
        :param bytes body: Optional upload bytes for STOR, STOU or APPE.
        :raises RequestSetupError: If the protocol method is unsupported.
        :raises OSError: If connecting, authenticating or requesting fails.
        :raises ValueError: If metadata or method arguments are invalid.
        """
        method = _ftp_method(options)
        if body is not None and method not in ("STOR", "STOU", "APPE"):
            raise ValueError("FTP request bodies require STOR, STOU or APPE.")
        self.ftp, self.stream, self.socket = _FtpClient(), None, None
        self.status, self.message, self.timestamp, self.content_length = (
            None,
            None,
            None,
            0,
        )
        self.banner_message, self.welcome_message = "", ""
        try:
            parts = urlsplit(url)
            self.banner_message = self.ftp.connect(
                parts.hostname, parts.port or 21, options["url_timeout"] or None
            )
            self.welcome_message = self.ftp.login(*_credentials(options, parts))
            path = unquote(parts.path)
            if timestamp:
                method = "MDTM"
            if method == "MDTM":
                response = self.ftp.sendcmd("MDTM " + path)
                parsed = datetime.datetime.strptime(
                    response[4:].strip(), "%Y%m%d%H%M%S"
                )
                self.timestamp = (
                    parsed - datetime.datetime(1970, 1, 1)
                ).total_seconds()
                self._reply(response)
                self.stream = io.BytesIO()
            elif method in ("RETR", "LIST", "NLST"):
                self.ftp.voidcmd("TYPE I")
                self.socket = self.ftp.transfercmd(method + " " + path)
                # The source's body-stream timeout is separate from GetResponse.
                self.socket.settimeout(300)
                self.stream = self.socket.makefile("rb")
                self._reply(self.ftp.response)
            elif method in ("STOR", "STOU", "APPE"):
                self._upload(method, path, body)
            elif method == "RENAME":
                self.ftp.sendcmd("RNFR " + path)
                self._reply(self.ftp.sendcmd("RNTO "))
                self.stream = io.BytesIO()
            else:
                command = method if method == "PWD" else method + " " + path
                self._reply(self.ftp.sendcmd(command))
                self.stream = io.BytesIO()
        except ftplib.Error as error:
            self.close()
            if body is not None and self.stream is None:
                # Connecting, authenticating and opening the upload stream
                # precede response handling. No accepted status can make a
                # request-stream failure into a completed body upload.
                raise OSError(str(_ftp_error(error))) from error
            raise self._protocol_failure(error) from error
        except BaseException:
            self.close()
            raise

    def _upload(self, method, path, body):
        self.ftp.voidcmd("TYPE I")
        if method == "STOU":
            if path not in ("", "/"):
                self.ftp.cwd(path)
            command = method
        else:
            command = method + " " + path
        self.socket = self.ftp.transfercmd(command)
        if body is not None:
            # Match the existing data-stream timeout, not the control
            # connection's request timeout. Closing signals upload EOF.
            self.socket.settimeout(300)
            for start in range(0, len(body), 65536):
                self.socket.sendall(body[start : start + 65536])
        self.socket.close()
        self.socket = None
        # Only after upload EOF is there a response stream and a final reply
        # whose status is eligible for the caller's response handling.
        self.stream = io.BytesIO()
        self._reply(self.ftp.voidresp())

    def _reply(self, response):
        self.status = int(response[:3])
        self.message = response.replace("\n", "\r\n") + "\r\n"
        if self.status in (125, 150):
            self.content_length = _preliminary_length(response)

    def _protocol_failure(self, error):
        failure = _ftp_error(error)
        if failure.status_code is not None and 400 <= failure.status_code < 600:
            # The connection is already closed. URI projects this actual reply;
            # GetURL still receives the same exception and status/message.
            self._reply(str(error))
            self.stream = io.BytesIO()
            failure.response = self
        return failure

    def read(self, size=65536):
        """Read binary FTP data from the owned data socket.

        :param int size: Maximum byte count.
        :returns: Data bytes, or empty bytes at EOF.
        :rtype: bytes
        :raises OSError: If the final transfer reply reports a protocol failure.
        """
        data = self.stream.read(size)
        if not data and self.socket is not None:
            self.stream.close()
            self.socket.close()
            self.stream, self.socket = None, None
            try:
                self._reply(self.ftp.voidresp())
            except ftplib.Error as error:
                raise _ftp_error(error) from error
        return data

    def modified(self):
        """Return MDTM's UTC timestamp.

        :returns: Epoch seconds, or None if this was a data request.
        :rtype: float or None
        """
        return self.timestamp

    def close(self):
        """Close owned FTP resources even after a partial transfer."""
        if self.stream is not None:
            self.stream.close()
        if self.socket is not None:
            self.socket.close()
        self.ftp.close()
