# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Control direct anonymous HTTP requests with Python 3.4.4's standard library."""

import email.utils
import http.client
import ipaddress
import socket
import threading
import time
from collections import OrderedDict
from urllib.parse import urlsplit, urlunsplit


def supports_request(url, options, headers):
    """Select the proved direct, anonymous, plain HTTP request boundary.

    :param str url: Canonical absolute resource URL.
    :param dict options: Bound common request options.
    :param dict headers: Prepared caller headers.
    :returns: Whether the standard library can serve this request policy.
    :rtype: bool
    """
    parts = urlsplit(url)
    return parts.scheme == "http" and _supports_direct_policy(parts, options, headers)


def _supports_direct_policy(parts, options, headers):
    return (
        parts.username is None
        and not options["use_proxy"]
        and not any(
            options[name]
            for name in (
                "url_username",
                "use_default_credential",
                "proxy_username",
                "proxy_use_default_credential",
                "client_cert",
            )
        )
        and not any(name.lower() == "transfer-encoding" for name in headers)
    )


def _timeout_error():
    return OSError(12002, "The operation has timed out")


def _connect(connection):
    try:
        connection.connect()
    except socket.gaierror as error:
        raise OSError(
            "The remote name could not be resolved: '{0}'".format(connection.host)
        ) from error
    except socket.timeout as error:
        raise _timeout_error() from error
    except OSError as error:
        raise OSError(12029, "Unable to connect to the remote server") from error


def _ipv6_authority(authority):
    if not authority.startswith("["):
        return authority
    literal, _bracket, port = authority[1:].partition("]")
    return "[{0}]{1}".format(
        ipaddress.IPv6Address(literal.split("%", 1)[0]).exploded.upper(), port
    )


def _http_authority(parts, default_port=80):
    authority = parts.netloc
    if parts.port == default_port:
        authority = authority.rsplit(":", 1)[0]
    return _ipv6_authority(authority)


def _response_url(url, parts, headers):
    authority = _http_authority(parts)
    for name, value in headers.items():
        if name.lower() == "host":
            authority = _http_authority(urlsplit("http://" + value))
    if authority == parts.netloc:
        return url
    return urlunsplit(
        (parts.scheme, authority, parts.path, parts.query, parts.fragment)
    )


def _request_headers(options, headers, authority, body, redirected):
    # Python 3.4 dictionaries do not retain order. The automatic fields must
    # reach the wire in the released request's measured order, not hash order.
    headers = OrderedDict(headers)
    names = {name.lower() for name in headers}
    if "user-agent" not in names:
        headers["User-Agent"] = options["http_agent"]
    if "host" not in names:
        headers["Host"] = _ipv6_authority(authority)
    else:
        for name, value in headers.items():
            if name.lower() == "host":
                headers[name] = _ipv6_authority(value)
    if body is not None:
        if "content-length" not in names:
            headers["Content-Length"] = str(len(body))
        if body and "expect" not in names:
            headers["Expect"] = "100-continue"
    if not redirected and "connection" not in names:
        headers["Connection"] = "Keep-Alive"
    return headers


def _expire_connection(connection):
    if connection.sock is not None:
        try:
            connection.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            # A completed peer close needs no further cancellation.
            pass


class PlainHttpResponse:
    """Own one direct anonymous HTTP response and its standard-library socket.

    :param str url: Canonical eligible plain HTTP resource URL.
    :param dict options: Bound request options and effective method.
    :param dict headers: Prepared caller headers, copied before sending.
    :param float deadline: Shared absolute monotonic header deadline, or None.
    :param bytes body: Upload bytes, or None for no upload request.
    :param bool redirected: Whether this is a later automatic redirect hop.
    :raises OSError: If connection, header receipt or cancellation fails.
    """

    # Request bytes and the shared redirect deadline are explicit participants in
    # this one response lifetime; hiding them inside options would obscure policy.
    # The header/body handoff needs both socket ownership references in this
    # operation; keeping them together makes cancellation and read lifetime clear.
    # pylint: disable-next=too-many-arguments,too-many-locals
    def __init__(self, url, options, headers, *, deadline, body=None, redirected=False):
        self.url, self.method = url, options["url_method"]
        self.connection, self.response = None, None
        parts = urlsplit(url)
        timeout = max(0, deadline - time.monotonic()) if deadline else None
        if timeout == 0:
            raise _timeout_error()
        self.connection = http.client.HTTPConnection(
            parts.hostname, parts.port or 80, timeout=timeout
        )
        timer = None
        try:
            _connect(self.connection)
            if deadline:
                timer = threading.Timer(
                    max(0, deadline - time.monotonic()),
                    _expire_connection,
                    [self.connection],
                )
                timer.start()
            target = parts.path or "/"
            if parts.query:
                target += "?" + parts.query
            self.connection.putrequest(
                self.method, target, skip_host=True, skip_accept_encoding=True
            )
            authority = _http_authority(parts)
            self.url = _response_url(url, parts, headers)
            headers = _request_headers(options, headers, authority, body, redirected)
            for name, value in headers.items():
                self.connection.putheader(name, value)
            if deadline:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _timeout_error()
                self.connection.sock.settimeout(remaining)
            self.connection.endheaders(body)
            body_socket = self.connection.sock
            self.response = self.connection.getresponse()
            # HTTPResponse also accepts EOF as the end of headers. Cancellation
            # must not turn that partial response into a successful deadline.
            if deadline is not None and time.monotonic() >= deadline:
                raise _timeout_error()
            self.status, self.message = self.response.status, self.response.reason
            # Closing responses transfer socket ownership to HTTPResponse.
            # Retain that socket to separate body reads from the header deadline.
            body_socket.settimeout(300)
        except BaseException as error:
            self.close()
            if isinstance(error, socket.timeout) or (
                isinstance(error, Exception)
                and deadline is not None
                and time.monotonic() >= deadline
            ):
                raise _timeout_error() from error
            raise
        finally:
            if timer is not None:
                timer.cancel()
                timer.join()

    def header(self, number, name=None):
        """Read a response header in the existing native query contract.

        :param int number: WinHTTP-compatible response information level.
        :param str name: Name for a custom header query, or None.
        :returns: Header text, or None when the header is absent.
        :rtype: str or None
        """
        if number == 22:
            return "HTTP/{0}.{1} {2} {3}\r\n{4}\r\n".format(
                self.response.version // 10,
                self.response.version % 10,
                self.status,
                self.message,
                "".join(
                    "{0}: {1}\r\n".format(key, value)
                    for key, value in self.response.getheaders()
                ),
            )
        if number in (19, 20):
            return str(self.status) if number == 19 else self.message
        name = {11: "Last-Modified", 33: "Location"}.get(number, name)
        return self.response.getheader(name) if name is not None else None

    def read(self, size=65536):
        """Read a bounded response chunk through the standard library.

        :param int size: Maximum byte count.
        :returns: Body bytes, or empty bytes at EOF.
        :rtype: bytes
        :raises OSError: If the response read times out or fails.
        """
        try:
            return self.response.read(size)
        except socket.timeout as error:
            raise _timeout_error() from error

    def modified(self):
        """Return remote last modification or the released current-time fallback.

        :returns: Epoch seconds.
        :rtype: float
        """
        value = self.header(11)
        date = email.utils.parsedate_tz(value) if value else None
        return email.utils.mktime_tz(date) if date else time.time()

    def close(self):
        """Close the response stream and its owned connection."""
        if self.response is not None:
            self.response.close()
        if self.connection is not None:
            self.connection.close()
