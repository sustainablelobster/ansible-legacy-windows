# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Download resources with the target's WinHTTP, CryptoAPI and Python library."""

# The concrete stdlib response lives in its own helper. This remaining module
# keeps native ownership, one redirect policy and download decisions together.
# pylint: disable=too-many-lines

import base64
import codecs
import ctypes
import email.utils
import hashlib
import ipaddress
import ntpath
import nturl2path
import os
import re
import socket
import tempfile
import threading
import time
from contextlib import ExitStack
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit

try:
    import winreg
except ImportError:
    winreg = None

import legacy_windows_certificate_store as certificates  # pylint: disable=import-error
import legacy_windows_copy as copying  # pylint: disable=import-error
import legacy_windows_get_url_ftp as ftp  # pylint: disable=import-error
import legacy_windows_get_url_http as plain_http  # pylint: disable=import-error
import legacy_windows_http_certificate as http_certificate  # pylint: disable=import-error
from legacy_windows_module import DOTNET_WHITESPACE  # pylint: disable=import-error

_DWORD = ctypes.c_uint32
_POINTER = ctypes.c_void_p
_BOOL = ctypes.c_int32
_WIDE = ctypes.c_wchar_p


class _ModuleFailure(ValueError):
    """Preserve source FailJson's result before request-finally updates elapsed."""


# These structures describe WinHTTP's ABI, not behavior-bearing objects.
# pylint: disable=too-few-public-methods
class _AsyncResult(ctypes.Structure):
    """Copy the native asynchronous error before callback memory is released."""

    _fields_ = [("operation", ctypes.c_size_t), ("error", _DWORD)]


class _ProxyInfo(ctypes.Structure):
    _fields_ = [("access_type", _DWORD), ("proxy", _POINTER), ("bypass", _POINTER)]


class _IEProxyConfig(ctypes.Structure):
    _fields_ = [
        ("auto_detect", _BOOL),
        ("auto_config_url", _POINTER),
        ("proxy", _POINTER),
        ("bypass", _POINTER),
    ]


class _AutoProxyOptions(ctypes.Structure):
    _fields_ = [
        ("flags", _DWORD),
        ("detect_flags", _DWORD),
        ("config_url", _WIDE),
        ("reserved", _POINTER),
        ("reserved_number", _DWORD),
        ("auto_logon", _BOOL),
    ]


# pylint: enable=too-few-public-methods


def _winhttp():
    library = ctypes.WinDLL("winhttp", use_last_error=True)
    signatures = {
        "WinHttpOpen": (_POINTER, [_WIDE, _DWORD, _WIDE, _WIDE, _DWORD]),
        "WinHttpConnect": (_POINTER, [_POINTER, _WIDE, ctypes.c_uint16, _DWORD]),
        "WinHttpOpenRequest": (
            _POINTER,
            [_POINTER, _WIDE, _WIDE, _WIDE, _WIDE, _POINTER, _DWORD],
        ),
        "WinHttpCloseHandle": (_BOOL, [_POINTER]),
        "WinHttpSetTimeouts": (_BOOL, [_POINTER] + [ctypes.c_int32] * 4),
        "WinHttpSetOption": (_BOOL, [_POINTER, _DWORD, _POINTER, _DWORD]),
        "WinHttpSendRequest": (
            _BOOL,
            [_POINTER, _WIDE, _DWORD, _POINTER, _DWORD, _DWORD, ctypes.c_size_t],
        ),
        "WinHttpReceiveResponse": (_BOOL, [_POINTER, _POINTER]),
        "WinHttpQueryHeaders": (
            _BOOL,
            [_POINTER, _DWORD, _WIDE, _POINTER, _POINTER, _POINTER],
        ),
        "WinHttpReadData": (_BOOL, [_POINTER, _POINTER, _DWORD, _POINTER]),
        "WinHttpQueryAuthSchemes": (
            _BOOL,
            [_POINTER, _POINTER, _POINTER, _POINTER],
        ),
        "WinHttpSetCredentials": (
            _BOOL,
            [_POINTER, _DWORD, _DWORD, _WIDE, _WIDE, _POINTER],
        ),
        "WinHttpSetStatusCallback": (
            _POINTER,
            [_POINTER, _POINTER, _DWORD, ctypes.c_size_t],
        ),
        "WinHttpGetIEProxyConfigForCurrentUser": (_BOOL, [_POINTER]),
        "WinHttpGetProxyForUrl": (_BOOL, [_POINTER, _WIDE, _POINTER, _POINTER]),
    }
    for name, signature in signatures.items():
        operation = getattr(library, name)
        operation.restype, operation.argtypes = signature
    return library


def _error(code=None, secure_failure=0):
    code = ctypes.get_last_error() if code is None else code
    code &= 0xFFFFFFFF
    if code in (12002, 12029, 12175):
        message = {
            12002: "The operation has timed out",
            12029: "Unable to connect to the remote server",
            12175: "Could not establish the SSL/TLS secure connection (WinHTTP 12175)",
        }[code]
        if code == 12175 and secure_failure:
            reasons = [
                reason
                for flag, reason in (
                    (0x1, "certificate revocation check failed"),
                    (0x2, "invalid certificate"),
                    (0x4, "revoked certificate"),
                    (0x8, "untrusted certificate authority"),
                    (0x10, "certificate hostname mismatch"),
                    (0x20, "certificate date invalid"),
                    (0x40, "certificate usage invalid"),
                    (0x80000000, "secure-channel error"),
                )
                if secure_failure & flag
            ]
            details = "; ".join(reasons) or "unrecognized secure-failure flags"
            message += ": {0} (WinHTTP flags 0x{1:08X})".format(details, secure_failure)
    else:
        # Python 3.4's FormatError accepts a signed Windows long, even for HRESULTs.
        message = ctypes.FormatError(ctypes.c_int32(code).value).rstrip("\r\n .")
        message += " (Windows error {0} / 0x{0:08X})".format(code)
    return OSError(code, message)


def _require(success):
    if not success:
        raise _error()


def _option(library, handle, number, value):
    value = _DWORD(value)
    _require(library.WinHttpSetOption(handle, number, ctypes.byref(value), 4))


def _configured_secure_protocols():
    if winreg is None:
        return False
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp",
            0,
            winreg.KEY_READ,
        ) as key:
            winreg.QueryValueEx(key, "DefaultSecureProtocols")
        return True
    except OSError as error:
        if getattr(error, "winerror", error.errno) not in (2, 3):
            raise
        return False


def _secure_protocols(library, session, agent):
    if _configured_secure_protocols():
        return
    probe = library.WinHttpOpen(agent, 1, None, None, 0)
    _require(probe)
    # SECURE_PROTOCOLS is set-only. Probe a separate, unconnected session so a
    # current native stack retains its untouched defaults, including TLS 1.3.
    protocols = 0xA0  # Documented older WinHTTP defaults: SSL 3.0 and TLS 1.0.
    try:
        for flag in (0x2000, 0x800, 0x200):
            candidate = _DWORD(flag)
            if library.WinHttpSetOption(probe, 84, ctypes.byref(candidate), 4):
                if flag == 0x2000:
                    return
                protocols |= flag
            else:
                code = ctypes.get_last_error()
                # This is a capability probe, not a failed-handshake retry.
                if code not in (87, 12009):
                    raise _error(code)
    finally:
        _require(library.WinHttpCloseHandle(probe))
    if protocols != 0xA0:
        _option(library, session, 84, protocols)


def _free_strings(structure, names):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GlobalFree.restype, kernel.GlobalFree.argtypes = _POINTER, [_POINTER]
    for name in names:
        pointer = getattr(structure, name)
        if pointer:
            kernel.GlobalFree(pointer)


def _proxy(library, session, request, url, options):
    if not options["use_proxy"]:
        return
    if options["proxy_url"]:
        proxy = urlsplit(options["proxy_url"])
        text = proxy.netloc or proxy.path
        # WebProxy(uri, true) bypasses unqualified local names.
        native_text = ctypes.create_unicode_buffer(text)
        bypass = ctypes.create_unicode_buffer("<local>")
        info = _ProxyInfo(
            3, ctypes.cast(native_text, _POINTER), ctypes.cast(bypass, _POINTER)
        )
        _require(
            library.WinHttpSetOption(
                request, 38, ctypes.byref(info), ctypes.sizeof(info)
            )
        )
        return
    config = _IEProxyConfig()
    try:
        _require(library.WinHttpGetIEProxyConfigForCurrentUser(ctypes.byref(config)))
        if config.auto_detect or config.auto_config_url:
            automatic = _AutoProxyOptions(
                (1 if config.auto_detect else 0) | (2 if config.auto_config_url else 0),
                3 if config.auto_detect else 0,
                (
                    ctypes.wstring_at(config.auto_config_url)
                    if config.auto_config_url
                    else None
                ),
                None,
                0,
                options["proxy_use_default_credential"],
            )
            info = _ProxyInfo()
            try:
                success = library.WinHttpGetProxyForUrl(
                    session, url, ctypes.byref(automatic), ctypes.byref(info)
                )
                if success:
                    _require(
                        library.WinHttpSetOption(
                            request, 38, ctypes.byref(info), ctypes.sizeof(info)
                        )
                    )
                    return
                if ctypes.get_last_error() != 12180:
                    raise _error()
            finally:
                _free_strings(info, ("proxy", "bypass"))
        if config.proxy:
            info = _ProxyInfo(3, config.proxy, config.bypass)
            _require(
                library.WinHttpSetOption(
                    request, 38, ctypes.byref(info), ctypes.sizeof(info)
                )
            )
    finally:
        _free_strings(config, ("proxy", "bypass", "auto_config_url"))


def _client_certificate(stack, path, password):
    installed = path.lower().startswith("cert:\\")
    if installed:
        parts = path.split("\\")
        if len(parts) != 4 or parts[1].lower() not in ("currentuser", "localmachine"):
            raise ValueError("Client certificate '{0}' does not exist".format(path))
        collection = stack.enter_context(
            certificates.open_store(parts[2], parts[1], "system", True)
        )
        records = certificates.matches(collection.records, parts[3])
    else:
        if not os.path.exists(path):
            raise ValueError("Client certificate '{0}' does not exist".format(path))
        collection = stack.enter_context(
            certificates.read_file(path, password, True, "default", persist=False)
        )
        records = collection.records
    if not records:
        raise ValueError("Client certificate '{0}' does not exist".format(path))
    for record in records:
        if record["has_private_key"]:
            if installed:
                return record["context"]
            return stack.enter_context(
                http_certificate.temporary_certificate(collection, record)
            )
    raise ValueError("Client certificate '{0}' has no private key".format(path))


# Native handles, completion events and callback state share one owned lifetime.
class _HttpResponse:  # pylint: disable=too-many-instance-attributes
    """Own the native session, connection, request and certificate lifetimes."""

    # Deadline and upload bytes belong to the existing owned request lifetime.
    # pylint: disable-next=too-many-arguments
    def __init__(
        self, url, options, headers, credentials=True, *, deadline=None, body=None
    ):
        host = (urlsplit(url).hostname or "").rstrip(".").lower()
        literal_address = False
        try:
            ipaddress.ip_address(host.split("%", 1)[0])
            literal_address = True
        except ValueError:
            try:
                # Windows accepts legacy numeric, octal and hex IPv4 forms too.
                socket.inet_aton(host)
                literal_address = True
            except OSError:
                pass
        origin_credentials = credentials and bool(
            options["url_username"] or options["use_default_credential"]
        )
        proxy_credentials = options["use_proxy"] and bool(
            options["proxy_username"] or options["proxy_use_default_credential"]
        )
        if (
            proxy_credentials
            and not origin_credentials
            and (host == "localhost" or literal_address)
        ):
            # WinHTTP's HIGH policy explicitly excludes localhost/IP origins.
            # Refuse this combination before connecting, including redirects.
            raise NotImplementedError(
                "Proxy-only authentication to localhost or an IP-address "
                "destination cannot safely isolate origin credentials in "
                "WinHTTP. Use a DNS machine name or fully qualified hostname, "
                "or explicitly supply the intended origin credentials."
            )
        self.stack = ExitStack()
        self.certificates = ExitStack()
        self.stack.callback(self.certificates.close)
        self.library = _winhttp()
        self.handle = None
        self.status = None
        self.message = None
        self.ready = threading.Event()
        self.closed = threading.Event()
        self.callback = None
        self.error = None
        self.secure_failure = 0
        self.received = 0
        self.url = url
        self.method = options["url_method"] or "GET"
        # WinHTTP may reuse this buffer for authentication until response receipt
        # or cancellation completes. The owned request keeps it alive throughout.
        self.body = ctypes.create_string_buffer(body) if body is not None else None
        self.body_length = len(body) if body is not None else 0
        self.deadline = deadline
        if self.deadline is None and options["url_timeout"]:
            self.deadline = time.monotonic() + options["url_timeout"]
        try:
            session = self._open(url, options)
            self._configure(url, options, session, credentials)
            self._send(options, headers, credentials)
        except BaseException:
            self.close()
            raise

    def _open(self, url, options):
        session = self._handle(
            self.library.WinHttpOpen(options["http_agent"], 1, None, None, 0x10000000)
        )
        parts = urlsplit(url)
        if parts.scheme == "https":
            _secure_protocols(self.library, session, options["http_agent"])
        connection = self._handle(
            self.library.WinHttpConnect(
                session,
                parts.hostname,
                parts.port or (443 if parts.scheme == "https" else 80),
                0,
            )
        )
        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query
        self.handle = self.library.WinHttpOpenRequest(
            connection,
            options["url_method"] or "GET",
            target,
            None,
            None,
            None,
            0x800000 if parts.scheme == "https" else 0,
        )
        _require(self.handle)
        self.stack.callback(self._close_request)
        timeout = options["url_timeout"] * 1000
        _require(
            self.library.WinHttpSetTimeouts(
                self.handle, timeout, timeout, timeout, timeout
            )
        )
        self._callbacks()
        return session

    def _callbacks(self):
        context = ctypes.c_size_t(1)
        _require(
            self.library.WinHttpSetOption(
                self.handle, 45, ctypes.byref(context), ctypes.sizeof(context)
            )
        )
        signature = ctypes.WINFUNCTYPE(
            None, _POINTER, ctypes.c_size_t, _DWORD, _POINTER, _DWORD
        )
        callback = signature(self._notify)
        previous = self.library.WinHttpSetStatusCallback(
            self.handle,
            callback,
            0x400000 | 0x20000 | 0x80000 | 0x200000 | 0x800 | 0x10000,
            0,
        )
        _require(previous != ctypes.c_void_p(-1).value)
        self.callback = callback

    def _notify(self, _handle, _context, status, information, length):
        if status == 0x800:
            self.closed.set()
        elif status == 0x10000:
            if information and length == ctypes.sizeof(_DWORD):
                self.secure_failure |= ctypes.cast(
                    information, ctypes.POINTER(_DWORD)
                ).contents.value
        elif status == 0x200000:
            self.error = ctypes.cast(
                information, ctypes.POINTER(_AsyncResult)
            ).contents.error
            self.ready.set()
        elif status in (0x400000, 0x20000, 0x80000):
            self.received = length
            self.ready.set()

    def _call(self, operation, timeout, *arguments):
        if timeout is not None and timeout <= 0:
            raise _error(12002)
        self.ready.clear()
        self.error = None
        self.secure_failure = 0
        success = operation(*arguments)
        if not success and ctypes.get_last_error() != 997:
            if ctypes.get_last_error() == 12175:
                raise _error(12175, self.secure_failure)
            raise _error()
        if not self.ready.wait(timeout):
            raise _error(12002)
        if self.error is not None:
            if self.error == 12175:
                raise _error(self.error, self.secure_failure)
            raise _error(self.error)

    def _close_request(self):
        _require(self.library.WinHttpCloseHandle(self.handle))
        if self.callback is not None:
            # This final callback is the lifetime boundary for its Python state.
            # Closing is safe because the request was opened asynchronously.
            self.closed.wait()

    def _configure(self, url, options, session, credentials):
        if options["url_timeout"] > 0:
            # Receive-idle timeout alone does not bound response-header arrival.
            _option(self.library, self.handle, 7, options["url_timeout"] * 1000)
        # HIGH autologon alone does not prevent loopback's implicit credentials.
        # Disable automatic authentication when no requested credentials exist.
        authenticate = bool(
            (
                credentials
                and (options["url_username"] or options["use_default_credential"])
            )
            or (
                options["use_proxy"]
                and (
                    options["proxy_username"] or options["proxy_use_default_credential"]
                )
            )
        )
        _option(self.library, self.handle, 63, 1 | 2 | (0 if authenticate else 4))
        # Bind explicit identities before WinHTTP's loopback autologon exception
        # can substitute the current account during the initial challenge.
        if (
            credentials
            and options["url_username"]
            and not options["use_default_credential"]
        ):
            _require(
                self.library.WinHttpSetCredentials(
                    self.handle,
                    0,
                    1 if options["force_basic_auth"] else 16,
                    options["url_username"],
                    options["url_password"] or "",
                    None,
                )
            )
        if (
            options["use_proxy"]
            and options["proxy_username"]
            and not options["proxy_use_default_credential"]
        ):
            _require(
                self.library.WinHttpSetCredentials(
                    self.handle,
                    1,
                    16,
                    options["proxy_username"],
                    options["proxy_password"] or "",
                    None,
                )
            )
        _option(
            self.library,
            self.handle,
            77,
            1 if credentials and options["use_default_credential"] else 2,
        )
        if not options["validate_certs"]:
            _option(self.library, self.handle, 31, 0x100 | 0x200 | 0x1000 | 0x2000)
        _proxy(self.library, session, self.handle, url, options)
        if options["client_cert"]:
            context = _client_certificate(
                self.certificates,
                options["client_cert"],
                options["client_cert_password"],
            )
            # CryptoAPI's existing context layout is the exact WinHTTP ABI.
            # pylint: disable-next=protected-access
            size = ctypes.sizeof(certificates._CertificateContext)
            _require(self.library.WinHttpSetOption(self.handle, 47, context, size))

    def _send(self, options, headers, credentials):
        if self.body is not None:
            names = {name.lower() for name in headers}
            if "content-length" not in names:
                headers["Content-Length"] = str(self.body_length)
            if self.body_length and "expect" not in names:
                headers["Expect"] = "100-continue"
        if (
            credentials
            and not options["use_default_credential"]
            and options["url_username"]
            and options["force_basic_auth"]
        ):
            value = "{0}:{1}".format(
                options["url_username"], options["url_password"] or ""
            )
            headers["Authorization"] = "Basic " + base64.b64encode(
                value.encode("ascii", "replace")
            ).decode("ascii")
        text = "".join(
            "{0}: {1}\r\n".format(name, value) for name, value in headers.items()
        )
        challenges = set()
        deadline = self.deadline
        anonymous_certificate = False
        while True:
            try:
                self._call(
                    self.library.WinHttpSendRequest,
                    max(0, deadline - time.monotonic()) if deadline else None,
                    self.handle,
                    text,
                    len(text),
                    self.body,
                    self.body_length,
                    self.body_length,
                    1,
                )
                if options["proxy_use_default_credential"] and not (
                    credentials and options["use_default_credential"]
                ):
                    # The authorized proxy's SSPI context is established while
                    # sending. Receiving must not permit a new origin logon.
                    _option(self.library, self.handle, 77, 2)
                self._call(
                    self.library.WinHttpReceiveResponse,
                    max(0, deadline - time.monotonic()) if deadline else None,
                    self.handle,
                    None,
                )
            except OSError as error:
                if (
                    error.errno != 12044
                    or options["client_cert"]
                    or anonymous_certificate
                ):
                    raise
                # A server may request, but not require, a client certificate.
                # Explicitly decline it rather than select an unrequested key.
                # WinHTTP reports this challenge only on stacks supporting the
                # documented WINHTTP_NO_CLIENT_CERT_CONTEXT (NULL, size zero).
                _require(self.library.WinHttpSetOption(self.handle, 47, None, 0))
                anonymous_certificate = True
                continue
            self.status = int(self.header(19))
            self.message = self.header(20)
            if self.status not in (401, 407) or self.status in challenges:
                return
            challenges.add(self.status)
            if not self._authenticate(options, credentials):
                return

    def _authenticate(self, options, credentials):
        proxy = self.status == 407
        if proxy and not options["use_proxy"]:
            return False
        username = (
            options["proxy_username"]
            if proxy
            else options["url_username"] if credentials else None
        )
        default = (
            options["proxy_use_default_credential"]
            if proxy
            else options["use_default_credential"] if credentials else False
        )
        if default:
            username = None
        if not username and not default:
            return False
        supported, first, target = _DWORD(), _DWORD(), _DWORD()
        _require(
            self.library.WinHttpQueryAuthSchemes(
                self.handle,
                ctypes.byref(supported),
                ctypes.byref(first),
                ctypes.byref(target),
            )
        )
        scheme = next(
            (
                kind
                for kind in (16, 2, 8, 1)
                if supported.value & kind and (username or kind in (16, 2))
            ),
            None,
        )
        if scheme is None:
            return False
        password = options["proxy_password"] if proxy else options["url_password"]
        if default:
            password = None
            if proxy:
                # HIGH otherwise prevents even explicitly selected default
                # proxy credentials. The send loop restores the origin policy.
                _option(self.library, self.handle, 77, 1)
        _require(
            self.library.WinHttpSetCredentials(
                self.handle, 1 if proxy else 0, scheme, username, password, None
            )
        )
        return True

    def _handle(self, handle):
        _require(handle)
        self.stack.callback(self.library.WinHttpCloseHandle, handle)
        return handle

    def header(self, number, name=None):
        """Read one response header without retaining WinHTTP-owned memory.

        :param int number: WinHTTP query information level.
        :param str name: Header name for a custom query, or None.
        :returns: Header text, or None when the header is absent.
        :rtype: str or None
        :raises OSError: If querying fails for a reason other than missing data.
        """
        size = _DWORD()
        success = self.library.WinHttpQueryHeaders(
            self.handle, number, name, None, ctypes.byref(size), None
        )
        if not success:
            code = ctypes.get_last_error()
            if code == 12150:
                return None
            if code != 122:
                raise _error(code)
        buffer = ctypes.create_unicode_buffer(max(1, size.value // 2))
        _require(
            self.library.WinHttpQueryHeaders(
                self.handle, number, name, buffer, ctypes.byref(size), None
            )
        )
        return buffer.value

    def read(self, size=65536):
        """Read at most size bytes from the response stream.

        :param int size: Maximum byte count.
        :returns: Body bytes, or empty bytes at EOF.
        :rtype: bytes
        :raises OSError: If the native read fails.
        """
        buffer = ctypes.create_string_buffer(size)
        self._call(self.library.WinHttpReadData, 300, self.handle, buffer, size, None)
        return buffer.raw[: self.received]

    def modified(self):
        """Return Last-Modified, or the source's current-time fallback.

        :returns: Epoch seconds; absent/invalid HTTP dates use the current time.
        :rtype: float
        """
        value = self.header(11)
        date = email.utils.parsedate_tz(value) if value else None
        return email.utils.mktime_tz(date) if date else time.time()

    def close(self):
        """Release the stream and all owned native resources."""
        self.stack.close()


class _FileResponse:
    """Expose a local resource through the same bounded streaming contract."""

    status, message = 200, "OK"

    def __init__(self, path, body=None):
        self.path = path
        if body is not None:
            raise NotImplementedError(
                "file:// requests with a body are not supported; use win_copy to write files."
            )
        # The response owns this stream until close(), beyond constructor scope.
        self.stream = open(path, "rb")  # pylint: disable=consider-using-with

    def read(self, size=65536):
        """Read resource bytes; the caller owns the resulting buffer.

        :param int size: Maximum byte count.
        :returns: Body bytes, or empty bytes at EOF.
        :rtype: bytes
        """
        return self.stream.read(size)

    def modified(self):
        """Return the resource's last-write UTC timestamp.

        :returns: Epoch seconds.
        :rtype: float
        """
        return os.stat(self.path).st_mtime

    def close(self):
        """Close the resource stream."""
        self.stream.close()


def _file_zero_response(path, body=None):
    # FileWebRequest queues the open: zero permits an already-ready result, not
    # a synchronous open or an unconditional timeout. The worker owns any result
    # that arrives after the caller abandons it, including an interrupted wait.
    ownership = threading.Lock()
    ready = threading.Event()
    pending = {"response": None, "error": None, "abandoned": False}

    def open_file():
        response, error = None, None
        try:
            response = (
                _FileResponse(path) if body is None else _FileResponse(path, body)
            )
        # Hand ready interruptions back rather than silently losing the worker.
        except BaseException as failure:  # pylint: disable=broad-exception-caught
            error = failure
        with ownership:
            abandoned = pending["abandoned"]
            if not abandoned:
                pending["response"], pending["error"] = response, error
                ready.set()
        if abandoned and response is not None:
            response.close()

    worker = threading.Thread(target=open_file)
    worker.daemon = True
    response, returned = None, False
    try:
        worker.start()
        if not ready.wait(0):
            raise _error(12002)
        with ownership:
            response, error = pending["response"], pending["error"]
            pending["response"] = None
        if error is not None:
            raise error
        returned = True
        return response
    finally:
        with ownership:
            pending["abandoned"] = True
            unclaimed = pending["response"]
            pending["response"] = None
        # Do not hold the ownership lock while closing an actual file stream.
        if unclaimed is not None:
            unclaimed.close()
        if response is not None and not returned:
            response.close()


def _uri(url):
    if re.match(r"^[A-Za-z]:[\\/]", url) or url.startswith("\\\\"):
        url = "file:" + nturl2path.pathname2url(url)
    parts = urlsplit(url)
    if parts.scheme.lower() not in ("file", "ftp", "http", "https"):
        raise ValueError("The URI prefix is not recognized.")
    path = quote(parts.path, safe="/%:@!$&'()*+,;=-._~")
    return urlunsplit(
        (parts.scheme.lower(), parts.netloc, path, parts.query, parts.fragment)
    )


def _file_path(url):
    parts = urlsplit(url)
    path = unquote(parts.path).replace("/", "\\")
    if parts.netloc and parts.netloc.lower() != "localhost":
        return "\\\\" + parts.netloc + path
    return path.lstrip("\\") if re.match(r"^\\[A-Za-z]:", path) else path


def _headers(options, warnings):
    headers = {name: str(value) for name, value in (options["headers"] or {}).items()}
    range_header = next((name for name in headers if name.lower() == "range"), None)
    if range_header is not None:
        first = int(headers[range_header])
        headers[range_header] = "bytes={0}{1}".format(first, "-" if first >= 0 else "")
    user_agent = next((name for name in headers if name.lower() == "user-agent"), None)
    if user_agent is not None:
        if options["http_agent"] == "ansible-httpget":
            options = dict(options, http_agent=headers[user_agent])
        else:
            warnings.append(
                "The 'User-Agent' header and the 'http_agent' was set, "
                "using the 'http_agent' for web request"
            )
        del headers[user_agent]
    return options, headers


def _redirect_discards_upload(method, status, headers, body=None):
    # Framework write mode comes from caller-supplied upload headers, not the
    # Content-Length: 0 that WinHTTP may add to an otherwise bodyless POST.
    upload = method.upper() not in ("GET", "HEAD", "CONNECT") and (
        body is not None
        or any(
            name.lower() in ("content-length", "transfer-encoding") for name in headers
        )
    )
    return upload and (
        status in (300, 303) or status in (301, 302) and method.upper() == "POST"
    )


# One send attempt needs the caller's headers/body, credential-forwarding policy
# and shared redirect deadline; bundling them into hidden state would obscure
# which request owns those values.
# pylint: disable-next=too-many-arguments
def _http_response(url, options, headers, credentials, *, deadline, body, redirected):
    if plain_http.supports_request(url, options, headers):
        return plain_http.PlainHttpResponse(
            url,
            options,
            headers,
            deadline=deadline,
            body=body,
            redirected=redirected,
        )
    return _HttpResponse(
        url,
        options,
        dict(headers),
        credentials,
        deadline=deadline,
        **({"body": body} if body is not None else {})
    )


# Keep protocol selection and the optional body's single redirect lifetime
# together; splitting these branches would obscure which request owns its bytes.
def open_resource(  # pylint: disable=too-many-locals,too-many-branches
    url, options, warnings, timestamp=False, *, body=None
):
    """Open one resource, handling redirects without forwarding credentials.

    :param str url: Absolute resource URI.
    :param dict options: Bound module request options.
    :param list warnings: Mutable list for source-compatible request warnings.
    :param bool timestamp: Request only remote last-modified metadata.
    :param bytes body: Upload bytes, or None to preserve a bodyless request.
        Empty bytes still select an upload request. The owned native buffer is
        retained through HTTP authentication, redirects, receipt and close.
        FTP supports STOR, STOU and APPE. File requests with a body, including
        empty bytes, are rejected without opening or replacing the resource.
    :returns: Owned response exposing read, modified and close. Direct anonymous
        HTTP uses standard-library header control; TLS, proxies, automatic
        credentials, client certificates and transfer encoding use WinHTTP.
        HTTP responses also expose url and method after redirects.
    :rtype: _HttpResponse or plain_http.PlainHttpResponse or _FileResponse or
        ftp.FtpResponse
    :raises OSError: If the server or native API cannot serve the request.
        A file request with timeout zero
        observes a queued open without waiting; an already-ready response or
        failure is preserved, and a late owned response is closed.
    :raises ValueError: If the URI or request options are invalid, including
        a nonpositive HTTP or HTTPS timeout.
    :raises NotImplementedError: If a file URI has a request body.
    :raises BaseException: If a native header lookup or zero-timeout file wait
        is interrupted; unclaimed responses are closed before propagation or
        by the file worker when a late open completes.
    """
    if body is not None and not isinstance(body, bytes):
        raise ValueError("Request body must be bytes or None.")
    if body is not None and len(body) > 0xFFFFFFFF:
        raise ValueError("Request body exceeds the target's WinHTTP buffer limit.")
    url = _uri(url)
    parts = urlsplit(url)
    if parts.scheme == "file":
        if options["url_timeout"] == 0:
            return (
                _file_zero_response(_file_path(url))
                if body is None
                else _file_zero_response(_file_path(url), body)
            )
        return (
            _FileResponse(_file_path(url))
            if body is None
            else _FileResponse(_file_path(url), body)
        )
    if parts.scheme == "ftp":
        return ftp.FtpResponse(url, options, timestamp, body=body)
    if options["url_timeout"] <= 0:
        raise ValueError("HTTP and HTTPS requests require a positive url_timeout.")
    options, headers = _headers(options, warnings)
    method = "HEAD" if timestamp else options["url_method"] or "GET"
    if method.upper() in ("GET", "HEAD"):
        method = method.upper()
    if method.upper() in ("GET", "HEAD", "CONNECT"):
        # These verbs select no upload mode; an explicit zero length is not
        # serialized by the released source request implementation.
        headers = {
            name: value
            for name, value in headers.items()
            if not (name.lower() == "content-length" and value == "0")
        }
    follow = options["follow_redirects"] == "all" or (
        options["follow_redirects"] == "safe" and method in ("GET", "HEAD")
    )
    redirects, credentials = 0, True
    deadline = (
        time.monotonic() + options["url_timeout"] if options["url_timeout"] else None
    )
    while True:
        response = _http_response(
            url,
            dict(options, url_method=method),
            headers,
            credentials,
            deadline=deadline,
            body=body,
            redirected=bool(redirects),
        )
        try:
            location = response.header(33)
        except BaseException:
            response.close()
            raise
        if (
            not follow
            or not options["maximum_redirection"]
            or response.status < 300
            or response.status >= 400
        ):
            return response
        response.close()
        if response.status not in (300, 301, 302, 303, 307) or not location:
            # Framework exceptions prefer canonical labels to the wire reason.
            reason = {
                300: "Multiple Choices Redirect",
                301: "Moved Permanently Redirect",
                302: "Redirect",
                303: "See Other",
                304: "Not Modified",
                305: "Use Proxy Redirect",
                307: "Temporary Redirect",
            }.get(response.status, response.message)
            error = OSError(
                "The remote server returned an error: ({0}){1}.".format(
                    response.status,
                    " " + reason if reason else "",
                )
            )
            error.status_code = response.status
            raise error
        redirects += 1
        if redirects > options["maximum_redirection"]:
            error = OSError("Too many automatic redirections were attempted.")
            error.status_code = response.status
            raise error
        url = _uri(urljoin(url, location))
        credentials = False
        if _redirect_discards_upload(method, response.status, headers, body):
            method = "GET"
            body = None
            headers = {
                name: value
                for name, value in headers.items()
                if name.lower() not in ("content-length", "transfer-encoding")
            }
        headers = {
            name: value
            for name, value in headers.items()
            if name.lower() != "authorization"
        }


def checksum_file(path, algorithm):
    """Hash a file through bounded reads with Python's standard library.

    :param str path: Existing literal file path.
    :param str algorithm: Bound hashing algorithm.
    :returns: Lowercase hexadecimal digest.
    :rtype: str
    :raises OSError: If reading the file fails.
    """
    digest = hashlib.new(algorithm)
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


# Five request participants plus an explicit metadata-only flag keep the call
# readable; hiding that flag inside public options would obscure its origin.
def _response(
    result, url, options, warnings, callback, *, timestamp=False
):  # pylint: disable=too-many-arguments
    started = time.time()
    response = None
    completed = True
    try:
        response = open_resource(url, options, warnings, timestamp)
        result["msg"], result["status_code"] = response.message, response.status
        if response.status is not None and response.status >= 400:
            raise OSError(
                "The remote server returned an error: ({0}) {1}.".format(
                    response.status, response.message
                )
            )
        return callback(response)
    except _ModuleFailure:
        completed = False
        raise
    except OSError as error:
        if response is None:
            result["status_code"] = getattr(error, "status_code", None)
        raise
    finally:
        if response is not None:
            response.close()
        if completed:
            result["elapsed"] = time.time() - started


def _checksum_record(response, source_url, checksum_url):
    data = b"".join(iter(lambda: response.read(65536), b""))
    encoding = "utf-8-sig"
    for marker, name in (
        (codecs.BOM_UTF32_LE, "utf-32"),
        (codecs.BOM_UTF32_BE, "utf-32"),
        (codecs.BOM_UTF16_LE, "utf-16"),
        (codecs.BOM_UTF16_BE, "utf-16"),
    ):
        if data.startswith(marker):
            encoding = name
            break
    text = data.decode(encoding, "replace")
    basename = re.escape(ntpath.basename(unquote(urlsplit(source_url).path)))
    for line in re.split(r"\r?\n", text):
        if re.search(r"\s+\.?/?\\?" + basename + r"\s*$", line, re.IGNORECASE):
            return re.sub(r"\W+", "", line.split(" ", 1)[0].strip(DOTNET_WHITESPACE))
    raise _ModuleFailure(
        "Checksum record not found for file name '{0}' in file from url: '{1}'".format(
            basename, checksum_url
        )
    )


def download(options, check_mode=False):
    """Apply the pinned get-url decision tree, retaining partial failure results.

    :param dict options: Validated public module parameters.
    :param bool check_mode: Predict destination replacement after a real download.
    :returns: Complete JSON result, including partial metadata on failure.
    :rtype: dict
    """
    result = {"changed": False, "elapsed": 0, "url": options["url"]}
    warnings = []
    try:
        _download(options, check_mode, result, warnings)
    except ftp.RequestSetupError as error:
        return {"changed": False, "failed": True, "msg": str(error)}
    except (OSError, ValueError, NotImplementedError) as error:
        result.update(failed=True, msg=str(error))
    if warnings:
        result["warnings"] = warnings
    return result


def _destination(options):
    url, dest = options["url"], options["dest"]
    if os.path.isdir(dest):
        parts = urlsplit(url)
        basename = ntpath.basename(unquote(parts.path))
        dest = os.path.join(dest, basename or parts.hostname or "")
    elif dest.endswith(("\\", "/")):
        raise ValueError(
            "The destination path '{0}' does not exist, or is not visible to "
            "the current user. Ensure download destination folder exists "
            "(perhaps using win_file state=directory) before win_get_url runs.".format(
                dest
            )
        )
    return dest


def _expected_checksum(options, result, warnings):
    checksum = options["checksum"]
    checksum = checksum.strip(DOTNET_WHITESPACE).lower() if checksum else checksum
    if options["checksum_url"]:
        checksum_url = options["checksum_url"].strip(DOTNET_WHITESPACE)
        try:
            scheme = urlsplit(_uri(checksum_url)).scheme
        except ValueError:
            scheme = None
        if scheme not in (
            "file",
            "ftp",
            "http",
            "https",
        ):
            raise ValueError(
                "Unsupported 'checksum_url' value for '{0}': '{1}'".format(
                    options["dest"], checksum_url
                )
            )
        try:
            checksum = _response(
                result,
                checksum_url,
                options,
                warnings,
                lambda response: _checksum_record(
                    response, options["url"], checksum_url
                ),
            )
        except OSError as error:
            raise ValueError(
                "Error when getting the remote checksum from '{0}'. {1}".format(
                    checksum_url, _message(error)
                )
            ) from error
    return checksum


def _needs_download(options, result, warnings, dest_checksum):
    url, dest, checksum = options["url"], options["dest"], options["checksum"]
    force = options["force"] or bool(checksum and dest_checksum != checksum)
    if dest_checksum and checksum and dest_checksum == checksum and not force:
        return False
    required = force or not os.path.exists(dest)
    if not required:
        file_url = _uri(url)
        if urlsplit(file_url).scheme == "file":
            return os.stat(_file_path(file_url)).st_mtime > os.stat(dest).st_mtime
        try:
            modified = _response(
                result,
                url,
                options,
                warnings,
                lambda response: response.modified(),
                timestamp=True,
            )
        except OSError as error:
            raise ValueError(
                "Error when requesting 'Last-Modified' date from '{0}'. {1}".format(
                    _uri(url), _message(error)
                )
            ) from error
        required = modified is not None and modified > os.stat(dest).st_mtime
    return required


def _download_file(options, result, warnings, check_mode, dest_checksum):
    url, dest, checksum = options["url"], options["dest"], options["checksum"]
    algorithm = options["checksum_algorithm"]
    parent = os.path.dirname(dest)
    if not os.path.isdir(parent):
        raise ValueError(
            "The path '{0}' does not exist for destination '{1}', or is not "
            "visible to the current user. Ensure download destination folder "
            "exists (perhaps using win_file state=directory) before "
            "win_get_url runs.".format(parent, dest)
        )
    descriptor, temporary = tempfile.mkstemp(prefix="legacy-get-url-")
    try:
        with os.fdopen(descriptor, "wb") as stream:

            def transfer(response):
                for block in iter(lambda: response.read(65536), b""):
                    stream.write(block)
                stream.flush()
                stream.close()
                source_checksum = checksum_file(temporary, algorithm)
                result["checksum_src"] = source_checksum
                if checksum and checksum != source_checksum:
                    raise _ModuleFailure(
                        "The checksum for {0} did not match '{1}', it was '{2}'".format(
                            _uri(url), checksum, source_checksum
                        )
                    )
                if dest_checksum == source_checksum:
                    result["checksum_dest"], result["size"] = (
                        dest_checksum,
                        os.path.getsize(dest),
                    )
                else:
                    if not check_mode:
                        copying.copy_file(temporary, dest, force=True)
                    result["changed"] = True

            try:
                _response(result, url, options, warnings, transfer)
            except OSError as error:
                raise ValueError(
                    "Error downloading '{0}' to '{1}': {2}".format(
                        _uri(url), dest, _message(error)
                    )
                ) from error
    finally:
        os.remove(temporary)


def _download(options, check_mode, result, warnings):
    dest = _destination(options)
    result["dest"] = dest
    options = dict(options, dest=dest)
    options["checksum"] = _expected_checksum(options, result, warnings)
    algorithm = options["checksum_algorithm"]
    dest_checksum = checksum_file(dest, algorithm) if os.path.exists(dest) else None
    if _needs_download(options, result, warnings, dest_checksum):
        _download_file(options, result, warnings, check_mode, dest_checksum)
    if "checksum_dest" not in result and os.path.exists(dest):
        result["checksum_dest"], result["size"] = checksum_file(
            dest, algorithm
        ), os.path.getsize(dest)


def _message(error):
    return (
        error.strerror if isinstance(error, OSError) and error.strerror else str(error)
    )
