# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Create and remove the local side of a trust with Windows LSA APIs."""

import ctypes
import os
from contextlib import contextmanager


# These structures mirror the documented Windows security ABI.
# pylint: disable=too-few-public-methods
# The same fixed LSA headers are also needed by the separate autologon backend.
# pylint: disable=duplicate-code
class _UnicodeString(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_uint16),
        ("maximum_length", ctypes.c_uint16),
        ("buffer", ctypes.c_void_p),
    ]


class _ObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_uint32),
        ("root", ctypes.c_void_p),
        ("name", ctypes.c_void_p),
        ("attributes", ctypes.c_uint32),
        ("security_descriptor", ctypes.c_void_p),
        ("security_quality_of_service", ctypes.c_void_p),
    ]


# pylint: enable=duplicate-code


class _DomainInformation(ctypes.Structure):
    _fields_ = [
        ("name", _UnicodeString),
        ("dns_name", _UnicodeString),
        ("forest_name", _UnicodeString),
        ("guid", ctypes.c_ubyte * 16),
        ("sid", ctypes.c_void_p),
    ]


class _TrustInformation(ctypes.Structure):
    _fields_ = [
        ("name", _UnicodeString),
        ("flat_name", _UnicodeString),
        ("sid", ctypes.c_void_p),
        ("direction", ctypes.c_uint32),
        ("trust_type", ctypes.c_uint32),
        ("attributes", ctypes.c_uint32),
    ]


class _Authentication(ctypes.Structure):
    _fields_ = [
        ("updated", ctypes.c_int64),
        ("kind", ctypes.c_uint32),
        ("length", ctypes.c_uint32),
        ("value", ctypes.c_void_p),
    ]


class _TrustAuthentication(ctypes.Structure):
    _fields_ = [
        ("incoming_count", ctypes.c_uint32),
        ("incoming", ctypes.POINTER(_Authentication)),
        ("previous_incoming", ctypes.POINTER(_Authentication)),
        ("outgoing_count", ctypes.c_uint32),
        ("outgoing", ctypes.POINTER(_Authentication)),
        ("previous_outgoing", ctypes.POINTER(_Authentication)),
    ]


class _ControllerInformation(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_wchar_p),
        ("address", ctypes.c_wchar_p),
        ("address_type", ctypes.c_uint32),
        ("guid", ctypes.c_ubyte * 16),
        ("domain_name", ctypes.c_wchar_p),
        ("forest_name", ctypes.c_wchar_p),
        ("flags", ctypes.c_uint32),
        ("site_name", ctypes.c_wchar_p),
        ("client_site_name", ctypes.c_wchar_p),
    ]


# pylint: enable=too-few-public-methods


def _libraries():
    if os.name != "nt":
        raise OSError("Domain trust operations require a Windows target.")
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    network = ctypes.WinDLL("netapi32", use_last_error=True)
    pointer, number = ctypes.c_void_p, ctypes.c_uint32
    signatures = (
        (
            "LsaOpenPolicy",
            [
                ctypes.POINTER(_UnicodeString),
                ctypes.POINTER(_ObjectAttributes),
                number,
                ctypes.POINTER(pointer),
            ],
        ),
        ("LsaQueryInformationPolicy", [pointer, ctypes.c_int, ctypes.POINTER(pointer)]),
        (
            "LsaQueryTrustedDomainInfoByName",
            [
                pointer,
                ctypes.POINTER(_UnicodeString),
                ctypes.c_int,
                ctypes.POINTER(pointer),
            ],
        ),
        (
            "LsaCreateTrustedDomainEx",
            [
                pointer,
                ctypes.POINTER(_TrustInformation),
                ctypes.POINTER(_TrustAuthentication),
                number,
                ctypes.POINTER(pointer),
            ],
        ),
        (
            "LsaSetTrustedDomainInfoByName",
            [pointer, ctypes.POINTER(_UnicodeString), ctypes.c_int, pointer],
        ),
        ("LsaDeleteTrustedDomain", [pointer, pointer]),
        ("LsaNtStatusToWinError", [number]),
        ("LsaClose", [pointer]),
        ("LsaFreeMemory", [pointer]),
        ("GetLengthSid", [pointer]),
    )
    for name, arguments in signatures:
        function = getattr(security, name)
        function.argtypes, function.restype = arguments, number
    for name, arguments in (
        ("OpenThreadToken", [pointer, number, ctypes.c_int, ctypes.POINTER(pointer)]),
        ("ImpersonateAnonymousToken", [pointer]),
        ("SetThreadToken", [pointer, pointer]),
        ("RevertToSelf", []),
    ):
        function = getattr(security, name)
        function.argtypes, function.restype = arguments, ctypes.c_int
    kernel.GetCurrentThread.argtypes, kernel.GetCurrentThread.restype = [], pointer
    kernel.CloseHandle.argtypes, kernel.CloseHandle.restype = [pointer], ctypes.c_int
    kernel.GetSystemTimeAsFileTime.argtypes = [ctypes.POINTER(ctypes.c_int64)]
    kernel.GetSystemTimeAsFileTime.restype = None
    network.DsGetDcNameW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        pointer,
        ctypes.c_wchar_p,
        number,
        ctypes.POINTER(pointer),
    ]
    network.DsGetDcNameW.restype = number
    network.NetApiBufferFree.argtypes, network.NetApiBufferFree.restype = [
        pointer
    ], number
    return security, kernel, network


def _check(security, status, operation):
    if status:
        code = security.LsaNtStatusToWinError(status & 0xFFFFFFFF)
        raise OSError(code, operation + ": " + ctypes.FormatError(code).strip())


def _text(value):
    return ctypes.string_at(value.buffer, value.length).decode("utf-16-le")


def _unicode(value):
    encoded = value.encode("utf-16-le")
    if len(encoded) > 0xFFFC:
        raise ValueError("The trust domain name is too long.")
    buffer = ctypes.create_string_buffer(encoded + b"\0\0")
    return (
        _UnicodeString(
            len(encoded), len(encoded) + 2, ctypes.cast(buffer, ctypes.c_void_p)
        ),
        buffer,
    )


@contextmanager
def _policy(security, server, access):
    name, buffer = _unicode(server.lstrip("\\"))
    attributes = _ObjectAttributes(ctypes.sizeof(_ObjectAttributes))
    handle = ctypes.c_void_p()
    try:
        _check(
            security,
            security.LsaOpenPolicy(
                ctypes.byref(name),
                ctypes.byref(attributes),
                access,
                ctypes.byref(handle),
            ),
            "Open domain security policy",
        )
        yield handle
    finally:
        if handle:
            security.LsaClose(handle)
        # Keep the UTF-16 backing storage alive until the native call completes.
        del buffer


@contextmanager
def _anonymous(security, kernel):
    previous = ctypes.c_void_p()
    thread = kernel.GetCurrentThread()
    if not security.OpenThreadToken(thread, 0xE, True, ctypes.byref(previous)):
        code = ctypes.get_last_error()
        if code != 1008:  # ERROR_NO_TOKEN means the thread uses its process token.
            raise OSError(
                code,
                "Read current thread identity: " + ctypes.FormatError(code).strip(),
            )
    impersonated = False
    try:
        if not security.ImpersonateAnonymousToken(thread):
            raise ctypes.WinError(ctypes.get_last_error())
        impersonated = True
        yield
    finally:
        try:
            if impersonated:
                restored = (
                    security.SetThreadToken(None, previous)
                    if previous
                    else security.RevertToSelf()
                )
                if not restored:
                    raise ctypes.WinError(ctypes.get_last_error())
        finally:
            if previous:
                kernel.CloseHandle(previous)


def _domain_information(security, server):
    with _policy(security, server, 1) as handle:
        buffer = ctypes.c_void_p()
        try:
            _check(
                security,
                security.LsaQueryInformationPolicy(handle, 12, ctypes.byref(buffer)),
                "Read trusted domain identity",
            )
            if not buffer:
                raise OSError("Windows returned no trusted domain identity.")
            information = ctypes.cast(
                buffer, ctypes.POINTER(_DomainInformation)
            ).contents
            if not information.sid:
                raise OSError("The target has no Active Directory domain SID.")
            return {
                "name": _text(information.dns_name),
                "flat_name": _text(information.name),
                "forest_name": _text(information.forest_name),
                "sid": ctypes.string_at(
                    information.sid, security.GetLengthSid(information.sid)
                ),
            }
        finally:
            if buffer:
                security.LsaFreeMemory(buffer)


def target_domain(name, forest=False):
    """Discover the remote domain identity without changing either domain.

    :param name: Requested DNS domain or forest name.
    :type name: str
    :param forest: Whether the name must identify the forest root domain.
    :type forest: bool
    :returns: DNS name, NetBIOS name, forest name and binary domain SID.
    :rtype: dict
    :raises OSError: Controller discovery or domain-policy reading fails.
    :raises ValueError: A requested forest name identifies a non-root domain.
    """
    security, kernel, network = _libraries()
    buffer = ctypes.c_void_p()
    try:
        # A PDC is writable and owns trust password changes. Return DNS names.
        code = network.DsGetDcNameW(
            None, name, None, None, 0x40000090, ctypes.byref(buffer)
        )
        if code:
            raise OSError(
                code,
                "Discover trusted domain controller: "
                + ctypes.FormatError(code).strip(),
            )
        if not buffer:
            raise OSError("Windows returned no trusted domain controller.")
        server = ctypes.cast(
            buffer, ctypes.POINTER(_ControllerInformation)
        ).contents.name
    finally:
        if buffer:
            network.NetApiBufferFree(buffer)
    try:
        information = _domain_information(security, server)
    except OSError as error:
        if error.errno not in (5, 1326):
            raise
        # The other forest does not yet trust our credentials. Windows exposes
        # this read-only identity query to anonymous callers when policy allows.
        with _anonymous(security, kernel):
            information = _domain_information(security, server)
    if forest and information["forest_name"].lower() != name.lower():
        raise ValueError("A forest trust requires the target forest root DNS name.")
    return information


def _authentication(kernel, password, direction):
    encoded = password.encode("utf-16-le")
    secret = ctypes.create_string_buffer(encoded)
    updated = ctypes.c_int64()
    kernel.GetSystemTimeAsFileTime(ctypes.byref(updated))
    authentication = _Authentication(
        updated.value, 2, len(encoded), ctypes.cast(secret, ctypes.c_void_p)
    )
    pointer = ctypes.pointer(authentication)
    return (
        _TrustAuthentication(
            int(bool(direction & 1)),
            pointer if direction & 1 else None,
            None,
            int(bool(direction & 2)),
            pointer if direction & 2 else None,
            None,
        ),
        secret,
    )


class TrustPolicy:
    """Own the security-policy handle used for one local-side trust change."""

    def __init__(self, server):
        self.server = server
        self.security, self.kernel, _network = _libraries()
        self.handle = None
        self._context = None

    def __enter__(self):
        self._context = _policy(self.security, self.server, 0x809)
        self.handle = self._context.__enter__()
        return self

    def __exit__(self, kind, value, traceback):
        return self._context.__exit__(kind, value, traceback)

    def create(self, information, direction, forest, password):
        """Create one trust and leave its opposite side untouched.

        :param information: Discovered DNS/NetBIOS names and binary domain SID.
        :type information: dict
        :param direction: Inbound=1, outbound=2 or bidirectional=3.
        :type direction: int
        :param forest: Whether the trust is forest-transitive.
        :type forest: bool
        :param password: Shared secret, passed only to the native security API.
        :type password: str
        :raises OSError: Windows rejects creation of the trust.
        """
        name, name_buffer = _unicode(information["name"])
        flat_name, flat_buffer = _unicode(information["flat_name"])
        sid_buffer = ctypes.create_string_buffer(information["sid"])
        trust_auth, secret = _authentication(self.kernel, password, direction)
        trust = _TrustInformation(
            name,
            flat_name,
            ctypes.cast(sid_buffer, ctypes.c_void_p),
            direction,
            2,
            8 if forest else 4,
        )
        handle = ctypes.c_void_p()
        try:
            _check(
                self.security,
                self.security.LsaCreateTrustedDomainEx(
                    self.handle,
                    ctypes.byref(trust),
                    ctypes.byref(trust_auth),
                    0x30,
                    ctypes.byref(handle),
                ),
                "Create local trust",
            )
        finally:
            if handle:
                self.security.LsaClose(handle)
            ctypes.memset(secret, 0, ctypes.sizeof(secret))
            del name_buffer, flat_buffer, sid_buffer

    def set_selective(self, name, enabled):
        """Change selective authentication while preserving other trust bits.

        :param name: Target forest DNS name.
        :type name: str
        :param enabled: Whether selective authentication should be enabled.
        :type enabled: bool
        :raises OSError: Native trust querying or updating fails.
        :raises ValueError: The existing trust is not forest-transitive.
        """
        target, backing = _unicode(name)
        buffer = ctypes.c_void_p()
        try:
            _check(
                self.security,
                self.security.LsaQueryTrustedDomainInfoByName(
                    self.handle, ctypes.byref(target), 6, ctypes.byref(buffer)
                ),
                "Read local trust",
            )
            if not buffer:
                raise OSError("Windows returned no local trust information.")
            information = ctypes.cast(
                buffer, ctypes.POINTER(_TrustInformation)
            ).contents
            if not information.attributes & 8:
                raise ValueError(
                    "Selective authentication can only be set on forest trusts, "
                    "not external trusts."
                )
            information.attributes = (
                information.attributes | 16 if enabled else information.attributes & ~16
            )
            _check(
                self.security,
                self.security.LsaSetTrustedDomainInfoByName(
                    self.handle, ctypes.byref(target), 6, buffer
                ),
                "Set selective authentication",
            )
        finally:
            if buffer:
                self.security.LsaFreeMemory(buffer)
            del backing

    def delete(self, sid):
        """Remove only the local trusted-domain object identified by its SID.

        :param sid: Existing trust's binary domain SID.
        :type sid: bytes
        :raises OSError: Windows rejects deletion of the local-side trust.
        """
        buffer = ctypes.create_string_buffer(sid)
        _check(
            self.security,
            self.security.LsaDeleteTrustedDomain(self.handle, buffer),
            "Remove local trust",
        )
