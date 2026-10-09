# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read online capability metadata through the installed native DISM library."""

import ctypes
import os

# The action stages the previously verified Windows wildcard implementation.
import legacy_windows_find_match as matching  # pylint: disable=import-error

# Keep the native online-image and package-state constants local.
# pylint: disable=duplicate-code
_ONLINE_IMAGE = "DISM_{53BFAE52-B167-4E2F-A258-0A37B57FF845}"
# pylint: enable=duplicate-code
# Keep the native online-image and package-state constants local.
# pylint: disable=duplicate-code
_STATES = (
    "NotPresent",
    "UninstallPending",
    "Staged",
    "Removed",
    "Installed",
    "InstallPending",
    "Superseded",
    "PartiallyInstalled",
)
# pylint: enable=duplicate-code


# These classes describe native records; adding methods would obscure the ABI.
class _Capability(ctypes.Structure):  # pylint: disable=too-few-public-methods
    # DISM arrays use four-byte packing, including on 64-bit Windows.
    _pack_ = 4
    _fields_ = [("name", ctypes.c_wchar_p), ("state", ctypes.c_int32)]


class _CapabilityInfo(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _pack_ = 4
    _fields_ = [
        ("name", ctypes.c_wchar_p),
        ("state", ctypes.c_int32),
        ("display_name", ctypes.c_wchar_p),
        ("description", ctypes.c_wchar_p),
        ("download_size", ctypes.c_uint32),
        ("install_size", ctypes.c_uint32),
    ]


class _DismString(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _pack_ = 4
    _fields_ = [("value", ctypes.c_wchar_p)]


def _library():
    if os.name != "nt":
        raise ValueError("Capability metadata requires a Windows target.")
    path = os.path.join(os.environ["SystemRoot"], "System32", "DismApi.dll")
    try:
        library = ctypes.WinDLL(path)
        library.DismInitialize.argtypes = [
            ctypes.c_int32,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
        ]
        library.DismInitialize.restype = ctypes.c_int32
        library.DismOpenSession.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        library.DismOpenSession.restype = ctypes.c_int32
        library.DismGetCapabilities.argtypes = [
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.POINTER(_Capability)),
            ctypes.POINTER(ctypes.c_uint32),
        ]
        library.DismGetCapabilities.restype = ctypes.c_int32
        library.DismGetCapabilityInfo.argtypes = [
            ctypes.c_uint32,
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.POINTER(_CapabilityInfo)),
        ]
        library.DismGetCapabilityInfo.restype = ctypes.c_int32
        library.DismGetLastErrorMessage.argtypes = [
            ctypes.POINTER(ctypes.POINTER(_DismString))
        ]
        library.DismGetLastErrorMessage.restype = ctypes.c_int32
        library.DismDelete.argtypes = [ctypes.c_void_p]
        library.DismDelete.restype = ctypes.c_int32
        library.DismCloseSession.argtypes = [ctypes.c_uint32]
        library.DismCloseSession.restype = ctypes.c_int32
        library.DismShutdown.argtypes = []
        library.DismShutdown.restype = ctypes.c_int32
    except (OSError, AttributeError) as error:
        raise OSError(
            "Windows capability metadata API is unavailable on this target: "
            + str(error)
        ) from error
    return library


def _check(library, status, operation):
    # This DISM wrapper owns and releases the API's allocated error string.
    # pylint: disable=duplicate-code
    if not status:
        return
    detail = ctypes.POINTER(_DismString)()
    message = ""
    try:
        if not library.DismGetLastErrorMessage(ctypes.byref(detail)) and detail:
            message = detail.contents.value or ""
    finally:
        if detail:
            library.DismDelete(detail)
    raise OSError(
        "{0} failed (HRESULT 0x{1:08X}): {2}".format(
            operation, status & 0xFFFFFFFF, message
        )
    )
    # pylint: enable=duplicate-code


def _information(library, session, name):
    information = ctypes.POINTER(_CapabilityInfo)()
    try:
        _check(
            library,
            library.DismGetCapabilityInfo(session, name, ctypes.byref(information)),
            "DismGetCapabilityInfo",
        )
        if not information:
            raise OSError("DISM returned no capability information for '" + name + "'.")
        value = information.contents
        state = value.state
        return {
            "name": value.name,
            "state": _STATES[state] if 0 <= state < len(_STATES) else str(state),
            "display_name": value.display_name,
            "description": value.description,
            "download_size": value.download_size,
            "install_size": value.install_size,
        }
    finally:
        if information:
            library.DismDelete(information)


def capabilities(patterns=None, log_level=None, log_path=None):
    """Read matching capabilities in native enumeration order without changes.

    :param list patterns: Alternative Windows wildcard patterns, or None for all.
    :param int log_level: Native logging level, or None for the upstream default.
    :param str log_path: Optional DISM log path, or None for the native default.
    :returns: Complete capability metadata dictionaries in native order.
    :rtype: list
    :raises ValueError: A reached wildcard pattern is invalid.
    :raises OSError: The provider is unavailable or a native metadata call fails.
    """
    library = _library()
    # The pinned source omits false-valued levels and paths from its cmdlet call.
    _check(
        library,
        library.DismInitialize(log_level or 2, log_path or None, None),
        "DismInitialize",
    )
    session = ctypes.c_uint32()
    try:
        _check(
            library,
            library.DismOpenSession(_ONLINE_IMAGE, None, None, ctypes.byref(session)),
            "DismOpenSession",
        )
        values = ctypes.POINTER(_Capability)()
        count = ctypes.c_uint32()
        try:
            _check(
                library,
                library.DismGetCapabilities(
                    session, ctypes.byref(values), ctypes.byref(count)
                ),
                "DismGetCapabilities",
            )
            if count.value and not values:
                raise OSError("DISM returned a count without a capability array.")
            return [
                _information(library, session, values[index].name)
                for index in range(count.value)
                if matching.matches(values[index].name, patterns)
            ]
        finally:
            if values:
                library.DismDelete(values)
            _check(library, library.DismCloseSession(session), "DismCloseSession")
    finally:
        # Shutdown is valid only after initialization and closes no live session.
        status = library.DismShutdown()
        if status:
            raise OSError(
                "DismShutdown failed (HRESULT 0x{0:08X}).".format(status & 0xFFFFFFFF)
            )
