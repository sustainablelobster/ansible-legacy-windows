# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read and set WinHTTP proxy settings through native Windows interfaces."""

import ctypes
import os


# These classes describe C records, not behavior-bearing Python objects.
class _ProxyInfo(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("access_type", ctypes.c_uint32),
        ("proxy", ctypes.c_void_p),
        ("bypass", ctypes.c_void_p),
    ]


class _IEProxyConfig(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("auto_detect", ctypes.c_int32),
        ("auto_config_url", ctypes.c_void_p),
        ("proxy", ctypes.c_void_p),
        ("bypass", ctypes.c_void_p),
    ]


def _winhttp():
    if os.name != "nt":
        raise OSError("WinHTTP proxy operations require a Windows target.")
    library = ctypes.WinDLL("winhttp", use_last_error=True)
    for name in (
        "WinHttpGetDefaultProxyConfiguration",
        "WinHttpSetDefaultProxyConfiguration",
    ):
        function = getattr(library, name)
        function.argtypes = [ctypes.POINTER(_ProxyInfo)]
        function.restype = ctypes.c_int32
    library.WinHttpGetIEProxyConfigForCurrentUser.argtypes = [
        ctypes.POINTER(_IEProxyConfig)
    ]
    library.WinHttpGetIEProxyConfigForCurrentUser.restype = ctypes.c_int32
    return library


def _kernel():
    library = ctypes.WinDLL("kernel32", use_last_error=True)
    library.GlobalFree.argtypes = [ctypes.c_void_p]
    library.GlobalFree.restype = ctypes.c_void_p
    return library


def _error(operation):
    code = ctypes.get_last_error()
    message = ctypes.FormatError(code).rstrip("\r\n .")
    return OSError(
        "{0}() failed ({1}, Win32ErrorCode {2})".format(operation, message, code)
    )


def get_proxy():
    """Read the machine-wide default WinHTTP proxy and bypass strings.

    :returns: A dictionary with nullable ``proxy`` and ``bypass`` strings.
    :rtype: dict
    :raises OSError: The target is not Windows or the native read fails.
    """
    library = _winhttp()
    kernel = _kernel()
    info = _ProxyInfo()
    try:
        if not library.WinHttpGetDefaultProxyConfiguration(ctypes.byref(info)):
            raise _error("WinHttpGetDefaultProxyConfiguration")
        return {
            "proxy": ctypes.wstring_at(info.proxy) if info.proxy else None,
            "bypass": ctypes.wstring_at(info.bypass) if info.bypass else None,
        }
    finally:
        for pointer in (info.proxy, info.bypass):
            if pointer:
                kernel.GlobalFree(pointer)


def get_ie_proxy():
    """Read the current user's static proxy for the active IE connection.

    Auto-detection and PAC configuration are not imported into WinHTTP.

    :returns: A dictionary with nullable ``proxy`` and ``bypass`` strings.
    :rtype: dict
    :raises OSError: The target is not Windows or the native read fails.
    """
    library = _winhttp()
    kernel = _kernel()
    info = _IEProxyConfig()
    try:
        if not library.WinHttpGetIEProxyConfigForCurrentUser(ctypes.byref(info)):
            raise _error("WinHttpGetIEProxyConfigForCurrentUser")
        return {
            "proxy": ctypes.wstring_at(info.proxy) if info.proxy else None,
            "bypass": ctypes.wstring_at(info.bypass) if info.bypass else None,
        }
    finally:
        for pointer in (info.auto_config_url, info.proxy, info.bypass):
            if pointer:
                kernel.GlobalFree(pointer)


def set_proxy(proxy, bypass):
    """Set or clear the machine-wide default WinHTTP proxy.

    Windows may normalize or reject individual string components without
    failing this call. The caller must read back and validate its request.

    :param proxy: Proxy string; None or an empty string selects direct access.
    :type proxy: str or None
    :param bypass: Bypass string; ignored when clearing the proxy.
    :type bypass: str or None
    :raises OSError: The target is not Windows or the native write fails.
    """
    library = _winhttp()
    proxy_buffer = ctypes.create_unicode_buffer(proxy) if proxy else None
    bypass_buffer = ctypes.create_unicode_buffer(bypass) if proxy and bypass else None
    info = _ProxyInfo(
        3 if proxy else 1,
        ctypes.cast(proxy_buffer, ctypes.c_void_p),
        ctypes.cast(bypass_buffer, ctypes.c_void_p),
    )
    if not library.WinHttpSetDefaultProxyConfiguration(ctypes.byref(info)):
        raise _error("WinHttpSetDefaultProxyConfiguration")
