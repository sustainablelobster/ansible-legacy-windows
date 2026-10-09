# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage per-connection WinINet proxy settings using native Windows APIs."""

import ctypes
import os


# These records mirror the Windows ABI, not behavior-bearing Python objects.
class _OptionValue(ctypes.Union):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("number", ctypes.c_uint32),
        ("text", ctypes.c_void_p),
        ("filetime", ctypes.c_uint32 * 2),
    ]


class _Option(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("option", ctypes.c_uint32), ("value", _OptionValue)]


class _OptionList(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("size", ctypes.c_uint32),
        ("connection", ctypes.c_wchar_p),
        ("count", ctypes.c_uint32),
        ("error", ctypes.c_uint32),
        ("options", ctypes.POINTER(_Option)),
    ]


def _library(name):
    if os.name != "nt":
        raise OSError("WinINet proxy operations require a Windows target.")
    return ctypes.WinDLL(name, use_last_error=True)


def _wininet():
    library = _library("wininet")
    library.InternetQueryOptionW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.InternetQueryOptionW.restype = ctypes.c_int32
    library.InternetSetOptionW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
    ]
    library.InternetSetOptionW.restype = ctypes.c_int32
    return library


def _kernel():
    library = _library("kernel32")
    library.GlobalFree.argtypes = [ctypes.c_void_p]
    library.GlobalFree.restype = ctypes.c_void_p
    return library


def _error(operation, code):
    message = ctypes.FormatError(code).rstrip("\r\n .")
    return OSError(
        "{0}() failed ({1}, Win32ErrorCode {2})".format(operation, message, code)
    )


def _option_list(connection, numbers):
    options = (_Option * len(numbers))()
    for option, number in zip(options, numbers):
        option.option = number
    listing = _OptionList(
        ctypes.sizeof(_OptionList), connection, len(options), 0, options
    )
    return listing, options


def valid_connection(name):
    """Determine whether a named entry exists in the current user's phonebook.

    :param name: Connection name passed unchanged to RasValidateEntryNameW.
    :type name: str
    :returns: Whether Windows reports ERROR_ALREADY_EXISTS, as upstream does.
    :rtype: bool
    :raises OSError: The target is not Windows or the RAS library cannot load.
    """
    library = _library("rasapi32")
    library.RasValidateEntryNameW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p]
    library.RasValidateEntryNameW.restype = ctypes.c_uint32
    return library.RasValidateEntryNameW(None, name) == 183


def get_proxy(connection=None):
    """Read active proxy configuration for LAN or an existing named connection.

    Latent strings are omitted when their corresponding connection flag is off.
    IE versions before IE8 use FLAGS instead of FLAGS_UI for the flags query.

    :param connection: Connection name; None selects LAN settings.
    :type connection: str or None
    :returns: Nullable auto_config_url/proxy/bypass strings and auto_detect bool.
    :rtype: dict
    :raises OSError: The native read fails or the target is not Windows.
    """
    library, kernel = _wininet(), _kernel()
    flag_option = 10
    while True:
        listing, options = _option_list(connection, (flag_option, 4, 2, 3))
        size = ctypes.c_uint32(ctypes.sizeof(listing))
        success = library.InternetQueryOptionW(
            None, 75, ctypes.byref(listing), ctypes.byref(size)
        )
        code = ctypes.get_last_error()
        try:
            if success:
                flags = options[0].value.number
                return {
                    "auto_detect": bool(flags & 8),
                    "auto_config_url": (
                        ctypes.wstring_at(options[1].value.text)
                        if flags & 4 and options[1].value.text
                        else None
                    ),
                    "proxy": (
                        ctypes.wstring_at(options[2].value.text)
                        if flags & 2 and options[2].value.text
                        else None
                    ),
                    "bypass": (
                        ctypes.wstring_at(options[3].value.text)
                        if flags & 2 and options[3].value.text
                        else None
                    ),
                }
            if flag_option != 10 or code != 87:
                raise _error("InternetQueryOptionW", code)
            flag_option = 1
        finally:
            for option in options[1:]:
                if option.value.text:
                    kernel.GlobalFree(option.value.text)


def set_proxy(config, connection=None):
    """Set all proxy options and notify WinINet instances of their change.

    The caller must read back and validate the resulting configuration because
    Windows may normalize strings without reporting a native write failure.

    :param config: Dictionary with auto_config_url, auto_detect, proxy, bypass.
    :type config: dict
    :param connection: Connection name; None selects LAN settings.
    :type connection: str or None
    :raises OSError: A native write or notification fails, or target is not Windows.
    """
    library = _wininet()
    listing, options = _option_list(connection, (4, 2, 3, 10))
    buffers = [
        ctypes.create_unicode_buffer(config[name]) if config[name] else None
        for name in ("auto_config_url", "proxy", "bypass")
    ]
    for option, buffer in zip(options, buffers):
        option.value.text = ctypes.cast(buffer, ctypes.c_void_p)
    options[3].value.number = (
        1
        | (8 if config["auto_detect"] else 0)
        | (4 if config["auto_config_url"] else 0)
        | (2 if config["proxy"] else 0)
    )
    if not library.InternetSetOptionW(None, 75, ctypes.byref(listing), listing.size):
        code = ctypes.get_last_error()
        if code != 87:
            raise _error("InternetSetOptionW", code)
        # IE6 rejects FLAGS_UI before changing any fields; FLAGS supports XP.
        options[3].option = 1
        if not library.InternetSetOptionW(
            None, 75, ctypes.byref(listing), listing.size
        ):
            raise _error("InternetSetOptionW", ctypes.get_last_error())
    if not library.InternetSetOptionW(None, 95, None, 0):
        raise _error("InternetSetOptionW", ctypes.get_last_error())
