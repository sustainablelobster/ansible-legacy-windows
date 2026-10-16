# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read and write Shell Link and Internet Shortcut native interfaces."""

import ctypes
import os
import uuid
from contextlib import ExitStack

from legacy_windows_wmi import (  # pylint: disable=import-error
    _check,
    _Guid,
    _libraries,
    _method,
    _release,
)

_POINTER = ctypes.c_void_p
_LONG = ctypes.c_int32
_ULONG = ctypes.c_uint32
_STYLES = {"normal": 1, "maximized": 3, "minimized": 7}
_MODIFIERS = (("Alt", 4), ("Ctrl", 2), ("Shift", 1), ("Ext", 8))


def _guid(value):
    return _Guid.from_buffer_copy(uuid.UUID(value).bytes_le)


def _hotkey(value):
    if not value:
        return 0
    parts = value.split("+")
    key = parts.pop().upper()
    modifiers = 0
    for name in parts:
        flag = next(
            (flag for modifier, flag in _MODIFIERS if modifier.lower() == name.lower()),
            None,
        )
        if flag is None:
            raise ValueError("Unknown shortcut hotkey modifier: " + name)
        modifiers |= flag
    if len(key) == 1 and key in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789":
        virtual = ord(key)
    elif key.startswith("F") and key[1:].isdigit() and 1 <= int(key[1:]) <= 24:
        virtual = 111 + int(key[1:])
    else:
        raise ValueError("Shortcut hotkey requires a letter, digit, or F1-F24 key.")
    return virtual | (modifiers << 8)


def _hotkey_text(value):
    if not value:
        return ""
    key, modifiers = value & 255, value >> 8
    # WScript returns Ctrl before Alt even when input lists Alt first.
    names = [
        name
        for name, flag in (("Ctrl", 2), ("Alt", 4), ("Shift", 1), ("Ext", 8))
        if modifiers & flag
    ]
    names.append("F" + str(key - 111) if 112 <= key <= 135 else chr(key))
    return "+".join(names)


class Shortcut:
    """Own one Shell Link or Internet Shortcut and its persistence interface.

    :param str path: Destination shortcut path, ending with .lnk or .url.
    :raises OSError: Windows cannot create or load the shortcut interfaces.
    """

    def __init__(self, path):
        self.path = os.path.abspath(path)
        self.url = path.lower().endswith(".url")
        self._cleanup = None
        self._link = None
        self._persist = None
        self._flags = None
        self._ole = None

    def _interface(self, pointer, identifier, cleanup):
        result = _POINTER()
        status = _method(
            pointer, 0, _LONG, [ctypes.POINTER(_Guid), ctypes.POINTER(_POINTER)]
        )(pointer, ctypes.byref(_guid(identifier)), ctypes.byref(result))
        cleanup.callback(_release, result)
        _check(status, "Shortcut.QueryInterface")
        return result

    def __enter__(self):
        self._ole, _automation = _libraries()
        with ExitStack() as cleanup:
            # Shell objects are apartment-threaded. MTA activation can require
            # unavailable proxies for their URL and data-list interfaces.
            status = self._ole.CoInitializeEx(None, 2)
            if status & 0xFFFFFFFF != 0x80010106:
                _check(status, "CoInitializeEx(shortcut)")
                cleanup.callback(self._ole.CoUninitialize)
            class_id = (
                "fbf23b40-e3f0-101b-8488-00aa003e56f8"
                if self.url
                else "00021401-0000-0000-c000-000000000046"
            )
            interface_id = (
                "cabb0da0-da57-11cf-9974-0020afd79762"
                if self.url
                else "000214f9-0000-0000-c000-000000000046"
            )
            self._link = _POINTER()
            cleanup.callback(_release, self._link)
            _check(
                self._ole.CoCreateInstance(
                    ctypes.byref(_guid(class_id)),
                    None,
                    1,
                    ctypes.byref(_guid(interface_id)),
                    ctypes.byref(self._link),
                ),
                "CoCreateInstance(shortcut)",
            )
            self._persist = self._interface(
                self._link, "0000010b-0000-0000-c000-000000000046", cleanup
            )
            if os.path.exists(self.path):
                _check(
                    _method(self._persist, 5, _LONG, [ctypes.c_wchar_p, _ULONG])(
                        self._persist, self.path, 0
                    ),
                    "IPersistFile.Load(shortcut)",
                )
            if not self.url:
                self._flags = self._interface(
                    self._link, "45e2b4ae-b1c3-11d0-b92f-00a0c90312e1", cleanup
                )
            self._cleanup = cleanup.pop_all()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._cleanup.close()

    def _text(self, slot):
        buffer = ctypes.create_unicode_buffer(32768)
        _check(
            _method(self._link, slot, _LONG, [ctypes.c_wchar_p, ctypes.c_int])(
                self._link, buffer, len(buffer)
            ),
            "IShellLink.GetText",
        )
        return buffer.value

    def _target(self):
        if self.url:
            pointer = _POINTER()
            _check(
                _method(self._link, 4, _LONG, [ctypes.POINTER(_POINTER)])(
                    self._link, ctypes.byref(pointer)
                ),
                "IUniformResourceLocator.GetURL",
            )
            try:
                return ctypes.wstring_at(pointer) if pointer else ""
            finally:
                self._ole.CoTaskMemFree.argtypes = [_POINTER]
                self._ole.CoTaskMemFree.restype = None
                self._ole.CoTaskMemFree(pointer)
        buffer = ctypes.create_unicode_buffer(32768)
        _check(
            _method(
                self._link, 3, _LONG, [ctypes.c_wchar_p, ctypes.c_int, _POINTER, _ULONG]
            )(self._link, buffer, len(buffer), None, 0),
            "IShellLink.GetPath",
        )
        return buffer.value

    def _parsed_source(self, source):
        shell = ctypes.WinDLL("shell32")
        shell.SHParseDisplayName.argtypes = [
            ctypes.c_wchar_p,
            _POINTER,
            ctypes.POINTER(_POINTER),
            _ULONG,
            ctypes.POINTER(_ULONG),
        ]
        shell.SHParseDisplayName.restype = _LONG
        pointer, attributes = _POINTER(), _ULONG()
        _check(
            shell.SHParseDisplayName(
                source, None, ctypes.byref(pointer), 0, ctypes.byref(attributes)
            ),
            "SHParseDisplayName(shortcut source)",
        )
        self._ole.CoTaskMemFree.argtypes = [_POINTER]
        self._ole.CoTaskMemFree.restype = None
        return shell, pointer

    def matches_source(self, source):
        """Compare a shell namespace target by item identity, not display text.

        :param str source: Requested shell namespace path.
        :returns: Whether the loaded shortcut targets the same shell item.
        :rtype: bool
        :raises OSError: Windows cannot resolve the requested namespace item.
        """
        shell, expected = self._parsed_source(source)
        actual = _POINTER()
        try:
            _check(
                _method(self._link, 4, _LONG, [ctypes.POINTER(_POINTER)])(
                    self._link, ctypes.byref(actual)
                ),
                "IShellLink.GetIDList",
            )
            if not actual:
                return False
            shell.ILIsEqual.argtypes = [_POINTER, _POINTER]
            shell.ILIsEqual.restype = ctypes.c_int
            return bool(shell.ILIsEqual(expected, actual))
        finally:
            self._ole.CoTaskMemFree(expected)
            self._ole.CoTaskMemFree(actual)

    def read(self):
        """Read the current in-memory shortcut properties.

        :returns: Upstream property names and their current values.
        :rtype: dict
        :raises OSError: Windows cannot read a shortcut property.
        """
        result = {"src": self._target()}
        if self.url:
            return result
        icon, icon_index = ctypes.create_unicode_buffer(32768), ctypes.c_int()
        _check(
            _method(
                self._link,
                16,
                _LONG,
                [ctypes.c_wchar_p, ctypes.c_int, ctypes.POINTER(ctypes.c_int)],
            )(self._link, icon, len(icon), ctypes.byref(icon_index)),
            "IShellLink.GetIconLocation",
        )
        hotkey, style, flags = ctypes.c_uint16(), ctypes.c_int(), _ULONG()
        _check(
            _method(self._link, 12, _LONG, [ctypes.POINTER(ctypes.c_uint16)])(
                self._link, ctypes.byref(hotkey)
            ),
            "IShellLink.GetHotkey",
        )
        _check(
            _method(self._link, 14, _LONG, [ctypes.POINTER(ctypes.c_int)])(
                self._link, ctypes.byref(style)
            ),
            "IShellLink.GetShowCmd",
        )
        _check(
            _method(self._flags, 6, _LONG, [ctypes.POINTER(_ULONG)])(
                self._flags, ctypes.byref(flags)
            ),
            "IShellLinkDataList.GetFlags",
        )
        result.update(
            args=self._text(10),
            directory=self._text(8),
            description=self._text(6),
            hotkey=_hotkey_text(hotkey.value),
            icon="{0},{1}".format(icon.value, icon_index.value),
            windowstyle=next(
                (name for name, value in _STYLES.items() if value == style.value), ""
            ),
            run_as_admin=bool(flags.value & 0x2000),
        )
        return result

    def set(self, name, value):
        """Set one requested in-memory property without saving the shortcut.

        :param str name: Public shortcut field name.
        :param value: Converted string or administrator boolean.
        :type value: str or bool
        :raises OSError: Windows rejects the requested property value.
        :raises ValueError: A hotkey or icon index is invalid.
        """
        if name == "src":
            if self.url:
                _check(
                    _method(self._link, 3, _LONG, [ctypes.c_wchar_p, _ULONG])(
                        self._link, value, 0
                    ),
                    "IUniformResourceLocator.SetURL",
                )
            elif value.lower().startswith("shell:"):
                _shell, pointer = self._parsed_source(value)
                try:
                    _check(
                        _method(self._link, 5, _LONG, [_POINTER])(self._link, pointer),
                        "IShellLink.SetIDList",
                    )
                finally:
                    self._ole.CoTaskMemFree(pointer)
            else:
                _check(
                    _method(self._link, 20, _LONG, [ctypes.c_wchar_p])(
                        self._link, value
                    ),
                    "IShellLink.SetPath",
                )
        elif name in ("args", "directory", "description"):
            _check(
                _method(
                    self._link,
                    {"args": 11, "directory": 9, "description": 7}[name],
                    _LONG,
                    [ctypes.c_wchar_p],
                )(self._link, value),
                "IShellLink.SetText",
            )
        elif name == "hotkey":
            _check(
                _method(self._link, 13, _LONG, [ctypes.c_uint16])(
                    self._link, _hotkey(value)
                ),
                "IShellLink.SetHotkey",
            )
        elif name == "windowstyle":
            _check(
                _method(self._link, 15, _LONG, [ctypes.c_int])(
                    self._link, _STYLES[value]
                ),
                "IShellLink.SetShowCmd",
            )
        elif name == "icon":
            icon, separator, index = value.rpartition(",")
            icon, index = (icon, int(index)) if separator else (value, 0)
            _check(
                _method(self._link, 17, _LONG, [ctypes.c_wchar_p, ctypes.c_int])(
                    self._link, icon, index
                ),
                "IShellLink.SetIconLocation",
            )
        elif name == "run_as_admin":
            flags = _ULONG()
            _check(
                _method(self._flags, 6, _LONG, [ctypes.POINTER(_ULONG)])(
                    self._flags, ctypes.byref(flags)
                ),
                "IShellLinkDataList.GetFlags",
            )
            flags.value = flags.value | 0x2000 if value else flags.value & ~0x2000
            _check(
                _method(self._flags, 7, _LONG, [_ULONG])(self._flags, flags.value),
                "IShellLinkDataList.SetFlags",
            )

    def save(self):
        """Save the modified shortcut to its destination.

        :raises OSError: Windows cannot write the shortcut file.
        """
        _check(
            _method(self._persist, 6, _LONG, [ctypes.c_wchar_p, ctypes.c_int])(
                self._persist, self.path, 1
            ),
            "IPersistFile.Save(shortcut)",
        )
