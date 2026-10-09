# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read and set native Windows regional settings on Python 3.4.4."""

import ctypes
import os

from legacy_windows_environment import values_equal  # pylint: disable=import-error

try:
    import winreg
except ImportError:
    winreg = None

_INTERNATIONAL = r"Control Panel\International"
_NLS = r"SYSTEM\CurrentControlSet\Control\Nls"
# Python 3.4.4 exposes QWORD values as bytes and has no REG_QWORD constant.
_REG_QWORD = 11
_FORMAT_TYPES = {
    "s1159": 0x28,
    "s2359": 0x29,
    "sCountry": 0x06,
    "sCurrency": 0x14,
    "sDate": 0x1D,
    "sDecimal": 0x0E,
    "sGrouping": 0x10,
    # Preserve the platform's camel-case registry value name.
    "sLanguage": 0x03,  # codespell:ignore slanguage
    "sList": 0x0C,
    "sLongDate": 0x20,
    "sMonDecimalSep": 0x16,
    "sMonGrouping": 0x18,
    "sMonThousandSep": 0x17,
    "sNativeDigits": 0x13,
    "sNegativeSign": 0x51,
    "sPositiveSign": 0x50,
    "sShortDate": 0x1F,
    "sThousand": 0x0F,
    "sTime": 0x1E,
    "sTimeFormat": 0x1003,
    "sYearMonth": 0x1006,
    "iCalendarType": 0x1009,
    "iCountry": 0x05,
    "iCurrDigits": 0x19,
    "iCurrency": 0x1B,
    "iDate": 0x21,
    "iDigits": 0x11,
    "NumShape": 0x1014,
    "iFirstDayOfWeek": 0x100C,
    "iFirstWeekOfYear": 0x100D,
    "iLZero": 0x12,
    "iMeasure": 0x0D,
    "iNegCurr": 0x1C,
    "iNegNumber": 0x1010,
    "iPaperSize": 0x100A,
    "iTime": 0x23,
    "iTimePrefix": 0x1005,
    "iTLZero": 0x25,
}


class HiveLoadError(RuntimeError):
    """Report the upstream default-profile constructor failure.

    :param OSError error: Native failure loading the default-user hive.
    """

    def __init__(self, error):
        code = getattr(error, "winerror", error.errno)
        detail = ctypes.FormatError(code).rstrip(".\r\n ")
        message = (
            'Unhandled exception while executing module: Exception calling ".ctor" '
            'with "2" argument(s): "Failed to load registry hive at '
            'C:\\Users\\Default\\NTUSER.DAT ({0}, Win32ErrorCode {1})"'
        ).format(detail, code)
        super().__init__(message)


def _kernel():
    if os.name != "nt":
        raise ValueError("Regional settings require a Windows target.")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetLocaleInfoW.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    kernel.GetLocaleInfoW.restype = ctypes.c_int
    kernel.GetUserDefaultLCID.argtypes = []
    kernel.GetUserDefaultLCID.restype = ctypes.c_uint32
    kernel.GetSystemDefaultLCID.argtypes = []
    kernel.GetSystemDefaultLCID.restype = ctypes.c_uint32
    for name in ("GetUserDefaultLocaleName", "GetSystemDefaultLocaleName"):
        if hasattr(kernel, name):
            function = getattr(kernel, name)
            function.argtypes = [ctypes.c_wchar_p, ctypes.c_int]
            function.restype = ctypes.c_int
    if hasattr(kernel, "GetLocaleInfoEx"):
        kernel.GetLocaleInfoEx.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_wchar_p,
            ctypes.c_int,
        ]
        kernel.GetLocaleInfoEx.restype = ctypes.c_int
    kernel.GetUserGeoID.argtypes = [ctypes.c_int]
    kernel.GetUserGeoID.restype = ctypes.c_int32
    kernel.SetUserGeoID.argtypes = [ctypes.c_int32]
    kernel.SetUserGeoID.restype = ctypes.c_int
    return kernel


def _info(locale, kind):
    kernel = _kernel()
    buffer = ctypes.create_unicode_buffer(500)
    if isinstance(locale, str):
        result = kernel.GetLocaleInfoEx(locale, kind, buffer, len(buffer))
    else:
        result = kernel.GetLocaleInfoW(locale, kind, buffer, len(buffer))
    if not result:
        raise ctypes.WinError(ctypes.get_last_error())
    return buffer.value


def cultures():
    """Enumerate the Windows target's supported culture names and locale IDs.

    :returns: Culture-name to locale-ID mapping, including the invariant culture.
    :rtype: dict
    :raises OSError: Windows cannot enumerate or read its locale catalogue.
    :raises ValueError: The target is not Windows.
    """
    kernel = _kernel()
    result = {"": 0x7F}
    names = []
    if hasattr(kernel, "EnumSystemLocalesEx"):
        callback_type = ctypes.WINFUNCTYPE(
            ctypes.c_int, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_ssize_t
        )

        def _collect(name, unused_flags, unused_context):
            names.append(name)
            return 1

        kernel.EnumSystemLocalesEx.argtypes = [
            callback_type,
            ctypes.c_uint32,
            ctypes.c_ssize_t,
            ctypes.c_void_p,
        ]
        kernel.EnumSystemLocalesEx.restype = ctypes.c_int
        success = kernel.EnumSystemLocalesEx(callback_type(_collect), 0, 0, None)
        for name in names:
            result[name] = int(_info(name, 0x01), 16)
    else:
        callback_type = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_wchar_p)

        def _collect_legacy(text):
            names.append(text)
            return 1

        kernel.EnumSystemLocalesW.argtypes = [callback_type, ctypes.c_uint32]
        kernel.EnumSystemLocalesW.restype = ctypes.c_int
        success = kernel.EnumSystemLocalesW(callback_type(_collect_legacy), 2)
        for text in names:
            lcid = int(text, 16)
            language = _info(lcid, 0x59)
            country = _info(lcid, 0x5A)
            result[language + "-" + country] = lcid
            result.setdefault(language, lcid & 0x3FF)
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())
    return result


def _culture(name):
    for candidate, lcid in cultures().items():
        if values_equal(candidate, name):
            return lcid
    raise ValueError("The requested culture is not supported by Windows.")


def valid_location(requested, catalogue):
    """Validate a GeoID against the countries represented by Windows cultures.

    :param str requested: Caller-supplied GeoID string.
    :param dict catalogue: Enumerated Windows culture names and locale IDs.
    :returns: Whether the GeoID is represented by a regional culture.
    :rtype: bool
    :raises OSError: Windows cannot read a supported culture's location.
    """
    try:
        value = int(requested)
    except ValueError:
        return False
    for name, lcid in catalogue.items():
        if not name or "-" not in name:
            continue
        try:
            geo = int(
                _info(name if hasattr(_kernel(), "GetLocaleInfoEx") else lcid, 0x5B)
            )
        except OSError:
            continue
        if geo == value:
            return True
    return False


def _locale_name(system):
    kernel = _kernel()
    name = "GetSystemDefaultLocaleName" if system else "GetUserDefaultLocaleName"
    if hasattr(kernel, name):
        buffer = ctypes.create_unicode_buffer(85)
        if not getattr(kernel, name)(buffer, len(buffer)):
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer.value
    lcid = kernel.GetSystemDefaultLCID() if system else kernel.GetUserDefaultLCID()
    return _info(lcid, 0x59) + "-" + _info(lcid, 0x5A)


def user_locale():
    """Read the current process's default user culture name.

    :returns: Windows user culture name.
    :rtype: str
    :raises OSError: Windows cannot read the current culture.
    :raises ValueError: The target is not Windows.
    """
    return _locale_name(False)


def change_location(requested, check_mode=False):
    """Set or predict the current user's geographical location.

    :param str requested: Validated geographical identifier string.
    :param bool check_mode: Predict changes without writing settings.
    :returns: Whether the location differs.
    :rtype: bool
    :raises OSError: Windows cannot read or write the location.
    :raises ValueError: The target is not Windows or the GeoID is invalid.
    """
    kernel = _kernel()
    modern = hasattr(kernel, "GetSystemTimePreciseAsFileTime")
    if modern:
        current = kernel.GetUserGeoID(16)
        changed = current != int(requested)
        if changed and not check_mode and not kernel.SetUserGeoID(int(requested)):
            raise ctypes.WinError(ctypes.get_last_error())
    else:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            _INTERNATIONAL + r"\Geo",
            0,
            winreg.KEY_READ | (0 if check_mode else winreg.KEY_SET_VALUE),
        ) as key:
            current = winreg.QueryValueEx(key, "Nation")[0]
            changed = not values_equal(str(current), requested)
            if changed and not check_mode:
                winreg.SetValueEx(key, "Nation", 0, winreg.REG_SZ, requested)
    return changed


def change_format(requested, check_mode=False):
    """Set existing International registry values to the selected culture.

    The original module overwrites existing values only, clearing unknown values
    rather than creating an entire replacement key.

    :param str requested: Validated Windows culture name.
    :param bool check_mode: Compute locale data without writing registry values.
    :raises OSError: Windows cannot read locale data or update the user key.
    :raises ValueError: The requested culture is not supported by Windows.
    """
    lcid = _culture(requested)
    locale = requested if hasattr(_kernel(), "GetLocaleInfoEx") else lcid
    wanted = {name: _info(locale, kind) for name, kind in _FORMAT_TYPES.items()}
    wanted.update({"Locale": "{0:08x}".format(lcid), "LocaleName": requested})
    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        _INTERNATIONAL,
        0,
        winreg.KEY_READ | (0 if check_mode else winreg.KEY_SET_VALUE),
    ) as key:
        values = [
            winreg.EnumValue(key, index) for index in range(winreg.QueryInfoKey(key)[1])
        ]
        if any(values_equal(name, "sShortTime") for name, unused, kind in values):
            wanted["sShortTime"] = _info(locale, 0x79)
        for name, previous, kind in values:
            matching = next(
                (
                    value
                    for candidate, value in wanted.items()
                    if values_equal(candidate, name)
                ),
                None,
            )
            if matching is None:
                matching = {
                    winreg.REG_BINARY: b"",
                    winreg.REG_DWORD: 0,
                    winreg.REG_MULTI_SZ: [],
                    _REG_QWORD: b"\0" * 8,
                }.get(kind, "")
            equal = (
                values_equal(str(previous), matching)
                if isinstance(matching, str)
                else previous == matching
            )
            if not equal and not check_mode:
                winreg.SetValueEx(key, name, 0, kind, matching)


def change_system_locale(requested, check_mode=False):
    """Set or predict the non-Unicode system locale without restarting Windows.

    :param str requested: Validated Windows culture name.
    :param bool check_mode: Predict changes without writing settings.
    :returns: Whether a pending system-locale change requires a restart.
    :rtype: bool
    :raises OSError: Windows cannot read or update system locale settings.
    :raises ValueError: The requested culture is not supported by Windows.
    """
    if hasattr(_kernel(), "GetSystemTimePreciseAsFileTime"):
        if values_equal(_locale_name(True), requested):
            return False
        if not check_mode:
            # The installed International cmdlet calls this same native export
            # with flags 2 and discards its return value in the pinned baseline.
            library = ctypes.WinDLL("intl.cpl", use_last_error=True)
            library.IntlUpdateSystemLocale.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_int32,
            ]
            library.IntlUpdateSystemLocale.restype = ctypes.c_int32
            canonical = next(
                name for name in cultures() if values_equal(name, requested)
            )
            library.IntlUpdateSystemLocale(canonical, 2)
        return True
    lcid = _culture(requested)
    locale = requested if hasattr(_kernel(), "GetLocaleInfoEx") else lcid
    wanted = (
        (_NLS + r"\Language", "Default", "{0:04x}".format(lcid)),
        (_NLS + r"\Locale", "(Default)", "{0:08x}".format(lcid)),
        (_NLS + r"\CodePage", "ACP", _info(locale, 0x1004)),
        (_NLS + r"\CodePage", "OEMCP", _info(locale, 0x0B)),
        (_NLS + r"\CodePage", "MACCP", _info(locale, 0x1011)),
    )
    changed = False
    for path, name, value in wanted:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            path,
            0,
            winreg.KEY_READ | (0 if check_mode else winreg.KEY_SET_VALUE),
        ) as key:
            try:
                previous = winreg.QueryValueEx(key, name)[0]
            except FileNotFoundError:
                previous = None
            if previous != value:
                changed = True
                if not check_mode:
                    winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
    return changed


def _copy_key(source_path, target_path):
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, source_path) as source:
        with winreg.CreateKeyEx(
            winreg.HKEY_USERS, target_path, 0, winreg.KEY_READ | winreg.KEY_WRITE
        ) as target:
            for index in range(winreg.QueryInfoKey(source)[1]):
                name, value, kind = winreg.EnumValue(source, index)
                winreg.SetValueEx(target, name, 0, kind, value)
        children = [
            winreg.EnumKey(source, index)
            for index in range(winreg.QueryInfoKey(source)[0])
        ]
    for name in children:
        _copy_key(source_path + "\\" + name, target_path + "\\" + name)


def _unload_hive():
    library = ctypes.WinDLL("advapi32", use_last_error=True)
    library.RegUnLoadKeyW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    library.RegUnLoadKeyW.restype = ctypes.c_int32
    code = library.RegUnLoadKeyW(winreg.HKEY_USERS, "ANSIBLE")
    if code:
        raise ctypes.WinError(code)


def copy_user_settings():
    """Copy the user's regional and input registry trees to default profiles.

    :returns: Warnings when the upstream reserved hive name was already loaded.
    :rtype: list[str]
    :raises HiveLoadError: Windows rejects loading the default-user hive.
    :raises OSError: Windows cannot copy or unload the default-user hive.
    """
    warnings = []
    try:
        with winreg.OpenKey(winreg.HKEY_USERS, "ANSIBLE"):
            pass
    except FileNotFoundError:
        pass
    else:
        warnings.append(
            "hive already loaded at HKU:\\ANSIBLE, had to unload "
            "hive for win_region to continue"
        )
        _unload_hive()
    try:
        winreg.LoadKey(winreg.HKEY_USERS, "ANSIBLE", r"C:\Users\Default\NTUSER.DAT")
    except OSError as error:
        raise HiveLoadError(error) from error
    try:
        for sid in ("ANSIBLE", ".DEFAULT", "S-1-5-19", "S-1-5-20"):
            for path in (
                r"Keyboard Layout",
                _INTERNATIONAL,
                r"Control Panel\Input Method",
            ):
                _copy_key(path, sid + "\\" + path)
    finally:
        _unload_hive()
    return warnings
