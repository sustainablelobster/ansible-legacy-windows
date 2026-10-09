# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read Windows product identification and licensing without changing activation."""

import ctypes
import sys

try:
    import winreg
except ImportError:
    winreg = None

# The action stages these Python 3.4-compatible helpers beside the payload.
# pylint: disable=import-error
from legacy_windows_product_key import decode_product_key
from legacy_windows_wmi import WmiConnection

# pylint: enable=import-error

_CURRENT_VERSION = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
_LICENSE_PROPERTIES = (
    "PartialProductKey",
    "Name",
    "ProductKeyChannel",
    "LicenseStatus",
)
_LICENSE_STATES = (
    "Unlicensed",
    "Licensed",
    "OOBGrace",
    "OOTGrace",
    "NonGenuineGrace",
    "Notification",
    "ExtendedGrace",
)


def _collapse(values):
    if not values:
        return None
    return values[0] if len(values) == 1 else values


def _present(value):
    if isinstance(value, (bytes, bytearray, list, tuple)):
        return len(value) > 1 or (len(value) == 1 and _present(value[0]))
    return bool(value)


def _registry_value(name):
    if winreg is None:
        raise OSError("Reading Windows product registry data requires Windows.")
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _CURRENT_VERSION) as key:
            return winreg.QueryValueEx(key, name)[0]
    except OSError:
        # Upstream treats every failed registry read as an unavailable key.
        return None


def _product_key(connection):
    try:
        rows = connection.query(
            "SELECT OA3xOriginalProductKey FROM SoftwareLicensingService",
            ["OA3xOriginalProductKey"],
        )
        key = _collapse([row["OA3xOriginalProductKey"] for row in rows])
    except OSError:
        key = None
    if _present(key):
        return key
    data = _registry_value("DigitalProductId")
    if not _present(data):
        data = _registry_value("DigitalProductId4")
    # Preserve an empty firmware string when neither registry value is usable.
    return decode_product_key(data) if _present(data) else key


def _name_mapper():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    operation = kernel.LCMapStringW
    # Keep this independently staged wrapper's native ABI declarations local.
    # pylint: disable=duplicate-code
    operation.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    operation.restype = ctypes.c_int
    # pylint: enable=duplicate-code
    return operation


def _windows_name(name):
    if not name:
        return False
    # The upstream regex is a fixed literal. Native account-culture lowercase
    # preserves its I/İ distinction without Python re's additional equivalences.
    operation = _name_mapper()
    length = len(name.encode("utf-16-le", "surrogatepass")) // 2
    flags = 0x01000100  # LCMAP_LINGUISTIC_CASING | LCMAP_LOWERCASE.
    size = operation(0x400, flags, name, length, None, 0)
    if not size and ctypes.get_last_error() == 1004:
        flags = 0x100  # XP/2003 do not support linguistic casing flags.
        size = operation(0x400, flags, name, length, None, 0)
    if not size:
        raise ctypes.WinError(ctypes.get_last_error())
    buffer = ctypes.create_unicode_buffer(size)
    written = operation(0x400, flags, name, length, buffer, size)
    if not written:
        raise ctypes.WinError(ctypes.get_last_error())
    return "windows" in buffer[:written]


def _license_rows(connection, warnings):
    try:
        rows = connection.query(
            "SELECT {0} FROM SoftwareLicensingProduct".format(
                ", ".join(_LICENSE_PROPERTIES)
            ),
            list(_LICENSE_PROPERTIES),
        )
    except OSError as error:
        if getattr(error, "hresult", None) == 0x80041017:
            # Older licensing schemas lack this optional property. Only a
            # successful query without it establishes that the other fields exist.
            properties = [
                name for name in _LICENSE_PROPERTIES if name != "ProductKeyChannel"
            ]
            rows = connection.query(
                "SELECT {0} FROM SoftwareLicensingProduct".format(
                    ", ".join(properties)
                ),
                properties,
            )
            for row in rows:
                row["ProductKeyChannel"] = None
            warnings.append(
                "ansible_os_license_channel is unavailable: SoftwareLicensingProduct "
                "does not provide ProductKeyChannel."
            )
        else:
            # WMI setup requires Windows, which supplies this platform-only API.
            if (
                getattr(error, "hresult", None) != 0x80041010
                or sys.getwindowsversion().major >= 6  # pylint: disable=no-member
            ):
                raise
            for field in ("edition", "channel", "status"):
                warnings.append(
                    "ansible_os_license_{0} is unavailable: this Windows version "
                    "does not provide SoftwareLicensingProduct.".format(field)
                )
            return []
    return [
        row
        for row in rows
        if _present(row["PartialProductKey"]) and _windows_name(row["Name"])
    ]


def _license_status(value):
    if isinstance(value, int) and 0 <= value < len(_LICENSE_STATES):
        return _LICENSE_STATES[value]
    return None


def read_facts(warnings):
    """Read the five upstream product facts using local WMI and the registry.

    :param list warnings: Receives named unsupported-license-field warnings on
        pre-Vista Windows when the modern licensing class does not exist, or an
        unsupported-channel warning when the class lacks ProductKeyChannel.
    :returns: Five ``ansible_os_*`` facts, preserving null/scalar/list shapes,
        native licensing order, firmware-key precedence, and registry fallback.
        Missing ProductKeyChannel values are null without discarding available
        edition and status fields. Product keys are sensitive; the caller must
        protect logging and storage.
    :rtype: dict
    :raises OSError: WMI, required properties, or native name matching fail.
        Firmware and registry read failures instead follow upstream fallback.
    :raises ValueError: Registry key data cannot be decoded.
    :raises TypeError: Registry key data is not a supported byte sequence.
    :raises MemoryError: Native WMI string allocation fails.
    """
    with WmiConnection() as connection:
        key = _product_key(connection)
        licenses = _license_rows(connection, warnings)
        operating_systems = connection.query(
            "SELECT SerialNumber FROM Win32_OperatingSystem", ["SerialNumber"]
        )
        return {
            "ansible_os_product_id": _collapse(
                [row["SerialNumber"] for row in operating_systems]
            ),
            "ansible_os_product_key": key,
            "ansible_os_license_edition": _collapse([row["Name"] for row in licenses]),
            "ansible_os_license_channel": _collapse(
                [row["ProductKeyChannel"] for row in licenses]
            ),
            "ansible_os_license_status": _collapse(
                [_license_status(row["LicenseStatus"]) for row in licenses]
            ),
        }
