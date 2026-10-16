# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read and activate installed power schemes through PowrProf."""

import ctypes
import uuid

_DWORD = ctypes.c_uint32
_POINTER = ctypes.c_void_p


# This structure describes the Windows GUID ABI, not an application object.
class _Guid(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("words", _DWORD * 4)]


def _guid(value):
    return _Guid.from_buffer_copy(uuid.UUID(value).bytes_le)


def _identity(value):
    return str(uuid.UUID(bytes_le=bytes(value)))


def _check(code, operation):
    if code:
        raise OSError("{0} failed (Windows error {1}).".format(operation, code))


def _modern_plans(power):
    # The published PowrProf signature is local to the power-scheme binding;
    # repeated pointer/DWORD positions do not imply a shared operation.
    # pylint: disable=duplicate-code
    power.PowerEnumerate.argtypes = [
        _POINTER,
        _POINTER,
        _POINTER,
        _DWORD,
        _DWORD,
        _POINTER,
        ctypes.POINTER(_DWORD),
    ]
    power.PowerEnumerate.restype = _DWORD
    # pylint: enable=duplicate-code
    power.PowerReadFriendlyName.argtypes = [
        _POINTER,
        ctypes.POINTER(_Guid),
        _POINTER,
        _POINTER,
        _POINTER,
        ctypes.POINTER(_DWORD),
    ]
    power.PowerReadFriendlyName.restype = _DWORD
    power.PowerGetActiveScheme.argtypes = [_POINTER, ctypes.POINTER(_POINTER)]
    power.PowerGetActiveScheme.restype = _DWORD
    active = _POINTER()
    _check(
        power.PowerGetActiveScheme(None, ctypes.byref(active)), "PowerGetActiveScheme"
    )
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes = [_POINTER]
    kernel.LocalFree.restype = _POINTER
    try:
        current = _identity(ctypes.cast(active, ctypes.POINTER(_Guid)).contents)
    finally:
        kernel.LocalFree(active)
    plans, index = {}, 0
    while True:
        scheme = _Guid()
        size = _DWORD(ctypes.sizeof(scheme))
        code = power.PowerEnumerate(
            None, None, None, 16, index, ctypes.byref(scheme), ctypes.byref(size)
        )
        if code == 259:
            break
        _check(code, "PowerEnumerate")
        size = _DWORD()
        code = power.PowerReadFriendlyName(
            None, ctypes.byref(scheme), None, None, None, ctypes.byref(size)
        )
        if code not in (0, 234):
            _check(code, "PowerReadFriendlyName")
        # Byte counts come from the native API; WCHAR is two bytes on Windows.
        buffer = ctypes.create_string_buffer(size.value)
        _check(
            power.PowerReadFriendlyName(
                None, ctypes.byref(scheme), None, None, buffer, ctypes.byref(size)
            ),
            "PowerReadFriendlyName",
        )
        plans[ctypes.wstring_at(buffer)] = _identity(scheme)
        index += 1
    return plans, current, True


def _legacy_plans(power):
    callback_type = ctypes.WINFUNCTYPE(
        ctypes.c_ubyte,
        _DWORD,
        _DWORD,
        ctypes.c_wchar_p,
        _DWORD,
        ctypes.c_wchar_p,
        _POINTER,
        ctypes.c_ssize_t,
    )
    plans = {}

    def _record(
        index, _name_size, name, _description_size, _description, _policy, _data
    ):
        plans[name] = index
        return 1

    callback = callback_type(_record)
    power.EnumPwrSchemes.argtypes = [callback_type, ctypes.c_ssize_t]
    power.EnumPwrSchemes.restype = ctypes.c_ubyte
    power.GetActivePwrScheme.argtypes = [ctypes.POINTER(_DWORD)]
    power.GetActivePwrScheme.restype = ctypes.c_ubyte
    if not power.EnumPwrSchemes(callback, 0):
        raise ctypes.WinError(ctypes.get_last_error())
    active = _DWORD()
    if not power.GetActivePwrScheme(ctypes.byref(active)):
        raise ctypes.WinError(ctypes.get_last_error())
    return plans, active.value, False


def read_plans():
    """Read installed schemes and the active identifier using available APIs.

    :returns: Name-to-identifier mapping, active identifier and GUID capability.
    :rtype: tuple
    :raises OSError: The native catalogue or active scheme cannot be read.
    """
    power = ctypes.WinDLL("powrprof", use_last_error=True)
    if hasattr(power, "PowerEnumerate"):
        return _modern_plans(power)
    return _legacy_plans(power)


def activate(identity, modern):
    """Activate a catalogue identity without modifying its stored policy.

    :param identity: GUID text or native numeric scheme identifier.
    :type identity: str or int
    :param bool modern: Whether the catalogue uses the GUID-based API.
    :raises OSError: Windows rejects the activation.
    """
    power = ctypes.WinDLL("powrprof", use_last_error=True)
    if modern:
        power.PowerSetActiveScheme.argtypes = [_POINTER, ctypes.POINTER(_Guid)]
        power.PowerSetActiveScheme.restype = _DWORD
        _check(
            power.PowerSetActiveScheme(None, ctypes.byref(_guid(identity))),
            "PowerSetActiveScheme",
        )
    else:
        power.SetActivePwrScheme.argtypes = [_DWORD, _POINTER, _POINTER]
        power.SetActivePwrScheme.restype = ctypes.c_ubyte
        if not power.SetActivePwrScheme(identity, None, None):
            raise ctypes.WinError(ctypes.get_last_error())
