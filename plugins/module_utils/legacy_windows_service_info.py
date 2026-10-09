# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read service information through the Windows service-control manager."""

import ctypes
import functools
import os

import legacy_windows_service_config as configuration  # pylint: disable=import-error
from legacy_windows_account import sid_to_name  # pylint: disable=import-error

# The target loads this sibling helper from its staged payload directory,
# not from the controller's collection package path.
# pylint: disable=import-error
from legacy_windows_find_match import compare_paths as compare_service_names
from legacy_windows_find_match import matches as matches_service_name

# pylint: enable=import-error

_ERROR_INSUFFICIENT_BUFFER = 122
_ERROR_MORE_DATA = 234
_ERROR_SERVICE_DOES_NOT_EXIST = 1060
_ENUMERATION_BUFFER_SIZE = 65536
_CONTROL_NAMES = (
    "stop",
    "pause_continue",
    "shutdown",
    "param_change",
    "netbind_change",
    "hardware_profile_change",
    "power_event",
    "session_change",
    "pre_shutdown",
)
_SERVICE_TYPES = {
    1: "kernel_driver",
    2: "file_system_driver",
    4: "adapter",
    8: "recognizer_driver",
    0x10: "win32_own_process",
    0x20: "win32_share_process",
    0x50: "user_own_process",
    0x60: "user_share_process",
    0x200: "pkg_service",
}
_START_MODES = {0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled"}
_STATES = {
    1: "stopped",
    2: "start_pending",
    3: "stop_pending",
    4: "started",
    5: "continue_pending",
    6: "pause_pending",
    7: "paused",
}
_ERROR_CONTROLS = {0: "ignore", 1: "normal", 2: "severe", 3: "critical"}


class ServiceOpenError(OSError):
    """A failure opening or reading the initial service configuration/status.

    :param error: Original native exception, whose message and code are retained.
    :type error: OSError
    """

    def __init__(self, error):
        OSError.__init__(self, *error.args)
        self.winerror = getattr(error, "winerror", error.errno)
        self._native_message = str(error)

    def __str__(self):
        return self._native_message


# Native structures retain their Windows DWORD widths on developer hosts too.
class _ServiceStatus(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("service_type", ctypes.c_uint32),
        ("state", ctypes.c_uint32),
        ("controls", ctypes.c_uint32),
        ("win32_exit_code", ctypes.c_uint32),
        ("service_exit_code", ctypes.c_uint32),
        ("checkpoint", ctypes.c_uint32),
        ("wait_hint", ctypes.c_uint32),
    ]


# The process variant appends two DWORDs to SERVICE_STATUS.
class _ServiceStatusProcess(_ServiceStatus):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("process_id", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
    ]


# Enumeration strings point into the buffer supplied to the native function.
class _EnumServiceStatus(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("name", ctypes.c_wchar_p),
        ("display_name", ctypes.c_wchar_p),
        ("status", _ServiceStatus),
    ]


# Process enumeration has the same prefix but a larger embedded status.
class _EnumServiceStatusProcess(
    ctypes.Structure
):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("name", ctypes.c_wchar_p),
        ("display_name", ctypes.c_wchar_p),
        ("status", _ServiceStatusProcess),
    ]


# Dependencies are MULTI_SZ, so preserve the pointer instead of c_wchar_p's
# automatic conversion, which would discard all but the first dependency.
class _ServiceConfig(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("service_type", ctypes.c_uint32),
        ("start_type", ctypes.c_uint32),
        ("error_control", ctypes.c_uint32),
        ("path", ctypes.c_wchar_p),
        ("load_order_group", ctypes.c_wchar_p),
        ("tag_id", ctypes.c_uint32),
        ("dependencies", ctypes.c_void_p),
        ("username", ctypes.c_wchar_p),
        ("display_name", ctypes.c_wchar_p),
    ]


def _advapi():
    if os.name != "nt":
        raise ValueError("Service information requires a Windows target.")
    library = ctypes.WinDLL("advapi32", use_last_error=True)
    pointer = ctypes.c_void_p
    dword = ctypes.c_uint32
    count = ctypes.POINTER(dword)
    wide = ctypes.c_wchar_p
    for name, arguments, result in (
        ("OpenSCManagerW", [wide, wide, dword], pointer),
        ("OpenServiceW", [pointer, wide, dword], pointer),
        ("CloseServiceHandle", [pointer], ctypes.c_int),
        ("QueryServiceConfigW", [pointer, pointer, dword, count], ctypes.c_int),
        (
            "QueryServiceConfig2W",
            [pointer, dword, pointer, dword, count],
            ctypes.c_int,
        ),
        (
            "QueryServiceStatusEx",
            [pointer, dword, pointer, dword, count],
            ctypes.c_int,
        ),
        (
            "EnumDependentServicesW",
            [pointer, dword, pointer, dword, count, count],
            ctypes.c_int,
        ),
        (
            "EnumServicesStatusExW",
            [pointer, dword, dword, dword, pointer, dword, count, count, count, wide],
            ctypes.c_int,
        ),
        ("GetServiceKeyNameW", [pointer, wide, wide, count], ctypes.c_int),
        ("GetServiceDisplayNameW", [pointer, wide, wide, count], ctypes.c_int),
    ):
        function = getattr(library, name)
        function.argtypes = arguments
        function.restype = result
    return library


def _open_manager(library, access):
    manager = library.OpenSCManagerW(None, None, access)
    if not manager:
        raise ctypes.WinError(ctypes.get_last_error())
    return manager


def _query_buffer(function, *arguments):
    needed = ctypes.c_uint32()
    buffer, size = None, 0
    while True:
        if function(*(arguments + (buffer, size, ctypes.byref(needed)))):
            return buffer
        error = ctypes.get_last_error()
        if error != _ERROR_INSUFFICIENT_BUFFER:
            raise ctypes.WinError(error)
        size = max(needed.value, size * 2, 1)
        buffer = ctypes.create_string_buffer(size)


def _dependent_names(library, service):
    needed, count = ctypes.c_uint32(), ctypes.c_uint32()
    buffer, size = None, 0
    while not library.EnumDependentServicesW(
        service, 3, buffer, size, ctypes.byref(needed), ctypes.byref(count)
    ):
        error = ctypes.get_last_error()
        if error != _ERROR_MORE_DATA:
            # PowerShell exposes this post-constructor getter failure as null.
            return None
        size = max(needed.value, size * 2, 1)
        buffer = ctypes.create_string_buffer(size)
    entries = ctypes.cast(buffer, ctypes.POINTER(_EnumServiceStatus))
    return [entries[index].name for index in range(count.value)]


def _configuration_fields(config):
    # An empty stored account (for example, Tcpip) fails the reference's
    # NTAccount construction; PowerShell exposes that failed getter as null.
    username = config.username or None
    if username == "LocalSystem":
        try:
            username = sid_to_name("S-1-5-18")
        except OSError:
            username = None
    return {
        "dependencies": configuration.multi_string_values(config.dependencies),
        "desktop_interact": bool(config.service_type & 0x100),
        "display_name": config.display_name,
        "error_control": _ERROR_CONTROLS.get(
            config.error_control, str(config.error_control)
        ),
        "load_order_group": config.load_order_group,
        "path": config.path,
        # Unmatched PowerShell switch results serialize as {}, not JSON null.
        "service_type": _SERVICE_TYPES.get(config.service_type & ~0x180, {}),
        "start_mode": _START_MODES.get(config.start_type, {}),
        "username": username,
    }


def _status_fields(status):
    # An unknown flag causes the upstream enum formatter to emit a number,
    # which its string-to-name mapping discards, including any known bits.
    controls = []
    if not status.controls & ~0x1FF:
        controls = [
            name
            for index, name in enumerate(_CONTROL_NAMES)
            if status.controls & (1 << index)
        ]
    return {
        "checkpoint": status.checkpoint,
        "controls_accepted": controls,
        "process_id": status.process_id,
        "service_exit_code": status.service_exit_code,
        "service_flags": ["runs_in_system_process"] if status.flags == 1 else [],
        "state": _STATES.get(status.state, {}),
        "wait_hint_ms": status.wait_hint,
        "win32_exit_code": status.win32_exit_code,
    }


def query_service(name, warnings):
    """Read service configuration, reporting unsupported modern fields as null.

    Unsupported modern Config2 levels append explicit warnings, including when
    automatic and delayed automatic start cannot be distinguished.
    Native description, dependent-service, and account getter failures return
    null. Failure-action getter failures return an empty action list and null
    scalar fields, matching the reference's post-constructor property handling.

    :param name: Exact service key name, preserved in the returned ``name`` field.
    :type name: str
    :param warnings: List receiving service-specific unsupported-field warnings.
    :type warnings: list[str]
    :returns: All 31 upstream-shaped configuration and status fields.
    :rtype: dict
    :raises ServiceOpenError: If opening the manager/service or reading its
        initial configuration/status fails, preserving the native error code.
    :raises ValueError: If the target is not Windows or a supported SID-info
        getter fails, preserving the reference's fatal chained-method boundary.
    """
    library = _advapi()
    manager, service = None, None
    try:
        try:
            manager = _open_manager(library, 1)
            service = library.OpenServiceW(manager, name, 1 | 4 | 8)
            if not service:
                raise ctypes.WinError(ctypes.get_last_error())
            config_buffer = _query_buffer(library.QueryServiceConfigW, service)
            status_buffer = _query_buffer(library.QueryServiceStatusEx, service, 0)
        except OSError as error:
            raise ServiceOpenError(error) from error
        result = _configuration_fields(_ServiceConfig.from_buffer(config_buffer))
        result.update(_status_fields(_ServiceStatusProcess.from_buffer(status_buffer)))
        result.update(
            configuration.query_config(
                library, service, name, result["start_mode"], warnings
            )
        )
        result.update(
            {
                "name": name,
                "dependency_of": _dependent_names(library, service),
            }
        )
        return result
    finally:
        if service:
            library.CloseServiceHandle(service)
        if manager:
            library.CloseServiceHandle(manager)


def enumerate_names():
    """Enumerate ordinary Win32 services, excluding drivers, in native order.

    :returns: Canonical service key names from every enumeration page.
    :rtype: list[str]
    :raises OSError: If Windows cannot enumerate services.
    :raises ValueError: If the target is not Windows.
    """
    library = _advapi()
    manager = _open_manager(library, 4)
    try:
        names = []
        resume = ctypes.c_uint32()
        needed, count = ctypes.c_uint32(), ctypes.c_uint32()
        buffer = ctypes.create_string_buffer(_ENUMERATION_BUFFER_SIZE)
        while True:
            success = library.EnumServicesStatusExW(
                manager,
                0,
                0x30,
                3,
                buffer,
                len(buffer),
                ctypes.byref(needed),
                ctypes.byref(count),
                ctypes.byref(resume),
                None,
            )
            error = 0 if success else ctypes.get_last_error()
            if error not in (0, _ERROR_MORE_DATA):
                raise ctypes.WinError(error)
            entries = ctypes.cast(buffer, ctypes.POINTER(_EnumServiceStatusProcess))
            names.extend(entries[index].name for index in range(count.value))
            if success:
                return names
    finally:
        library.CloseServiceHandle(manager)


def _lookup_service_name(function, manager, name):
    size = ctypes.c_uint32()
    buffer = None
    while True:
        if function(manager, name, buffer, ctypes.byref(size)):
            return buffer.value
        error = ctypes.get_last_error()
        if error == _ERROR_SERVICE_DOES_NOT_EXIST:
            return None
        if error != _ERROR_INSUFFICIENT_BUFFER:
            raise ctypes.WinError(error)
        # The API's required count excludes the terminating NUL character.
        size.value += 1
        buffer = ctypes.create_unicode_buffer(size.value)


def resolve_name(name):
    """Resolve an exact display or service name, including a driver name.

    Display-name lookup supplies its canonical service key. A literal service
    key lookup retains the supplied spelling, as the reference lookup does.

    :param name: Literal name; wildcard processing belongs to the caller.
    :type name: str
    :returns: Service key name, or ``None`` if lookup or status reading fails.
    :rtype: str or None
    :raises ValueError: If the target is not Windows.
    """
    library = _advapi()
    manager, service = None, None
    try:
        manager = _open_manager(library, 1)
        key_name = _lookup_service_name(library.GetServiceKeyNameW, manager, name)
        if key_name is None:
            display_name = _lookup_service_name(
                library.GetServiceDisplayNameW, manager, name
            )
            if display_name is None:
                return None
            key_name = name
        service = library.OpenServiceW(manager, key_name, 4)
        if not service:
            raise ctypes.WinError(ctypes.get_last_error())
        _query_buffer(library.QueryServiceStatusEx, service, 0)
        return key_name
    except OSError:
        # Get-Service's exact fallback validates Status and suppresses native
        # lookup/status failures under the module's SilentlyContinue setting.
        return None
    finally:
        if service:
            library.CloseServiceHandle(service)
        if manager:
            library.CloseServiceHandle(manager)


def _invariant_equal(left, right):
    if os.name != "nt":
        raise ValueError("Service name comparison requires a Windows target.")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    # The fixed native ABI also serves current-culture sorting. Exact service
    # selection needs invariant comparison, not an invariant lowercase key.
    # pylint: disable=duplicate-code
    kernel.CompareStringW.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    kernel.CompareStringW.restype = ctypes.c_int
    # pylint: enable=duplicate-code
    strings = (
        left,
        len(left.encode("utf-16-le", "surrogatepass")) // 2,
        right,
        len(right.encode("utf-16-le", "surrogatepass")) // 2,
    )
    result = kernel.CompareStringW(0x7F, 0x08000001, *strings)
    if not result and ctypes.get_last_error() == 1004:
        result = kernel.CompareStringW(0x7F, 1, *strings)
    if not result:
        raise ctypes.WinError(ctypes.get_last_error())
    return result == 2


def _contains_wildcards(name):
    index = 0
    while index < len(name):
        character = name[index]
        if character == "`":
            index += 2
            continue
        if character in "*?[]":
            return True
        index += 1
    return False


def select_names(name):
    """Select service names using the reference module's lookup precedence.

    An exact invariant-culture match among ordinary services takes priority
    over wildcards. Wildcards match ordinary service key names, never display
    names or drivers. Literal fallback can resolve display names and drivers.
    Sorting uses the account's current culture, as Windows PowerShell 5.1 does.

    Native culture tables differ across Windows versions: the tested ``Rpc`` +
    soft hyphen + ``Ss`` literal matched ``RpcSs`` on Server 2025 but not on XP
    or Server 2003.
    Equal sort keys retain enumeration order rather than reproducing
    PowerShell's unspecified ordering of ties.

    :param name: Requested name/pattern; ``None`` or empty selects all services.
    :type name: str or None
    :returns: Selected service key names in current-culture case-insensitive order.
    :rtype: list[str]
    :raises ValueError: If the name is not a string/None, a wildcard is invalid,
        or the target is not Windows.
    :raises OSError: If enumeration, comparison, or wildcard casing fails.
    """
    if name is not None and not isinstance(name, str):
        raise ValueError("Service name must be a string or None.")
    names = enumerate_names()
    selected = (
        names
        if not name
        else [candidate for candidate in names if _invariant_equal(candidate, name)]
    )
    if not selected:
        if not name:
            selected = enumerate_names()
        elif _contains_wildcards(name):
            selected = [
                candidate
                for candidate in enumerate_names()
                if matches_service_name(candidate, [name])
            ]
        else:
            resolved = resolve_name(name)
            selected = [] if resolved is None else [resolved]
    return sorted(selected, key=functools.cmp_to_key(compare_service_names))
