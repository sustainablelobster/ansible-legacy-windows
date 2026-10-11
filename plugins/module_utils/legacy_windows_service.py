# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read, configure, and control services through the Windows SCM APIs."""

import contextlib
import ctypes
import os
import sys
import time

_DWORD = ctypes.c_uint32
_POINTER = ctypes.c_void_p
_WIDE = ctypes.c_wchar_p
_NO_CHANGE = 0xFFFFFFFF
# Keep this service wrapper's native enum lookup explicit.
# pylint: disable=duplicate-code
_STATES = {
    1: "stopped",
    2: "start_pending",
    3: "stop_pending",
    4: "started",
    5: "continue_pending",
    6: "pause_pending",
    7: "paused",
}
# pylint: enable=duplicate-code
# Keep this service wrapper's native enum lookup explicit.
# pylint: disable=duplicate-code
_TYPES = {
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
# pylint: enable=duplicate-code
_MODES = {0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled"}
_ERRORS = {0: "ignore", 1: "normal", 2: "severe", 3: "critical"}
_ACTIONS = {0: "none", 1: "restart", 2: "reboot", 3: "run_command"}


# These fields describe the fixed Windows ABI, not the controller's C long.
class _Status(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        (name, _DWORD)
        for name in (
            "service_type",
            "state",
            "controls",
            "win32_exit_code",
            "service_exit_code",
            "checkpoint",
            "wait_hint",
            "process_id",
            "flags",
        )
    ]


# Keep MULTI_SZ as an address so ctypes does not truncate it at its first NUL.
class _Config(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("service_type", _DWORD),
        ("start_type", _DWORD),
        ("error_control", _DWORD),
        ("path", _WIDE),
        ("load_order_group", _WIDE),
        ("tag_id", _DWORD),
        ("dependencies", _POINTER),
        ("username", _WIDE),
        ("display_name", _WIDE),
    ]


# A dependent-service enumeration embeds the seven-DWORD non-process status.
class _Dependent(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("name", _WIDE), ("display_name", _WIDE), ("status", _DWORD * 7)]


# Each action has DWORD type and millisecond delay even on 64-bit Windows.
class _Action(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("type", _DWORD), ("delay", _DWORD)]


# Pointers borrow the containing query buffer or the setter's local storage.
class _Failures(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("reset_period", _DWORD),
        ("reboot_message", _WIDE),
        ("command", _WIDE),
        ("count", _DWORD),
        ("actions", ctypes.POINTER(_Action)),
    ]


# TOKEN_PRIVILEGES with one DWORD-aligned LUID_AND_ATTRIBUTES record.
class _Privilege(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("count", _DWORD),
        ("low", _DWORD),
        ("high", ctypes.c_int32),
        ("attributes", _DWORD),
    ]


def _library():
    if os.name != "nt":
        raise ValueError("Service management requires a Windows target.")
    library = ctypes.WinDLL("advapi32", use_last_error=True)
    count = ctypes.POINTER(_DWORD)
    definitions = (
        ("OpenSCManagerW", [_WIDE, _WIDE, _DWORD], _POINTER),
        ("OpenServiceW", [_POINTER, _WIDE, _DWORD], _POINTER),
        ("CloseServiceHandle", [_POINTER], ctypes.c_int),
        ("GetServiceKeyNameW", [_POINTER, _WIDE, _WIDE, count], ctypes.c_int),
        ("GetServiceDisplayNameW", [_POINTER, _WIDE, _WIDE, count], ctypes.c_int),
        ("QueryServiceConfigW", [_POINTER, _POINTER, _DWORD, count], ctypes.c_int),
        (
            "QueryServiceConfig2W",
            [_POINTER, _DWORD, _POINTER, _DWORD, count],
            ctypes.c_int,
        ),
        (
            "QueryServiceStatusEx",
            [_POINTER, _DWORD, _POINTER, _DWORD, count],
            ctypes.c_int,
        ),
        (
            "EnumDependentServicesW",
            [_POINTER, _DWORD, _POINTER, _DWORD, count, count],
            ctypes.c_int,
        ),
        (
            "CreateServiceW",
            [
                _POINTER,
                _WIDE,
                _WIDE,
                _DWORD,
                _DWORD,
                _DWORD,
                _DWORD,
                _WIDE,
                _WIDE,
                count,
                _WIDE,
                _WIDE,
                _WIDE,
            ],
            _POINTER,
        ),
        (
            "ChangeServiceConfigW",
            [
                _POINTER,
                _DWORD,
                _DWORD,
                _DWORD,
                _WIDE,
                _WIDE,
                count,
                _WIDE,
                _WIDE,
                _WIDE,
                _WIDE,
            ],
            ctypes.c_int,
        ),
        ("ChangeServiceConfig2W", [_POINTER, _DWORD, _POINTER], ctypes.c_int),
        ("StartServiceW", [_POINTER, _DWORD, _POINTER], ctypes.c_int),
        ("ControlService", [_POINTER, _DWORD, _POINTER], ctypes.c_int),
        ("DeleteService", [_POINTER], ctypes.c_int),
    )
    for name, arguments, result in definitions:
        function = getattr(library, name)
        function.argtypes, function.restype = arguments, result
    return library


@contextlib.contextmanager
def _handles(name, access, manager_access=1):
    library = _library()
    manager = library.OpenSCManagerW(None, None, manager_access)
    if not manager:
        raise ctypes.WinError(ctypes.get_last_error())
    service = None
    try:
        if name is not None:
            service = library.OpenServiceW(manager, name, access)
            if not service:
                raise ctypes.WinError(ctypes.get_last_error())
        yield library, manager, service
    finally:
        if service:
            library.CloseServiceHandle(service)
        library.CloseServiceHandle(manager)


def _buffer(function, service, level=None):
    needed = _DWORD()
    buffer, size = None, 0
    while True:
        arguments = [service] + ([] if level is None else [level])
        if function(*(arguments + [buffer, size, ctypes.byref(needed)])):
            return buffer
        error = ctypes.get_last_error()
        if error != 122:
            raise ctypes.WinError(error)
        size = max(needed.value, size * 2, 1)
        buffer = ctypes.create_string_buffer(size)


def _strings(pointer):
    values = []
    while pointer:
        value = ctypes.wstring_at(pointer)
        if not value:
            break
        values.append(value)
        pointer += (len(value.encode("utf-16-le", "surrogatepass")) // 2 + 1) * 2
    return values


def _lookup(function, manager, name):
    count = _DWORD(256)
    while True:
        buffer = ctypes.create_unicode_buffer(count.value)
        if function(manager, name, buffer, ctypes.byref(count)):
            return buffer.value
        error = ctypes.get_last_error()
        if error == 1060:
            return None
        if error != 122:
            raise ctypes.WinError(error)
        count.value += 1


def resolve_name(name):
    """Resolve an exact service key or display name without wildcard matching.

    :param name: Literal service key or display name.
    :type name: str
    :returns: Canonical key, or ``None`` when neither name exists.
    :rtype: str or None
    :raises OSError: If the service manager cannot be queried.
    """
    with _handles(None, 0) as (library, manager, _service):
        display = _lookup(library.GetServiceDisplayNameW, manager, name)
        if display is not None:
            return _lookup(library.GetServiceKeyNameW, manager, display)
        return _lookup(library.GetServiceKeyNameW, manager, name)


def _dependents(library, service):
    needed, count = _DWORD(), _DWORD()
    buffer, size = None, 0
    while True:
        if library.EnumDependentServicesW(
            service, 3, buffer, size, ctypes.byref(needed), ctypes.byref(count)
        ):
            entries = ctypes.cast(buffer, ctypes.POINTER(_Dependent))
            return [entries[index].name for index in range(count.value)]
        error = ctypes.get_last_error()
        if error != 234:
            raise ctypes.WinError(error)
        size = max(needed.value, size * 2, 1)
        buffer = ctypes.create_string_buffer(size)


def supports_delayed_start():
    """Report the OS boundary for delayed automatic service startup.

    :returns: Whether Windows is Vista / Server 2008 or newer.
    :rtype: bool
    """
    # This standard-library function is present only on the Windows target.
    return sys.getwindowsversion().major >= 6  # pylint: disable=no-member


def read(name, warnings, access=0):
    """Read mutable configuration, status, and dependent service names.

    :param name: Resolved service key.
    :type name: str
    :param warnings: List receiving unavailable modern read-field notices.
    :type warnings: list[str]
    :param access: Additional SCM rights required by the pending module operation.
    :type access: int
    :returns: Configuration plus private native control fields.
    :rtype: dict
    :raises OSError: A required query fails; an unreadable description is null.
    """
    with _handles(name, 1 | 4 | 8 | access) as (library, _manager, service):
        config = _Config.from_buffer(_buffer(library.QueryServiceConfigW, service))
        status = _Status.from_buffer(_buffer(library.QueryServiceStatusEx, service, 0))
        result = {
            "name": name,
            "dependencies": _strings(config.dependencies),
            "display_name": config.display_name,
            "path": config.path,
            "load_order_group": config.load_order_group,
            "username": config.username,
            "error_control": _ERRORS.get(
                config.error_control, str(config.error_control)
            ),
            "service_type": _TYPES.get(
                config.service_type & ~0x180, str(config.service_type & ~0x180)
            ),
            "desktop_interact": bool(config.service_type & 0x100),
            "start_mode": _MODES.get(config.start_type, str(config.start_type)),
            "state": _STATES.get(status.state, str(status.state)),
            "_service_type": config.service_type,
            "_start_type": config.start_type,
            "_status": status.state,
            "_controls": status.controls,
            "_pid": status.process_id,
            "_dependents": _dependents(library, service),
        }
        for level, field in (
            (1, "description"),
            (2, "failure_actions"),
            (3, "start_mode"),
            (4, "failure_actions_on_non_crash_failure"),
            (5, "sid_info"),
            (6, "required_privileges"),
            (7, "pre_shutdown_timeout_ms"),
        ):
            if level == 3 and (config.start_type != 2 or not supports_delayed_start()):
                continue
            try:
                buffer = _buffer(library.QueryServiceConfig2W, service, level)
            except OSError as error:
                if level == 1:
                    # A failed released description-property read produces null.
                    result[field] = None
                    continue
                if getattr(error, "winerror", None) != 124:
                    raise
                result[field] = None
                warnings.append(
                    (
                        "Service '{0}' cannot read '{1}': Windows error 124 "
                        "(unsupported configuration level)."
                    ).format(name, field)
                )
                continue
            if level == 1:
                result[field] = _WIDE.from_buffer(buffer).value
            elif level == 2:
                failures = _Failures.from_buffer(buffer)
                result.update(
                    failure_actions=[
                        {
                            "type": _ACTIONS.get(action.type, str(action.type)),
                            "delay_ms": action.delay,
                        }
                        for action in failures.actions[: failures.count]
                    ],
                    failure_command=failures.command,
                    failure_reboot_msg=failures.reboot_message,
                    failure_reset_period_sec=failures.reset_period,
                )
            elif level == 3:
                result[field] = (
                    "delayed" if _DWORD.from_buffer(buffer).value else "auto"
                )
            elif level == 4:
                result[field] = bool(_DWORD.from_buffer(buffer).value)
            elif level == 5:
                value = _DWORD.from_buffer(buffer).value
                result[field] = {0: "none", 1: "unrestricted", 3: "restricted"}.get(
                    value, str(value)
                )
            elif level == 6:
                result[field] = _strings(_POINTER.from_buffer(buffer).value)
            else:
                result[field] = _DWORD.from_buffer(buffer).value
        return result


def create(name, path):
    """Create a stopped LocalSystem own-process service with automatic startup.

    :param name: New service key.
    :type name: str
    :param path: Executable command line.
    :type path: str
    :raises OSError: If creation fails.
    """
    with _handles(None, 0, 2) as (library, manager, _service):
        service = library.CreateServiceW(
            manager, name, name, 1, 0x10, 2, 1, path, None, None, None, None, None
        )
        if not service:
            raise ctypes.WinError(ctypes.get_last_error())
        library.CloseServiceHandle(service)


def change(name, **fields):
    """Apply one basic configuration setter, preserving unspecified fields.

    :param name: Service key.
    :type name: str
    :param fields: Native basic configuration fields to change.
    :type fields: dict
    :raises OSError: If Windows rejects the write.
    """
    dependencies = fields.get("dependencies")
    if dependencies:
        dependencies = "\0".join(dependencies) + "\0\0"
    else:
        # The pinned runtime marshals an empty dependency list as NULL too.
        dependencies = None
    with _handles(name, 2) as (library, _manager, service):
        if not library.ChangeServiceConfigW(
            service,
            fields.get("service_type", _NO_CHANGE),
            fields.get("start_type", _NO_CHANGE),
            fields.get("error_control", _NO_CHANGE),
            fields.get("path"),
            fields.get("load_order_group"),
            None,
            dependencies,
            fields.get("username"),
            fields.get("password"),
            fields.get("display_name"),
        ):
            raise ctypes.WinError(ctypes.get_last_error())


def set_extended(name, field, value, access=0):
    """Apply one extended setter; unsupported requested levels fail explicitly.

    :param name: Service key.
    :type name: str
    :param field: Extended field name.
    :type field: str
    :param value: Requested scalar, list, or failure-action update dictionary.
    :type value: object
    :param access: Additional rights requested by the original module operation.
    :type access: int
    :raises OSError: If Windows rejects the write, including unavailable levels.
    """
    levels = {
        "description": 1,
        "failures": 2,
        "delayed": 3,
        "failure_actions_on_non_crash_failure": 4,
        "sid_info": 5,
        "required_privileges": 6,
        "pre_shutdown_timeout_ms": 7,
    }
    level = levels[field]
    storage = None
    if level == 1:
        native = _WIDE(value)
    elif level == 2:
        actions = value.get("failure_actions")
        if actions is not None:
            storage = (_Action * max(len(actions), 1))()
            for index, action in enumerate(actions):
                storage[index] = _Action(
                    next(
                        key for key, item in _ACTIONS.items() if item == action["type"]
                    ),
                    action["delay_ms"],
                )
        native = _Failures(
            value.get("failure_reset_period_sec", 0),
            value.get("failure_reboot_msg"),
            value.get("failure_command"),
            0 if actions is None else len(actions),
            storage,
        )
    elif level == 6:
        storage = ctypes.create_unicode_buffer("\0".join(value) + "\0\0")
        native = _POINTER(ctypes.addressof(storage))
    else:
        native = _DWORD(value)
    with _handles(name, 2 | access) as (library, _manager, service):
        reboot = level == 2 and any(
            action["type"] == "reboot" for action in value.get("failure_actions") or []
        )
        with _shutdown_privilege(library, reboot):
            if not library.ChangeServiceConfig2W(service, level, ctypes.byref(native)):
                raise ctypes.WinError(ctypes.get_last_error())


@contextlib.contextmanager
def _shutdown_privilege(library, required):
    if not required:
        yield
        return
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = _POINTER
    kernel.CloseHandle.argtypes = [_POINTER]
    kernel.CloseHandle.restype = ctypes.c_int
    library.OpenProcessToken.argtypes = [_POINTER, _DWORD, ctypes.POINTER(_POINTER)]
    library.OpenProcessToken.restype = ctypes.c_int
    library.LookupPrivilegeValueW.argtypes = [_WIDE, _WIDE, _POINTER]
    library.LookupPrivilegeValueW.restype = ctypes.c_int
    library.AdjustTokenPrivileges.argtypes = [
        _POINTER,
        ctypes.c_int,
        _POINTER,
        _DWORD,
        _POINTER,
        _POINTER,
    ]
    library.AdjustTokenPrivileges.restype = ctypes.c_int
    token = _POINTER()
    if not library.OpenProcessToken(
        kernel.GetCurrentProcess(), 0x20 | 8, ctypes.byref(token)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    previous, desired = _Privilege(), _Privilege(1, 0, 0, 2)
    adjusted = False
    try:
        luid = ctypes.byref(desired, _Privilege.low.offset)
        if not library.LookupPrivilegeValueW(None, "SeShutdownPrivilege", luid):
            raise ctypes.WinError(ctypes.get_last_error())
        needed = _DWORD()
        if not library.AdjustTokenPrivileges(
            token,
            False,
            ctypes.byref(desired),
            ctypes.sizeof(previous),
            ctypes.byref(previous),
            ctypes.byref(needed),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        adjusted = True
        if ctypes.get_last_error() == 1300:
            raise ctypes.WinError(1300)
        yield
    finally:
        try:
            if adjusted and not library.AdjustTokenPrivileges(
                token, False, ctypes.byref(previous), 0, None, None
            ):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            kernel.CloseHandle(token)


def expand_path(value):
    """Expand Windows environment references in a service command line.

    :param value: Command line, or ``None``.
    :type value: str or None
    :returns: Expanded command line, preserving ``None``.
    :rtype: str or None
    :raises OSError: If expansion fails.
    :raises ValueError: If the target is not Windows.
    """
    if value is None:
        return None
    if os.name != "nt":
        raise ValueError("Service path expansion requires a Windows target.")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.ExpandEnvironmentStringsW.argtypes = [_WIDE, _WIDE, _DWORD]
    kernel.ExpandEnvironmentStringsW.restype = _DWORD
    size = kernel.ExpandEnvironmentStringsW(value, None, 0)
    while size:
        buffer = ctypes.create_unicode_buffer(size)
        needed = kernel.ExpandEnvironmentStringsW(value, buffer, size)
        if not needed:
            break
        if needed <= size:
            return buffer.value
        size = needed
    raise ctypes.WinError(ctypes.get_last_error())


def _wait(library, service, desired):
    checkpoint, progress = None, time.monotonic()
    while True:
        status = _Status.from_buffer(_buffer(library.QueryServiceStatusEx, service, 0))
        if status.state == desired:
            return
        if status.state not in (2, 3, 5, 6):
            raise ValueError(
                "Service did not reach {0}; native state {1}, exit code {2}.".format(
                    _STATES[desired], status.state, status.win32_exit_code
                )
            )
        if checkpoint != status.checkpoint:
            checkpoint, progress = status.checkpoint, time.monotonic()
        if time.monotonic() - progress > max(status.wait_hint / 1000.0, 1.0):
            raise ValueError(
                "Service stopped reporting progress while waiting for "
                + _STATES[desired]
                + "."
            )
        time.sleep(min(max(status.wait_hint / 10000.0, 0.05), 1.0))


def control(name, state, force=False):
    """Start, stop, pause, resume, or restart a service and wait for its state.

    :param name: Service key.
    :type name: str
    :param state: Desired module state.
    :type state: str
    :param force: Stop active dependent services before stopping this service.
    :type force: bool
    :raises OSError: If a control request fails.
    :raises ValueError: If a service terminates or ceases making progress.
    """
    if state == "restarted":
        stopped = _control(name, "stopped", force)
        _control(name, "started", False)
        for dependent in reversed(stopped):
            if dependent != name:
                _control(dependent, "started", False)
        return
    _control(name, state, force)


def _control(name, state, force):
    with _handles(name, 4) as (library, _manager, service):
        status = _Status.from_buffer(_buffer(library.QueryServiceStatusEx, service, 0))
    desired = {"stopped": 1, "paused": 7, "started": 4}[state]
    if status.state == desired:
        return []
    access = (
        32
        if state == "stopped"
        else 64 if state == "paused" or status.state == 7 else 16
    )
    with _handles(name, 4 | access | (8 if force and state == "stopped" else 0)) as (
        library,
        _manager,
        service,
    ):
        stopped = []
        if state == "stopped" and status.state != 1 and force:
            for dependent in _dependents(library, service):
                stopped.extend(_control(dependent, "stopped", True))
        if state == "started" and status.state != 7:
            success = library.StartServiceW(service, 0, None)
        else:
            code = {"stopped": 1, "paused": 2, "started": 3}[state]
            success = library.ControlService(service, code, ctypes.byref(status))
        if not success:
            raise ctypes.WinError(ctypes.get_last_error())
        _wait(library, service, desired)
        return stopped + [name] if state == "stopped" else []


def remove(name):
    """Mark a service for deletion, closing its handle before returning.

    :param name: Service key.
    :type name: str
    :raises OSError: If deletion fails.
    """
    with _handles(name, 0x10000) as (library, _manager, service):
        if not library.DeleteService(service):
            raise ctypes.WinError(ctypes.get_last_error())
