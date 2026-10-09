# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage classic event logs through the registry and native event-log API."""

import ctypes
import ntpath
import os
import sys
import unicodedata
from collections import OrderedDict

try:
    import winreg
except ImportError:
    winreg = None

import legacy_windows_environment as environment  # pylint: disable=import-error
from legacy_windows_module import expand_environment  # pylint: disable=import-error

ROOT = r"SYSTEM\CurrentControlSet\Services\EventLog"
RESOURCE_VALUES = (
    ("category_file", "CategoryMessageFile"),
    ("message_file", "EventMessageFile"),
    ("parameter_file", "ParameterMessageFile"),
)


def _api():
    library = ctypes.WinDLL("advapi32", use_last_error=True)
    library.OpenEventLogW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p]
    library.OpenEventLogW.restype = ctypes.c_void_p
    library.GetNumberOfEventLogRecords.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.GetNumberOfEventLogRecords.restype = ctypes.c_int
    library.ClearEventLogW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    library.ClearEventLogW.restype = ctypes.c_int
    library.CloseEventLog.argtypes = [ctypes.c_void_p]
    library.CloseEventLog.restype = ctypes.c_int
    return library


def _value(key, name, default=None):
    try:
        value, kind = winreg.QueryValueEx(key, name)
        return expand_environment(value) if kind == winreg.REG_EXPAND_SZ else value
    except OSError as error:
        if getattr(error, "winerror", error.errno) == 2:
            return default
        raise


def _names(key):
    return [winreg.EnumKey(key, index) for index in range(winreg.QueryInfoKey(key)[0])]


def _legacy_windows():
    # This interpreter API exists on Windows targets but not the lint workstation.
    return sys.getwindowsversion().major < 6  # pylint: disable=no-member


def _log_name(name):
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ROOT) as root:
        for log in _names(root):
            if environment.values_equal(log, name):
                return log
    # The Windows code is needed alongside errno for registry missing-log handling.
    raise OSError(2, "The event log is not registered: " + name, None, 2)


def _log_key(name, access=None):
    return winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        ROOT + "\\" + _log_name(name),
        0,
        winreg.KEY_READ if access is None else access,
    )


def _with_log(name, operation):
    # OpenEventLog silently falls back to Application for an unregistered name.
    name = _log_name(name)
    library = _api()
    handle = library.OpenEventLogW(None, name)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return operation(library, handle)
    finally:
        library.CloseEventLog(handle)


def _count(library, handle):
    count = ctypes.c_uint32()
    if not library.GetNumberOfEventLogRecords(handle, ctypes.byref(count)):
        raise ctypes.WinError(ctypes.get_last_error())
    return count.value


def log_details(name):
    """Read the classic log's public properties and source resource settings.

    :param name: Local classic log name.
    :type name: str
    :returns: Actual state, including ordered source/resource dictionaries.
    :rtype: dict
    :raises OSError: Registry or native entry-count reads fail.
    """
    result = {"name": name, "exists": False}
    try:
        key = _log_key(name)
    except OSError as error:
        if getattr(error, "winerror", error.errno) in (2, 3):
            return result
        raise
    with key:
        retention = _value(key, "Retention", 604800)
        signed_retention = ctypes.c_int32(retention).value
        result.update(
            exists=True,
            maximum_size_kb=_value(key, "MaxSize", 524288) // 1024,
            overflow_action=(
                "OverwriteAsNeeded"
                if retention == 0
                else "DoNotOverwrite" if retention == 0xFFFFFFFF else "OverwriteOlder"
            ),
            retention_days=(
                signed_retention
                if signed_retention in (0, -1)
                else int(signed_retention / 86400)
            ),
            sources=OrderedDict(),
        )
        for source in _names(key):
            with winreg.OpenKey(key, source) as source_key:
                result["sources"][source] = {
                    option: _value(source_key, registry_name)
                    for option, registry_name in RESOURCE_VALUES
                }
    result["entries"] = _with_log(name, _count)
    return result


def source_log(source):
    """Locate a source across all classic logs without changing registration.

    :param source: Source name, unique across local classic logs.
    :type source: str
    :returns: Its registered parent log, or None when absent.
    :rtype: str or None
    :raises OSError: Source registry lookup fails.
    """
    if not source:
        return None
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ROOT) as root:
        for log in _names(root):
            with winreg.OpenKey(root, log) as key:
                try:
                    with winreg.OpenKey(key, source):
                        return log
                except OSError as error:
                    if getattr(error, "winerror", error.errno) not in (2, 3):
                        raise
    return None


def _delete_tree(key, name):
    with winreg.OpenKey(key, name, 0, winreg.KEY_READ | winreg.KEY_WRITE) as child:
        for descendant in _names(child):
            _delete_tree(child, descendant)
    winreg.DeleteKey(key, name)


def remove_source(name, source):
    """Remove one registered source while preserving the parent log.

    :param name: Registered parent log name.
    :type name: str
    :param source: Non-default registered source name.
    :type source: str
    :raises OSError: Registry removal fails.
    """
    with _log_key(name, winreg.KEY_READ | winreg.KEY_WRITE) as key:
        _delete_tree(key, source)
        if _legacy_windows():
            sources = _value(key, "Sources", [])
            winreg.SetValueEx(
                key,
                "Sources",
                0,
                winreg.REG_MULTI_SZ,
                [entry for entry in sources if entry != source],
            )
        winreg.FlushKey(key)


def _default_message_file():
    # Only register the reference message-resource path; no managed code is loaded.
    directory = "Framework64" if ctypes.sizeof(ctypes.c_void_p) == 8 else "Framework"
    version = "v2.0.50727" if _legacy_windows() else "v4.0.30319"
    filename = ntpath.join(
        os.environ["SystemRoot"],
        "Microsoft.NET",
        directory,
        version,
        "EventLogMessages.dll",
    )
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    # Keep this independently staged wrapper's native ABI declarations local.
    # pylint: disable=duplicate-code
    kernel.GetLongPathNameW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    ]
    kernel.GetLongPathNameW.restype = ctypes.c_uint32
    # pylint: enable=duplicate-code
    capacity = len(filename) + 1
    while True:
        buffer = ctypes.create_unicode_buffer(capacity)
        length = kernel.GetLongPathNameW(filename, buffer, capacity)
        if not length:
            # Missing legacy resources remain metadata, not a runtime dependency.
            return filename
        if length < capacity:
            return buffer.value
        capacity = length + 1


def _write_source(key, source, resources):
    with winreg.CreateKeyEx(
        key, source, 0, winreg.KEY_READ | winreg.KEY_WRITE
    ) as child:
        for option, registry_name in RESOURCE_VALUES:
            value = resources.get(option)
            if option == "message_file" and not value:
                value = _default_message_file()
            if value:
                winreg.SetValueEx(
                    child, registry_name, 0, winreg.REG_EXPAND_SZ, ntpath.abspath(value)
                )
                if option == "category_file":
                    winreg.SetValueEx(child, "CategoryCount", 0, winreg.REG_DWORD, 0)
        winreg.FlushKey(child)


def _open_or_create_log(name):
    try:
        key = _log_key(name, winreg.KEY_READ | winreg.KEY_WRITE)
        created = False
    except OSError as error:
        if getattr(error, "winerror", error.errno) not in (2, 3):
            raise
        if name[:8].lower() in ("appevent", "secevent", "sysevent"):
            raise ValueError(
                "The log name: '" + name + "' is invalid for customer log creation."
            ) from error
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ROOT) as root:
            for log in _names(root):
                if len(name) >= 8 and environment.values_equal(name[:8], log[:8]):
                    raise ValueError(
                        "Log name shares its first eight characters with " + log
                    ) from error
        if source_log(name):
            raise ValueError(
                "Log name already exists as an event source: " + name
            ) from error
        key = winreg.CreateKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            ROOT + "\\" + name,
            0,
            winreg.KEY_READ | winreg.KEY_WRITE,
        )
        created = True
    return key, created


def _log_defaults(key, name, source):
    for registry_name, default in (("MaxSize", 524288), ("AutoBackupLogFiles", 0)):
        if _value(key, registry_name) is None:
            winreg.SetValueEx(key, registry_name, 0, winreg.REG_DWORD, default)
    if _legacy_windows():
        if _value(key, "Retention") is None:
            winreg.SetValueEx(key, "Retention", 0, winreg.REG_DWORD, 604800)
        if _value(key, "File") is None:
            winreg.SetValueEx(
                key,
                "File",
                0,
                winreg.REG_EXPAND_SZ,
                "%SystemRoot%\\System32\\config\\" + name[:8] + ".evt",
            )
        sources = _value(key, "Sources", [name])
        if source not in sources:
            sources.append(source)
        winreg.SetValueEx(key, "Sources", 0, winreg.REG_MULTI_SZ, sources)


def create_source(name, source, resources):
    """Register a classic source and, if absent, its log and default source.

    :param name: Parent classic log name.
    :type name: str
    :param source: Unique source name.
    :type source: str
    :param resources: Requested category, message, and parameter resource paths.
    :type resources: dict
    :raises ValueError: Log or source names are invalid or collide.
    :raises OSError: Registry writes fail.
    """
    if not name or any(
        unicodedata.category(char) == "Cc" or char in "\\*?" for char in name
    ):
        # The reference error text mentions spaces, though its validation allows them.
        raise ValueError(
            "Event log names must consist of printable characters and cannot "
            "contain \\, *, ?, or spaces"
        )
    if not source:
        raise ValueError("Source must not be empty.")
    if len(source.encode("utf-16-le", "surrogatepass")) // 2 > 212:
        raise ValueError("Source name is too long.")
    key, created = _open_or_create_log(name)
    with key:
        _log_defaults(key, name, source)
        if created:
            _write_source(key, name, resources)
        if source != name:
            _write_source(key, source, resources)
        winreg.FlushKey(key)


def validate_limit(name, overflow_action, retention_days, check_mode):
    """Validate the upstream Limit-EventLog binding and missing-log failures.

    :param name: Requested classic log name.
    :type name: str
    :param overflow_action: Optional requested overflow policy.
    :type overflow_action: str or None
    :param retention_days: Optional requested retention days.
    :type retention_days: int or None
    :param check_mode: Whether setters will be skipped.
    :type check_mode: bool
    :raises ValueError: A binding, missing-log, or overflow-policy validation fails.
    :raises OSError: Registry reads fail.
    """
    if retention_days is not None and not 1 <= retention_days <= 365:
        raise ValueError("RetentionDays must be between 1 and 365.")
    try:
        with _log_key(name) as key:
            retention = _value(key, "Retention", 604800)
    except OSError as error:
        if getattr(error, "winerror", error.errno) not in (2, 3):
            raise
        raise ValueError(
            'The Log name "' + name + '" does not exist in the computer "localhost".'
        ) from error
    if (
        not check_mode
        and retention_days is not None
        and (
            overflow_action in ("DoNotOverwrite", "OverwriteAsNeeded")
            or overflow_action is None
            and retention in (0, 0xFFFFFFFF)
        )
    ):
        raise ValueError(
            'Retention days is valid only if the overflow action is "OverwriteOlder". '
            "Please change  and try again."
        )


def limit_log(name, maximum_bytes, overflow_action, retention_days):
    """Apply size and overflow settings in the upstream setter order.

    :param name: Existing classic log name.
    :type name: str
    :param maximum_bytes: New size in bytes, or None to leave unchanged.
    :type maximum_bytes: int or None
    :param overflow_action: Overflow action, or None to preserve the current one.
    :type overflow_action: str or None
    :param retention_days: Retention days, or None to use the current value.
    :type retention_days: int or None
    :raises ValueError: OverwriteOlder retention is outside 1 through 365 days.
    :raises OSError: Registry reads or setters fail.
    """
    with _log_key(name, winreg.KEY_READ | winreg.KEY_WRITE) as key:
        retention = _value(key, "Retention", 604800)
        if overflow_action is not None or retention_days is not None:
            if overflow_action is None or overflow_action == "OverwriteOlder":
                days = (
                    retention_days
                    if retention_days is not None
                    else int(retention / 86400)
                )
                if not 1 <= days <= 365:
                    raise ValueError("RetentionDays must be between 1 and 365.")
                retention = days * 86400
            else:
                retention = 0 if overflow_action == "OverwriteAsNeeded" else 0xFFFFFFFF
            winreg.SetValueEx(key, "Retention", 0, winreg.REG_DWORD, retention)
        if maximum_bytes is not None:
            winreg.SetValueEx(key, "MaxSize", 0, winreg.REG_DWORD, maximum_bytes)


def _clear(library, handle):
    if not library.ClearEventLogW(handle, None):
        raise ctypes.WinError(ctypes.get_last_error())


def clear_log(name):
    """Clear the entries in an existing local classic log.

    :param name: Existing classic log name.
    :type name: str
    :raises OSError: Native opening or clearing fails.
    """
    _with_log(name, _clear)


def remove_log(name):
    """Clear and remove a log and its sources; attempt its registered file removal.

    :param name: Existing classic log name.
    :type name: str
    :raises OSError: Clearing or registry deletion fails.
    """
    name = _log_name(name)
    clear_log(name)
    with _log_key(name) as key:
        filename = _value(key, "File")
    if filename:
        try:
            os.remove(filename)
        except OSError:
            # The reference removal suppresses file failures before removing registration.
            pass
    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE, ROOT, 0, winreg.KEY_READ | winreg.KEY_WRITE
    ) as root:
        _delete_tree(root, name)
