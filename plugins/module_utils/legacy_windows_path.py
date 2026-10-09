# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read and edit persisted semicolon-delimited Windows path variables."""

import os
import re

import legacy_windows_environment as environment  # pylint: disable=import-error
import legacy_windows_reg_stat as registry  # pylint: disable=import-error
from legacy_windows_module import DOTNET_WHITESPACE  # pylint: disable=import-error

try:
    import winreg
except ImportError:
    winreg = None

_MACHINE_KEY = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
_SPACE = "[" + re.escape(DOTNET_WHITESPACE) + "]"
_ELEMENT = re.compile("(" + _SPACE + '*"[^"]+"' + _SPACE + "*|[^;]+)(?:;|$)")


def _location(scope):
    if os.name != "nt":
        raise ValueError("Path operations require a Windows target.")
    if scope == "user":
        return winreg.HKEY_CURRENT_USER, "Environment"
    if scope == "machine":
        return winreg.HKEY_LOCAL_MACHINE, _MACHINE_KEY
    raise ValueError("Path scope must be user or machine.")


def read_value(name, scope):
    """Read a persisted value without expanding environment references.

    The raw registry reader preserves signed integers and array values. Its
    missing or unreadable value result becomes an empty string; a missing
    parent environment key is an error. This does not read the process
    environment.

    :param name: Registry value name.
    :type name: str or None
    :param scope: ``user`` or ``machine``.
    :type scope: str
    :returns: Raw value, or an empty string when no supported value exists.
    :rtype: str or int or list
    :raises ValueError: If the scope is invalid or the target is not Windows.
    :raises OSError: If opening the key fails or the raw reader raises an error.
    """
    root, path = _location(scope)
    with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
        value, _ = registry.read_value(key, name)
    return "" if value is None else value


def set_value(name, value, scope):
    """Write a persisted expandable string, retaining empty values.

    No key is created and no notification is sent. The caller must broadcast
    the environment change after a successful write.

    The provider's ``(default)`` alias selects the unnamed registry value,
    using the account's case-insensitive collation. Reads do not apply this
    alias because the reference reads through the raw registry API.

    :param name: Registry value name.
    :type name: str
    :param value: Complete path string to store as REG_EXPAND_SZ.
    :type value: str
    :param scope: ``user`` or ``machine``.
    :type scope: str
    :raises ValueError: If the name is null or empty, the scope is invalid, or
        the target is not Windows.
    :raises OSError: If opening or writing the environment key fails.
    """
    if name is None:
        raise ValueError("Cannot bind argument to parameter 'Name' because it is null.")
    if name == "":
        raise ValueError(
            "Cannot bind argument to parameter 'Name' because it is an empty string."
        )
    root, path = _location(scope)
    with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
        if environment.values_equal(name, "(default)", invariant=False):
            name = ""
        winreg.SetValueEx(key, name, 0, winreg.REG_EXPAND_SZ, value)


def _find(elements, requested):
    requested = requested.strip('"').strip("\\")
    for index, element in enumerate(elements):
        if environment.values_equal(element.strip('"').strip("\\"), requested):
            return index
    return -1


def edit_value(current, elements, state):
    """Calculate the reference module's ordered path edit without writing it.

    Quoted semicolons remain within an element. Empty segments are discarded
    from the returned string even when no requested edit marks it changed.
    Matching ignores invariant case and surrounding quotes, then backslashes;
    surviving elements keep their spelling unless moved to satisfy ordering.
    Each absent request removes only its first match.

    Raw registry arrays become space-separated text before parsing; an empty
    array fails because the reference function yields a null pipeline result.
    Signed registry integers use their decimal representation.

    :param current: Raw stored registry value from :func:`read_value`.
    :type current: str or int or list
    :param elements: Requested elements in priority order, or no requests.
    :type elements: list[str] or None
    :param state: ``present``, ``absent``, or None for no requested edit.
    :type state: str or None
    :returns: ``changed`` and ``path_value``; absent requests also return the
        last attempted ``removed_idx``, including -1 for an unmatched request.
    :rtype: dict
    :raises ValueError: If the stored value is an empty array or None, or native
        comparison is requested outside Windows.
    :raises OSError: If native case-insensitive comparison fails.
    """
    if current is None or current == []:
        raise ValueError("The stored path value is null or an empty registry array.")
    if isinstance(current, list):
        current = " ".join(str(value) for value in current)
    else:
        current = str(current)
    existing = [match.group(1) for match in _ELEMENT.finditer(current)]
    result = {"changed": False}
    last_index = -1
    for requested in elements or []:
        if state not in ("present", "absent"):
            break
        index = _find(existing, requested)
        if state == "absent":
            result["removed_idx"] = index
            if index >= 0:
                existing.pop(index)
                result["changed"] = True
        elif index < 0 or index < last_index:
            if index >= 0:
                existing.pop(index)
            existing.append(requested)
            last_index = len(existing) - 1
            result["changed"] = True
        else:
            last_index = index
    result["path_value"] = ";".join(existing)
    return result
