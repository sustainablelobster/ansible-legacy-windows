"""Snapshot and restore an installed lab SNMP service without exposing values."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import hashlib
import json
import sys

# This fixture runs on Windows independently of the collection payload.
import winreg  # pylint: disable=import-error

BASE = r"SYSTEM\CurrentControlSet\Services\SNMP\Parameters" + "\\"
NAMES = ("PermittedManagers", "ValidCommunities")


def _read():
    result = {}
    for name in NAMES:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, BASE + name) as key:
            values = [
                winreg.EnumValue(key, index)
                for index in range(winreg.QueryInfoKey(key)[1])
            ]
            result[name] = sorted(values, key=lambda value: value[0])
    return result


def main():
    """Read state, save it or restore the previously owned snapshot file.

    :raises ValueError: The requested operation is not recognized.
    """
    mode, path = sys.argv[1:]
    if mode == "snapshot":
        with open(path, "x", encoding="utf-8") as stream:
            json.dump(_read(), stream)
    elif mode == "restore":
        with open(path, "r", encoding="utf-8") as stream:
            original = json.load(stream)
        for name in NAMES:
            access = winreg.KEY_READ | winreg.KEY_SET_VALUE
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, BASE + name, 0, access
            ) as key:
                for index in reversed(range(winreg.QueryInfoKey(key)[1])):
                    winreg.DeleteValue(key, winreg.EnumValue(key, index)[0])
                for value_name, value, kind in original[name]:
                    winreg.SetValueEx(key, value_name, 0, kind, value)
    elif mode != "read":
        raise ValueError("Unknown fixture operation")
    encoded = json.dumps(_read(), ensure_ascii=True, sort_keys=True).encode("ascii")
    print(hashlib.sha256(encoded).hexdigest())


if __name__ == "__main__":
    main()
