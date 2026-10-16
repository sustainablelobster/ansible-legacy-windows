"""Read the active power-scheme identity independently through the registry."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import json

# This fixture executes only on an actual Windows target.
import winreg  # pylint: disable=import-error


def main():
    """Print the native active identifier without loading collection helpers."""
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes",
        )
    except FileNotFoundError:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Control Panel\PowerCfg") as key:
            identity = winreg.QueryValueEx(key, "CurrentPowerPolicy")[0]
    else:
        with key:
            identity = winreg.QueryValueEx(key, "ActivePowerScheme")[0]
    print(json.dumps(identity))


if __name__ == "__main__":
    main()
