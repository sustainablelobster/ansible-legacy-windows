"""Read NetBIOS configuration independently through Python's native registry."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import json

# This independent registry reader executes only on the Windows fixture.
import winreg  # pylint: disable=import-error

ROOT = (
    r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
)
NETBT = r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_"


def main():
    """Print adapter captions and native NetBIOS settings as JSON."""
    result = []
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, ROOT) as parent:
        for index in range(winreg.QueryInfoKey(parent)[0]):
            guid = winreg.EnumKey(parent, index)
            try:
                with winreg.OpenKey(parent, guid + r"\Connection") as connection:
                    name = winreg.QueryValueEx(connection, "Name")[0]
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, NETBT + guid) as config:
                    value = winreg.QueryValueEx(config, "NetbiosOptions")[0]
            except FileNotFoundError:
                continue
            result.append({"name": name, "value": value})
    print(json.dumps(result))


if __name__ == "__main__":
    main()
