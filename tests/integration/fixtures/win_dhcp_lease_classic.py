# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe raw DHCP state and recover only one journal-owned inactive scope."""

import binascii
import datetime
import json
import os
import subprocess
import sys
import uuid

import legacy_windows_dhcp_api as dhcp_api  # pylint: disable=import-error
import legacy_windows_wmi as wmi  # pylint: disable=import-error

_SCOPES = ("192.0.2.0", "198.51.100.0", "203.0.113.0")
_NETWORK_FIELDS = (
    "Index",
    "SettingID",
    "DHCPEnabled",
    "DHCPServer",
    "IPAddress",
    "IPSubnet",
    "DefaultIPGateway",
    "DNSServerSearchOrder",
    "DNSDomain",
    "DNSDomainSuffixSearchOrder",
)
_SERVICE_FIELDS = ("Name", "StartMode", "PathName", "StartName")


def _encode(row):
    return {
        key: (
            binascii.hexlify(value).decode("ascii")
            if isinstance(value, bytes)
            else list(value) if isinstance(value, tuple) else value
        )
        for key, value in row.items()
    }


def _command(arguments):
    with subprocess.Popen(
        ["netsh.exe", "dhcp", "server", "127.0.0.1"] + arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        stdout, stderr = process.communicate(timeout=60)
        if process.returncode:
            raise OSError(
                "Native DHCP fixture command failed: "
                + stdout.decode("mbcs")
                + stderr.decode("mbcs")
            )
    return stdout.decode("mbcs")


def _snapshot(api):
    with wmi.WmiConnection() as connection:
        network = connection.query(
            "SELECT * FROM Win32_NetworkAdapterConfiguration",
            _NETWORK_FIELDS,
        )
        services = connection.query("SELECT * FROM Win32_Service", _SERVICE_FIELDS)
        runtime = connection.query(
            "SELECT * FROM Win32_Service WHERE Name='DHCPServer'",
            ["Name", "State"],
        )
    scopes, records = [], {}
    for scope in api.subnets():
        scopes.append(_encode(api.subnet(scope)))
        records[scope] = {
            "leases": [_encode(row) for row in api.clients(scope)],
            "reservations": [_encode(row) for row in api.reservations(scope)],
        }
    return {
        "network": network,
        "services": services,
        "runtime": runtime,
        "bindings": _command(["show", "bindings"]),
        "scopes": scopes,
        "records": records,
    }


def _write(path, journal):
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(journal, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    with open(path, encoding="utf-8") as stream:
        assert json.load(stream) == journal


def _load(path, workspace):
    with open(path, encoding="utf-8") as stream:
        journal = json.load(stream)
    assert journal["workspace"] == workspace and journal["scope"] in _SCOPES
    assert journal["name"].startswith("legacy-windows-dhcp-")
    return journal


def _address(journal, suffix):
    return journal["scope"].rsplit(".", 1)[0] + "." + str(suffix)


def _protected(snapshot, journal):
    return dict(
        snapshot,
        scopes=[
            row for row in snapshot["scopes"] if row["address"] != journal["scope"]
        ],
        records={
            key: value
            for key, value in snapshot["records"].items()
            if key != journal["scope"]
        },
    )


def _verify(snapshot, journal, records=True):
    scopes = [row for row in snapshot["scopes"] if row["address"] == journal["scope"]]
    assert len(scopes) == 1 and scopes[0]["name"] == journal["name"]
    assert scopes[0]["state"] == 1
    assert _protected(snapshot, journal) == journal["original"]
    if records:
        for kind, rows in snapshot["records"][journal["scope"]].items():
            for row in rows:
                if row["address"] in [
                    _address(journal, suffix) for suffix in (25, 26, 27)
                ]:
                    assert row["hardware"].endswith(
                        tuple(
                            "0200000000" + "{0:02d}".format(suffix)
                            for suffix in (25, 26, 27)
                        )
                    )
                else:
                    assert row["address"] == _address(journal, 254)
                    assert row["hardware"].endswith("02fffffffffe")
            original = [
                row
                for row in journal["initial"]["records"][journal["scope"]][kind]
                if row["address"] == _address(journal, 254)
            ]
            current = [row for row in rows if row["address"] == _address(journal, 254)]
            assert current == original


def _create_scope(api, journal):
    scope = journal["scope"]
    _command(["add", "scope", scope, "255.255.255.0", journal["name"], "owned fixture"])
    # Netsh creates an enabled but empty scope; disable it before adding a pool.
    _command(["scope", scope, "set", "state", "0"])
    assert api.subnet(scope)["state"] == 1
    _command(
        [
            "scope",
            scope,
            "add",
            "iprange",
            _address(journal, 10),
            _address(journal, 254),
        ]
    )
    _command(
        [
            "scope",
            scope,
            "add",
            "reservedip",
            _address(journal, 254),
            "02fffffffffe",
            "protected.invalid",
            "protected owned sibling",
            "BOTH",
        ]
    )


def _remove_scope(api, journal):
    current = api.subnet(journal["scope"])
    assert current["name"] == journal["name"] and current["state"] == 1
    _command(["delete", "scope", journal["scope"], "DHCPFullForce"])


def main():
    """Execute one bounded fixture operation and emit its raw native observation."""
    assert sys.version_info[:3] == (3, 4, 4)
    workspace, operation = sys.argv[1:3]
    path = os.path.join(workspace, "dhcp-lease-recovery.json")
    api = dhcp_api.DhcpApi()
    if operation == "setup":
        assert not os.path.exists(path)
        original = _snapshot(api)
        existing = {row["address"] for row in original["scopes"]}
        scope = next(value for value in _SCOPES if value not in existing)
        journal = {
            "workspace": workspace,
            "scope": scope,
            "name": "legacy-windows-dhcp-" + uuid.uuid4().hex,
            "original": original,
        }
        _write(path, journal)
        _create_scope(api, journal)
        journal["initial"] = _snapshot(api)
        _verify(journal["initial"], journal)
        _write(path, journal)
        result = {
            "scope": scope,
            "ip": _address(journal, 25),
            "initial": journal["initial"],
        }
    else:
        journal = _load(path, workspace)
        current = _snapshot(api)
        _verify(current, journal)
        if operation == "reset":
            _remove_scope(api, journal)
            _create_scope(api, journal)
            seed = json.loads(sys.argv[3])
            if seed:
                if seed["kind"] == "Reservation":
                    _command(
                        [
                            "scope",
                            journal["scope"],
                            "add",
                            "reservedip",
                            _address(journal, 25),
                            "020000000025",
                            "original.invalid",
                            "original description",
                            "BOTH",
                        ]
                    )
                else:
                    api.save_client(
                        {
                            "address": _address(journal, 25),
                            "mask": "255.255.255.0",
                            "hardware": binascii.unhexlify("020000000025"),
                            "name": "original.invalid",
                            "comment": "original description",
                            "expires": (
                                datetime.date(2099, 1, 1) - datetime.date(1601, 1, 1)
                            ).days
                            * 864000000000,
                            "owner": (0, None, None),
                            "kind": 1,
                        },
                        create=True,
                    )
            result = _snapshot(api)
            _verify(result, journal)
        elif operation == "observe":
            result = current
        else:
            assert operation == "cleanup"
            _remove_scope(api, journal)
            final = _snapshot(api)
            assert final == journal["original"]
            os.remove(path)
            result = {"restored": True, "original": journal["original"], "final": final}
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
