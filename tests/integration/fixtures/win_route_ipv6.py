# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Observe one owned IPv6 prefix through the installed legacy native tools."""

import ipaddress
import json
import os
import re
import subprocess
import sys
import uuid

_ROW = re.compile(r"^(no|age|yes)\s+(\S+)\s+(\d+)\s+(\S+/\d+)\s+(\d+)\s+(.+)$", re.I)


# Keep this independent netsh observer beside its recovery journal, without a
# dependency on the production facts reader's unrelated command helper.
# pylint: disable=duplicate-code
def _command(arguments):
    executable = os.path.join(os.environ["SystemRoot"], "System32", "netsh.exe")
    with subprocess.Popen(
        [executable, "interface", "ipv6"] + arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        output, errors = process.communicate()
    if process.returncode:
        raise OSError(
            "Native IPv6 observation failed ({0}): {1} {2}".format(
                process.returncode,
                output.decode("mbcs", "replace"),
                errors.decode("mbcs", "replace"),
            )
        )
    return output.decode("mbcs", "replace")


# pylint: enable=duplicate-code
def _routes(store):
    rows = []
    for line in _command(["show", "routes", "store=" + store]).splitlines():
        found = _ROW.match(line.strip())
        if found:
            publish, kind, metric, prefix, index, gateway = found.groups()
            rows.append(
                {
                    "publish": publish,
                    "kind": kind,
                    "metric": int(metric),
                    "prefix": str(ipaddress.ip_network(prefix)),
                    "index": int(index),
                    "gateway": gateway,
                }
            )
        elif "/" in line and not line.strip().startswith("Publish"):
            raise ValueError("Unrecognized native IPv6 route row: " + line)
    return sorted(rows, key=lambda row: json.dumps(row, sort_keys=True))


def _observe():
    # The installed tool's dump contains persistent commands, not address timers.
    return {
        "active": _routes("active"),
        "persistent": _routes("persistent"),
        "configuration": [
            line.strip() for line in _command(["dump"]).splitlines() if line.strip()
        ],
    }


def _interface_name(index):
    names = []
    for line in _command(["show", "interface"]).splitlines():
        found = re.match(
            r"^\s*(\d+)\s+\d+\s+\d+\s+(?:connected|disconnected)\s+(.+)$", line, re.I
        )
        if found and int(found.group(1)) == index:
            names.append(found.group(2).strip())
    assert len(names) == 1, "The selected native interface must have one installed name"
    return names[0]


def _persistent_command(record):
    return 'add route prefix={0} interface="{1}" metric=0 nexthop={2}'.format(
        record["prefix"], record["interface_name"], record["gateway"]
    )


def _save(path, record, mode):
    with open(path, mode, encoding="utf-8") as stream:
        json.dump(record, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())


def _load(path, workspace):
    with open(path, "r", encoding="utf-8") as stream:
        record = json.load(stream)
    network = ipaddress.ip_network(record["prefix"])
    assert record["workspace"] == workspace
    assert network.version == 6 and network.prefixlen == 128
    assert network.network_address in ipaddress.ip_network("2001:db8::/32")
    assert not any(
        row["prefix"] == record["prefix"]
        for row in record["initial"]["active"] + record["initial"]["persistent"]
    )
    assert ipaddress.ip_address(record["gateway"]).version == 6
    assert isinstance(record["index"], int) and record["index"] > 0
    return record


def _setup(path, workspace, gateway, index):
    if os.listdir(workspace):
        raise ValueError("The owned IPv6 workspace must initially be empty")
    assert ipaddress.ip_address(gateway).version == 6 and index > 0
    initial = _observe()
    number = uuid.uuid4().int & ((1 << 96) - 1)
    address = ipaddress.IPv6Address((0x20010DB8 << 96) | number)
    record = {
        "workspace": workspace,
        "prefix": str(address) + "/128",
        "gateway": gateway,
        "index": index,
        "interface_name": _interface_name(index),
        "initial": initial,
    }
    _save(path, record, "x")
    assert _load(path, workspace) == record and _observe() == initial
    return record


def _cleanup(path, workspace):
    if not os.path.exists(path):
        assert os.listdir(workspace) == []
        return {"restored": True, "mutations_started": False}
    record = _load(path, workspace)
    current = _observe()
    owned = [row for row in current["persistent"] if row["prefix"] == record["prefix"]]
    # Server 2003's persistent table reports index zero. Prove the actual named
    # binding and active index before using the originally selected interface.
    record.setdefault("interface_name", _interface_name(record["index"]))
    active = [row for row in current["active"] if row["prefix"] == record["prefix"]]
    assert len(owned) <= 1
    for row in owned:
        assert row["index"] == 0 and row["gateway"] == record["gateway"]
        assert len(active) == 1 and active[0]["index"] == record["index"]
        assert active[0]["gateway"] == record["gateway"]
        assert _persistent_command(record) in current["configuration"]
        _command(
            [
                "delete",
                "route",
                "prefix=" + record["prefix"],
                "interface=" + str(record["index"]),
                "nexthop=" + row["gateway"],
                "store=persistent",
            ]
        )
    final = _observe()
    assert (
        final == record["initial"]
    ), "Full native IPv6 route/configuration state changed"
    os.unlink(path)
    assert os.listdir(workspace) == []
    return {"restored": True, "before": record["initial"], "after": final}


def main():
    """Journal, observe or recover the one owned documentation prefix.

    :raises AssertionError: Native identity, ownership or recovery differs.
    :raises OSError: Windows cannot read or restore the bounded native route.
    :raises ValueError: The installed native table or supplied operation is invalid.
    """
    assert sys.version_info[:3] == (3, 4, 4)
    workspace, operation = sys.argv[1:3]
    path = os.path.join(workspace, "ipv6-route-recovery.json")
    if operation == "setup":
        result = _setup(path, workspace, sys.argv[3], int(sys.argv[4]))
    elif operation == "observe":
        _load(path, workspace)
        result = _observe()
    elif operation == "cleanup":
        result = _cleanup(path, workspace)
    else:
        raise ValueError("Unknown IPv6 fixture operation")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
