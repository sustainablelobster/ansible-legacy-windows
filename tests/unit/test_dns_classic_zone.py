"""Exercise the existing zone interface over an installed classic DNS facility."""

# SPDX-License-Identifier: GPL-3.0-or-later
# pylint: disable=protected-access

import copy
from typing import Any
from unittest.mock import MagicMock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="server")
def classic_server(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Expose observable native zone state while exercising public reconciliation.

    :param monkeypatch: Scoped native substitutions and helper imports.
    :returns: Public helper, original-classic state and mutation observations.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    helper = load_module(
        ROOT / "plugins/module_utils/legacy_windows_dns_zone.py", "classic_zone_test"
    )
    classic = helper.classic
    state: dict[str, Any] = {"rows": [], "writes": []}
    connection = MagicMock()

    def _query(query: str, _properties: list[str]) -> list[dict[str, Any]]:
        if "meta_class" in query:
            return [{"__CLASS": "MicrosoftDNS_Zone"}]
        if "MicrosoftDNS_Server" in query:
            return [{"DsAvailable": False}]
        return copy.deepcopy(state["rows"])

    connection.query.side_effect = _query

    def _call(
        _connection: Any, _path: str, method: str, inputs: dict[str, Any]
    ) -> dict[str, Any]:
        state["writes"].append((method, dict(inputs)))
        assert method == "CreateZone"
        state["rows"] = [
            {
                "__PATH": "actual-observed-owned-path",
                "Name": inputs["ZoneName"],
                "ZoneType": inputs["ZoneType"] + 1,
                "DsIntegrated": inputs["DsIntegrated"],
                "AllowUpdate": 0,
                "DataFile": inputs["ZoneName"] + ".dns",
                "Paused": False,
                "Shutdown": False,
                "Reverse": False,
                "MasterServers": inputs.get("IpAddr"),
                "ForwarderTimeout": 5,
            }
        ]
        return {}

    def _update(_connection: Any, path: str, values: dict[str, Any]) -> None:
        assert path == state["rows"][0]["__PATH"]
        state["writes"].append(("update", dict(values)))
        state["rows"][0].update(values)

    def _delete(_connection: Any, path: str) -> None:
        assert path == state["rows"][0]["__PATH"]
        state["writes"].append(("delete", path))
        state["rows"] = []

    monkeypatch.setattr(classic, "call", _call)
    monkeypatch.setattr(classic, "update", _update)
    monkeypatch.setattr(classic, "delete", _delete)
    absent = OSError("modern namespace absent")
    absent.hresult = 0x8004100E  # type: ignore[attr-defined]

    def _connection(namespace: str) -> Any:
        if namespace == helper._NAMESPACE:
            raise absent
        assert namespace == classic.NAMESPACE
        context = MagicMock()
        context.__enter__.return_value = connection
        return context

    monkeypatch.setattr(helper.wmi, "WmiConnection", _connection)
    return helper, state


def _options(kind: str, **changes: Any) -> dict[str, Any]:
    return {
        "name": "owned.invalid",
        "type": kind,
        "state": "present",
        "replication": "none",
        "dynamic_update": None,
        "dns_servers": None if kind == "primary" else ["192.0.2.53"],
        "forwarder_timeout": None,
        "directory_partition": None,
        **changes,
    }


@pytest.mark.parametrize("kind", ["primary", "secondary", "stub", "forwarder"])
def test_classic_public_create_repeat_preview_and_remove(
    server: Any, kind: str
) -> None:
    helper, state = server
    options = _options(kind)
    created = helper.manage(options, diff_mode=True)
    assert created["changed"] and created["zone"]["type"] == kind
    assert created["zone"]["name"] == options["name"]
    assert created["zone"]["replication"] == "none"
    assert "DataFileName" not in state["writes"][0][1]
    assert helper.manage(options) == {"changed": False}
    before = copy.deepcopy(state)
    preview = helper.manage(options, check_mode=True, diff_mode=True)
    assert not preview["changed"] and state == before
    removed = helper.manage(dict(options, state="absent"), diff_mode=True)
    assert removed["changed"] and removed["diff"]["after"] == ""
    assert state["rows"] == []
    assert helper.manage(dict(options, state="absent")) == {"changed": False}


def test_classic_missing_zone_preview_never_creates_a_zone(server: Any) -> None:
    helper, state = server
    result = helper.manage(_options("primary"), check_mode=True, diff_mode=True)
    assert result["failed"] and not result["changed"]
    assert state["rows"] == [] and state["writes"] == []


def test_classic_directory_storage_absence_fails_before_creation(server: Any) -> None:
    helper, state = server
    result = helper.manage(_options("primary", replication="forest"))
    assert result["failed"] and not result["changed"]
    assert "no Active Directory zone storage facility" in result["msg"]
    assert state["rows"] == [] and state["writes"] == []


def test_classic_forwarder_update_and_repeat_preserve_real_server_order(
    server: Any,
) -> None:
    helper, state = server
    options = _options("forwarder")
    assert helper.manage(options)["changed"]
    replacement = dict(
        options, dns_servers=["192.0.2.54", "192.0.2.53"], forwarder_timeout=3
    )
    changed = helper.manage(replacement)
    assert changed["zone"]["dns_servers"] == replacement["dns_servers"]
    assert changed["zone"]["forwarder_timeout"] == 3
    before = copy.deepcopy(state)
    assert helper.manage(replacement) == {"changed": False}
    assert state["rows"] == before["rows"]


def test_classic_literal_names_cannot_change_the_query(server: Any) -> None:
    helper, _state = server
    assert helper.classic.literal("owned'\\zone") == "'owned\\'\\\\zone'"
    with pytest.raises(ValueError, match="null character"):
        helper.classic.literal("owned\0zone")
