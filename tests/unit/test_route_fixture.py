"""Exercise the maintained Route journal and exact recovery without Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import copy
import ipaddress
import json
import os
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

# PyYAML is provided by the pinned developer environment without typing stubs.
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


@pytest.fixture(name="fixture")
def route_fixture(tmp_path: Path) -> Any:
    """Execute the maintained journal functions against observable native state.

    :param tmp_path: Isolated durable journal directory.
    :returns: Mutable state and real journal functions.
    """
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/route_fixture.yml").read_text()
    )["route_fixture"]
    definitions: list[ast.stmt] = [
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef)
        and node.name in {"save", "load", "backup", "cleanup"}
    ]
    initial = {
        "active": [
            {"Destination": "0.0.0.0", "NextHop": "192.168.0.1", "InterfaceIndex": 11}
        ],
        "persistent": [],
        "registry": [],
        "modern": [],
    }
    state = SimpleNamespace(
        initial=copy.deepcopy(initial),
        current=copy.deepcopy(initial),
        journal=tmp_path / "route-recovery.json",
    )
    provider = Mock()
    provider.query.return_value = [
        {
            "IPAddress": ["192.168.0.105"],
            "DefaultIPGateway": ["192.168.0.1"],
            "InterfaceIndex": 11,
        }
    ]
    context = MagicMock()
    context.__enter__.return_value = provider

    def _command(arguments: list[str]) -> dict[str, Any]:
        destination = arguments[-1]
        for kind in ("active", "persistent"):
            state.current[kind] = [
                row for row in state.current[kind] if row["Destination"] != destination
            ]
        return {"status": 0}

    namespace: dict[str, Any] = {
        "os": os,
        "json": json,
        "ipaddress": ipaddress,
        "uuid": uuid,
        "JOURNAL": str(state.journal),
        "WORKSPACE": str(tmp_path),
        "ADDRESS": "192.168.0.105",
        "MODERN": True,
        "KEY": "persistent",
        "WmiConnection": Mock(return_value=context),
        "observe": Mock(side_effect=lambda: copy.deepcopy(state.current)),
        "registry": Mock(side_effect=lambda: state.current["registry"]),
        "command": Mock(side_effect=_command),
        "winreg": MagicMock(),
    }
    # Run the maintained recovery contract, not a second recovery implementation.
    # pylint: disable-next=exec-used
    exec(
        compile(
            ast.Module(body=definitions, type_ignores=[]), "<Route fixture>", "exec"
        ),
        namespace,
    )
    state.functions = namespace
    namespace["winreg"].DeleteValue.side_effect = lambda unused, name: setattr(
        state,
        "current",
        dict(
            state.current,
            registry=[value for value in state.current["registry"] if value[0] != name],
        ),
    )
    return state


def test_verified_durable_journal_precedes_any_mutation(fixture: Any) -> None:
    record = fixture.functions["backup"]()
    assert record["initial"] == fixture.initial
    assert fixture.functions["load"]() == record
    assert not record["restored"]
    fixture.functions["command"].assert_not_called()
    assert all(
        ipaddress.ip_address(value) in ipaddress.ip_network("192.0.2.0/24")
        for value in record["destinations"]
    )


def test_journal_failure_cannot_start_mutations(fixture: Any) -> None:
    fixture.functions["save"] = Mock(side_effect=OSError("disk full"))
    with pytest.raises(OSError, match="disk full"):
        fixture.functions["backup"]()
    fixture.functions["command"].assert_not_called()
    assert fixture.current == fixture.initial


def test_owned_partial_change_is_removed_without_touching_existing_routes(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SystemRoot", "C:\\Windows")
    record = fixture.functions["backup"]()
    destination = record["destinations"][0]
    fixture.current["active"].append({"Destination": destination})
    fixture.current["persistent"].append({"Destination": destination})
    result = fixture.functions["cleanup"](record)
    assert result["restored"] and result["initial"] == result["final"]
    assert fixture.current == fixture.initial
    assert fixture.functions["load"]()["restored"]
    assert fixture.functions["command"].call_args.args[0][-2:] == [
        "delete",
        destination,
    ]


def test_failed_recovery_keeps_original_snapshot_and_retryable_journal(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SystemRoot", "C:\\Windows")
    record = fixture.functions["backup"]()
    fixture.current["active"].append({"Destination": record["destinations"][0]})
    command = fixture.functions["command"]
    fixture.functions["command"] = Mock(return_value={"status": 1})
    with pytest.raises(AssertionError, match="not restored"):
        fixture.functions["cleanup"](record)
    assert fixture.functions["load"]()["initial"] == fixture.initial
    assert not fixture.functions["load"]()["restored"]
    fixture.functions["command"] = command
    assert fixture.functions["cleanup"](fixture.functions["load"]())["restored"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("address", "192.168.0.106"),
        ("workspace", "elsewhere"),
        ("destinations", ["0.0.0.0"]),
        ("ipv6", "::/0"),
    ],
)
def test_foreign_or_unsafe_journal_cannot_authorize_cleanup(
    fixture: Any, field: str, value: Any
) -> None:
    record = fixture.functions["backup"]()
    record[field] = value
    fixture.functions["save"](record, "w")
    with pytest.raises(AssertionError):
        fixture.functions["load"]()
    fixture.functions["command"].assert_not_called()


def test_complete_snapshot_drift_blocks_success_and_retains_journal(
    fixture: Any,
) -> None:
    record = fixture.functions["backup"]()
    fixture.current["active"].append({"Destination": "203.0.113.17"})
    with pytest.raises(AssertionError, match="not restored"):
        fixture.functions["cleanup"](record)
    assert not fixture.functions["load"]()["restored"]
    fixture.functions["command"].assert_not_called()


def test_unloaded_owned_registry_record_is_recovered_without_deleting_other_values(
    fixture: Any,
) -> None:
    record = fixture.functions["backup"]()
    name = record["destinations"][0] + ",255.255.255.255,192.168.0.1,0"
    fixture.current["registry"] = [[name, "", 1]]
    assert fixture.functions["cleanup"](record)["restored"]
    assert fixture.current == fixture.initial
    fixture.functions["command"].assert_not_called()
    fixture.functions["winreg"].DeleteValue.assert_called_once()


def test_destination_selection_preserves_unreported_preexisting_registry_record(
    fixture: Any,
) -> None:
    fixture.current["registry"] = [["192.0.2.6,255.255.255.255,192.168.0.1,0", "", 1]]
    fixture.functions["uuid"] = SimpleNamespace(uuid4=lambda: SimpleNamespace(int=4))
    record = fixture.functions["backup"]()
    assert "192.0.2.6" not in record["destinations"]


def test_existing_canonical_documentation_route_cannot_be_owned_by_the_fixture(
    fixture: Any,
) -> None:
    fixture.current["persistent"].append({"Destination": "192.0.2.0"})
    with pytest.raises(AssertionError, match="network base must be unused"):
        fixture.functions["backup"]()
    assert not fixture.journal.exists()
    fixture.functions["command"].assert_not_called()


def test_accidental_host_bit_normalization_is_recovered_from_the_same_journal(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SystemRoot", "C:\\Windows")
    record = fixture.functions["backup"]()
    assert "192.0.2.0" in record["destinations"]
    fixture.current["active"].append({"Destination": "192.0.2.0"})
    fixture.current["persistent"].append({"Destination": "192.0.2.0"})
    assert fixture.functions["cleanup"](record)["restored"]
    assert fixture.current == fixture.initial


def test_fixture_is_python34_native_and_independent_of_route_helper() -> None:
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/route_fixture.yml").read_text()
    )["route_fixture"]
    ast.parse(source, feature_version=(3, 4))
    assert "legacy_windows_route" not in source
    assert "os.fsync" in source and 'save(state, "x")' in source
    assert 'final == state["initial"]' in source
