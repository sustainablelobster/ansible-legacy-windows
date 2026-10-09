"""Verify maintained DNS journaling and recovery without contacting Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import copy
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

# PyYAML is provided by the pinned developer environment without typing stubs.
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


@pytest.fixture(name="fixture")
def dns_fixture(tmp_path: Path) -> Any:
    """Execute maintained recovery functions with native operations replaced.

    :param tmp_path: Isolated journal directory.
    :returns: Real journal functions and stateful native substitutes.
    """
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/dns_client_fixture.yml").read_text()
    )["dns_client_fixture"]
    definitions: list[ast.stmt] = [
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef)
        and node.name in {"backup", "load", "save", "setup", "cleanup"}
    ]
    identity = {"name": "Ethernet", "guid": "owned-guid", "path": "owned-path"}
    value = {"exists": True, "type": 1, "data": "saved"}
    initial = {
        "identity": identity,
        "v4": {"values": {"NameServer": value}, "security": "unchanged"},
        "v6": None,
        "global": {"values": {"SearchList": value}, "security": "unchanged"},
        "suffixes": ["original.invalid"],
    }
    state = SimpleNamespace(
        initial=copy.deepcopy(initial),
        current=copy.deepcopy(initial),
        journal=tmp_path / "dns-client-recovery.json",
    )

    def servers(unused_identity: Any, v4: str, unused_v6: str) -> None:
        state.current["v4"]["values"]["NameServer"] = (
            value if v4 == "saved" else {"exists": True, "type": 1, "data": v4}
        )

    def suffixes(values: list[str]) -> None:
        state.current["suffixes"] = list(values)
        state.current["global"]["values"]["SearchList"] = (
            value
            if values == initial["suffixes"]
            else {"exists": True, "type": 1, "data": ",".join(values)}
        )

    def _registry(path: str, unused_names: Any) -> Any:
        return copy.deepcopy(state.current["v4" if "Interfaces" in path else "global"])

    namespace = {
        "os": os,
        "json": json,
        "JOURNAL": str(state.journal),
        "WORKSPACE": str(tmp_path),
        "ADDRESS": "192.0.2.10",
        "TCPIP": "tcpip",
        "locate": Mock(return_value=identity),
        "observe": Mock(side_effect=lambda unused: copy.deepcopy(state.current)),
        "servers": Mock(side_effect=servers),
        "suffixes": Mock(side_effect=suffixes),
        "text": lambda entry: entry["data"] if entry["exists"] else "",
        "registry": Mock(side_effect=_registry),
        "restore_value": Mock(),
    }
    # Exercise the maintained recovery contract, not a separate recovery implementation.
    # pylint: disable-next=exec-used
    exec(
        compile(ast.Module(body=definitions, type_ignores=[]), "<DNS fixture>", "exec"),
        namespace,
    )
    state.functions = namespace
    return state


def test_backup_is_verified_before_any_dns_mutation(fixture: Any) -> None:
    record = fixture.functions["backup"]()
    assert record["initial"] == fixture.initial
    assert fixture.functions["load"]() == record
    fixture.functions["servers"].assert_not_called()
    fixture.functions["suffixes"].assert_not_called()


def test_journal_failure_prevents_mutation(fixture: Any) -> None:
    fixture.functions["save"] = Mock(side_effect=OSError("disk full"))
    with pytest.raises(OSError, match="disk full"):
        fixture.functions["backup"]()
    assert fixture.current == fixture.initial
    fixture.functions["servers"].assert_not_called()


def test_partial_setup_retains_journal_and_restores_original(fixture: Any) -> None:
    state = fixture.functions["backup"]()
    setter = fixture.functions["suffixes"]
    fixture.functions["suffixes"] = Mock(
        side_effect=OSError("provider denied suffixes")
    )
    with pytest.raises(OSError, match="provider denied"):
        fixture.functions["setup"](state)
    assert fixture.functions["load"]()["initial"] == fixture.initial
    fixture.functions["suffixes"] = setter
    fixture.functions["cleanup"](state)
    assert fixture.current == fixture.initial
    assert fixture.functions["load"]()["restored"] is True


def test_restoration_failure_keeps_initial_snapshot_and_allows_retry(
    fixture: Any,
) -> None:
    state = fixture.functions["backup"]()
    fixture.functions["setup"](state)
    setter = fixture.functions["servers"]
    fixture.functions["servers"] = Mock(side_effect=OSError("provider denied reset"))
    with pytest.raises(OSError, match="provider denied"):
        fixture.functions["cleanup"](state)
    assert fixture.functions["load"]()["restored"] is False
    fixture.functions["servers"] = setter
    fixture.functions["cleanup"](fixture.functions["load"]())
    assert fixture.current == fixture.initial


def test_journal_from_another_address_cannot_authorize_cleanup(fixture: Any) -> None:
    state = fixture.functions["backup"]()
    state["address"] = "192.0.2.11"
    fixture.functions["save"](state, "w")
    with pytest.raises(AssertionError):
        fixture.functions["load"]()


def test_fixture_is_python34_native_and_does_not_import_payload_helper() -> None:
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/dns_client_fixture.yml").read_text()
    )["dns_client_fixture"]
    ast.parse(source, feature_version=(3, 4))
    assert "legacy_windows_dns_client" not in source
    assert "os.fsync" in source and 'save(state, "x")' in source
    assert "assert observe(identity) == initial" in source


@pytest.mark.parametrize("settles", [True, False])
def test_observer_waits_for_cached_suffixes_without_weakening_snapshot(
    settles: bool,
) -> None:
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/dns_client_fixture.yml").read_text()
    )["dns_client_fixture"]
    definition = next(
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name == "observe"
    )
    connection = Mock()
    connection.query.side_effect = [
        [{"DNSDomainSuffixSearchOrder": []}],
        [{"DNSDomainSuffixSearchOrder": ["one.invalid"]}],
    ]
    context = MagicMock()
    context.__enter__.return_value = connection
    clock = SimpleNamespace(
        monotonic=Mock(side_effect=[0, 1 if settles else 16]), sleep=Mock()
    )

    def _registry(path: str, unused_names: Any) -> Any:
        if path == "Tcpip":
            return {"values": {"SearchList": "one.invalid"}}
        if path == "Tcpip\\Interfaces\\guid":
            return {"values": {"NameServer": "192.0.2.1"}}
        return None

    namespace: dict[str, Any] = {
        "WmiConnection": Mock(return_value=context),
        "TCPIP": "Tcpip",
        "registry": Mock(side_effect=_registry),
        "text": lambda value: value,
        "time": clock,
        "ctypes": SimpleNamespace(WinDLL=Mock(return_value=SimpleNamespace())),
    }
    # Run the maintained observer with a delayed provider, not a second observer.
    # pylint: disable-next=exec-used
    exec(
        compile(
            ast.Module(body=[definition], type_ignores=[]), "<DNS observe>", "exec"
        ),
        namespace,
    )
    if settles:
        snapshot = namespace["observe"]({"guid": "guid"})
        assert snapshot["wmi"]["DNSDomainSuffixSearchOrder"] == ["one.invalid"]
        assert snapshot["suffixes"] == ["one.invalid"]
        clock.sleep.assert_called_once_with(0.25)
    else:
        with pytest.raises(AssertionError, match="did not settle"):
            namespace["observe"]({"guid": "guid"})
        clock.sleep.assert_not_called()
