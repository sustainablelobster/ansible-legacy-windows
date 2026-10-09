"""Check the native IPv6 fixture's durable ownership and exact recovery."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import copy
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT

SOURCE = ROOT / "tests/integration/fixtures/win_route_ipv6.py"


@pytest.fixture(name="fixture")
def ipv6_fixture() -> dict[str, Any]:
    """Load maintained functions without invoking the Windows entry point.

    :returns: The fixture namespace for scoped native-command substitutions.
    """
    namespace: dict[str, Any] = {"__name__": "fixture"}
    # Execute the maintained fixture; no second recovery implementation is used.
    # pylint: disable-next=exec-used
    exec(compile(SOURCE.read_text(), str(SOURCE), "exec"), namespace)
    return namespace


def test_actual_native_rows_are_parsed_without_header_guessing(fixture: Any) -> None:
    fixture["_command"] = Mock(
        return_value="Publish Type Met Prefix Idx Gateway/Interface Name\n"
        "------- ---- --- ------ --- ----------------------\n"
        "No Autoconf 8 fd51:8b11:5130:b4de::/64 5 Local Area Connection\n"
        "No Manual 0 2001:db8::1/128 5 fd51:8b11:5130:b4de::2\n"
    )
    assert fixture["_routes"]("persistent") == [
        {
            "publish": "No",
            "kind": "Autoconf",
            "metric": 8,
            "prefix": "fd51:8b11:5130:b4de::/64",
            "index": 5,
            "gateway": "Local Area Connection",
        },
        {
            "publish": "No",
            "kind": "Manual",
            "metric": 0,
            "prefix": "2001:db8::1/128",
            "index": 5,
            "gateway": "fd51:8b11:5130:b4de::2",
        },
    ]


def test_unrecognized_route_cannot_be_silently_omitted(fixture: Any) -> None:
    fixture["_command"] = Mock(return_value="Unexpected Manual 0 2001:db8::1/128 5 ::1")
    with pytest.raises(ValueError, match="Unrecognized"):
        fixture["_routes"]("active")


def test_installed_interface_name_is_selected_from_the_native_table(
    fixture: Any,
) -> None:
    fixture["_command"] = Mock(
        return_value="Idx Met MTU State Name\n"
        "1 0 1500 Connected Loopback Pseudo-Interface\n"
        "5 0 1500 Connected Local Area Connection\n"
    )
    assert fixture["_interface_name"](5) == "Local Area Connection"
    with pytest.raises(AssertionError, match="one installed name"):
        fixture["_interface_name"](7)


def test_durable_journal_precedes_writes_and_owned_cleanup_is_exact(
    fixture: Any, tmp_path: Path
) -> None:
    state: dict[str, Any] = {"active": [], "persistent": [], "configuration": []}
    initial = copy.deepcopy(state)
    fixture["_observe"] = Mock(side_effect=lambda: copy.deepcopy(state))
    fixture["_interface_name"] = Mock(return_value="Local Area Connection")
    fixture["_command"] = Mock()
    journal = str(tmp_path / "ipv6-route-recovery.json")
    record = fixture["_setup"](journal, str(tmp_path), "fd51:8b11:5130:b4de::2", 5)
    assert fixture["_load"](journal, str(tmp_path)) == record
    fixture["_command"].assert_not_called()
    state["active"].append(
        {"prefix": record["prefix"], "index": 5, "gateway": record["gateway"]}
    )
    state["persistent"].append(
        {"prefix": record["prefix"], "index": 0, "gateway": record["gateway"]}
    )
    state["configuration"].append(fixture["_persistent_command"](record))
    fixture["_command"].side_effect = lambda _arguments: state.update(
        copy.deepcopy(initial)
    )
    assert fixture["_cleanup"](journal, str(tmp_path))["restored"]
    assert not Path(journal).exists()
    assert fixture["_command"].call_args.args[0] == [
        "delete",
        "route",
        "prefix=" + record["prefix"],
        "interface=5",
        "nexthop=" + record["gateway"],
        "store=persistent",
    ]


def test_foreign_drift_retains_retryable_original_journal(
    fixture: Any, tmp_path: Path
) -> None:
    state: dict[str, Any] = {"active": [], "persistent": [], "configuration": []}
    fixture["_observe"] = Mock(side_effect=lambda: copy.deepcopy(state))
    fixture["_interface_name"] = Mock(return_value="Loopback Pseudo-Interface")
    fixture["_command"] = Mock()
    journal = str(tmp_path / "ipv6-route-recovery.json")
    record = fixture["_setup"](journal, str(tmp_path), "::1", 1)
    state["configuration"].append("unowned change")
    with pytest.raises(AssertionError, match="Full native"):
        fixture["_cleanup"](journal, str(tmp_path))
    assert fixture["_load"](journal, str(tmp_path)) == record
    fixture["_command"].assert_not_called()


def test_zero_persistent_index_cannot_authorize_a_foreign_active_interface(
    fixture: Any, tmp_path: Path
) -> None:
    state: dict[str, Any] = {"active": [], "persistent": [], "configuration": []}
    fixture["_observe"] = Mock(side_effect=lambda: copy.deepcopy(state))
    fixture["_interface_name"] = Mock(return_value="Local Area Connection")
    fixture["_command"] = Mock()
    journal = str(tmp_path / "ipv6-route-recovery.json")
    record = fixture["_setup"](journal, str(tmp_path), "fd51:8b11:5130:b4de::2", 5)
    state["active"].append(
        {"prefix": record["prefix"], "index": 7, "gateway": record["gateway"]}
    )
    state["persistent"].append(
        {"prefix": record["prefix"], "index": 0, "gateway": record["gateway"]}
    )
    state["configuration"].append(fixture["_persistent_command"](record))
    with pytest.raises(AssertionError):
        fixture["_cleanup"](journal, str(tmp_path))
    assert fixture["_load"](journal, str(tmp_path)) == record
    fixture["_command"].assert_not_called()


def test_fixture_keeps_the_python34_target_floor() -> None:
    ast.parse(SOURCE.read_text(), feature_version=(3, 4))
