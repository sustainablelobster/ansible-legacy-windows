"""Verify reboot-aware hostname backup and recovery without Windows access."""

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

# The pinned Nix environment supplies PyYAML without its optional typing stubs.
import yaml  # type: ignore[import-untyped]
from jinja2 import Environment

from tests.unit.payload_support import ROOT


@pytest.fixture(name="fixture")
def hostname_fixture(tmp_path: Path) -> Any:
    """Load only the fixture's journal and rename-recovery contracts.

    :param tmp_path: Disposable controller-only journal directory.
    :returns: Real recovery functions with independent observation stand-ins.
    """
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/hostname_fixture.yml").read_text()
    )["hostname_fixture"].replace(
        "{{ hostname_helper_sources | to_json | to_json }}", "'{}'"
    )
    names = {"backup", "restore", "verify", "save_journal", "read_journal", "observe"}
    definitions: list[ast.stmt] = [
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    original_names = {
        "effective_name": "original-host",
        "wmi_dns_hostname": "original-host",
        "wmi_dns_available": True,
        "native": {
            "netbios": "ORIGINAL-HOST",
            "physical_netbios": "ORIGINAL-HOST",
            "dns_hostname": "original-host",
            "physical_dns_hostname": "original-host",
        },
        "registry": {
            name: {"exists": True, "type": 1, "value": value}
            for name, value in (
                ("active", "ORIGINAL-HOST"),
                ("pending", "ORIGINAL-HOST"),
                ("hostname", "original-host"),
                ("nv_hostname", "original-host"),
            )
        },
    }
    initial = {"names": original_names, "boot_id": "original boot"}
    api = SimpleNamespace(
        initial=copy.deepcopy(initial),
        current=copy.deepcopy(initial),
        journal=tmp_path / "hostname-recovery.json",
    )

    def _rename(name: str) -> None:
        assert name == "original-host"
        registry = api.current["names"]["registry"]
        registry["pending"]["value"] = "ORIGINAL-HOST"
        registry["nv_hostname"]["value"] = name

    helper = SimpleNamespace(rename_hostname=Mock(side_effect=_rename))
    namespace: dict[str, Any] = {
        "json": json,
        "os": os,
        "JOURNAL": str(api.journal),
        "TEST_NAME": "LWH-TEST",
        "observe": Mock(side_effect=lambda: copy.deepcopy(api.current)),
        "load_helpers": Mock(return_value=helper),
    }
    # Load journal contracts only; native imports and main are not executed.
    # pylint: disable-next=exec-used
    exec(
        compile(
            ast.Module(body=definitions, type_ignores=[]), "<hostname fixture>", "exec"
        ),
        namespace,
    )
    api.native_observe = namespace["observe"]
    namespace["observe"] = Mock(side_effect=lambda: copy.deepcopy(api.current))
    api.functions, api.helper = namespace, helper
    return api


def test_backup_preserves_original_name_case_and_boot_before_writes(
    fixture: Any,
) -> None:
    state = fixture.functions["backup"]()
    assert state["initial"] == fixture.initial
    assert state["test_name"] == "LWH-TEST"
    assert state["restored"] is False
    assert json.loads(fixture.journal.read_text()) == state
    fixture.helper.rename_hostname.assert_not_called()


@pytest.mark.parametrize("field", ["pending", "nv_hostname"])
def test_existing_pending_rename_is_not_overwritten(fixture: Any, field: str) -> None:
    fixture.current["names"]["registry"][field]["value"] = "earlier-name"
    with pytest.raises(AssertionError, match="earlier .* rename is pending"):
        fixture.functions["backup"]()
    assert not fixture.journal.exists()
    fixture.helper.rename_hostname.assert_not_called()


def test_existing_journal_cannot_be_replaced(fixture: Any) -> None:
    fixture.journal.write_text("earlier recovery")
    with pytest.raises(AssertionError, match="already exists"):
        fixture.functions["backup"]()
    assert fixture.journal.read_text() == "earlier recovery"
    fixture.helper.rename_hostname.assert_not_called()


def test_failed_journal_write_never_renames_the_host(fixture: Any) -> None:
    fixture.functions["save_journal"] = Mock(side_effect=OSError("disk full"))
    with pytest.raises(OSError, match="disk full"):
        fixture.functions["backup"]()
    assert fixture.current == fixture.initial
    fixture.helper.rename_hostname.assert_not_called()


def test_pending_only_change_can_be_cancelled_without_reboot(fixture: Any) -> None:
    state = fixture.functions["backup"]()
    registry = fixture.current["names"]["registry"]
    registry["pending"]["value"] = "LWH-TEST"
    registry["nv_hostname"]["value"] = "LWH-TEST"
    result = fixture.functions["restore"](state)
    assert result["reboot_required"] is False
    assert result["snapshot"] == fixture.initial
    assert json.loads(fixture.journal.read_text())["restored"] is False
    fixture.functions["verify"](state)
    assert json.loads(fixture.journal.read_text())["restored"] is True


def test_activated_rename_requires_reboot_before_journal_is_verified(
    fixture: Any,
) -> None:
    state = fixture.functions["backup"]()
    names = fixture.current["names"]
    names["effective_name"] = "LWH-TEST"
    names["wmi_dns_hostname"] = "LWH-TEST"
    names["native"] = {key: "LWH-TEST" for key in names["native"]}
    for value in names["registry"].values():
        value["value"] = "LWH-TEST"
    fixture.current["boot_id"] = "test-name boot"
    result = fixture.functions["restore"](state)
    assert result["reboot_required"] is True
    with pytest.raises(AssertionError, match="has not been restored"):
        fixture.functions["verify"](state)
    assert json.loads(fixture.journal.read_text())["restored"] is False
    fixture.current = copy.deepcopy(fixture.initial)
    fixture.current["boot_id"] = "restored-name boot"
    fixture.functions["verify"](fixture.functions["read_journal"]())
    assert json.loads(fixture.journal.read_text())["restored"] is True


def test_failed_original_rename_preserves_journal_for_retry(fixture: Any) -> None:
    state = fixture.functions["backup"]()
    fixture.current["names"]["registry"]["pending"]["value"] = "LWH-TEST"
    rename = fixture.helper.rename_hostname.side_effect
    fixture.helper.rename_hostname.side_effect = OSError("rename failed")
    with pytest.raises(OSError, match="rename failed"):
        fixture.functions["restore"](state)
    assert json.loads(fixture.journal.read_text()) == state
    fixture.helper.rename_hostname.side_effect = rename
    result = fixture.functions["restore"](fixture.functions["read_journal"]())
    assert result["reboot_required"] is False
    fixture.functions["verify"](state)


def test_matching_original_names_are_not_rewritten(fixture: Any) -> None:
    state = fixture.functions["backup"]()
    result = fixture.functions["restore"](state)
    assert result["reboot_required"] is False
    fixture.helper.rename_hostname.assert_not_called()


def test_xp_observer_records_unavailable_dns_property_and_native_fallback(
    fixture: Any,
) -> None:
    connection = Mock()
    connection.query.return_value = [{"LastBootUpTime": "XP boot"}]
    context = MagicMock()
    context.__enter__.return_value = connection
    fixture.functions.update(
        {
            "sys": SimpleNamespace(
                getwindowsversion=lambda: (5, 1, 2600, 2, ""),
                modules={
                    "legacy_windows_wmi": SimpleNamespace(
                        WmiConnection=Mock(return_value=context)
                    )
                },
            ),
            "native_name": Mock(return_value="native-xp-name"),
            "registry_name": Mock(return_value={"exists": False}),
            "COMPUTER_KEY": "computer key",
            "TCPIP_KEY": "tcpip key",
        }
    )
    actual = fixture.native_observe()
    assert actual["boot_id"] == "XP boot"
    assert actual["names"]["wmi_dns_available"] is False
    assert actual["names"]["wmi_dns_hostname"] is None
    assert actual["names"]["effective_name"] == "native-xp-name"
    connection.query.assert_called_once_with(
        "SELECT LastBootUpTime FROM Win32_OperatingSystem", ["LastBootUpTime"]
    )
    fixture.helper.rename_hostname.assert_not_called()


def test_non_reboot_cases_cannot_load_connection_reset() -> None:
    tasks = yaml.safe_load(
        (ROOT / "tests/integration/tasks/win_hostname_case.yml").read_text()
    )
    assert len(tasks) == 2
    include, public = tasks
    assert include["ansible.builtin.include_tasks"] == "win_hostname_reboot.yml"
    assert "apply" not in include
    cases = yaml.safe_load((ROOT / "tests/integration/vars/hostname.yml").read_text())[
        "hostname_cases"
    ]
    environment = Environment()
    reboot_condition = environment.compile_expression(include["when"])
    public_condition = environment.compile_expression(public["when"])
    for case in cases + [{"reboot": False}]:
        is_reboot = case.get("reboot", False)
        assert reboot_condition(hostname_case=case) is is_reboot
        assert public_condition(hostname_case=case) is not is_reboot
    pending = [public]
    while pending:
        task = pending.pop()
        assert task.keys().isdisjoint(
            {
                "ansible.builtin.meta",
                "ansible.builtin.include_tasks",
                "ansible.builtin.import_tasks",
            }
        )
        for section in ("block", "rescue", "always"):
            pending.extend(task.get(section, []))


def test_reboot_connection_reset_has_no_conditional_ancestor() -> None:
    tasks = yaml.safe_load(
        (ROOT / "tests/integration/tasks/win_hostname_reboot.yml").read_text()
    )
    assert len(tasks) == 8
    assert all(
        task.keys().isdisjoint({"when", "block", "rescue", "always"}) for task in tasks
    )
    assert [
        task["ansible.builtin.meta"] for task in tasks if "ansible.builtin.meta" in task
    ] == ["reset_connection"]
