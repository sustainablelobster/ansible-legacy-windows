"""Exercise firewall journals, strict import repair, and retryable recovery."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Fixture substitutes isolate policy mutation from real hosts.
# pylint: disable=exec-used

import ast
import copy
import hashlib
import json
import sys
from contextlib import nullcontext
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

# PyYAML comes from the pinned developer environment without typing stubs.
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


@pytest.fixture(name="fixture")
def recovery_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Load the target fixture with scoped paths and native replacements.

    :param tmp_path: Isolated recovery workspace.
    :param monkeypatch: Scoped Windows module and argument substitutes.
    :returns: The fixture's functions and globals, without executing its main.
    """
    monkeypatch.setitem(sys.modules, "winreg", ModuleType("winreg"))
    monkeypatch.setattr(sys, "argv", ["fixture", str(tmp_path), "cleanup"])
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/firewall_fixture.yml").read_text(
            encoding="utf-8"
        )
    )["firewall_fixture"]
    namespace: dict[str, Any] = {"__name__": "fixture"}
    exec(compile(source, "firewall_fixture.py", "exec"), namespace)
    namespace["sys"] = SimpleNamespace(version_info=(3, 4, 4), argv=sys.argv)
    namespace["security_privileges"] = nullcontext
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.query.return_value = []
    namespace["WmiConnection"] = Mock(return_value=connection)
    namespace["snapshot"] = Mock()
    namespace["netsh"] = Mock(return_value={"rc": 0, "stdout": "", "stderr": ""})
    namespace["delete_empty"] = Mock()
    namespace["restore_rule_security"] = Mock()
    return namespace


def _baseline(fixture: dict[str, Any], supported: bool = True) -> dict[str, Any]:
    profiles = {
        name: {
            "values": {"EnableFirewall": [1, 4]},
            "security": "profile-security",
            "children": {
                "Logging": {
                    "children": {},
                    "security": "logging-security",
                    "values": {"LogFilePath": ["%systemroot%\\Firewall.log", 2]},
                }
            },
        }
        for name in fixture["profile_keys"].values()
    }
    profiles["FirewallRules"] = {
        "values": {"SSH": ["unchanged", 1]},
        "children": {},
        "security": "rule-security",
    }
    return {
        "configured": [] if supported else None,
        "native": {"current": 4, "profiles": {}},
        "effective": {"rc": 0, "stdout": "Unchanged policy", "stderr": ""},
        "registry": {
            fixture["base"]: {
                "values": {},
                "children": profiles,
                "security": "base-security",
            },
            fixture["paths"][1]: None,
        },
    }


def make_journal(
    fixture: dict[str, Any], before: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Write the precise workspace-owned journal and verified policy backup.

    :param fixture: Isolated fixture namespace.
    :param before: Optional original complete policy snapshot.
    :returns: The persisted journal record.
    """
    original = _baseline(fixture) if before is None else before
    digest = None
    if original["configured"] is not None:
        policy = Path(fixture["policy_path"])
        policy.write_bytes(b"journal-owned firewall policy backup")
        digest = hashlib.sha256(policy.read_bytes()).hexdigest()
    record = {
        "workspace": fixture["workspace"],
        "policy": fixture["policy_path"],
        "digest": digest,
        "before": original,
    }
    Path(fixture["journal_path"]).write_text(json.dumps(record), encoding="utf-8")
    fixture["snapshot"].return_value = copy.deepcopy(original)
    return record


def test_cleanup_without_journal_does_not_touch_policy(fixture: dict[str, Any]) -> None:
    assert fixture["main"]() == {"restored": True, "journal_absent": True}
    fixture["snapshot"].assert_not_called()
    fixture["netsh"].assert_not_called()
    fixture["WmiConnection"].assert_not_called()


def test_existing_journal_is_not_overwritten(fixture: dict[str, Any]) -> None:
    make_journal(fixture)
    before = Path(fixture["journal_path"]).read_bytes()
    with pytest.raises(ValueError, match="must not be overwritten"):
        fixture["setup"]()
    assert Path(fixture["journal_path"]).read_bytes() == before
    fixture["netsh"].assert_not_called()


@pytest.mark.parametrize(
    "field,value",
    [("workspace", "unowned"), ("policy", "C:\\unowned.wfw"), ("digest", "wrong")],
)
def test_invalid_ownership_or_backup_digest_fails_before_mutation(
    fixture: dict[str, Any], field: str, value: str
) -> None:
    record = make_journal(fixture)
    record[field] = value
    Path(fixture["journal_path"]).write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(ValueError):
        fixture["cleanup"]()
    fixture["snapshot"].assert_not_called()
    fixture["netsh"].assert_not_called()
    fixture["WmiConnection"].assert_not_called()
    assert Path(fixture["journal_path"]).exists()


def test_policy_backup_tampering_retains_recovery_data(fixture: dict[str, Any]) -> None:
    make_journal(fixture)
    Path(fixture["policy_path"]).write_bytes(b"changed backup")
    with pytest.raises(ValueError, match="backup changed"):
        fixture["cleanup"]()
    assert Path(fixture["journal_path"]).exists()
    fixture["netsh"].assert_not_called()


def test_setup_requires_safe_inactive_profiles_before_export(
    fixture: dict[str, Any],
) -> None:
    before = _baseline(fixture)
    before["native"]["current"] = 1
    fixture["snapshot"].return_value = before
    with pytest.raises(ValueError, match="inactive Domain/Private"):
        fixture["setup"]()
    assert not Path(fixture["journal_path"]).exists()
    fixture["netsh"].assert_not_called()


def test_setup_verifies_snapshot_again_before_authorizing_first_mutation(
    fixture: dict[str, Any],
) -> None:
    before = _baseline(fixture)
    changed = copy.deepcopy(before)
    changed["effective"]["stdout"] = "Changed externally"
    fixture["snapshot"].side_effect = [before, changed]

    def _export(arguments: list[str]) -> dict[str, Any]:
        assert arguments == ["export", fixture["policy_path"]]
        Path(fixture["policy_path"]).write_bytes(b"policy backup")
        return {"rc": 0, "stdout": "", "stderr": ""}

    fixture["netsh"].side_effect = _export
    with pytest.raises(ValueError, match="changed before first mutation"):
        fixture["setup"]()
    assert Path(fixture["journal_path"]).exists()
    assert fixture["journal"]()["before"] == before


def test_unsupported_host_is_journaled_without_policy_export(
    fixture: dict[str, Any],
) -> None:
    before = _baseline(fixture, False)
    fixture["snapshot"].return_value = before
    result = fixture["setup"]()
    assert result["journaled"] and not result["supported"] and result["digest"] is None
    assert fixture["cleanup"]()["after"] == before
    assert not Path(fixture["journal_path"]).exists()
    fixture["netsh"].assert_not_called()
    fixture["WmiConnection"].assert_not_called()


def test_unsupported_host_change_is_not_repaired_with_invented_profile_semantics(
    fixture: dict[str, Any],
) -> None:
    before = _baseline(fixture, False)
    make_journal(fixture, before)
    current = copy.deepcopy(before)
    current["effective"]["stdout"] = "Unexpected mutation"
    fixture["snapshot"].return_value = current
    with pytest.raises(ValueError, match="changed unexpectedly"):
        fixture["cleanup"]()
    assert Path(fixture["journal_path"]).exists()
    fixture["netsh"].assert_not_called()


def _classic_baseline(fixture: dict[str, Any]) -> dict[str, Any]:
    before = _baseline(fixture, False)
    before["native"] = {
        "current_legacy": 1,
        "profiles": {"Domain": {"enabled": -1}, "Standard": {"enabled": -1}},
    }
    return before


def test_classic_recovery_restores_only_the_owned_domain_state(
    fixture: dict[str, Any],
) -> None:
    before = _classic_baseline(fixture)
    make_journal(fixture, before)
    changed = copy.deepcopy(before)
    changed["native"]["profiles"]["Domain"]["enabled"] = 0
    changed["registry"][fixture["base"]]["children"]["DomainProfile"]["values"][
        "EnableFirewall"
    ] = [0, 4]
    fixture["snapshot"].side_effect = [changed, before]
    fixture["com_profiles"] = Mock()
    result = fixture["cleanup"]()
    assert result["restored"] and result["after"] == before
    fixture["com_profiles"].assert_called_once_with(True)
    assert not Path(fixture["journal_path"]).exists()
    fixture["netsh"].assert_not_called()


def test_classic_recovery_rejects_unrelated_policy_changes_and_keeps_journal(
    fixture: dict[str, Any],
) -> None:
    before = _classic_baseline(fixture)
    make_journal(fixture, before)
    changed = copy.deepcopy(before)
    changed["native"]["profiles"]["Standard"]["enabled"] = 0
    fixture["snapshot"].return_value = changed
    fixture["com_profiles"] = Mock()
    with pytest.raises(ValueError, match="outside the owned Domain"):
        fixture["cleanup"]()
    fixture["com_profiles"].assert_not_called()
    assert Path(fixture["journal_path"]).exists()


def test_classic_recovery_removes_only_the_new_owned_domain_leaf(
    fixture: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = _classic_baseline(fixture)
    del before["registry"][fixture["base"]]["children"]["DomainProfile"]
    make_journal(fixture, before)
    current = copy.deepcopy(before)
    current["registry"][fixture["base"]]["children"]["DomainProfile"] = {
        "values": {"EnableFirewall": [1, 4]},
        "security": "new-owned-domain-security",
        "children": {},
    }
    fixture["snapshot"].side_effect = [current, before]
    fixture["com_profiles"] = Mock()
    registry = fixture["winreg"]
    monkeypatch.setattr(registry, "HKEY_LOCAL_MACHINE", 123, raising=False)
    delete = Mock()
    monkeypatch.setattr(registry, "DeleteKey", delete, raising=False)
    assert fixture["cleanup"]()["restored"]
    delete.assert_called_once_with(123, fixture["base"] + "\\DomainProfile")
    fixture["com_profiles"].assert_not_called()


def test_classic_seed_accepts_only_real_domain_enabled_state(
    fixture: dict[str, Any],
) -> None:
    before = _classic_baseline(fixture)
    make_journal(fixture, before)
    fixture["com_profiles"] = Mock()
    assert fixture["seed"]("Domain", "Enabled", 0) == before
    fixture["com_profiles"].assert_called_once_with(False)
    for parameters in [
        ("Private", "Enabled", 0),
        ("Domain", "DefaultInboundAction", 4),
        ("Domain", "Enabled", 2),
    ]:
        with pytest.raises(ValueError, match="Only the inactive classic Domain"):
            fixture["seed"](*parameters)
    fixture["WmiConnection"].assert_not_called()


def test_classic_public_proof_selects_eight_bounded_cases() -> None:
    cases = yaml.safe_load(
        (ROOT / "tests/integration/vars/firewall_classic.yml").read_text()
    )["firewall_unsupported_cases"]
    assert len(cases) == 8
    assert sum(bool(case.get("check")) for case in cases) == 2
    assert sum(bool(case.get("failed")) for case in cases) == 2
    assert sum(case["changed"] and not case.get("check") for case in cases) == 2


def test_exact_cleanup_deletes_only_verified_journal_and_backup(
    fixture: dict[str, Any],
) -> None:
    record = make_journal(fixture)
    result = fixture["cleanup"]()
    assert result["restored"] and result["after"] == record["before"]
    assert result["import"] is None and result["repairs"] is None
    assert not Path(fixture["journal_path"]).exists()
    assert not Path(fixture["policy_path"]).exists()
    fixture["netsh"].assert_not_called()


def test_failed_backup_import_retains_journal_for_retry(
    fixture: dict[str, Any],
) -> None:
    record = make_journal(fixture)
    changed = copy.deepcopy(record["before"])
    changed["effective"]["stdout"] = "Altered settings"
    fixture["snapshot"].return_value = changed
    fixture["netsh"].return_value = {"rc": 5, "stdout": "Import denied", "stderr": ""}
    result = fixture["cleanup"]()
    assert not result["restored"] and result["import"]["rc"] == 5
    assert (
        Path(fixture["journal_path"]).exists() and Path(fixture["policy_path"]).exists()
    )
    fixture["snapshot"].return_value = record["before"]
    assert fixture["cleanup"]()["restored"]
    assert not Path(fixture["journal_path"]).exists()


def _import_effects(
    fixture: dict[str, Any], original: dict[str, Any]
) -> dict[str, Any]:
    current = copy.deepcopy(original)
    children = current["registry"][fixture["base"]]["children"]
    for key in fixture["profile_keys"].values():
        for name in ("AuthorizedApplications", "GloballyOpenPorts"):
            children[key]["children"][name] = {
                "values": {},
                "children": {},
                "security": "new-empty-key",
            }
        children[key]["children"]["Logging"]["values"]["LogFilePath"][1] = 1
    children["FirewallRules"]["security"] = "measured-import-security"
    return current


def test_only_measured_import_effects_are_repaired_after_whole_snapshot_validation(
    fixture: dict[str, Any],
) -> None:
    original = _baseline(fixture)
    current = _import_effects(fixture, original)
    key = MagicMock()
    key.__enter__.return_value = key
    registry = Mock(HKEY_LOCAL_MACHINE=1, KEY_SET_VALUE=2)
    registry.OpenKey.return_value = key
    fixture["winreg"] = registry
    result = fixture["repair_import"](original, current)
    assert len(result["removed_empty_keys"]) == 6
    assert len(result["restored_value_types"]) == 3
    assert fixture["delete_empty"].call_count == 6
    assert registry.SetValueEx.call_count == 3
    fixture["restore_rule_security"].assert_called_once_with("rule-security")
    assert current == _import_effects(fixture, original)


@pytest.mark.parametrize("difference", ["nonempty", "value", "child", "effective"])
def test_unexpected_recovery_difference_aborts_before_any_repair(
    fixture: dict[str, Any], difference: str
) -> None:
    original = _baseline(fixture)
    current = _import_effects(fixture, original)
    children = current["registry"][fixture["base"]]["children"]
    if difference == "nonempty":
        children["DomainProfile"]["children"]["AuthorizedApplications"]["values"][
            "not-owned"
        ] = [1, 4]
    elif difference == "value":
        children["DomainProfile"]["values"]["EnableFirewall"] = [0, 4]
    elif difference == "child":
        children["FirewallRules"]["children"]["not-owned"] = {}
    else:
        current["effective"]["stdout"] = "Unexpected effective policy"
    with pytest.raises(ValueError):
        fixture["repair_import"](original, current)
    fixture["delete_empty"].assert_not_called()
    fixture["restore_rule_security"].assert_not_called()


def test_failed_exact_repair_keeps_backup_and_journal(fixture: dict[str, Any]) -> None:
    record = make_journal(fixture)
    current = _import_effects(fixture, record["before"])
    fixture["snapshot"].return_value = current
    fixture["repair_import"] = Mock(
        side_effect=OSError("Observed security restoration denial")
    )
    with pytest.raises(OSError, match="restoration denial"):
        fixture["cleanup"]()
    assert (
        Path(fixture["journal_path"]).exists() and Path(fixture["policy_path"]).exists()
    )


def test_active_public_seed_is_rejected_before_any_profile_write(
    fixture: dict[str, Any],
) -> None:
    make_journal(fixture)
    with pytest.raises(ValueError, match="Only inactive"):
        fixture["seed"]("Public", "Enabled", 0)
    fixture["WmiConnection"].assert_not_called()


def _policy2_baseline(fixture: dict[str, Any]) -> dict[str, Any]:
    original = _baseline(fixture, supported=False)
    original["native"]["profiles"] = {
        name: {"enabled": -1, "inbound": 0, "outbound": 1}
        for name in ("Domain", "Private", "Public")
    }
    return original


def test_policy2_setup_selects_native_facility_without_configured_export(
    fixture: dict[str, Any],
) -> None:
    original = _policy2_baseline(fixture)
    fixture["snapshot"].return_value = original
    result = fixture["setup"]()
    assert result["supported"] and result["snapshot"] == original
    assert result["digest"] is None
    fixture["netsh"].assert_not_called()


def test_policy2_seed_uses_only_the_inactive_native_domain(
    fixture: dict[str, Any],
) -> None:
    original = _policy2_baseline(fixture)
    make_journal(fixture, original)
    fixture["com_profiles"] = Mock()
    assert fixture["seed"]("Domain", "Enabled", 0) == original
    fixture["com_profiles"].assert_called_once_with(policy2_domain={"enabled": 0})
    fixture["WmiConnection"].assert_not_called()


def test_policy2_seed_rejects_active_public_before_native_writes(
    fixture: dict[str, Any],
) -> None:
    make_journal(fixture, _policy2_baseline(fixture))
    fixture["com_profiles"] = Mock()
    with pytest.raises(ValueError, match="Only the inactive native Domain"):
        fixture["seed"]("Public", "Enabled", 0)
    fixture["com_profiles"].assert_not_called()


def test_policy2_cleanup_removes_only_materialized_owned_default_scalars(
    fixture: dict[str, Any],
) -> None:
    original = _policy2_baseline(fixture)
    make_journal(fixture, original)
    current = copy.deepcopy(original)
    values = current["registry"][fixture["base"]]["children"]["DomainProfile"]["values"]
    values.update(DefaultInboundAction=[1, 4], DefaultOutboundAction=[0, 4])
    fixture["snapshot"].side_effect = [current, current, original]
    fixture["com_profiles"] = Mock()
    registry = SimpleNamespace(
        HKEY_LOCAL_MACHINE=object(),
        KEY_SET_VALUE=2,
        OpenKey=MagicMock(),
        SetValueEx=Mock(),
        DeleteValue=Mock(),
        FlushKey=Mock(),
    )
    fixture["winreg"] = registry
    result = fixture["cleanup"]()
    assert result["restored"] and result["after"] == original
    fixture["com_profiles"].assert_called_once_with(
        policy2_domain=original["native"]["profiles"]["Domain"]
    )
    assert [item.args[1] for item in registry.DeleteValue.call_args_list] == [
        "DefaultInboundAction",
        "DefaultOutboundAction",
    ]
    registry.SetValueEx.assert_not_called()
    fixture["netsh"].assert_not_called()
    assert not Path(fixture["journal_path"]).exists()


def test_policy2_cleanup_refuses_foreign_changes_before_registry_repair(
    fixture: dict[str, Any],
) -> None:
    original = _policy2_baseline(fixture)
    make_journal(fixture, original)
    current = copy.deepcopy(original)
    current["registry"][fixture["base"]]["values"]["foreign"] = [1, 4]
    fixture["snapshot"].return_value = current
    fixture["com_profiles"] = Mock()
    registry = SimpleNamespace(OpenKey=Mock())
    fixture["winreg"] = registry
    with pytest.raises(ValueError, match="outside the owned Domain scalars"):
        fixture["cleanup"]()
    registry.OpenKey.assert_not_called()
    fixture["netsh"].assert_not_called()
    assert Path(fixture["journal_path"]).exists()


@pytest.mark.parametrize(
    "filename", ["win_firewall.yml", "tasks/win_firewall_case.yml"]
)
def test_owned_assertion_conditions_are_not_yaml_mappings(filename: str) -> None:
    document = yaml.safe_load(
        (ROOT / "tests/integration" / filename).read_text(encoding="utf-8")
    )
    conditions: list[Any] = []

    def _visit(value: Any) -> None:
        if isinstance(value, dict):
            if "ansible.builtin.assert" in value:
                conditions.extend(value["ansible.builtin.assert"]["that"])
            for child in value.values():
                _visit(child)
        elif isinstance(value, list):
            for child in value:
                _visit(child)

    _visit(document)
    assert conditions and all(isinstance(item, (str, bool)) for item in conditions)


def test_fixture_uses_python34_syntax_and_distinguishes_configured_enums() -> None:
    document = yaml.safe_load(
        (ROOT / "tests/integration/vars/firewall_fixture.yml").read_text(
            encoding="utf-8"
        )
    )
    ast.parse(document["firewall_fixture"], feature_version=(3, 4))
    assert "MSFT_NetFirewallProfile" in document["firewall_fixture"]
    assert "SetSecurityInfo" in document["firewall_fixture"]
    assert "RegGetKeySecurity(int(key), 15" in document["firewall_fixture"]
    assert document["firewall_registry_path"] == (
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
    )
