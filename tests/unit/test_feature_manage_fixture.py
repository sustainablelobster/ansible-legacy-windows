"""Exercise feature journal ownership, strict recovery and safe finalization."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Controller substitutions are not evidence of Windows execution support.
# The maintained embedded fixture is executed only to test its own behavior.
# pylint: disable=exec-used

import ast
import copy
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest

# PyYAML is pinned by the developer environment and has no packaged stubs.
import yaml  # type: ignore[import-untyped]
from jinja2 import Environment

from tests.unit.payload_support import ROOT


@pytest.fixture(name="fixture")
def feature_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Load the durable journal with isolated native observations.

    :param tmp_path: Private journal directory.
    :param monkeypatch: Scoped Windows imports and arguments.
    :returns: Fixture functions and controller-only observation substitutes.
    """
    monkeypatch.setitem(sys.modules, "winreg", ModuleType("winreg"))
    monkeypatch.setenv("SystemRoot", str(tmp_path / "windows"))
    monkeypatch.setattr(sys, "argv", ["fixture", str(tmp_path), "setup"])
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/feature_fixture.yml").read_text(
            encoding="utf-8"
        )
    )["feature_fixture"]
    ast.parse(source, feature_version=(3, 4))
    namespace: dict[str, Any] = {"__name__": "fixture"}
    exec(compile(source, "feature_fixture.py", "exec"), namespace)
    namespace["catalogue"] = Mock(
        return_value={
            "TelnetClient": "Disabled",
            "TFTP": "Disabled",
            "Other": "Enabled",
        }
    )
    namespace["components"] = Mock(
        return_value={"Telnet-Client": {"Installed": 0}, "Other": {"Installed": 1}}
    )
    namespace["services"] = Mock(
        return_value={
            "TrustedInstaller": {"Name": "TrustedInstaller", "State": "Stopped"}
        }
    )
    namespace["pending"] = Mock(return_value={"CBS": None, "WU": None})
    namespace["identity"] = Mock(
        return_value={
            "boot": "first",
            "image": {"build": [26100, 1]},
            "files": {"python": "unchanged"},
            "python": "3.4.4",
        }
    )
    namespace["restore_service"] = Mock()
    namespace["dism"] = Mock(return_value={"rc": 0, "stdout": "", "stderr": ""})
    namespace["time"] = Mock()
    namespace["time"].monotonic.side_effect = range(100)
    return namespace


def test_durable_baseline_precedes_every_provider_read(fixture: dict[str, Any]) -> None:
    original: dict[str, Any] = copy.deepcopy(fixture["components"].return_value)

    def _read() -> dict[str, Any]:
        record = fixture["read"]()
        assert not record["complete"]
        assert record["before"]["components"] is None
        assert record["before"]["features"] is None
        assert record["before"]["services"] == fixture["services"]()
        assert record["before"]["identity"] == fixture["identity"]()
        return original

    fixture["components"].side_effect = _read
    setup = fixture["setup"]()
    assert fixture["read"]()["before"] == setup["before"]
    assert fixture["read"]()["complete"]
    fixture["dism"].assert_not_called()


def test_existing_journal_is_not_overwritten(fixture: dict[str, Any]) -> None:
    fixture["setup"]()
    path = Path(fixture["journal_path"])
    before = path.read_bytes()
    with pytest.raises(AssertionError):
        fixture["setup"]()
    assert path.read_bytes() == before


def test_read_only_observer_avoids_slow_dism_but_keeps_full_native_state(
    fixture: dict[str, Any],
) -> None:
    observed = fixture["snapshot"](False)
    assert observed["features"] is None
    assert observed["components"] == fixture["components"]()
    assert observed["services"] == fixture["services"]()
    assert observed["identity"] == fixture["identity"]()
    fixture["catalogue"].assert_not_called()


@pytest.mark.parametrize("field", ["features", "components", "identity", "services"])
def test_unowned_changes_block_finalization_and_retain_journal(
    fixture: dict[str, Any], field: str
) -> None:
    fixture["setup"]()
    reader = {
        "features": "catalogue",
        "components": "components",
        "identity": "identity",
        "services": "services",
    }[field]
    altered = copy.deepcopy(fixture[reader].return_value)
    if field == "features":
        altered["Other"] = "Disabled"
    elif field == "components":
        altered["Other"]["Installed"] = 0
    elif field == "identity":
        altered["files"]["python"] = "altered"
    else:
        altered["TrustedInstaller"]["Name"] = "unowned"
    fixture[reader].return_value = altered
    with pytest.raises(AssertionError):
        fixture["cleanup"]()
    assert Path(fixture["journal_path"]).exists()
    with pytest.raises(AssertionError):
        fixture["finalize"]()
    fixture["dism"].assert_not_called()


def test_only_owned_enabled_feature_can_be_removed(fixture: dict[str, Any]) -> None:
    original = fixture["setup"]()["before"]
    altered = dict(original["features"], TelnetClient="Enabled")
    fixture["catalogue"].return_value = altered

    def _remove(arguments: list[str]) -> dict[str, Any]:
        assert arguments == [
            "/Disable-Feature",
            "/FeatureName:TelnetClient",
            "/NoRestart",
        ]
        fixture["catalogue"].return_value = original["features"]
        return {"rc": 0, "stdout": "", "stderr": ""}

    fixture["dism"].side_effect = _remove
    restored = fixture["cleanup"]()
    assert restored["restored"] and restored["before"] == restored["after"]
    assert fixture["dism"].call_count == 1
    assert Path(fixture["journal_path"]).exists()


def test_reported_restart_requires_real_boot_before_finalization(
    fixture: dict[str, Any],
) -> None:
    fixture["setup"]()
    fixture["note_reboot"]()
    result = fixture["cleanup"]()
    assert result["requires_reboot"] and not result["restored"]
    assert not fixture["read"]().get("verified", False)
    with pytest.raises(AssertionError):
        fixture["finalize"]()
    fixture["identity"].return_value = dict(
        fixture["identity"].return_value, boot="second"
    )
    assert fixture["cleanup"]()["restored"]
    assert fixture["finalize"]()["journal_absent"]


def test_preexisting_pending_request_is_not_erased(fixture: dict[str, Any]) -> None:
    fixture["pending"].return_value = {"CBS": {"pending": ["existing", 1]}, "WU": None}
    fixture["setup"]()
    fixture["note_reboot"]()
    with pytest.raises(AssertionError):
        fixture["cleanup"]()
    assert fixture["pending"]()["CBS"] == {"pending": ["existing", 1]}
    assert Path(fixture["journal_path"]).exists()


def test_wrong_workspace_is_rejected_before_provider_queries(
    fixture: dict[str, Any],
) -> None:
    fixture["setup"]()
    record = fixture["read"]()
    record["workspace"] = "unowned"
    Path(fixture["journal_path"]).write_text(json.dumps(record), encoding="utf-8")
    fixture["components"].reset_mock()
    with pytest.raises(AssertionError):
        fixture["cleanup"]()
    fixture["components"].assert_not_called()


def test_journal_stays_until_independent_public_service_gate(
    fixture: dict[str, Any],
) -> None:
    setup = fixture["setup"]()
    cleanup = fixture["cleanup"]()
    assert cleanup["before"] == cleanup["after"] == setup["before"]
    assert Path(fixture["journal_path"]).exists()
    assert fixture["read"]()["verified"]
    assert fixture["finalize"]()["journal_absent"]


def test_unavailable_provider_uses_no_servicing_and_recovers_all_state(
    fixture: dict[str, Any],
) -> None:
    fixture["components"].return_value = None
    fixture["catalogue"].return_value = None
    assert not fixture["setup"]()["supported"]
    assert fixture["cleanup"]()["restored"]
    assert fixture["finalize"]()["journal_absent"]
    fixture["catalogue"].assert_not_called()
    fixture["dism"].assert_not_called()


def test_unavailable_provider_snapshot_does_not_start_workstation_servicing(
    fixture: dict[str, Any],
) -> None:
    fixture["components"].return_value = None
    observed = fixture["snapshot"]()
    assert observed["components"] is None and observed["features"] is None
    assert observed["services"] == fixture["services"]()
    assert observed["pending"] == fixture["pending"]()
    assert observed["identity"] == fixture["identity"]()
    fixture["catalogue"].assert_not_called()
    fixture["dism"].assert_not_called()


@pytest.mark.parametrize(
    "change,allowed",
    [
        ("idle_installer", True),
        ("installer_config", False),
        ("ssh_runtime", False),
        ("component", False),
        ("metadata_order", False),
        ("pending", False),
        ("image", False),
    ],
)
def test_read_only_gate_retains_only_the_measured_idle_worker_exception(
    change: str, allowed: bool
) -> None:
    document = yaml.safe_load(
        (ROOT / "tests/integration/tasks/win_feature_case.yml").read_text(
            encoding="utf-8"
        )
    )
    gate = next(
        task["ansible.builtin.assert"]["that"]
        for task in document
        if task["name"] == "Require full nonmutation for check failures and idempotence"
    )
    before: dict[str, Any] = {
        "components": {"Telnet": 0, "Role": {"SubFeatures": ["first", "second"]}},
        "pending": {},
        "features": None,
        "identity": {"build": 26100},
        "services": {
            "TrustedInstaller": {"State": "Running", "StartMode": "Manual"},
            "BvSshServer": {"State": "Running", "StartMode": "Auto"},
        },
    }
    before["comparison_components"] = copy.deepcopy(before["components"])
    after = copy.deepcopy(before)
    if change == "idle_installer":
        after["services"]["TrustedInstaller"]["State"] = "Stopped"
    elif change == "installer_config":
        after["services"]["TrustedInstaller"]["StartMode"] = "Auto"
    elif change == "ssh_runtime":
        after["services"]["BvSshServer"]["State"] = "Stopped"
    elif change == "component":
        after["components"]["Telnet"] = 1
        after["comparison_components"]["Telnet"] = 1
    elif change == "metadata_order":
        after["components"]["Role"]["SubFeatures"].reverse()
    elif change == "pending":
        after["pending"]["CBS"] = "restart"
    else:
        after["identity"]["build"] += 1
    environment = Environment()
    environment.filters["dict2items"] = lambda values: [
        {"key": key, "value": value} for key, value in values.items()
    ]
    actual = all(
        environment.compile_expression(expression)(initial=before, final=after)
        for expression in gate
    )
    assert actual is allowed


def test_canonical_metadata_comparison_preserves_raw_order_duplicates_and_other_arrays(
    fixture: dict[str, Any],
) -> None:
    first = {"__CLASS": "Companion", "Name": "first"}
    second = {"__CLASS": "Companion", "Name": "second"}
    raw: dict[str, Any] = {
        "Role": {
            "SubFeatures": ["second", "first", "first"],
            "OptionalCompanions": [second, first, first],
            "NonAncestorDependencies": ["second", "first"],
            "SystemServices": ["service2", "service1"],
            "Installed": 0,
        }
    }
    saved = copy.deepcopy(raw)
    canonical = fixture["comparable_components"](raw)
    assert raw == saved
    assert canonical["Role"]["SubFeatures"] == ["first", "first", "second"]
    assert canonical["Role"]["OptionalCompanions"] == [first, first, second]
    assert canonical["Role"]["NonAncestorDependencies"] == ["second", "first"]
    assert canonical["Role"]["SystemServices"] == ["service2", "service1"]
    altered = copy.deepcopy(raw)
    altered["Role"]["SubFeatures"].remove("first")
    assert fixture["comparable_components"](altered) != canonical
    altered = copy.deepcopy(raw)
    altered["Role"]["NonAncestorDependencies"].reverse()
    assert fixture["comparable_components"](altered) != canonical


@pytest.mark.parametrize("field", ["SubFeatures", "OptionalCompanions"])
def test_final_recovery_rejects_metadata_order_changes_and_retains_journal(
    fixture: dict[str, Any], field: str
) -> None:
    entries = (
        ["first", "second"]
        if field == "SubFeatures"
        else [{"Name": "first"}, {"Name": "second"}]
    )
    fixture["components"].return_value["Other"][field] = entries
    fixture["setup"]()
    fixture["components"].return_value["Other"][field].reverse()
    assert fixture["snapshot"]()["comparison_components"] == (
        fixture["read"]()["before"]["comparison_components"]
    )
    with pytest.raises(AssertionError):
        fixture["cleanup"]()
    assert not fixture["read"]().get("verified", False)
    assert Path(fixture["journal_path"]).exists()
    fixture["dism"].assert_not_called()
    with pytest.raises(AssertionError):
        fixture["finalize"]()


def test_final_recovery_reobserves_transient_cache_after_original_service_restoration(
    fixture: dict[str, Any],
) -> None:
    fixture["components"].return_value["Other"]["SubFeatures"] = ["first", "second"]
    original = copy.deepcopy(fixture["setup"]()["before"]["components"])
    fixture["components"].return_value["Other"]["SubFeatures"].reverse()

    def _restore(_services: dict[str, Any]) -> None:
        fixture["components"].return_value = copy.deepcopy(original)

    fixture["restore_service"].side_effect = _restore
    result = fixture["cleanup"]()
    assert result["restored"]
    assert result["after"]["components"] == result["before"]["components"]
    assert fixture["restore_service"].call_count == 2
    assert fixture["read"]()["verified"]


def test_final_recovery_waits_for_delayed_metadata_notifications(
    fixture: dict[str, Any],
) -> None:
    fixture["components"].return_value["Other"]["SubFeatures"] = ["first", "second"]
    original = copy.deepcopy(fixture["setup"]()["before"]["components"])
    reordered = copy.deepcopy(original)
    reordered["Other"]["SubFeatures"].reverse()
    fixture["components"].side_effect = [reordered, reordered, reordered, original]
    restored = fixture["cleanup"]()
    assert restored["restored"]
    assert restored["after"]["components"] == original
    assert fixture["time"].sleep.call_args_list == [((0.5,),), ((0.5,),)]
    assert fixture["restore_service"].call_count == 2
    assert fixture["read"]()["verified"]


def test_metadata_wait_rejects_unrelated_changes_without_retrying(
    fixture: dict[str, Any],
) -> None:
    fixture["components"].return_value["Other"]["SubFeatures"] = ["first", "second"]
    original = copy.deepcopy(fixture["setup"]()["before"]["components"])
    reordered = copy.deepcopy(original)
    reordered["Other"]["SubFeatures"].reverse()
    unrelated = copy.deepcopy(reordered)
    unrelated["Other"]["Installed"] = 0
    fixture["components"].side_effect = [reordered, unrelated]
    with pytest.raises(AssertionError):
        fixture["cleanup"]()
    fixture["time"].sleep.assert_not_called()
    assert fixture["restore_service"].call_count == 2
    assert not fixture["read"]().get("verified", False)


def test_failed_metadata_observation_restores_worker_and_retains_journal(
    fixture: dict[str, Any],
) -> None:
    fixture["components"].return_value["Other"]["SubFeatures"] = ["first", "second"]
    fixture["setup"]()
    reordered = copy.deepcopy(fixture["components"].return_value)
    reordered["Other"]["SubFeatures"].reverse()
    fixture["components"].side_effect = [reordered, OSError("provider failed")]
    with pytest.raises(OSError, match="provider failed"):
        fixture["cleanup"]()
    assert fixture["restore_service"].call_count == 2
    assert not fixture["read"]().get("verified", False)
    assert Path(fixture["journal_path"]).exists()
