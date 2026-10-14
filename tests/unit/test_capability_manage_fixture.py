"""Exercise capability fixture ownership, journal durability and exact recovery."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These isolated fixture substitutes establish no Windows servicing support.
# pylint: disable=exec-used

import ast
import copy
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

# The Nix environment supplies PyYAML without typing stubs.
import yaml  # type: ignore[import-untyped]
from ansible.parsing.dataloader import DataLoader  # type: ignore[import-untyped]
from ansible.template import (  # type: ignore[import-untyped]
    Templar,
    trust_as_template,
)
from jinja2 import Environment

from tests.unit.payload_support import ROOT


@pytest.fixture(name="fixture")
def capability_fixture(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> dict[str, Any]:
    """Load real recovery definitions with substituted native observations.

    :param monkeypatch: Scoped Windows imports and runtime values.
    :param tmp_path: Owned journal directory.
    :returns: Fixture namespace with independently controlled snapshots.
    """
    monkeypatch.setitem(sys.modules, "winreg", ModuleType("winreg"))
    monkeypatch.setenv("SystemRoot", str(tmp_path / "windows"))
    monkeypatch.setattr(sys, "argv", ["fixture", str(tmp_path), "setup"])
    monkeypatch.setattr(
        sys, "getwindowsversion", lambda: SimpleNamespace(major=10), raising=False
    )
    document = yaml.safe_load(
        (ROOT / "tests/integration/vars/capability_fixture.yml").read_text()
    )
    namespace: dict[str, Any] = {"__name__": "fixture"}
    exec(compile(document["capability_fixture"], "fixture.py", "exec"), namespace)
    namespace["supported"] = True
    namespace["catalogue"] = Mock(
        return_value={namespace["target"]: "NotPresent", "Unrelated": "Installed"}
    )
    namespace["native_pending"] = namespace["pending"]
    namespace["pending"] = Mock(return_value={"CBS": None, "WU": None})
    namespace["services"] = Mock(
        return_value={
            "TrustedInstaller": {"Name": "TrustedInstaller", "State": "Stopped"}
        }
    )
    namespace["protected_files"] = Mock(
        return_value={"python.exe": "original", "BvSshServer.exe": "original"}
    )
    namespace["task_resources"] = Mock(
        return_value={"tasks": ["unrelated"], "batch_directories": []}
    )
    namespace["restore_service"] = Mock()
    namespace["remove_target"] = Mock(return_value={"rc": 0})
    namespace["boot_identity"] = Mock(return_value="original-boot")
    return namespace


def test_journal_precedes_provider_read_and_is_not_overwritten(
    fixture: dict[str, Any],
) -> None:
    def _read() -> dict[str, str]:
        record = fixture["read"]()
        assert not record["complete"] and record["before"]["capabilities"] is None
        assert record["before"]["files"]["python.exe"] == "original"
        return {fixture["target"]: "NotPresent"}

    fixture["catalogue"].side_effect = _read
    fixture["setup"]()
    before = Path(fixture["journal_path"]).read_bytes()
    with pytest.raises(AssertionError):
        fixture["setup"]()
    assert Path(fixture["journal_path"]).read_bytes() == before


def test_healthy_recovery_preserves_full_snapshot_until_finalize(
    fixture: dict[str, Any],
) -> None:
    initial = fixture["setup"]()["before"]
    restored = fixture["cleanup"]()
    assert restored["restored"] and restored["before"] == restored["after"] == initial
    fixture["remove_target"].assert_not_called()
    assert Path(fixture["journal_path"]).exists()
    assert fixture["finalize"]()["finalized"]
    assert not Path(fixture["journal_path"]).exists()


@pytest.mark.parametrize("failure", [OSError("write failed"), KeyboardInterrupt()])
def test_interrupted_journal_update_preserves_original_recovery(
    fixture: dict[str, Any], monkeypatch: pytest.MonkeyPatch, failure: BaseException
) -> None:
    fixture["setup"]()
    original = Path(fixture["journal_path"]).read_bytes()

    def _partial_write(_record: Any, stream: Any, **_options: Any) -> None:
        stream.write('{"partial":')
        raise failure

    with monkeypatch.context() as scope:
        scope.setattr(fixture["json"], "dump", _partial_write)
        with pytest.raises(type(failure)):
            fixture["note_reboot"]()
    assert Path(fixture["journal_path"]).read_bytes() == original
    assert not list(Path(fixture["workspace"]).glob("*.writing"))
    assert fixture["cleanup"]()["restored"]
    assert fixture["finalize"]()["finalized"]


@pytest.mark.parametrize("function", ["fsync", "replace"])
def test_failed_journal_flush_or_replace_keeps_usable_original(
    fixture: dict[str, Any], monkeypatch: pytest.MonkeyPatch, function: str
) -> None:
    fixture["setup"]()
    original = Path(fixture["journal_path"]).read_bytes()
    with monkeypatch.context() as scope:
        scope.setattr(fixture["os"], function, Mock(side_effect=OSError("failed")))
        with pytest.raises(OSError, match="failed"):
            fixture["note_reboot"]()
    assert Path(fixture["journal_path"]).read_bytes() == original
    assert not list(Path(fixture["workspace"]).glob("*.writing"))
    assert fixture["cleanup"]()["restored"]
    assert fixture["finalize"]()["finalized"]


def test_owned_installed_target_is_only_resource_removed(
    fixture: dict[str, Any],
) -> None:
    fixture["setup"]()
    current = copy.deepcopy(fixture["catalogue"].return_value)
    current[fixture["target"]] = "Installed"
    fixture["catalogue"].return_value = current

    def _remove() -> dict[str, int]:
        fixture["catalogue"].return_value[fixture["target"]] = "NotPresent"
        return {"rc": 0}

    fixture["remove_target"].side_effect = _remove
    restored = fixture["cleanup"]()
    assert restored["restored"] and restored["actions"] == [{"rc": 0}]
    fixture["remove_target"].assert_called_once_with()


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.mark.parametrize(
    "field", ["capabilities", "pending", "files", "task_resources", "services"]
)
def test_unowned_change_retains_journal_and_cannot_finalize(
    fixture: dict[str, Any], field: str
) -> None:
    fixture["setup"]()
    function = (
        "catalogue"
        if field == "capabilities"
        else ("protected_files" if field == "files" else field)
    )
    original = copy.deepcopy(fixture[function].return_value)
    if field == "capabilities":
        original["Unrelated"] = "NotPresent"
    elif field == "pending":
        original["CBS"] = {}
    elif field == "files":
        original["python.exe"] = "changed"
    elif field == "task_resources":
        original["batch_directories"] = ["leaked"]
    else:
        original["TrustedInstaller"]["Name"] = "changed"
    fixture[function].return_value = original
    if field == "pending":
        assert fixture["cleanup"]()["requires_reboot"]
    else:
        with pytest.raises(AssertionError):
            fixture["cleanup"]()
    assert Path(fixture["journal_path"]).exists()
    with pytest.raises(AssertionError):
        fixture["finalize"]()


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.mark.parametrize("field", ["workspace", "target"])
def test_foreign_journal_rejected_before_native_call(
    fixture: dict[str, Any], field: str
) -> None:
    fixture["setup"]()
    record = fixture["read"]()
    record[field] = "foreign"
    Path(fixture["journal_path"]).write_text(json.dumps(record), encoding="utf-8")
    fixture["catalogue"].reset_mock()
    with pytest.raises(AssertionError):
        fixture["cleanup"]()
    fixture["catalogue"].assert_not_called()
    fixture["remove_target"].assert_not_called()


# pylint: enable=duplicate-code


def test_failed_setup_retains_original_service_journal_and_recovers(
    fixture: dict[str, Any],
) -> None:
    fixture["catalogue"].side_effect = OSError("unavailable")
    with pytest.raises(OSError):
        fixture["setup"]()
    assert not fixture["read"]()["complete"]
    fixture["catalogue"].side_effect = None
    assert fixture["cleanup"]()["setup_incomplete"]
    fixture["finalize"]()


def test_pending_target_requests_reboot_without_second_removal(
    fixture: dict[str, Any],
) -> None:
    fixture["setup"]()
    fixture["catalogue"].return_value[fixture["target"]] = "UninstallPending"
    assert fixture["cleanup"]()["requires_reboot"]
    fixture["remove_target"].assert_not_called()
    assert Path(fixture["journal_path"]).exists()


def test_legacy_missing_provider_has_no_servicing_or_reboot(
    fixture: dict[str, Any],
) -> None:
    fixture["supported"] = False
    fixture["catalogue"].return_value = None
    assert not fixture["setup"]()["supported"]
    assert fixture["cleanup"]()["restored"]
    fixture["remove_target"].assert_not_called()
    assert fixture["finalize"]()["finalized"]


def test_provider_exports_not_manifest_version_choose_modern_cases(
    fixture: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    library = SimpleNamespace(
        DismGetCapabilities=Mock(),
        DismAddCapability=Mock(),
        DismRemoveCapability=Mock(),
    )
    monkeypatch.setattr(fixture["os"].path, "isfile", lambda _path: True)
    monkeypatch.setattr(
        fixture["ctypes"], "WinDLL", lambda _path: library, raising=False
    )
    monkeypatch.setattr(
        sys,
        "getwindowsversion",
        lambda: SimpleNamespace(major=6, build=9200),
        raising=False,
    )
    assert fixture["provider_available"]()
    del library.DismAddCapability
    assert not fixture["provider_available"]()


def test_original_pending_values_are_preserved_without_reboot(
    fixture: dict[str, Any],
) -> None:
    original = {"CBS": {}, "WU": {"Existing": [1, 4]}}
    fixture["pending"].return_value = original
    assert fixture["setup"]()["before"]["pending"] == original
    assert fixture["cleanup"]()["after"]["pending"] == original
    assert fixture["finalize"]()["finalized"]


def test_pending_reader_keeps_lossless_file_renames_and_ignores_unrelated_values(
    fixture: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = fixture["pending_paths"]
    rows: dict[str, list[tuple[str, Any, int]]] = {
        paths[0]: [],
        paths[1]: [("Existing", b"\x00\xff", 3)],
        paths[2]: [
            ("BootExecute", ["autocheck autochk *"], 7),
            ("PendingFileRenameOperations", ["source", "destination"], 7),
        ],
    }

    def _open(_root: Any, path: str) -> Any:
        context = MagicMock()
        context.fixture_path = path
        return context

    registry = fixture["winreg"]
    monkeypatch.setattr(registry, "HKEY_LOCAL_MACHINE", 1, raising=False)
    monkeypatch.setattr(registry, "OpenKey", _open, raising=False)
    monkeypatch.setattr(
        registry,
        "QueryInfoKey",
        lambda key: (0, len(rows[key.fixture_path]), 0),
        raising=False,
    )
    monkeypatch.setattr(
        registry,
        "EnumValue",
        lambda key, index: rows[key.fixture_path][index],
        raising=False,
    )
    assert fixture["native_pending"]() == {
        paths[0]: {},
        paths[1]: {"Existing": [{"hex": "00ff"}, 3]},
        paths[2]: {"PendingFileRenameOperations": [["source", "destination"], 7]},
    }
    rows[paths[2]].pop()
    assert fixture["native_pending"]()[paths[2]] is None


def test_recovery_cannot_reboot_away_preexisting_pending_file_renames(
    fixture: dict[str, Any],
) -> None:
    fixture["pending"].return_value = {
        "CBS": None,
        "WU": None,
        "Rename": {"PendingFileRenameOperations": [["source", "destination"], 7]},
    }
    fixture["setup"]()
    fixture["catalogue"].return_value[fixture["target"]] = "UninstallPending"
    with pytest.raises(AssertionError):
        fixture["cleanup"]()
    assert Path(fixture["journal_path"]).exists()
    fixture["remove_target"].assert_not_called()


def test_reported_servicing_reboot_is_not_inferred_from_equal_markers(
    fixture: dict[str, Any],
) -> None:
    fixture["setup"]()
    fixture["note_reboot"]()
    assert fixture["cleanup"]()["requires_reboot"]
    assert Path(fixture["journal_path"]).exists()
    with pytest.raises(AssertionError):
        fixture["finalize"]()
    fixture["boot_identity"].return_value = "new-boot"
    assert fixture["cleanup"]()["restored"]
    assert fixture["finalize"]()["finalized"]


def test_recovery_remove3010_obligation_survives_equal_catalogue(
    fixture: dict[str, Any],
) -> None:
    fixture["setup"]()
    fixture["catalogue"].return_value[fixture["target"]] = "Installed"

    def _remove() -> dict[str, int]:
        fixture["catalogue"].return_value[fixture["target"]] = "NotPresent"
        return {"rc": 3010}

    fixture["remove_target"].side_effect = _remove
    assert fixture["cleanup"]()["requires_reboot"]
    assert fixture["read"]()["servicing_reboot"]
    fixture["boot_identity"].return_value = "new-boot"
    assert fixture["cleanup"]()["restored"]
    fixture["remove_target"].assert_called_once()


def test_maintained_program_and_payloads_parse_as_python34() -> None:
    document = yaml.safe_load(
        (ROOT / "tests/integration/vars/capability_fixture.yml").read_text()
    )
    wmi = (
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_wmi.py"
    ).read_text()
    program = (
        Environment()
        .from_string(document["capability_program"])
        .render(
            capability_wmi_source=wmi, capability_fixture=document["capability_fixture"]
        )
    )
    ast.parse(program, feature_version=(3, 4))
    for path in (
        "legacy_windows/plugins/modules/win_capability.py",
        "legacy_windows/plugins/module_utils/legacy_windows_capability_manage.py",
    ):
        ast.parse((ROOT / path).read_text(), feature_version=(3, 4))


def test_declared_lifecycle_has_real_install_remove_and_exact_check_cases() -> None:
    cases = yaml.safe_load((ROOT / "tests/integration/vars/capability.yml").read_text())
    mutations = [case for case in cases["capability_cases"] if case.get("mutation")]
    assert [case["target_state"] for case in mutations] == ["Installed", "NotPresent"]
    assert all(not case.get("check") for case in mutations)
    assert len(cases["capability_legacy_cases"]) == 3
    assert all(
        case["failed"] and not case["changed"]
        for case in cases["capability_legacy_cases"]
    )


def test_case_expectations_use_setup_not_an_unavailable_future_observation() -> None:
    source = (ROOT / "tests/integration/vars/capability.yml").read_text(
        encoding="utf-8"
    )
    assert "capability_before" not in source
    assert "capability_setup.stdout" in source
    play = yaml.safe_load(
        (ROOT / "tests/integration/win_capability.yml").read_text(encoding="utf-8")
    )[0]
    assert play["tasks"][1]["tags"] == ["capability-fixture-validate"]
    assert "capability_setup" in play["tasks"][1]["vars"]


@pytest.mark.parametrize(
    "changed_field", [None, "state", "process_id", "win32_exit_code", "start_mode"]
)
def test_final_public_recovery_keeps_every_field_and_ignores_mapping_order(
    changed_field: str | None,
) -> None:
    play = yaml.safe_load(
        (ROOT / "tests/integration/win_capability.yml").read_text(encoding="utf-8")
    )[0]
    protected = next(task for task in play["tasks"] if "always" in task)
    assertion = next(
        task["ansible.builtin.assert"]["that"]
        for task in protected["always"]
        if task["name"] == "Require exact recovery before deleting journal evidence"
    )[-1]
    original = {
        "name": "TrustedInstaller",
        "state": "stopped",
        "process_id": 0,
        "win32_exit_code": 0,
        "start_mode": "manual",
    }
    final = dict(reversed(list(original.items())))
    if changed_field is not None:
        final[changed_field] = "changed"
    templar = Templar(
        loader=DataLoader(),
        variables={
            "capability_original_service": {"services": [original]},
            "capability_final_service": {"services": [final]},
        },
    )
    assert templar.template(trust_as_template("{{ " + assertion + " }}")) is (
        changed_field is None
    )


def test_full_original_public_capture_precedes_provider_side_effects() -> None:
    play = yaml.safe_load(
        (ROOT / "tests/integration/win_capability.yml").read_text(encoding="utf-8")
    )[0]
    block = next(task["block"] for task in play["tasks"] if "always" in task)
    original = next(
        index
        for index, task in enumerate(block)
        if task.get("register") == "capability_original_service"
    )
    setup = next(
        index
        for index, task in enumerate(block)
        if task.get("register") == "capability_setup"
    )
    post_setup = next(
        index
        for index, task in enumerate(block)
        if task.get("register") == "capability_setup_service"
    )
    assert original < setup < post_setup
    capture = block[original + 1]["ansible.builtin.copy"]["content"]
    assert "capability_original_service" in capture
    assert "staging_before" in capture
