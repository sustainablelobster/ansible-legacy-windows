"""Check registry fixture ownership, complete parity and bounded file clocks."""

# SPDX-License-Identifier: GPL-3.0-or-later
# The separate MSI fixture has a similar import harness, but combining them
# would couple their different Windows namespaces and cleanup contracts.
# pylint: disable=duplicate-code

import base64
import copy
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tests/integration/vars/package_registry_fixture.yml"
COMPARE = ROOT / "tests/integration/files/package_registry_compare.py"


def _comparator() -> Any:
    spec = importlib.util.spec_from_file_location("package_registry_compare", COMPARE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _empty_state() -> dict[str, Any]:
    return {
        "utc": 100.0,
        "registry": {"HKCU/native": {"values": [], "children": []}},
        "pending": {"marker": None},
        "services": {"BvSshServer": {"State": "Running"}},
        "sources": {"installer": {"sha256": "unchanged", "mtime": 11}},
        "outputs": {},
    }


@pytest.fixture(name="fixture")
def registry_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Load the actual maintained Python3.4 fixture with mocked native operations.

    :param tmp_path: Owned private journal directory.
    :param monkeypatch: Scoped Windows imports and process arguments.
    :returns: Fixture namespace with pristine protected state.
    """
    source = yaml.safe_load(SOURCE.read_text(encoding="utf-8"))[
        "package_registry_fixture_source"
    ]
    source = source[: source.rindex('\nif __name__ == "__main__":')]
    for name in ("winreg", "legacy_windows_acl", "legacy_windows_wmi"):
        module = ModuleType(name)
        if name == "winreg":
            module.HKEY_LOCAL_MACHINE = 1  # type: ignore[attr-defined]
            module.HKEY_CURRENT_USER = 2  # type: ignore[attr-defined]
        if name == "legacy_windows_wmi":
            module.WmiConnection = Mock()  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.setattr(sys, "argv", ["fixture", str(tmp_path), "cleanup"])
    namespace: dict[str, Any] = {}
    exec(compile(source, str(SOURCE), "exec"), namespace)  # pylint: disable=exec-used
    before = _empty_state()
    record = {
        "workspace": str(tmp_path),
        "identifier": namespace["identifier"](),
        "before": before,
        "complete": True,
        "verified": False,
        "sources": before["sources"],
        "protected_runtime": {},
    }
    namespace["write"](record)
    (tmp_path / "installer").write_bytes(b"owned")
    namespace["remove_owned_operation"] = namespace["remove_owned"]
    namespace["snapshot_operation"] = namespace["snapshot"]
    namespace["remove_owned"] = Mock()
    namespace["snapshot"] = lambda: copy.deepcopy(before)
    return namespace


@pytest.mark.parametrize(
    "field", ["registry", "pending", "services", "sources", "outputs"]
)
def test_literal_recovery_refuses_protected_difference(
    fixture: dict[str, Any], field: str
) -> None:
    final = fixture["snapshot"]()
    final[field] = {"unknown": "retain"}
    fixture["snapshot"] = lambda: final
    with pytest.raises(AssertionError):
        fixture["cleanup"]()
    assert Path(fixture["JOURNAL"]).exists()
    assert fixture["read"]()["verified"] is False


def test_verified_cleanup_is_independently_rechecked_before_removal(
    fixture: dict[str, Any],
) -> None:
    assert fixture["cleanup"]()["restored"] is True
    assert fixture["read"]()["verified"] is True
    assert fixture["finalize"]() == {"finalized": True}
    assert not Path(fixture["JOURNAL"]).exists()


def test_changed_state_after_cleanup_retains_journal(fixture: dict[str, Any]) -> None:
    fixture["cleanup"]()
    fixture["snapshot"] = lambda: {"unexpected": "retain"}
    with pytest.raises((AssertionError, KeyError)):
        fixture["finalize"]()
    assert Path(fixture["JOURNAL"]).exists()


def test_unknown_partial_workspace_is_not_cleaned(fixture: dict[str, Any]) -> None:
    Path(fixture["JOURNAL"]).unlink()
    Path(fixture["ROOT"], "unknown").write_text("retain", encoding="utf-8")
    for operation in ("cleanup", "finalize"):
        with pytest.raises(AssertionError):
            fixture[operation]()
    fixture["remove_owned"].assert_not_called()


def test_empty_workspace_without_journal_is_safe(fixture: dict[str, Any]) -> None:
    Path(fixture["JOURNAL"]).unlink()
    Path(fixture["ROOT"], "installer").unlink()
    assert fixture["cleanup"]() == {"restored": True, "journal_absent": True}
    assert fixture["finalize"]() == {"finalized": True, "journal_absent": True}


def test_foreign_journal_is_not_adopted(fixture: dict[str, Any]) -> None:
    record = fixture["read"]()
    record["workspace"] = "unrelated"
    fixture["write"](record)
    with pytest.raises(AssertionError):
        fixture["cleanup"]()
    fixture["remove_owned"].assert_not_called()


def test_native_registry_tuples_project_to_stable_journal_arrays(
    fixture: dict[str, Any],
) -> None:
    fixture["winreg"].QueryInfoKey = lambda _key: (0, 2, 0)
    fixture["winreg"].EnumValue = lambda _key, index: (
        ("text", "literal", 1) if index == 0 else ("bytes", b"\xff", 3)
    )
    values = fixture["registry_values"](None)
    assert values == [["text", "literal", 1], ["bytes", b"\xff", 3]]
    record = fixture["read"]()
    record["registry_values"] = values
    fixture["write"](record)
    assert fixture["read"]()["registry_values"] == values


@pytest.mark.parametrize("view", [0, 0x100])
def test_owned_registry_cleanup_uses_available_view_specific_delete(
    fixture: dict[str, Any], view: int
) -> None:
    fixture["VIEW"] = view
    registry = fixture["winreg"]
    registry.KEY_READ = 0x20019
    registry.OpenKey = MagicMock()
    registry.QueryValueEx = Mock(return_value=(fixture["ROOT"], 1))
    registry.QueryInfoKey = Mock(return_value=(0, 1, 0))
    registry.DeleteKey = Mock()
    registry.DeleteKeyEx = Mock()
    fixture["remove_owned_registry_parents"] = Mock()
    fixture["remove_owned_operation"]()
    used = registry.DeleteKeyEx if view else registry.DeleteKey
    unavailable = registry.DeleteKey if view else registry.DeleteKeyEx
    assert used.call_count == 4
    unavailable.assert_not_called()


def test_unknown_file_prevents_verified_workspace_deletion(
    fixture: dict[str, Any],
) -> None:
    Path(fixture["ROOT"], "unknown").write_bytes(b"retain")
    with pytest.raises(AssertionError):
        fixture["cleanup"]()
    assert fixture["read"]()["verified"] is False


def _capture() -> dict[str, Any]:
    identifier = "LegacyWindowsPackage-test"
    before = _empty_state()
    before["preparation_started_utc"] = 99.0
    after = copy.deepcopy(before)
    after.pop("preparation_started_utc")
    after["utc"] = 101.0
    after["registry"]["HKCU/native"]["children"] = [
        {"name": identifier, "values": [["marker", "owned", 1]]}
    ]
    payload = json.dumps({"identifier": identifier, "location": "HKCU/native"})
    after["outputs"] = {
        "installed.json": {
            "mtime": 100_500_000_000,
            "bytes": {"raw_bytes": base64.b64encode(payload.encode()).decode()},
            "attributes": 32,
            "acl": "literal",
        }
    }
    public = {"changed": True, "failed": False, "rc": 0, "reboot_required": False}
    original_after = copy.deepcopy(after)
    original_after["outputs"]["installed.json"]["mtime"] = 100_750_000_000
    return {
        "setup": {"stdout": json.dumps({"identifier": identifier})},
        "results": [
            {
                "name": "owned install",
                "validated": True,
                "expected": {
                    "hive": "HKCU",
                    "branch": "native",
                    "changed": True,
                    "installed": True,
                },
                "native": public,
                "original": dict(public),
                "before": {"stdout": json.dumps(before)},
                "before_original": {"stdout": json.dumps(before)},
                "after_native": {"stdout": json.dumps(after)},
                "after_original": {"stdout": json.dumps(original_after)},
            }
        ],
    }


def test_pair_preserves_public_values_and_bounds_each_output_clock() -> None:
    assert _comparator().verify_capture(_capture(), paired=True, running=True)[
        "verified"
    ]


def _uninstall_capture() -> dict[str, Any]:
    capture = _capture()
    setup = json.loads(capture["setup"]["stdout"])
    setup["workspace"] = r"C:\Owned Package"
    capture["setup"]["stdout"] = json.dumps(setup)
    record = capture["results"][0]
    record["expected"].update(
        installed=False,
        initial="present",
        state="absent",
        repeat=True,
        uninstall_arguments=["", "two words", 'quoted "value"', "trailing slash\\"],
    )
    log = {
        "identifier": setup["identifier"],
        "invocations": [
            {
                "executable": setup["workspace"] + r"\registry installer.exe",
                "arguments": record["expected"]["uninstall_arguments"],
                "operation": "remove",
            }
        ],
    }
    for side in ("native", "original"):
        before = json.loads(record["after_" + side]["stdout"])
        before["utc"] = 100.0
        before["preparation_started_utc"] = 99.0
        before["outputs"]["installed.json"]["mtime"] = 99_500_000_000
        record["before" if side == "native" else "before_original"]["stdout"] = (
            json.dumps(before)
        )
        after = copy.deepcopy(before)
        after["utc"] = 101.0
        after.pop("preparation_started_utc")
        after["registry"]["HKCU/native"]["children"] = []
        after["outputs"] = {
            "uninstall-arguments.json": {
                "mtime": 100_500_000_000 if side == "native" else 100_750_000_000,
                "bytes": {
                    "raw_bytes": base64.b64encode(json.dumps(log).encode()).decode()
                },
            }
        }
        record["after_" + side]["stdout"] = json.dumps(after)
    record["native_repeat"] = {
        "changed": False,
        "failed": False,
        "rc": 0,
        "reboot_required": False,
    }
    record["after_native_repeat"] = dict(record["after_native"])
    return capture


def test_uninstall_oracle_requires_exact_arguments_single_launch_and_no_repeat_changes() -> (
    None
):
    assert _comparator().verify_capture(
        _uninstall_capture(), paired=True, running=True
    )["verified"]


@pytest.mark.parametrize("side", ["native", "original"])
@pytest.mark.parametrize("difference", ["arguments", "executable", "multiple_launches"])
def test_uninstall_oracle_rejects_wrong_arguments_executable_or_launch_count(
    side: str, difference: str
) -> None:
    capture = _uninstall_capture()
    record = capture["results"][0]
    after = json.loads(record["after_" + side]["stdout"])
    output = after["outputs"]["uninstall-arguments.json"]["bytes"]
    log = json.loads(base64.b64decode(output["raw_bytes"]))
    if difference == "multiple_launches":
        log["invocations"] *= 2
    else:
        log["invocations"][0][difference] = "wrong value"
    output["raw_bytes"] = base64.b64encode(json.dumps(log).encode()).decode()
    record["after_" + side]["stdout"] = json.dumps(after)
    with pytest.raises(AssertionError):
        _comparator().verify_capture(capture, paired=True, running=True)


def test_repeat_uninstall_oracle_rejects_an_extra_write() -> None:
    capture = _uninstall_capture()
    record = capture["results"][0]
    after = json.loads(record["after_native_repeat"]["stdout"])
    after["outputs"]["uninstall-arguments.json"]["mtime"] += 1
    record["after_native_repeat"]["stdout"] = json.dumps(after)
    with pytest.raises(AssertionError):
        _comparator().verify_capture(capture, paired=True, running=True)


@pytest.mark.parametrize(
    "field,value",
    [
        ("changed", True),
        ("failed", True),
        ("rc", 23),
        ("rc", False),
        ("reboot_required", True),
        ("unexpected", "retain"),
        ("warnings", ["different warning"]),
    ],
)
def test_repeat_uninstall_oracle_rejects_changed_failure_types_or_extra_fields(
    field: str, value: Any
) -> None:
    capture = _uninstall_capture()
    capture["results"][0]["native_repeat"][field] = value
    with pytest.raises(AssertionError):
        _comparator().verify_capture(capture, paired=True, running=True)


def test_repeat_uninstall_retains_the_same_controller_warnings() -> None:
    capture = _uninstall_capture()
    record = capture["results"][0]
    for field in ("native", "original", "native_repeat"):
        record[field]["warnings"] = ["controller task argument warning"]
    assert _comparator().verify_capture(capture, paired=True, running=True)["verified"]


def test_failed_uninstall_can_log_arguments_but_cannot_change_installation() -> None:
    capture = _uninstall_capture()
    record = capture["results"][0]
    record["expected"].update(failed=True, installed=True, changed=False)
    record["expected"].pop("repeat")
    for side in ("native", "original"):
        record[side].update(failed=True, changed=False, rc=23)
        before = json.loads(
            record["before" if side == "native" else "before_original"]["stdout"]
        )
        after = json.loads(record["after_" + side]["stdout"])
        after["registry"] = before["registry"]
        after["outputs"].update(before["outputs"])
        record["after_" + side]["stdout"] = json.dumps(after)
    assert _comparator().verify_capture(capture, paired=True, running=True)["verified"]
    after = json.loads(record["after_native"]["stdout"])
    after["outputs"]["installed.json"]["mtime"] += 1
    record["after_native"]["stdout"] = json.dumps(after)
    with pytest.raises(AssertionError):
        _comparator().verify_capture(capture, paired=True, running=True)


def test_observation_clock_is_recorded_after_all_protected_state_reads(
    fixture: dict[str, Any],
) -> None:
    order = []

    def _observe(operation: str) -> dict[str, Any]:
        order.append(operation)
        return {}

    def _clock() -> float:
        order.append("clock")
        return 100.0

    for name in ("registry_catalogue", "pending", "services", "source_files"):
        fixture[name] = lambda operation=name: _observe(operation)
    fixture["now"] = _clock
    assert fixture["snapshot_operation"]()["utc"] == 100.0
    assert order == [
        "registry_catalogue",
        "pending",
        "services",
        "source_files",
        "clock",
    ]


@pytest.mark.parametrize("mode", ["native", "x86"])
def test_fixture_binary_mode_preserves_exact_input_bytes_and_native_runtime(
    fixture: dict[str, Any], monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    record = fixture["read"]()
    record["complete"] = False
    fixture["write"](record)
    monkeypatch.setattr(sys, "argv", ["fixture", fixture["ROOT"], "setup", mode])
    sources = {
        "registry installer.exe": {
            "sha256": "3cc2f65337ff5d3f40af829d78dfe3a9a93f24ba2b4059be174ed2b4db2d3b68"
        },
        "python34.dll": {
            "sha256": "fdcb5f85b9fa3bedcc9b2a999e8bd733412b60d9e5f9faa9d1a5858ae753f3c4"
        },
        "registry_installer.py": {"sha256": "script"},
    }
    if mode == "x86":
        sources["MSVCR100.dll"] = {
            "sha256": "60c06e0fa4449314da3a0a87c1a9d9577df99226f943637e06f61188e5862efa"
        }
    fixture["source_files"] = lambda: sources
    fixture["python_dll"] = lambda: "source.dll"
    fixture["file_state"] = Mock(
        side_effect=[sources["registry installer.exe"], sources["python34.dll"]]
    )
    copied = Mock()
    monkeypatch.setattr(fixture["shutil"], "copy2", copied)
    assert fixture["setup"]()["sha256"] == {
        name: fields["sha256"] for name, fields in sources.items()
    }
    assert copied.call_count == (2 if mode == "native" else 0)
    assert fixture["file_state"].call_count == (2 if mode == "native" else 0)
    assert fixture["read"]()["sources"] == sources


def test_x86_fixture_rejects_unknown_binary_bytes_without_completing_journal(
    fixture: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    record = fixture["read"]()
    record["complete"] = False
    fixture["write"](record)
    monkeypatch.setattr(sys, "argv", ["fixture", fixture["ROOT"], "setup", "x86"])
    fixture["source_files"] = lambda: {
        name: {"sha256": "unknown"}
        for name in (
            "registry installer.exe",
            "python34.dll",
            "MSVCR100.dll",
            "registry_installer.py",
        )
    }
    with pytest.raises(AssertionError):
        fixture["setup"]()
    assert fixture["read"]()["complete"] is False


def test_source_protection_includes_optional_owned_x86_runtime(
    fixture: dict[str, Any], tmp_path: Path
) -> None:
    names = {"registry installer.exe", "python34.dll", "registry_installer.py"}
    fixture["file_state"] = lambda path: {"path": path}
    for name in names:
        (tmp_path / name).write_bytes(b"owned fixture")
    assert set(fixture["source_files"]()) == names
    (tmp_path / "MSVCR100.dll").write_bytes(b"owned runtime")
    assert set(fixture["source_files"]()) == names | {"MSVCR100.dll"}


def test_staged_runtime_remains_within_the_explicit_x86_fixture_branch() -> None:
    play = yaml.safe_load(
        (ROOT / "tests/integration/win_package_registry.yml").read_text()
    )[0]
    stage = next(
        task
        for task in play["tasks"][3]["block"]
        if task["name"].startswith("Stage exact existing x86")
    )
    assert stage["when"] == "package_registry_x86_binary_dir is defined"
    assert stage["loop"] == ["registry installer.exe", "python34.dll", "MSVCR100.dll"]


@pytest.mark.parametrize("side", ["after_native", "after_original"])
@pytest.mark.parametrize("mtime", [99_000_000_000, 102_000_000_000])
def test_output_clock_outside_its_own_operation_fails(side: str, mtime: int) -> None:
    capture = _capture()
    after = json.loads(capture["results"][0][side]["stdout"])
    after["outputs"]["installed.json"]["mtime"] = mtime
    capture["results"][0][side]["stdout"] = json.dumps(after)
    with pytest.raises(AssertionError):
        _comparator().verify_capture(capture, paired=True, running=True)


@pytest.mark.parametrize("field", ["mtime", "sha256"])
def test_protected_input_difference_is_never_normalized(field: str) -> None:
    capture = _capture()
    after = json.loads(capture["results"][0]["after_original"]["stdout"])
    after["sources"]["installer"][field] = "changed"
    capture["results"][0]["after_original"]["stdout"] = json.dumps(after)
    with pytest.raises(AssertionError):
        _comparator().verify_capture(capture, paired=True, running=True)


def test_json_type_and_error_message_must_match_literally() -> None:
    for key, value in (("rc", False), ("msg", "different")):
        capture = _capture()
        capture["results"][0]["original"][key] = value
        with pytest.raises(AssertionError):
            _comparator().verify_capture(capture, paired=True, running=True)


def test_only_unsupported_parameter_collection_name_is_replaced() -> None:
    comparator = _comparator()
    capture = _capture()
    raw: dict[str, Any] = {
        "msg": "Unsupported parameters for (ansible.windows.win_package) "
        "module: timeout. Supported parameters include: url_timeout",
    }
    capture["results"][0]["original"].update(raw)
    capture["results"][0]["native"]["msg"] = raw["msg"].replace(
        "ansible.windows.win_package", "sustainablelobster.legacy_windows.win_package"
    )
    assert comparator.verify_capture(capture, paired=True, running=True)["verified"]
    assert "ansible.windows.win_package" in raw["msg"]
    capture["results"][0]["original"][
        "msg"
    ] = "Error with ansible.windows.win_package: literal error"
    capture["results"][0]["native"][
        "msg"
    ] = "Error with sustainablelobster.legacy_windows.win_package: literal error"
    with pytest.raises(AssertionError):
        comparator.verify_capture(capture, paired=True, running=True)


def test_fixture_has_no_powershell_dotnet_or_persistent_environment_write() -> None:
    source = yaml.safe_load(SOURCE.read_text(encoding="utf-8"))
    installer = source["package_registry_installer_source"]
    fixture = source["package_registry_fixture_source"]
    assert "winreg.DeleteKey(hive, path)" in installer
    assert 'journal["registry_view"]' in installer
    assert 'record["missing_parents"]' in fixture
    assert 'environment["PYTHONHOME"] = sys.prefix' in fixture
    for payload in (installer, fixture):
        compile(payload, str(SOURCE), "exec")
        assert "powershell" not in payload.lower()
        assert "pythonnet" not in payload.lower()
