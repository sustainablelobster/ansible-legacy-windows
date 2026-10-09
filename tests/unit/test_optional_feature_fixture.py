"""Exercise feature-journal ownership, preflight, strict recovery and retries."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Fixture substitutes isolate real servicing from controller-only tests.
# pylint: disable=exec-used

import ast
import copy
import ctypes
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, cast
from unittest.mock import Mock

import pytest

# PyYAML comes from the pinned developer environment without typing stubs.
import yaml  # type: ignore[import-untyped]
from jinja2 import Environment

from tests.unit.payload_support import ROOT


@pytest.fixture(name="fixture")
def optional_feature_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, Any]:
    """Load only fixture definitions with isolated paths and native substitutes.

    :param tmp_path: Private recovery workspace.
    :param monkeypatch: Scoped Windows import and argument replacements.
    :returns: Fixture namespace without executing its main.
    """
    monkeypatch.setitem(sys.modules, "winreg", ModuleType("winreg"))
    monkeypatch.setenv("SystemRoot", str(tmp_path / "windows"))
    monkeypatch.setattr(sys, "argv", ["fixture", str(tmp_path), "setup"])
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/optional_feature_fixture.yml").read_text(
            encoding="utf-8"
        )
    )["optional_feature_fixture"]
    namespace: dict[str, Any] = {"__name__": "fixture"}
    exec(compile(source, "optional_feature_fixture.py", "exec"), namespace)
    namespace["service_snapshot"] = Mock(
        return_value={
            "TrustedInstaller": {"Name": "TrustedInstaller", "State": "Stopped"},
            "BvSshServer": {"Name": "BvSshServer", "State": "Running"},
        }
    )
    namespace["binaries"] = Mock(return_value={"telnet.exe": None})
    namespace["pending"] = Mock(return_value={"CBS": None, "WU": None})
    namespace["inventory"] = Mock(
        return_value={
            "TelnetClient": "Disabled",
            "TFTP": "Disabled",
            "Other": "Enabled",
        }
    )
    namespace["dism"] = Mock(return_value={"rc": 0, "stdout": "", "stderr": ""})
    namespace["real_native_features"] = namespace["native_features"]

    def _native(names: list[str]) -> list[dict[str, Any]]:
        if not namespace["supported"]:
            return []
        return [
            {"requested": name, "status": 0, "name": name, "state": 4} for name in names
        ]

    namespace["native_features"] = Mock(side_effect=_native)
    namespace["restore_installer"] = Mock()
    namespace["supported"] = True
    return namespace


def _journal(fixture: dict[str, Any]) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads(Path(fixture["journal_path"]).read_text(encoding="utf-8")),
    )


def test_complete_journal_precedes_servicing_and_keeps_full_original_state(
    fixture: dict[str, Any],
) -> None:
    def _read() -> dict[str, str]:
        early = _journal(fixture)
        assert not early["complete"] and early["before"]["features"] is None
        return {"TelnetClient": "Disabled", "TFTP": "Disabled", "Other": "Enabled"}

    fixture["inventory"].side_effect = _read
    setup = fixture["setup"]()
    record = _journal(fixture)
    assert record["complete"] and record["before"] == setup["snapshot"]
    assert setup["snapshot"]["features"]["Other"] == "Enabled"
    assert Path(setup["source"]).is_dir() and Path(setup["source_file"]).is_file()
    assert not Path(setup["missing_source"]).exists()
    fixture["dism"].assert_not_called()


def test_existing_journal_is_not_overwritten(fixture: dict[str, Any]) -> None:
    fixture["setup"]()
    before = Path(fixture["journal_path"]).read_bytes()
    with pytest.raises(ValueError, match="must not be overwritten"):
        fixture["setup"]()
    assert Path(fixture["journal_path"]).read_bytes() == before


@pytest.mark.parametrize(
    "field,value", [("workspace", "unowned"), ("targets", ["Other"])]
)
def test_tampered_ownership_fails_before_servicing(
    fixture: dict[str, Any], field: str, value: Any
) -> None:
    fixture["setup"]()
    record = _journal(fixture)
    record[field] = value
    Path(fixture["journal_path"]).write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(ValueError, match="does not own"):
        fixture["cleanup"]()
    fixture["dism"].assert_not_called()


@pytest.mark.parametrize("state", ["Enabled", "Enable Pending", None])
def test_unusable_fixture_feature_fails_before_mutation_and_recovers_incomplete_setup(
    fixture: dict[str, Any], state: str | None
) -> None:
    fixture["inventory"].return_value = {"TelnetClient": state, "TFTP": "Disabled"}
    if state is None:
        del fixture["inventory"].return_value["TelnetClient"]
    with pytest.raises(ValueError):
        fixture["setup"]()
    assert not _journal(fixture)["complete"]
    result = fixture["cleanup"]()
    assert result["restored"] and result["setup_incomplete"]
    assert not Path(fixture["journal_path"]).exists()
    fixture["dism"].assert_not_called()


def test_preexisting_reboot_request_is_never_cleared(fixture: dict[str, Any]) -> None:
    fixture["pending"].return_value["CBS"] = {}
    with pytest.raises(ValueError, match="no original reboot request"):
        fixture["setup"]()
    assert fixture["cleanup"]()["restored"]
    assert fixture["pending"].return_value["CBS"] == {}
    fixture["dism"].assert_not_called()


def test_unavailable_backend_journals_and_recovers_without_servicing(
    fixture: dict[str, Any],
) -> None:
    fixture["supported"] = False
    fixture["inventory"].return_value = None
    setup = fixture["setup"]()
    assert setup["journaled"] and not setup["supported"]
    assert setup["snapshot"]["features"] is None
    assert fixture["cleanup"]()["restored"]
    fixture["dism"].assert_not_called()


def test_unchanged_policy_requires_no_servicing_and_deletes_only_verified_journal(
    fixture: dict[str, Any],
) -> None:
    setup = fixture["setup"]()
    result = fixture["cleanup"]()
    assert result["restored"] and result["after"] == setup["snapshot"]
    assert result["actions"] == []
    assert not Path(fixture["journal_path"]).exists()
    assert Path(setup["source_file"]).exists()
    fixture["dism"].assert_not_called()


def test_recovery_restores_complete_feature_delta_not_unrelated_features(
    fixture: dict[str, Any],
) -> None:
    setup = fixture["setup"]()
    current = copy.deepcopy(setup["snapshot"]["features"])
    current["TelnetClient"] = "Enabled"
    fixture["inventory"].side_effect = lambda: dict(current)

    def _disable(arguments: list[str]) -> dict[str, Any]:
        assert arguments == ["/Disable-Feature", "/FeatureName:TelnetClient"]
        current["TelnetClient"] = "Disabled"
        return {"rc": 0}

    fixture["dism"].side_effect = _disable
    result = fixture["cleanup"]()
    assert result["restored"] and result["after"] == setup["snapshot"]
    assert current["Other"] == "Enabled"
    fixture["dism"].assert_called_once()


def test_failed_recovery_retains_retryable_journal(fixture: dict[str, Any]) -> None:
    fixture["setup"]()
    fixture["inventory"].return_value["TelnetClient"] = "Enabled"
    fixture["dism"].side_effect = OSError("Servicing recovery failed")
    with pytest.raises(OSError, match="recovery failed"):
        fixture["cleanup"]()
    assert Path(fixture["journal_path"]).exists()
    fixture["restore_installer"].assert_not_called()


def test_unexpected_inventory_name_change_fails_before_recovery_write(
    fixture: dict[str, Any],
) -> None:
    fixture["setup"]()
    fixture["inventory"].return_value["Unjournaled"] = "Enabled"
    with pytest.raises(ValueError, match="names changed unexpectedly"):
        fixture["cleanup"]()
    assert Path(fixture["journal_path"]).exists()
    fixture["dism"].assert_not_called()


def test_reboot_needed_recovery_keeps_journal_then_exact_retry_can_complete(
    fixture: dict[str, Any],
) -> None:
    setup = fixture["setup"]()
    current = copy.deepcopy(setup["snapshot"]["features"])
    current["TelnetClient"] = "Enabled"
    fixture["inventory"].side_effect = lambda: dict(current)

    def _pending(_arguments: list[str]) -> dict[str, Any]:
        current["TelnetClient"] = "Disable Pending"
        fixture["pending"].return_value["CBS"] = {}
        return {"rc": 3010}

    fixture["dism"].side_effect = _pending
    anchor = fixture["snapshot"]()
    first = fixture["cleanup"]()
    assert not first["restored"] and first["requires_reboot"]
    assert first["before_recovery"] == anchor
    assert Path(fixture["journal_path"]).exists()
    fixture["restore_installer"].assert_not_called()
    current["TelnetClient"] = "Disabled"
    fixture["pending"].return_value["CBS"] = None
    second = fixture["cleanup"]()
    assert second["restored"] and second["after"] == setup["snapshot"]
    assert fixture["dism"].call_count == 1
    assert second["before_recovery"] != anchor
    play = yaml.safe_load(
        (ROOT / "tests/integration/win_optional_feature.yml").read_text(
            encoding="utf-8"
        )
    )[0]
    recovery_tasks = play["tasks"][-1]["always"][0]["block"]
    retention = next(
        task
        for task in recovery_tasks
        if task["name"] == "Retain the first pre-recovery boundary through any reboot"
    )
    boundary = next(
        task
        for task in recovery_tasks
        if task["name"] == "Verify the final read-only batch catalogue boundary"
    )
    environment = Environment()
    environment.filters["from_json"] = json.loads
    original_command = {"stdout": json.dumps(first)}
    expression = retention["ansible.builtin.set_fact"][
        "optional_feature_initial_cleanup"
    ].strip()[2:-2]
    saved = environment.compile_expression(expression)(
        optional_feature_cleanup=original_command
    )
    assert saved == original_command
    assert environment.compile_expression(
        boundary["ansible.builtin.assert"]["that"][0]
    )(
        optional_feature_initial_cleanup=saved,
        optional_feature_cleanup={"stdout": json.dumps(second)},
        optional_feature_anchor=anchor,
    )


def test_service_or_binary_mismatch_keeps_recovery_evidence(
    fixture: dict[str, Any],
) -> None:
    fixture["setup"]()
    fixture["binaries"].return_value["telnet.exe"] = "unexpected-new-bytes"
    with pytest.raises(ValueError, match="state differs"):
        fixture["cleanup"]()
    assert Path(fixture["journal_path"]).exists()


def test_selected_observation_keeps_duplicates_unknowns_and_extra_row_separate(
    fixture: dict[str, Any],
) -> None:
    fixture["native_features"].return_value = None
    fixture["native_features"].side_effect = lambda _names: [
        {"requested": "tftp", "name": "TFTP", "state": 2, "status": 0},
        {"requested": "Missing", "status": 0x800F080C},
        {"requested": "tftp", "name": "TFTP", "state": 2, "status": 0},
        {"requested": "TelnetClient", "name": "TelnetClient", "state": 4, "status": 0},
        {"requested": "TFTP", "name": "TFTP", "state": 2, "status": 0},
        {
            "requested": "Microsoft-RemoteDesktopConnection",
            "state": 4,
            "name": "Microsoft-RemoteDesktopConnection",
            "status": 0,
        },
    ]
    observed = fixture["snapshot"]("selected", "tftp,Missing,tftp")
    fixture["inventory"].assert_not_called()
    assert observed["features"] == {"TFTP": "Disabled", "TelnetClient": "Enabled"}
    assert [row["requested"] for row in observed["native_requested"]] == [
        "tftp",
        "Missing",
        "tftp",
        "TelnetClient",
        "TFTP",
    ]
    assert observed["native_extra"][0]["name"] not in observed["features"]
    fixture["native_features"].assert_called_once_with(
        [
            "tftp",
            "Missing",
            "tftp",
            "TelnetClient",
            "TFTP",
            "Microsoft-RemoteDesktopConnection",
        ]
    )


@pytest.mark.parametrize("names", [None, [], "", ["TFTP", "TFTP"]])
def test_selected_observation_always_checks_both_owned_features(
    fixture: dict[str, Any], names: Any
) -> None:
    fixture["snapshot"]("selected", names)
    observed_names = fixture["native_features"].call_args.args[0]
    assert observed_names[-3:] == [
        "TelnetClient",
        "TFTP",
        "Microsoft-RemoteDesktopConnection",
    ]


def test_extra_native_row_mismatch_retains_recovery_data_without_servicing(
    fixture: dict[str, Any],
) -> None:
    fixture["setup"]()
    fixture["native_features"].side_effect = lambda names: [
        {"requested": name, "status": 0, "name": name, "state": 2} for name in names
    ]
    with pytest.raises(ValueError, match="state differs"):
        fixture["cleanup"]()
    assert Path(fixture["journal_path"]).exists()
    fixture["dism"].assert_not_called()


def test_cleanup_reuses_unchanged_full_catalogue_and_retains_final_batch_boundary(
    fixture: dict[str, Any],
) -> None:
    original = fixture["setup"]()["snapshot"]
    fixture["inventory"].reset_mock()
    result = fixture["cleanup"]()
    fixture["inventory"].assert_called_once()
    assert result["before_recovery"] == original
    assert result["after"] == original


def test_final_batch_boundary_keeps_pre_restore_servicing_runtime(
    fixture: dict[str, Any],
) -> None:
    original = fixture["setup"]()["snapshot"]
    running = copy.deepcopy(original["services"])
    running["TrustedInstaller"]["State"] = "Running"
    fixture["service_snapshot"].return_value = running

    def _stop(_services: Any) -> None:
        fixture["service_snapshot"].return_value = original["services"]

    fixture["restore_installer"].side_effect = _stop
    result = fixture["cleanup"]()
    assert result["before_recovery"]["services"] == running
    assert result["after"] == original


@pytest.mark.parametrize("failure", [0, 0x800F080C, 0x80070005])
def test_native_getters_use_packed_prefix_and_close_all_resources(
    fixture: dict[str, Any], monkeypatch: pytest.MonkeyPatch, failure: int
) -> None:
    library = Mock()
    monkeypatch.setattr(fixture["os"].path, "isfile", lambda _path: True)
    library.DismInitialize.return_value = 0
    library.DismOpenSession.return_value = 0
    library.DismCloseSession.return_value = 0
    library.DismShutdown.return_value = 0
    library.DismDelete.return_value = 0
    allocated = []

    def _get(
        _session: Any, name: str, _identifier: Any, _kind: Any, result: Any
    ) -> int:
        # ctypes publishes pointer targets through its documented _type_.
        info_pointer = library.DismGetFeatureInfo.argtypes[-1]
        info_type = info_pointer._type_._type_  # pylint: disable=protected-access
        assert info_type._pack_ == 4  # pylint: disable=protected-access
        assert ctypes.sizeof(info_type) == ctypes.sizeof(ctypes.c_void_p) + 4
        info = info_type(name, 4)
        allocated.append(info)
        ctypes.cast(result, library.DismGetFeatureInfo.argtypes[-1])[0] = (
            ctypes.pointer(info)
        )
        return failure if name == "Second" else 0

    library.DismGetFeatureInfo.side_effect = _get
    monkeypatch.setattr(ctypes, "WinDLL", Mock(return_value=library), raising=False)
    if failure == 0x80070005:
        with pytest.raises(OSError, match="DismGetFeatureInfo: 80070005"):
            fixture["real_native_features"](["First", "Second"])
    else:
        rows = fixture["real_native_features"](["First", "Second"])
        assert rows[0] == {
            "requested": "First",
            "name": "First",
            "state": 4,
            "status": 0,
        }
        assert rows[1]["status"] == failure
        assert ("state" in rows[1]) == (failure == 0)
    assert library.DismDelete.call_count == 2
    library.DismCloseSession.assert_called_once()
    library.DismShutdown.assert_called_once()


def test_failed_native_session_open_still_shuts_down(
    fixture: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    library = Mock()
    monkeypatch.setattr(fixture["os"].path, "isfile", lambda _path: True)
    library.DismInitialize.return_value = 0
    library.DismOpenSession.return_value = 0x80070005
    library.DismShutdown.return_value = 0
    monkeypatch.setattr(ctypes, "WinDLL", Mock(return_value=library), raising=False)
    with pytest.raises(OSError, match="DismOpenSession: 80070005"):
        fixture["real_native_features"](["TFTP"])
    library.DismCloseSession.assert_not_called()
    library.DismShutdown.assert_called_once()


def test_real_absent_dism_api_uses_complete_native_catalogue_without_dll_calls(
    fixture: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fixture["os"].path, "isfile", lambda _path: False)
    library = Mock()
    monkeypatch.setattr(ctypes, "WinDLL", library, raising=False)
    fixture["supported"] = True
    rows = fixture["real_native_features"](["telnetclient", "unknown", "TFTP"])
    assert rows == [
        {"requested": "telnetclient", "name": "TelnetClient", "state": 2, "status": 0},
        {"requested": "unknown", "status": 0x800F080C},
        {"requested": "TFTP", "name": "TFTP", "state": 2, "status": 0},
    ]
    library.assert_not_called()


def test_fixture_retains_python34_syntax_and_no_newer_bytes_hex_method() -> None:
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/optional_feature_fixture.yml").read_text(
            encoding="utf-8"
        )
    )["optional_feature_fixture"]
    tree = ast.parse(source, feature_version=(3, 4))
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "hex"
        for node in ast.walk(tree)
    )


def test_every_owned_assertion_item_is_string_or_bool() -> None:
    def _check(value: Any) -> None:
        if isinstance(value, dict):
            if "that" in value:
                assert isinstance(value["that"], list)
                assert all(isinstance(item, (str, bool)) for item in value["that"])
            for child in value.values():
                _check(child)
        elif isinstance(value, list):
            for child in value:
                _check(child)

    for filename in [
        "win_optional_feature.yml",
        "tasks/win_optional_feature_case.yml",
        "vars/optional_feature.yml",
        "vars/optional_feature_fixture.yml",
    ]:
        _check(
            yaml.safe_load(
                (ROOT / "tests/integration" / filename).read_text(encoding="utf-8")
            )
        )
