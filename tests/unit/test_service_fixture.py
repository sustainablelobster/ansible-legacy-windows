"""Review maintained service fixture ownership and its native dispatcher offline."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import ctypes
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


@pytest.fixture(name="source")
def fixture_source() -> str:
    """Read the exact maintained target fixture.

    :returns: Embedded Python source.
    """
    data = yaml.safe_load(
        (ROOT / "tests/integration/vars/service_fixture.yml").read_text()
    )
    return str(data["service_fixture"])


def test_fixture_and_dispatcher_parse_as_python34_and_use_no_external_runtime(
    source: str,
) -> None:
    tree = ast.parse(source, feature_version=(3, 4))
    constant = next(
        node.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "dispatcher"
            for target in node.targets
        )
    )
    assert isinstance(constant, ast.Constant) and isinstance(constant.value, str)
    dispatcher = constant.value
    ast.parse(dispatcher, feature_version=(3, 4))
    assert "StartServiceCtrlDispatcherW" in dispatcher
    assert "RegisterServiceCtrlHandlerExW" in dispatcher
    assert "WINFUNCTYPE" in dispatcher
    assert "report(7)" in dispatcher and "report(4)" in dispatcher
    assert "report(1)" in dispatcher
    assert not any(
        value in dispatcher for value in ("powershell", "pywin32", "subprocess", "nssm")
    )


@pytest.mark.parametrize("duplicate_succeeds", [False, True])
def test_dispatcher_reports_actual_identity_and_closes_token_observation_handles(
    source: str, duplicate_succeeds: bool
) -> None:
    constant = next(
        node.value
        for node in ast.parse(source).body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "dispatcher"
            for target in node.targets
        )
    )
    assert isinstance(constant, ast.Constant) and isinstance(constant.value, str)
    definition = next(
        node
        for node in ast.parse(constant.value).body
        if isinstance(node, ast.FunctionDef) and node.name == "token_observation"
    )
    identity = ctypes.create_unicode_buffer("S-1-5-18")

    def _open(_process: int, access: int, token: Any) -> bool:
        assert access == 0xF
        token._obj.value = 11  # pylint: disable=protected-access
        return True

    def _information(
        _token: Any, kind: int, data: Any, _size: int, needed: Any
    ) -> bool:
        assert kind == 1
        needed._obj.value = 16  # pylint: disable=protected-access
        if data is not None:
            ctypes.c_void_p.from_buffer(data).value = 123
        return data is not None

    def _convert(_sid: Any, text: Any) -> bool:
        text._obj.value = ctypes.addressof(identity)  # pylint: disable=protected-access
        return True

    def _duplicate(*arguments: Any) -> bool:
        if duplicate_succeeds:
            arguments[-1]._obj.value = 22  # pylint: disable=protected-access
        return duplicate_succeeds

    security = SimpleNamespace(
        OpenProcessToken=_open,
        GetTokenInformation=_information,
        ConvertSidToStringSidW=_convert,
        DuplicateTokenEx=_duplicate,
    )
    kernel = SimpleNamespace(
        GetCurrentProcess=lambda: 1, CloseHandle=Mock(), LocalFree=Mock()
    )
    native = SimpleNamespace(
        byref=ctypes.byref,
        create_string_buffer=ctypes.create_string_buffer,
        wstring_at=ctypes.wstring_at,
        get_last_error=lambda: 5,
    )
    namespace: dict[str, Any] = {
        "advapi": security,
        "kernel": kernel,
        "ctypes": native,
        "pointer": ctypes.c_void_p,
        "dword": ctypes.c_uint32,
    }
    # Execute the maintained observation while replacing only its Windows calls.
    # pylint: disable-next=exec-used
    exec(
        compile(ast.Module(body=[definition], type_ignores=[]), "probe", "exec"),
        namespace,
    )
    observed = namespace["token_observation"]()
    assert observed == {
        "sid": "S-1-5-18",
        "token_access": 0xF,
        "primary_token_duplicate": duplicate_succeeds,
        "duplicate_error": None if duplicate_succeeds else 5,
    }
    assert [call.args[0].value for call in kernel.CloseHandle.call_args_list] == (
        [22, 11] if duplicate_succeeds else [11]
    )
    assert kernel.LocalFree.call_args.args[0].value == ctypes.addressof(identity)


def test_credential_cases_cover_password_rotation_prediction_denial_and_recovery() -> (
    None
):
    data = yaml.safe_load(
        (ROOT / "tests/integration/vars/service_credentials.yml").read_text()
    )
    cases = [case for group in data.values() for case in group]
    assert len(cases) == 13
    assert sum(bool(case.get("failed")) for case in cases) == 2
    assert sum(bool(case.get("check")) for case in cases) == 2
    assert any(case.get("expected_sid") == "S-1-5-18" for case in cases)
    assert {case["params"].get("update_password") for case in cases} >= {
        "always",
        "on_create",
    }
    assert all(case["message"] == "1069" for case in cases if case.get("failed"))
    assert cases[-1]["name"].startswith("Recover")


def test_service_case_retention_redacts_passwords_before_writing_evidence() -> None:
    source = (ROOT / "tests/integration/tasks/win_service_case.yml").read_text()
    assert "combine({'password': 'REDACTED'})" in source
    assert "select('in', service_result | to_json)" in source
    assert "select('in', service_case_capture | to_json)" in source


def test_journal_is_atomically_persisted_before_resource_creation(
    source: str, tmp_path: Path
) -> None:
    definition = next(
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name == "save"
    )
    namespace: dict[str, Any] = {
        "json": json,
        "os": os,
        "journal_path": str(tmp_path / "service-journal.json"),
    }
    # Run the maintained persistence routine, not a second journal implementation.
    # pylint: disable-next=exec-used
    exec(
        compile(
            ast.Module(body=[definition], type_ignores=[]), "service_fixture", "exec"
        ),
        namespace,
    )
    journal = {"names": {"primary": "uniquely-owned"}, "initial_absence": True}
    namespace["save"](journal)
    assert json.loads((tmp_path / "service-journal.json").read_text()) == journal
    assert not (tmp_path / "service-journal.json.new").exists()
    assert source.index("save(journal)") < source.index("with open(script_path")


def test_cleanup_refuses_foreign_commands_and_waits_for_process_and_scm_absence(
    source: str,
) -> None:
    assert "values['ImagePath'] != journal['commands'][role]" in source
    assert source.index("unexpected command line") < source.index(
        "advapi.DeleteService(service)"
    )
    assert "kernel.WaitForSingleObject(process, 30000)" in source
    assert "error.winerror != 1072" in source
    assert "service is None and registry(name) is None" in source
    assert "('primary', 'companion')" in source
    assert "restored': True" in source


@pytest.mark.parametrize("expired", [False, True])
def test_cleanup_never_infers_process_absence_from_denied_access(
    source: str, expired: bool
) -> None:
    definition = next(
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name == "process_handle"
    )
    kernel = Mock()
    kernel.OpenProcess.return_value = 0
    clock = Mock()
    clock.monotonic.side_effect = [0, 31 if expired else 1]
    native = SimpleNamespace(
        c_uint64=ctypes.c_uint64,
        get_last_error=Mock(side_effect=[5, 87]),
        WinError=lambda code: OSError("Windows error " + str(code)),
    )
    namespace: dict[str, Any] = {"kernel": kernel, "ctypes": native, "time": clock}
    # Run the maintained cleanup function with only the native boundary replaced.
    # pylint: disable-next=exec-used
    exec(
        compile(
            ast.Module(body=[definition], type_ignores=[]), "service_fixture", "exec"
        ),
        namespace,
    )
    if expired:
        with pytest.raises(OSError, match="Windows error 5"):
            namespace["process_handle"]({"pid": 123, "creation": 456})
        clock.sleep.assert_not_called()
    else:
        assert namespace["process_handle"]({"pid": 123, "creation": 456}) is None
        clock.sleep.assert_called_once_with(0.05)
    kernel.GetProcessTimes.assert_not_called()


def test_cases_cover_real_lifecycle_check_mode_partial_failure_and_owned_dependencies() -> (
    None
):
    data = yaml.safe_load((ROOT / "tests/integration/vars/service.yml").read_text())
    cases = data["service_cases"]
    assert {case["params"].get("state") for case in cases} >= {
        "started",
        "stopped",
        "paused",
        "restarted",
        "absent",
    }
    assert any(case.get("check") and case["changed"] for case in cases)
    assert any(case.get("failed") and case["changed"] for case in cases)
    assert all("service_names" in case["params"]["name"] for case in cases)
    dependencies = [
        item for case in cases for item in case["params"].get("dependencies", [])
    ]
    assert dependencies == ["{{ service_names.companion }}"]


def test_legacy_cases_exercise_normal_modes_and_nonmutating_delayed_rejection() -> None:
    data = yaml.safe_load((ROOT / "tests/integration/vars/service.yml").read_text())
    cases = data["service_legacy_cases"]
    assert {case["params"].get("start_mode") for case in cases} >= {
        "auto",
        "manual",
        "disabled",
        "delayed",
    }
    delayed = [case for case in cases if case["params"].get("start_mode") == "delayed"]
    assert len(delayed) == 4
    assert all(case["failed"] and not case["changed"] for case in delayed)
    assert {case.get("check", False) for case in delayed} == {False, True}
    assert any(case.get("failed") and case["changed"] for case in cases)


def test_binding_cases_preserve_caller_output_and_semantic_idempotence() -> None:
    cases = yaml.safe_load((ROOT / "tests/integration/vars/service.yml").read_text())[
        "service_cases"
    ]
    mixed = next(
        case for case in cases if case["name"].startswith("Bind mixed nested keys")
    )
    assert mixed["params"]["failure_actions"] == [{"Type": "RESTART", "Delay_ms": 3.5}]
    assert mixed["params"]["pre_shutdown_timeout"] == 2.5
    assert mixed["public_after"]["failure_reset_period_sec"] == 2
    alias = next(
        case for case in cases if case["name"].startswith("Nested delay alias")
    )
    assert alias["params"]["failure_actions"][0]["delay_ms"] == 1
    assert alias["public_after"]["failure_actions"][0]["delay_ms"] == 9
    repeated = next(
        case for case in cases if case["name"].startswith("Caller spelling")
    )
    assert not repeated["changed"] and repeated["public_after"] == alias["public_after"]


def test_mixed_case_alias_and_collision_cases_preserve_binding_order() -> None:
    cases = yaml.safe_load((ROOT / "tests/integration/vars/service.yml").read_text())[
        "service_cases"
    ]
    mixed = [case for case in cases if case["name"].startswith("Mixed-case delay")]
    assert len(mixed) == 2
    assert [
        case["public_after"]["failure_actions"][0]["delay_ms"] for case in mixed
    ] == [
        0,
        1,
    ]
    collisions = [case for case in cases if "collision" in case["name"]]
    assert len(collisions) == 3
    for case in collisions:
        assert case["failed"] and not case["changed"] and case["exists"] is None
        assert case["public_absent"] == ["exists", "diff", "invocation"]
        assert "msg" in case["public"]


def test_case_checks_resolved_journal_ownership_before_the_public_request() -> None:
    source = (ROOT / "tests/integration/tasks/win_service_case.yml").read_text()
    assert source.index("service_case.params.name in [service_names.primary") < (
        source.index("sustainablelobster.legacy_windows.win_service:")
    )
    assert "in service_commands.values()" in source
