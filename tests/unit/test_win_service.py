"""Exercise service ordering, public results, and recovery through JSON requests."""

# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

Request = Callable[[dict[str, Any]], tuple[int, dict[str, Any]]]


def _initial(name: str, path: str) -> dict[str, Any]:
    return {
        "name": name,
        "path": path,
        "display_name": name,
        "description": None,
        "dependencies": [],
        "desktop_interact": False,
        "error_control": "normal",
        "failure_actions": [],
        "failure_actions_on_non_crash_failure": False,
        "failure_command": None,
        "failure_reboot_msg": None,
        "failure_reset_period_sec": 0,
        "load_order_group": "",
        "pre_shutdown_timeout_ms": 180000,
        "required_privileges": [],
        "service_type": "win32_own_process",
        "sid_info": "none",
        "start_mode": "auto",
        "state": "stopped",
        "username": "LocalSystem",
        "_service_type": 16,
        "_start_type": 2,
        "_status": 1,
        "_controls": 0,
        "_pid": 0,
        "_dependents": [],
    }


@pytest.fixture(name="native")
def native_state() -> Any:
    """Provide an independent mutable SCM boundary with ordered call recording.

    :returns: Mutable services and callable native substitutes.
    """
    state = SimpleNamespace(services={}, calls=Mock(), fail=None, modern=True)

    def _create(name: str, path: str) -> None:
        state.services[name] = _initial(name, path)

    def _change(name: str, **fields: Any) -> None:
        record = state.services[name]
        for field, value in fields.items():
            if field == "error_control":
                value = {0: "ignore", 1: "normal", 2: "severe", 3: "critical"}[value]
            elif field == "service_type":
                record["_service_type"] = value
                record["desktop_interact"] = bool(value & 0x100)
                continue
            elif field == "start_type":
                record["_start_type"] = value
                record["start_mode"] = {2: "auto", 3: "manual", 4: "disabled"}[value]
                continue
            elif field == "password":
                continue
            elif field == "dependencies" and not value:
                continue
            record[field] = copy.deepcopy(value)

    def _extended(name: str, field: str, value: Any, access: int = 0) -> None:
        if field == state.fail:
            raise ValueError("Synthetic unavailable setter: " + field)
        record = state.services[name]
        if field == "failures":
            if not access & 16 and any(
                action["type"] == "restart"
                for action in value.get("failure_actions", [])
            ):
                error = OSError(5, "Access is denied.")
                error.winerror = 5  # type: ignore[attr-defined]
                raise error
            record.update(
                {
                    key: item or None if isinstance(item, str) else item
                    for key, item in value.items()
                }
            )
        elif field == "sid_info":
            record[field] = {0: "none", 1: "unrestricted", 3: "restricted"}[value]
        elif field == "delayed":
            if record["_start_type"] == 2:
                record["start_mode"] = "delayed" if value else "auto"
        else:
            record[field] = copy.deepcopy(
                value or None if field == "description" else value
            )

    def _control(name: str, desired: str, unused_force: bool = False) -> None:
        record = state.services[name]
        record["state"] = "started" if desired == "restarted" else desired
        record["_controls"] = 0 if desired == "stopped" else 3

    state.calls.create.side_effect = _create
    state.calls.change.side_effect = _change
    state.calls.set_extended.side_effect = _extended
    state.calls.control.side_effect = _control
    state.calls.remove.side_effect = state.services.pop
    state.calls.read.side_effect = (
        lambda name, unused_warnings, unused_access=0: copy.deepcopy(
            state.services[name]
        )
    )
    state.calls.resolve_name.side_effect = lambda name: next(
        (
            key
            for key, record in state.services.items()
            if name.lower() in (key.lower(), record["display_name"].lower())
        ),
        None,
    )

    def _expand(value: str | None) -> str | None:
        return value

    state.calls.expand_path.side_effect = _expand
    return state


@pytest.fixture(name="run_request")
def service_request(
    monkeypatch: pytest.MonkeyPatch,
    native: Any,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> Request:
    """Invoke the public JSON entry point with only native calls substituted.

    :param monkeypatch: Scoped boundary and argument replacements.
    :param native: Independent service model.
    :param tmp_path: Private argument directory.
    :param capsys: Protocol output capture.
    :returns: Public request function.
    """
    payload = load_payload("win_service", monkeypatch)
    for name in (
        "create",
        "change",
        "set_extended",
        "control",
        "remove",
        "read",
        "resolve_name",
        "expand_path",
    ):
        monkeypatch.setattr(payload.service, name, getattr(native.calls, name))
    monkeypatch.setattr(
        payload.service, "supports_delayed_start", lambda: native.modern
    )
    monkeypatch.setattr(
        payload.environment,
        "values_equal",
        lambda left, right: str(left).lower() == str(right).lower(),
    )
    names = {
        "system": "S-1-5-18",
        "localsystem": "S-1-5-18",
        "nt authority\\system": "S-1-5-18",
        "nt authority\\local service": "S-1-5-19",
        "nt authority\\localservice": "S-1-5-19",
    }
    monkeypatch.setattr(
        payload.account, "name_to_sid", lambda name: names.get(name.lower(), name)
    )
    monkeypatch.setattr(
        payload.account,
        "sid_to_name",
        lambda sid: {
            "S-1-5-18": "NT AUTHORITY\\SYSTEM",
            "S-1-5-19": "NT AUTHORITY\\LOCAL SERVICE",
        }.get(sid, sid),
    )
    path = tmp_path / "service-request.json"
    monkeypatch.setattr(sys, "argv", ["win_service.py", str(path)])

    def _request(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        path.write_text(json.dumps(arguments), encoding="utf-8")
        return invoke_payload(payload, capsys)

    return _request


def test_missing_query_check_creation_real_repeat_and_absence(
    run_request: Request, native: Any
) -> None:
    assert run_request({"name": "owned"}) == (0, {"changed": False, "exists": False})
    args = {
        "name": "owned",
        "path": "owned.exe",
        "start_mode": "manual",
        "_ansible_diff": True,
    }
    code, predicted = run_request(dict(args, _ansible_check_mode=True))
    assert code == 0 and predicted["changed"] and predicted["exists"]
    assert predicted["username"] is None and predicted["state"] == ""
    assert (
        predicted["diff"]["before"] == ""
        and predicted["diff"]["after"]["dependencies"] is None
    )
    assert native.services == {} and not native.calls.create.called
    code, created = run_request(args)
    assert code == 0 and created["changed"] and created["state"] == "stopped"
    assert (
        created["username"] == "LocalSystem"
        and created["can_pause_and_continue"] is False
    )
    assert created["diff"]["after"]["username"] == "NT AUTHORITY\\SYSTEM"
    code, repeated = run_request(args)
    assert code == 0 and not repeated["changed"]
    assert repeated["diff"]["before"] == repeated["diff"]["after"]
    native.calls.reset_mock()
    assert run_request(
        {"name": "owned", "state": "absent", "_ansible_check_mode": True}
    ) == (0, {"changed": True, "exists": False})
    assert not native.calls.remove.called and "owned" in native.services
    assert run_request({"name": "owned", "state": "absent"}) == (
        0,
        {"changed": True, "exists": False},
    )
    assert run_request({"name": "owned", "state": "absent"}) == (
        0,
        {"changed": False, "exists": False},
    )


def test_invocation_keeps_original_creation_parameters(run_request: Request) -> None:
    code, result = run_request(
        {"name": "owned", "path": "owned.exe", "_ansible_inject_invocation": True}
    )
    assert code == 0
    assert result["invocation"]["module_args"]["update_password"] is None
    assert result["invocation"]["module_args"]["path"] == "owned.exe"


def test_named_account_change_supplies_password_in_the_same_native_write(
    run_request: Request, native: Any
) -> None:
    run_request({"name": "owned", "path": "owned.exe"})
    native.calls.reset_mock()
    original_change = native.calls.change.side_effect

    def _credential_checked_change(name: str, **fields: Any) -> None:
        if fields.get("username") == "owned-account":
            if fields.get("password") != "Synthetic-Owned-Credential":
                error = OSError(1057, "The new service account needs its password")
                error.winerror = 1057  # type: ignore[attr-defined]
                raise error
        original_change(name, **fields)

    native.calls.change.side_effect = _credential_checked_change
    code, result = run_request(
        {
            "name": "owned",
            "username": "owned-account",
            "password": "Synthetic-Owned-Credential",
            "update_password": "on_create",
            "_ansible_diff": True,
            "_ansible_inject_invocation": True,
        }
    )
    assert code == 0 and result["changed"]
    assert result["username"] == "owned-account"
    assert result["diff"]["after"]["password"] == "CHANGED REDACTED"
    assert "Synthetic-Owned-Credential" not in json.dumps(result)
    assert native.calls.change.call_args_list == [
        (
            ("owned",),
            {"username": "owned-account", "password": "Synthetic-Owned-Credential"},
        )
    ]


def test_full_ordered_configuration_preserves_unknown_password_and_dependencies(
    run_request: Request, native: Any
) -> None:
    run_request({"name": "owned", "path": "owned.exe"})
    native.services["owned"]["dependencies"] = ["Original", "original"]
    native.calls.reset_mock()
    args = {
        "name": "owned",
        "username": "NT AUTHORITY\\LocalService",
        "password": "Synthetic-Only",
        "dependencies": ["Original", "New", "New"],
        "description": "description",
        "display_name": "display",
        "error_control": "ignore",
        "failure_actions": [{"type": "restart", "delay": 10}],
        "failure_actions_on_non_crash_failure": True,
        "load_order_group": "group",
        "path": "revised.exe",
        "pre_shutdown_timeout": 100,
        "required_privileges": [],
        "sid_info": "unrestricted",
        "start_mode": "manual",
        "service_type": "win32_share_process",
        "state": "started",
        "_ansible_diff": True,
        "_ansible_inject_invocation": True,
    }
    code, result = run_request(args)
    assert code == 0 and result["changed"]
    assert "Synthetic-Only" not in json.dumps(result)
    assert result["diff"]["after"]["password"] == "CHANGED REDACTED"
    assert result["diff"]["after"]["dependencies"] == ["Original", "New"]
    assert result["diff"]["after"]["failure_actions_on_non_crash_failure"] is None
    setters = [
        call
        for call in native.calls.mock_calls
        if call[0] in ("change", "set_extended", "control")
    ]
    assert [
        (call[0], call.args[1] if call[0] != "change" else next(iter(call.kwargs)))
        for call in setters
    ] == [
        ("change", "username"),
        ("change", "password"),
        ("change", "dependencies"),
        ("set_extended", "description"),
        ("change", "display_name"),
        ("change", "error_control"),
        ("set_extended", "failure_actions_on_non_crash_failure"),
        ("set_extended", "failures"),
        ("change", "load_order_group"),
        ("change", "path"),
        ("set_extended", "pre_shutdown_timeout_ms"),
        ("set_extended", "sid_info"),
        ("change", "start_type"),
        ("set_extended", "delayed"),
        ("change", "service_type"),
        ("control", "started"),
    ]


def test_check_mode_preserves_every_native_field_and_reports_current_controls(
    run_request: Request, native: Any
) -> None:
    run_request({"name": "owned", "path": "owned.exe"})
    before = copy.deepcopy(native.services)
    native.calls.reset_mock()
    code, result = run_request(
        {
            "name": "owned",
            "description": "new",
            "state": "started",
            "_ansible_check_mode": True,
            "_ansible_diff": True,
        }
    )
    assert code == 0 and result["changed"] and result["state"] == "running"
    assert result["can_pause_and_continue"] is False
    assert native.services == before
    assert not native.calls.control.called and not native.calls.set_extended.called


def test_partial_write_is_retained_and_a_second_request_recovers(
    run_request: Request, native: Any
) -> None:
    run_request({"name": "owned", "path": "owned.exe"})
    native.fail = "required_privileges"
    code, failed = run_request(
        {
            "name": "owned",
            "description": "retained",
            "required_privileges": ["Invalid"],
            "state": "started",
        }
    )
    assert code == 1 and failed["failed"] and failed["changed"]
    assert native.services["owned"]["description"] == "retained"
    assert native.services["owned"]["state"] == "stopped"
    native.fail = None
    code, recovered = run_request(
        {"name": "owned", "description": "recovered", "required_privileges": []}
    )
    assert (
        code == 0
        and recovered["changed"]
        and native.services["owned"]["description"] == "recovered"
    )


def test_composite_start_setter_can_write_before_reporting_unchanged_failure(
    run_request: Request, native: Any
) -> None:
    run_request({"name": "owned", "path": "owned.exe"})
    native.fail = "delayed"
    code, failed = run_request({"name": "owned", "start_mode": "manual"})
    assert code == 1 and failed["failed"] and not failed["changed"]
    assert native.services["owned"]["_start_type"] == 3
    assert native.services["owned"]["start_mode"] == "manual"
    native.fail = None
    code, retry = run_request({"name": "owned", "start_mode": "manual"})
    assert code == 0 and not retry["changed"]


@pytest.mark.parametrize(
    "mode,native_mode", [("auto", 2), ("manual", 3), ("disabled", 4)]
)
def test_legacy_normal_start_modes_do_not_write_a_delayed_flag(
    run_request: Request, native: Any, mode: str, native_mode: int
) -> None:
    native.modern = False
    run_request({"name": "owned", "path": "owned.exe", "start_mode": "manual"})
    native.calls.reset_mock()
    code, result = run_request({"name": "owned", "start_mode": mode})
    assert code == 0 and result["start_mode"] == mode
    assert native.services["owned"]["_start_type"] == native_mode
    assert not native.calls.set_extended.called
    assert result["changed"] == (mode != "manual")
    assert not run_request({"name": "owned", "start_mode": mode})[1]["changed"]


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("exists", [False, True])
def test_legacy_delayed_request_fails_before_any_service_operation(
    run_request: Request, native: Any, check: bool, exists: bool
) -> None:
    native.modern = False
    if exists:
        run_request({"name": "owned", "path": "owned.exe"})
    before = copy.deepcopy(native.services)
    native.calls.reset_mock()
    code, result = run_request(
        {
            "name": "owned",
            "path": "owned.exe",
            "description": "must not be written",
            "start_mode": "delayed",
            "_ansible_check_mode": check,
        }
    )
    assert code == 1 and result["failed"] and not result["changed"]
    assert result["msg"] == (
        "start_mode=delayed is not supported before Windows Vista / Server 2008."
    )
    assert native.services == before and native.calls.mock_calls == []


@pytest.mark.parametrize("check", [False, True])
def test_pause_validates_current_controls_even_in_check_mode(
    run_request: Request, native: Any, check: bool
) -> None:
    run_request({"name": "owned", "path": "owned.exe"})
    code, failure = run_request(
        {"name": "owned", "state": "paused", "_ansible_check_mode": check}
    )
    assert code == 1 and not failure["changed"]
    assert (
        failure["msg"]
        == "failed to pause service owned: The service does not support pausing"
    )
    assert native.services["owned"]["state"] == "stopped"


@pytest.mark.parametrize(
    "state,changed",
    [("started", False), ("paused", True), ("restarted", True), ("stopped", True)],
)
def test_public_state_and_real_idempotence(
    run_request: Request, state: str, changed: bool
) -> None:
    run_request({"name": "owned", "path": "owned.exe", "state": "started"})
    code, result = run_request({"name": "owned", "state": state})
    assert code == 0 and result["changed"] == changed
    assert result["state"] == (
        "running" if state in ("started", "restarted") else state
    )


@pytest.mark.parametrize(
    "args,message",
    [
        ({}, "missing required arguments: name"),
        ({"name": "owned", "password": "secret"}, "required by 'password'"),
        ({"name": "owned", "state": "invalid"}, "value of state"),
        ({"name": "owned", "state": "started"}, "need to set 'path'"),
        ({"name": "owned", "failure_reset_period": -1}, "unsigned 32-bit"),
        (
            {"name": "owned", "failure_actions": [{}]},
            "missing required arguments: type",
        ),
        (
            {
                "name": "owned",
                "failure_actions": [{"type": "none", "delay_ms": 4294967296}],
            },
            "unsigned 32-bit",
        ),
        ({"name": "owned", "unexpected": True}, "Unsupported parameters"),
    ],
)
def test_invalid_requests_fail_before_native_mutation(
    run_request: Request, native: Any, args: dict[str, Any], message: str
) -> None:
    code, failure = run_request(args)
    assert code == 1 and not failure["changed"] and message in failure["msg"]
    assert native.services == {}


def test_reset_period_requires_actions_and_original_caller_access(
    run_request: Request, native: Any
) -> None:
    run_request({"name": "owned", "path": "owned.exe"})
    code, failed = run_request({"name": "owned", "failure_reset_period_sec": 10})
    assert code == 1 and "no existing Actions" in failed["msg"]
    run_request(
        {
            "name": "owned",
            "failure_actions": [{"type": "restart", "delay_ms": 1}],
            "failure_reset_period_sec": 10,
        }
    )
    code, result = run_request(
        {
            "name": "owned",
            "description": "retained",
            "failure_reset_period_sec": 20,
            "_ansible_diff": True,
        }
    )
    assert (code, result) == (
        1,
        {
            "changed": False,
            "failed": True,
            "exception": "(traceback unavailable)",
            "msg": "Unhandled exception while executing module: "
            'Exception setting "FailureActions": '
            '"Failed to change service config (Access is denied, '
            'Win32ErrorCode 5 - 0x00000005)"',
        },
    )
    assert native.services["owned"]["description"] == "retained"
    assert native.services["owned"]["failure_reset_period_sec"] == 10
    assert native.services["owned"]["failure_actions"] == [
        {"type": "restart", "delay_ms": 1}
    ]
    code, recovered = run_request(
        {
            "name": "owned",
            "failure_reset_period_sec": 20,
            "failure_actions": [{"type": "restart", "delay_ms": 1}],
        }
    )
    assert code == 0 and recovered["changed"]
    assert native.services["owned"]["failure_reset_period_sec"] == 20


def test_empty_strings_clear_but_empty_dependencies_preserve_native_fields(
    run_request: Request, native: Any
) -> None:
    run_request(
        {
            "name": "owned",
            "path": "owned.exe",
            "description": "old",
            "dependencies": ["companion"],
            "failure_command": "old",
            "failure_reboot_msg": "old",
        }
    )
    code, result = run_request(
        {
            "name": "owned",
            "description": "",
            "dependencies": [],
            "failure_command": "",
            "failure_reboot_msg": "",
            "_ansible_diff": True,
        }
    )
    assert code == 0 and result["changed"]
    assert result["diff"]["after"]["dependencies"] == []
    assert native.services["owned"]["dependencies"] == ["companion"]
    assert all(
        native.services["owned"][key] is None
        for key in ("description", "failure_command", "failure_reboot_msg")
    )
    assert not run_request(
        {
            "name": "owned",
            "description": "",
            "failure_command": "",
            "failure_reboot_msg": "",
        }
    )[1]["changed"]


def test_choice_comparison_preserves_caller_output_casing(run_request: Request) -> None:
    run_request({"name": "owned", "path": "owned.exe", "start_mode": "manual"})
    code, result = run_request(
        {
            "name": "owned",
            "dependency_action": "SET",
            "error_control": "IGNORE",
            "start_mode": "MANUAL",
            "sid_info": "NONE",
            "state": "STOPPED",
            "update_password": "ON_CREATE",
            "service_type": "WIN32_OWN_PROCESS",
            "_ansible_diff": True,
        }
    )
    assert code == 0 and result["changed"]
    assert result["start_mode"] == "MANUAL" and result["state"] == "STOPPED"
    assert {
        key: result["diff"]["after"][key]
        for key in ("error_control", "sid_info", "start_mode", "state", "service_type")
    } == {
        "error_control": "IGNORE",
        "sid_info": "NONE",
        "start_mode": "MANUAL",
        "state": "STOPPED",
        "service_type": "win32_own_process",
    }


def test_refused_dependent_stop_returns_complete_original_failure(
    run_request: Request, native: Any
) -> None:
    run_request({"name": "owned", "path": "owned.exe", "state": "started"})
    error = OSError(
        1051,
        "A stop control has been sent to a service that other running services "
        "are dependent on.",
    )
    error.winerror = 1051  # type: ignore[attr-defined]
    native.calls.control.side_effect = error
    before = copy.deepcopy(native.services)
    assert run_request(
        {"name": "owned", "state": "stopped", "_ansible_diff": True}
    ) == (
        1,
        {
            "changed": False,
            "failed": True,
            "exception": "(traceback unavailable)",
            "msg": "Unhandled exception while executing module: "
            "Cannot stop service 'owned (owned)' "
            "because it has dependent services. It can only be stopped if the Force flag is set.",
        },
    )
    assert native.services == before


@pytest.mark.parametrize(
    "action,bound,delay",
    [
        ({"Type": "RESTART", "Delay_ms": 11}, {"type": "RESTART", "delay_ms": 11}, 11),
        (
            {"type": "restart", "Delay": 9},
            {"type": "restart", "delay": 9, "delay_ms": 0},
            0,
        ),
        (
            {"type": "restart", "delay_ms": 1, "Delay": 9},
            {"type": "restart", "delay_ms": 1, "delay": 9},
            1,
        ),
        (
            {"type": "RESTART", "delay": 12},
            {"type": "RESTART", "delay": 12, "delay_ms": 12},
            12,
        ),
        (
            {"type": "RESTART", "delay_ms": 1, "delay": 9},
            {"type": "RESTART", "delay_ms": 9, "delay": 9},
            9,
        ),
        (
            {"type": "RESTART", "delay_ms": 1, "delay": 1.5},
            {"type": "RESTART", "delay_ms": 2, "delay": 1.5},
            2,
        ),
    ],
)
def test_recursive_binding_preserves_public_choices_and_aliases(
    run_request: Request,
    native: Any,
    action: dict[str, Any],
    bound: dict[str, Any],
    delay: int,
) -> None:
    run_request({"name": "owned", "path": "owned.exe"})
    code, result = run_request(
        {
            "name": "owned",
            "failure_actions": [action],
            "_ansible_diff": True,
            "_ansible_inject_invocation": True,
        }
    )
    assert code == 0 and result["changed"]
    assert result["diff"]["after"]["failure_actions"] == [bound]
    assert result["invocation"]["module_args"]["failure_actions"] == [bound]
    assert native.services["owned"]["failure_actions"] == [
        {"type": "restart", "delay_ms": delay}
    ]


@pytest.mark.parametrize("alias_value,converted", [(9, 9), (1.5, 2)])
def test_root_aliases_override_canonical_and_retain_raw_invocation_values(
    run_request: Request,
    native: Any,
    alias_value: int | float,
    converted: int,
) -> None:
    run_request({"name": "owned", "path": "owned.exe"})
    code, result = run_request(
        {
            "name": "owned",
            "pre_shutdown_timeout_ms": 1,
            "pre_shutdown_timeout": alias_value,
            "failure_reset_period_sec": 1,
            "failure_reset_period": alias_value,
            "failure_actions": [{"type": "restart", "delay_ms": 100}],
            "_ansible_diff": True,
            "_ansible_inject_invocation": True,
        }
    )
    assert code == 0 and result["changed"]
    for canonical, alias in (
        ("pre_shutdown_timeout_ms", "pre_shutdown_timeout"),
        ("failure_reset_period_sec", "failure_reset_period"),
    ):
        assert result["diff"]["after"][canonical] == converted
        assert result["invocation"]["module_args"][canonical] == converted
        assert result["invocation"]["module_args"][alias] == alias_value
        assert native.services["owned"][canonical] == converted


@pytest.mark.parametrize(
    "values,expected",
    [
        ((1.5, 2.5, 3.5), (2, 2, 4)),
        ((1.2, 1.7, 1.1), (1, 2, 1)),
    ],
)
def test_fractional_numeric_binding_rounds_nearest_even_in_all_uint32_fields(
    run_request: Request,
    native: Any,
    values: tuple[float, float, float],
    expected: tuple[int, int, int],
) -> None:
    reset, shutdown, delay = values
    run_request({"name": "owned", "path": "owned.exe"})
    code, result = run_request(
        {
            "name": "owned",
            "pre_shutdown_timeout_ms": shutdown,
            "failure_reset_period_sec": reset,
            "failure_actions": [{"type": "restart", "delay_ms": delay}],
            "_ansible_diff": True,
            "_ansible_inject_invocation": True,
        }
    )
    assert code == 0 and result["changed"]
    fields = {
        "failure_reset_period_sec": expected[0],
        "pre_shutdown_timeout_ms": expected[1],
        "failure_actions": [{"type": "restart", "delay_ms": expected[2]}],
    }
    for key, value in fields.items():
        assert result["diff"]["after"][key] == value
        assert result["invocation"]["module_args"][key] == value
        assert native.services["owned"][key] == value


def test_action_binding_spelling_does_not_defeat_semantic_idempotence(
    run_request: Request,
    native: Any,
) -> None:
    run_request(
        {
            "name": "owned",
            "path": "owned.exe",
            "failure_actions": [{"type": "restart", "delay_ms": 100}],
        }
    )
    before = copy.deepcopy(native.services)
    native.calls.reset_mock()
    code, result = run_request(
        {
            "name": "owned",
            "failure_actions": [{"Type": "RESTART", "delay": 100}],
            "_ansible_diff": True,
            "_ansible_inject_invocation": True,
        }
    )
    bound = [{"type": "RESTART", "delay": 100, "delay_ms": 100}]
    assert code == 0 and not result["changed"]
    assert result["diff"]["after"]["failure_actions"] == bound
    assert result["invocation"]["module_args"]["failure_actions"] == bound
    assert native.services == before and not native.calls.set_extended.called


@pytest.mark.parametrize(
    "action,message",
    [
        (
            {"type": "restart", "Delay_ms": 1, "delay": 9},
            'Unhandled exception while executing module: Exception calling "Create" '
            'with "2" argument(s): "An item with the same key has already been added."',
        ),
        (
            {"type": "restart", "delay": 9, "Delay": 11},
            "failure during exec_wrapper: Cannot convert the JSON string because a "
            "dictionary that was converted from the string contains the duplicated "
            "keys 'delay' and 'Delay'.",
        ),
        (
            {"type": "restart", "delay_ms": 1, "Delay_ms": 2},
            "failure during exec_wrapper: Cannot convert the JSON string because a "
            "dictionary that was converted from the string contains the duplicated "
            "keys 'delay_ms' and 'Delay_ms'.",
        ),
        (
            "type=restart delay=9 Delay=11",
            'Unhandled exception while executing module: Exception calling "Create" '
            'with "2" argument(s): "System.Management.Automation.PSObject cannot be '
            'converted to a dict"',
        ),
        (
            '{"type":"restart","delay":9,"Delay":11}',
            'Unhandled exception while executing module: Exception calling "Create" '
            'with "2" argument(s): "System.Management.Automation.PSObject cannot be '
            'converted to a dict"',
        ),
    ],
)
def test_nested_key_collisions_fail_before_service_fields_or_invocation(
    run_request: Request, native: Any, action: dict[str, Any] | str, message: str
) -> None:
    run_request({"name": "owned", "path": "owned.exe"})
    before = copy.deepcopy(native.services)
    native.calls.reset_mock()
    code, result = run_request(
        {
            "name": "owned",
            "failure_actions": [action],
            "_ansible_diff": True,
            "_ansible_inject_invocation": True,
        }
    )
    assert code == 1
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    assert result == {
        "changed": False,
        "failed": True,
        "msg": message,
        "exception": "(traceback unavailable)",
    }
    # pylint: enable=duplicate-code
    assert native.services == before and not native.calls.mock_calls
