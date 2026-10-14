"""Exercise membership's public JSON contract and native operation boundaries."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Tests control the payload and Windows API boundaries, not public call sites.
# pylint: disable=protected-access

import ctypes
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, Callable
from unittest.mock import Mock, call

import pytest
from ansible_collections.sustainablelobster.legacy_ad.plugins.action.membership import (
    ActionModule,
)

from tests.unit.payload_support import ROOT, invoke_payload, load_module
from tests.unit.test_python_action import _action

_DOMAIN = "example.test"
_PASSWORD = "fixture-secret"
_DEFAULTS = {
    "state": "domain",
    "dns_domain_name": _DOMAIN,
    "domain_admin_user": "administrator@example.test",
    "domain_admin_password": _PASSWORD,
}
_CURRENT = {
    "hostname": "Existing-Host",
    "state": "workgroup",
    "dns_domain_name": None,
    "workgroup_name": "WORKGROUP",
}


@pytest.fixture(name="native")
def _native() -> Mock:
    native = Mock()
    native.current_state.return_value = _CURRENT.copy()
    return native


@pytest.fixture(name="run_request")
def _request(
    monkeypatch: pytest.MonkeyPatch,
    native: Mock,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> Callable[[dict[str, Any]], tuple[int, dict[str, Any]]]:
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    monkeypatch.setitem(sys.modules, "legacy_ad_membership", native)
    module = load_module(
        ROOT / "legacy_ad/plugins/modules/membership.py", "tested_ad_membership"
    )
    arguments = tmp_path / "arguments.json"
    monkeypatch.setattr(sys, "argv", ["membership.py", str(arguments)])

    def _run(values: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        arguments.write_text(json.dumps(values), encoding="utf-8")
        return invoke_payload(module, capsys)

    return _run


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("diff", [False, True])
def test_join_predictions_and_native_execution_keep_upstream_result_shape(
    run_request: Callable[..., Any],
    native: Mock,
    check: bool,
    diff: bool,
) -> None:
    arguments = dict(_DEFAULTS, _ansible_check_mode=check, _ansible_diff=diff)
    expected: dict[str, Any] = {"changed": True, "reboot_required": True}
    if diff:
        expected["diff"] = {
            "before": _CURRENT,
            "after": {
                "dns_domain_name": _DOMAIN,
                "hostname": _CURRENT["hostname"],
                "state": "domain",
                "workgroup_name": None,
            },
        }
    assert run_request(arguments) == (0, expected)
    assert native.mock_calls == [call.current_state()] + (
        []
        if check
        else [
            call.join_domain(
                _DOMAIN, _DEFAULTS["domain_admin_user"], _PASSWORD, None, None, None
            )
        ]
    )


@pytest.mark.parametrize("check", [False, True])
def test_combined_join_rename_sends_final_name_once_and_preserves_upstream_diff(
    run_request: Callable[..., Any],
    native: Mock,
    check: bool,
) -> None:
    code, result = run_request(
        dict(
            _DEFAULTS,
            hostname="Renamed",
            domain_ou_path="OU=Machines,DC=example,DC=test",
            domain_server="dc01.example.test",
            _ansible_check_mode=check,
            _ansible_diff=True,
        )
    )
    assert code == 0 and result["changed"] and result["reboot_required"]
    assert result["diff"]["after"]["hostname"] == "Existing-Host"
    native.rename.assert_not_called()
    if check:
        native.join_domain.assert_not_called()
    else:
        native.join_domain.assert_called_once_with(
            _DOMAIN,
            _DEFAULTS["domain_admin_user"],
            _PASSWORD,
            "OU=Machines,DC=example,DC=test",
            "dc01.example.test",
            "Renamed",
        )


@pytest.mark.parametrize("domain", [_DOMAIN, _DOMAIN.upper()])
def test_matching_domain_is_unchanged_without_credential_use_or_ou_validation(
    run_request: Callable[..., Any],
    native: Mock,
    domain: str,
) -> None:
    native.current_state.return_value.update(
        state="domain", dns_domain_name=_DOMAIN, workgroup_name=None
    )
    assert run_request(
        dict(_DEFAULTS, dns_domain_name=domain, domain_ou_path="invalid")
    ) == (
        0,
        {"changed": False, "reboot_required": False},
    )
    assert native.mock_calls == [call.current_state()]


@pytest.mark.parametrize("check", [False, True])
def test_switching_domains_is_rejected_before_any_mutation(
    run_request: Callable[..., Any],
    native: Mock,
    check: bool,
) -> None:
    native.current_state.return_value.update(
        state="domain", dns_domain_name="old.test", workgroup_name=None
    )
    code, result = run_request(dict(_DEFAULTS, _ansible_check_mode=check))
    assert code == 1 and not result["changed"] and not result["reboot_required"]
    assert (
        result["msg"]
        == "Host is already joined to 'old.test', switching domains is not implemented"
    )
    assert native.mock_calls == [call.current_state()]


@pytest.mark.parametrize("domain_member", [False, True])
@pytest.mark.parametrize("check", [False, True])
def test_workgroup_rename_passes_membership_after_leave_not_stale_domain_state(
    run_request: Callable[..., Any],
    native: Mock,
    domain_member: bool,
    check: bool,
) -> None:
    if domain_member:
        native.current_state.return_value.update(
            state="domain", dns_domain_name=_DOMAIN, workgroup_name=None
        )
    arguments = dict(
        _DEFAULTS,
        state="workgroup",
        workgroup_name="LAB",
        hostname="Renamed",
        _ansible_check_mode=check,
    )
    assert run_request(arguments) == (0, {"changed": True, "reboot_required": True})
    if check:
        assert native.mock_calls == [call.current_state()]
    else:
        assert native.mock_calls == [
            call.current_state(),
            call.join_workgroup(
                "LAB", _DEFAULTS["domain_admin_user"], _PASSWORD, domain_member
            ),
            call.rename(
                "Renamed",
                _DEFAULTS["domain_admin_user"],
                _PASSWORD,
                domain_member=False,
            ),
        ]


def test_repeating_pending_hostname_change_remains_changed_until_active_name_changes(
    run_request: Callable[..., Any],
    native: Mock,
) -> None:
    native.current_state.return_value.update(
        state="domain", dns_domain_name=_DOMAIN, workgroup_name=None
    )
    arguments = dict(_DEFAULTS, hostname="Renamed")
    for _ in range(2):
        assert run_request(arguments) == (0, {"changed": True, "reboot_required": True})
    native.current_state.return_value["hostname"] = "Renamed"
    native.reset_mock()
    assert run_request(arguments) == (0, {"changed": False, "reboot_required": False})
    assert native.mock_calls == [call.current_state()]


@pytest.mark.parametrize("check", [False, True])
def test_offline_join_stages_binary_only_outside_check_mode(
    run_request: Callable[..., Any],
    native: Mock,
    check: bool,
) -> None:
    assert run_request(
        {
            "state": "domain",
            "offline_join_blob": "YWJjAA==",
            "_ansible_check_mode": check,
        }
    ) == (
        0,
        {"changed": True, "reboot_required": True},
    )
    assert native.mock_calls == [call.current_state(), call.require_offline_join()] + (
        [] if check else [call.join_offline(b"abc\0")]
    )


def test_offline_blob_of_unknown_domain_does_not_rejoin_existing_domain(
    run_request: Callable[..., Any],
    native: Mock,
) -> None:
    native.current_state.return_value.update(
        state="domain", dns_domain_name=_DOMAIN, workgroup_name=None
    )
    assert run_request({"state": "domain", "offline_join_blob": "not-validated"}) == (
        0,
        {"changed": False, "reboot_required": False},
    )
    assert native.mock_calls == [call.current_state()]


def test_offline_blob_accepts_windows_base64_whitespace(
    run_request: Callable[..., Any],
    native: Mock,
) -> None:
    assert run_request(
        {"state": "domain", "offline_join_blob": " YW\tJj\r\nAA== "}
    ) == (
        0,
        {"changed": True, "reboot_required": True},
    )
    native.join_offline.assert_called_once_with(b"abc\0")


@pytest.mark.parametrize("blob", ["invalid", "~~~", "é", "eA==="])
def test_invalid_offline_data_fails_without_native_write_or_echoing_blob(
    run_request: Callable[..., Any],
    native: Mock,
    blob: str,
) -> None:
    code, result = run_request({"state": "domain", "offline_join_blob": blob})
    assert code == 1 and not result["changed"]
    assert blob not in json.dumps(result)
    native.join_offline.assert_not_called()


@pytest.mark.parametrize(
    "field", ["dns_domain_name", "hostname", "domain_admin_user", "domain_ou_path"]
)
def test_offline_blob_mutually_exclusive_parameters_fail_before_state_read(
    run_request: Callable[..., Any],
    native: Mock,
    field: str,
) -> None:
    code, result = run_request(
        {"state": "domain", "offline_join_blob": "YWJj", field: "value"}
    )
    assert code == 1 and "mutually exclusive" in result["msg"]
    assert native.mock_calls == []


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"state": "bad"},
        {"state": "domain"},
        {"state": "workgroup", "workgroup_name": "LAB"},
        {"state": "domain", "domain_admin_user": "user"},
        dict(_DEFAULTS, domain_admin_user="bad\0user"),
    ],
)
def test_invalid_arguments_never_enter_native_operations(
    run_request: Callable[..., Any],
    native: Mock,
    arguments: dict[str, Any],
) -> None:
    assert run_request(arguments)[0] == 1
    assert native.mock_calls == []


@pytest.mark.parametrize("partial", [False, True])
def test_failed_join_preserves_applied_rename_and_redacts_credentials(
    run_request: Callable[..., Any],
    native: Mock,
    partial: bool,
) -> None:
    error = OSError(5, "denied " + _PASSWORD)
    error.rename_applied = partial  # type: ignore[attr-defined]
    native.join_domain.side_effect = error
    code, result = run_request(
        dict(_DEFAULTS, hostname="Renamed", _ansible_inject_invocation=True)
    )
    assert (
        code == 1
        and result["changed"] is partial
        and result["reboot_required"] is partial
    )
    assert _PASSWORD not in json.dumps(result)
    assert (
        result["invocation"]["module_args"]["domain_admin_password"]
        == "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
    )


def test_invalid_ou_failure_retains_actionable_hint(
    run_request: Callable[..., Any], native: Mock
) -> None:
    native.join_domain.side_effect = OSError(2, "file missing")
    code, result = run_request(_DEFAULTS)
    assert code == 1 and result["msg"].endswith(
        "Check domain_ou_path is pointing to a valid OU in the target domain."
    )


@pytest.fixture(name="helper")
def _helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    return load_module(
        ROOT / "legacy_ad/plugins/module_utils/legacy_ad_membership.py",
        "tested_membership_native",
    )


@pytest.mark.parametrize("part_of_domain", [False, True])
def test_native_state_uses_dns_domain_not_workgroup_or_netbios_name(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    part_of_domain: bool,
) -> None:
    connection = Mock()
    connection.__enter__ = Mock(return_value=connection)
    connection.__exit__ = Mock(return_value=None)
    connection.query.return_value = [
        {"Domain": "EXAMPLE", "PartOfDomain": part_of_domain}
    ]
    monkeypatch.setattr(helper, "WmiConnection", Mock(return_value=connection))
    monkeypatch.setattr(helper, "_dns_domain", Mock(return_value=_DOMAIN))
    monkeypatch.setattr(helper.socket, "gethostname", lambda: "Active")
    result = helper.current_state()
    assert result == {
        "hostname": "Active",
        "state": "domain" if part_of_domain else "workgroup",
        "dns_domain_name": _DOMAIN if part_of_domain else None,
        "workgroup_name": None if part_of_domain else "EXAMPLE",
    }
    assert helper._dns_domain.call_count == int(part_of_domain)


def test_native_dns_domain_is_copied_before_its_buffer_is_freed(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = Mock()
    info = helper._DomainInformation(dns_name=_DOMAIN)

    def _query(_server: Any, level: int, output: Any) -> int:
        assert level == 1
        ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(info)
        return 0

    api.DsRoleGetPrimaryDomainInformation.side_effect = _query
    monkeypatch.setattr(helper, "_library", lambda: api)
    assert helper._dns_domain() == _DOMAIN
    api.DsRoleFreeMemory.assert_called_once()
    assert api.DsRoleFreeMemory.call_args.args[0].value == ctypes.addressof(info)


def test_local_rename_requests_the_pending_physical_dns_name(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = Mock()
    kernel.SetComputerNameExW.return_value = 1
    monkeypatch.setattr(ctypes, "WinDLL", Mock(return_value=kernel), raising=False)
    helper.rename("new-host", domain_member=False)
    kernel.SetComputerNameExW.assert_called_once_with(5, "new-host")


def test_missing_offline_join_api_is_actionable_before_any_native_write(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = Mock()
    api.NetRequestOfflineDomainJoin = None
    monkeypatch.setattr(helper, "_library", lambda: api)
    with pytest.raises(OSError, match="NetRequestOfflineDomainJoin"):
        helper.require_offline_join()
    assert not api.mock_calls


def test_offline_join_uses_the_online_caller_flag_and_exact_binary_size(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    received: list[tuple[bytes, int, str]] = []

    def _join(buffer: Any, size: int, flags: int, windows_path: str) -> int:
        received.append((ctypes.string_at(buffer, size), flags, windows_path))
        return 0

    monkeypatch.setattr(helper, "require_offline_join", lambda: _join)
    monkeypatch.setenv("SystemRoot", "C:\\Windows")
    helper.join_offline(b"binary\0blob")
    assert received == [(b"binary\0blob", 0x40000000, "C:\\Windows")]


@pytest.mark.parametrize(
    "major,expected_flags,order",
    [
        (5, 0x103, ["join", "rename"]),
        (6, 0x403, ["local", "join"]),
    ],
)
def test_join_rename_uses_legacy_supported_flags_and_correct_call_order(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    major: int,
    expected_flags: int,
    order: list[str],
) -> None:
    events: list[str] = []
    api = Mock()

    def _joined(*_args: Any) -> int:
        events.append("join")
        return 0

    def _renamed(*_args: Any) -> int:
        events.append("rename")
        return 0

    api.NetJoinDomain.side_effect = _joined
    api.NetRenameMachineInDomain.side_effect = _renamed
    monkeypatch.setattr(helper, "_library", lambda: api)
    monkeypatch.setattr(helper, "_rename_local", lambda *_: events.append("local"))
    monkeypatch.setattr(
        sys, "getwindowsversion", lambda: SimpleNamespace(major=major), raising=False
    )
    helper.join_domain(_DOMAIN, "user", _PASSWORD, "OU=Machines", "\\\\DC", "new-host")
    assert events == order
    api.NetJoinDomain.assert_called_once_with(
        None, _DOMAIN + "\\DC", "OU=Machines", "user", _PASSWORD, expected_flags
    )


def test_failed_legacy_rename_reports_completed_domain_join(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = Mock()
    api.NetJoinDomain.return_value = 0
    api.NetRenameMachineInDomain.return_value = 5
    monkeypatch.setattr(helper, "_library", lambda: api)
    monkeypatch.setattr(ctypes, "FormatError", lambda _: "denied", raising=False)
    monkeypatch.setattr(
        sys, "getwindowsversion", lambda: SimpleNamespace(major=5), raising=False
    )
    with pytest.raises(OSError) as caught:
        helper.join_domain(_DOMAIN, "user", _PASSWORD, hostname="new-host")
    assert caught.value.join_applied is True  # type: ignore[attr-defined]
    assert caught.value.rename_applied is False  # type: ignore[attr-defined]


def test_workgroup_failure_reports_prior_unjoin_and_disables_not_deletes_account(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = Mock()
    api.NetUnjoinDomain.return_value = 0
    api.NetJoinDomain.return_value = 5
    monkeypatch.setattr(helper, "_library", lambda: api)
    monkeypatch.setattr(ctypes, "FormatError", lambda _: "denied", raising=False)
    with pytest.raises(OSError) as caught:
        helper.join_workgroup("LAB", "user", _PASSWORD, domain_member=True)
    assert caught.value.unjoin_applied is True  # type: ignore[attr-defined]
    assert api.mock_calls == [
        call.NetUnjoinDomain(None, "user", _PASSWORD, 4),
        call.NetJoinDomain(None, "LAB", None, None, None, 0),
    ]


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("failure", [False, True])
def test_membership_action_reuses_windows_reboot_and_preserves_failure_context(
    monkeypatch: pytest.MonkeyPatch,
    check: bool,
    failure: bool,
) -> None:
    action, shell, events = _action(ActionModule, monkeypatch)
    action._task.args = {"reboot": True, "reboot_timeout": 321}
    action._task.check_mode = check
    reboot_task = SimpleNamespace()
    action._task.copy = Mock(return_value=reboot_task)
    reboot = Mock()
    reboot.run.return_value = {"failed": failure, "rebooted": not failure}
    loader = Mock()
    loader.get.return_value = reboot
    action._shared_loader_obj = SimpleNamespace(action_loader=loader)
    module_result = {
        "changed": True,
        "reboot_required": True,
        "invocation": {"module_args": {}},
    }
    monkeypatch.setattr(
        action, "_execute_module", Mock(return_value=module_result.copy())
    )
    result = action.run(task_vars={"test": "value"})
    assert (
        shell.tmpdir is None
        and len([event for event in events if event[0] == "cleanup"]) == 1
    )
    if check:
        loader.get.assert_not_called()
        assert result["reboot_required"] is False and result["changed"] is True
    else:
        assert reboot_task.action == "sustainablelobster.legacy_windows.win_reboot"
        assert reboot_task.args == {"reboot_timeout": 321}
        reboot.run.assert_called_once_with(task_vars={"test": "value"})
        if failure:
            assert result["failed"] is True and result["module_result"] == module_result
        else:
            assert result["reboot_required"] is False and result["changed"] is True
    assert result["invocation"] == module_result["invocation"]


def test_async_with_reboot_is_rejected_before_staging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, _, events = _action(ActionModule, monkeypatch, async_val=60)
    action._task.args = {"reboot": "true"}
    result = action.run()
    assert result == {
        "failed": True,
        "changed": False,
        "msg": "async is not supported for this task when reboot=true",
    }
    assert not events
