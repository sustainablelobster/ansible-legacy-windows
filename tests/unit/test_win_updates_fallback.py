"""Keep Update worker identity fallback strictly before any work starts."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native launch, worker ownership and cleanup are intentionally inspected.
# pylint: disable=protected-access

import ctypes
import os
import sys
from contextlib import contextmanager
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module

# Pytest registers this imported decorated fixture using its declared name.
# pylint: disable-next=unused-import
from tests.unit.test_win_updates_worker import owned_fixture


@pytest.mark.parametrize(
    "access,denied",
    [
        ({"ReturnValue": 0, "rights": 1}, True),
        ({"ReturnValue": 0, "rights": 0}, True),
        ({"ReturnValue": False, "rights": 0}, False),
        ({"ReturnValue": 5, "rights": 0}, False),
        ({"ReturnValue": 0, "rights": None}, False),
        ({"ReturnValue": 0, "rights": False}, False),
        ({"ReturnValue": 0, "rights": -1}, False),
    ],
)
@pytest.mark.parametrize("dynamic_cloaking", [False, True])
def test_preflight_denial_is_proven_before_process_creation_dispatch(
    fixture: Any,
    monkeypatch: pytest.MonkeyPatch,
    access: dict[str, Any],
    denied: bool,
    dynamic_cloaking: bool,
) -> None:
    connection = SimpleNamespace(call_method=Mock(return_value=access))

    @contextmanager
    def _connection(**arguments: Any) -> Any:
        assert arguments == ({"dynamic_cloaking": True} if dynamic_cloaking else {})
        yield connection

    dispatch = Mock()
    monkeypatch.setattr(fixture.helper.wmi, "WmiConnection", _connection)
    monkeypatch.setattr(fixture.helper.wmi, "_get_object", dispatch)
    with pytest.raises(OSError) as error:
        fixture.helper._launch("command", "root", {}, dynamic_cloaking)
    assert isinstance(error.value, fixture.helper._LaunchDenied) is denied
    connection.call_method.assert_called_once_with(
        "__SystemSecurity=@", "GetCallerAccessRights", ["ReturnValue", "rights"]
    )
    dispatch.assert_not_called()


@pytest.mark.parametrize(
    "returned,pid,denied",
    [
        (0, 123, False),
        (2, None, True),
        (3, 0, True),
        (3, 123, False),
        (8, None, False),
        (0, None, False),
        (2, False, False),
        (3, "", False),
        (2, [], False),
        (3, 0.0, False),
        (2, -1, False),
        (3, 0x100000000, False),
        (False, 123, False),
        (-1, None, False),
        (0x100000000, None, False),
        (None, None, False),
        (2, ..., False),
        (0, ..., False),
    ],
)
@pytest.mark.parametrize("dynamic_cloaking", [False, True])
# Keep each native response field and identity setting visible in the test cases.
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def test_native_wmi_result_proves_rejection_only_without_a_process_id(
    fixture: Any,
    monkeypatch: pytest.MonkeyPatch,
    returned: Any,
    pid: Any,
    denied: bool,
    dynamic_cloaking: bool,
) -> None:
    helper = fixture.helper
    connection = SimpleNamespace(
        call_method=Mock(return_value={"ReturnValue": 0, "rights": 2}),
        _services=ctypes.c_void_p(1),
        _automation=SimpleNamespace(VariantClear=Mock(return_value=0)),
        _method_inputs=Mock(return_value=ctypes.c_void_p(4)),
        _properties=Mock(
            return_value=(
                {"ReturnValue": returned}
                if pid is ...
                else {"ReturnValue": returned, "ProcessId": pid}
            )
        ),
    )

    @contextmanager
    def _connection(**arguments: Any) -> Any:
        assert arguments == ({"dynamic_cloaking": True} if dynamic_cloaking else {})
        yield connection

    def _method(_object: Any, slot: int, *_signature: Any) -> Any:
        def _invoke(*args: Any) -> int:
            if slot == 15:
                args[-1]._obj.value = 10
            if slot == 24:
                args[-2]._obj.value = 11
            return 0

        return _invoke

    monkeypatch.setattr(helper.wmi, "WmiConnection", _connection)
    monkeypatch.setattr(helper.wmi, "_method", _method)
    monkeypatch.setattr(
        helper.wmi, "_get_object", Mock(return_value=ctypes.c_void_p(2))
    )
    monkeypatch.setattr(helper.wmi, "_put_integer", Mock())
    monkeypatch.setattr(helper.wmi, "_put_string_array", Mock())
    monkeypatch.setattr(helper.wmi, "_bstr", lambda *_args: ctypes.c_void_p(20))
    monkeypatch.setattr(helper.wmi, "_release", Mock())
    valid_status = isinstance(returned, int) and not isinstance(returned, bool)
    valid_pid = isinstance(pid, int) and not isinstance(pid, bool) and pid > 0
    if valid_status and returned == 0 and valid_pid:
        assert helper._launch("command", "root", {}, dynamic_cloaking) == pid
    else:
        with pytest.raises(OSError) as error:
            helper._launch("command", "root", {}, dynamic_cloaking)
        assert isinstance(error.value, helper._LaunchDenied) is denied


def test_owner_sid_needs_only_native_query_access_not_wmi_methods(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    helper = load_module(
        ROOT / "plugins/module_utils/legacy_windows_updates_worker.py",
        "native_updates_owner",
    )
    kernel = SimpleNamespace(OpenProcess=Mock(return_value=70), CloseHandle=Mock())

    def _open(_process: Any, access: int, result: Any) -> bool:
        assert access == 8
        result._obj.value = 71
        return True

    def _information(
        _token: Any, kind: int, buffer: Any, length: int, needed: Any
    ) -> bool:
        assert kind == 1
        needed._obj.value = ctypes.sizeof(ctypes.c_void_p)
        if not buffer:
            assert length == 0
            return False
        ctypes.c_void_p.from_buffer(buffer).value = 72
        return True

    security = SimpleNamespace(
        OpenProcessToken=Mock(side_effect=_open),
        GetTokenInformation=Mock(side_effect=_information),
    )
    monkeypatch.setattr(helper, "_kernel", lambda: kernel)
    monkeypatch.setattr(
        ctypes, "WinDLL", lambda *_args, **_kwargs: security, raising=False
    )
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 122, raising=False)
    monkeypatch.setattr(helper.account, "sid_to_string", Mock(return_value="owned-sid"))
    assert helper._sid(123) == "owned-sid"
    kernel.OpenProcess.assert_called_once_with(0x400, False, 123)
    helper.account.sid_to_string.assert_called_once_with(72)
    assert [
        getattr(call.args[0], "value", call.args[0])
        for call in kernel.CloseHandle.call_args_list
    ] == [71, 70]


@pytest.mark.parametrize("major,access", [(5, 0x100400), (6, 0x101000), (10, 0x101000)])
@pytest.mark.parametrize("wait", [0, 258])
def test_process_birth_and_liveness_use_minimum_version_supported_query_rights(
    monkeypatch: pytest.MonkeyPatch, major: int, access: int, wait: int
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    helper = load_module(
        ROOT / "plugins/module_utils/legacy_windows_updates_worker.py",
        "native_updates_process",
    )

    def _times(_handle: Any, created: Any, *_other: Any) -> bool:
        created._obj.value = 987
        return True

    kernel = SimpleNamespace(
        OpenProcess=Mock(return_value=70),
        GetProcessTimes=Mock(side_effect=_times),
        WaitForSingleObject=Mock(return_value=wait),
        CloseHandle=Mock(return_value=True),
    )
    monkeypatch.setattr(helper, "_kernel", lambda: kernel)
    monkeypatch.setattr(
        helper,
        "sys",
        SimpleNamespace(getwindowsversion=lambda: SimpleNamespace(major=major)),
    )
    assert helper._process(123) == {"pid": 123, "created": 987, "alive": wait == 258}
    kernel.OpenProcess.assert_called_once_with(access, False, 123)
    kernel.WaitForSingleObject.assert_called_once_with(70, 0)
    kernel.CloseHandle.assert_called_once_with(70)


@pytest.mark.parametrize("code", [5, 87])
def test_process_open_failure_is_not_treated_as_death_except_absent_pid(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    helper = load_module(
        ROOT / "plugins/module_utils/legacy_windows_updates_worker.py",
        "native_updates_process_failure",
    )
    kernel = SimpleNamespace(OpenProcess=Mock(return_value=None), CloseHandle=Mock())
    monkeypatch.setattr(helper, "_kernel", lambda: kernel)
    monkeypatch.setattr(
        helper.sys, "getwindowsversion", lambda: SimpleNamespace(major=6), raising=False
    )
    monkeypatch.setattr(ctypes, "get_last_error", lambda: code, raising=False)
    monkeypatch.setattr(
        ctypes,
        "WinError",
        lambda error: OSError(error, "native query failed"),
        raising=False,
    )
    if code == 87:
        assert helper._process(123) is None
    else:
        with pytest.raises(OSError, match="native query failed"):
            helper._process(123)
    kernel.OpenProcess.assert_called_once_with(0x101000, False, 123)
    kernel.CloseHandle.assert_not_called()


@pytest.mark.parametrize("error", [None, "rejected", "ambiguous", "servicing"])
def test_only_conclusive_rejection_switches_worker_sid_once(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, error: str | None
) -> None:
    helper = fixture.helper
    request = {"sid": fixture.journal["sid"], "environment": {"EXACT": "λ %PATH%"}}
    failure = (
        helper._LaunchDenied("native ReturnValue 2")
        if error == "rejected"
        else OSError(error or "")
    )
    launched = Mock(side_effect=failure if error else None, return_value=123)
    fallback = Mock(return_value=456)
    publish = Mock()
    monkeypatch.setattr(helper, "_launch", launched)
    monkeypatch.setattr(helper, "_launch_system", fallback)
    if error in ("ambiguous", "servicing"):
        with pytest.raises(OSError, match=error):
            helper._launch_owned("exact-command", "owned-root", request, publish)
    else:
        assert helper._launch_owned(
            "exact-command", "owned-root", request, publish
        ) == (456 if error else 123)
    launched.assert_called_once_with(
        "exact-command", "owned-root", request["environment"]
    )
    if error == "rejected":
        assert request["worker_sid"] == "S-1-5-18"
        publish.assert_called_once()
        fallback.assert_called_once_with(
            "exact-command", "owned-root", request["environment"]
        )
    else:
        assert "worker_sid" not in request
        publish.assert_not_called()
        fallback.assert_not_called()


def test_already_system_never_retries_the_same_identity(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = fixture.helper
    monkeypatch.setattr(
        helper, "_launch", Mock(side_effect=helper._LaunchDenied("denied"))
    )
    fallback = Mock()
    monkeypatch.setattr(helper, "_launch_system", fallback)
    with pytest.raises(helper._LaunchDenied):
        helper._launch_owned(
            "command", "root", {"sid": "S-1-5-18", "environment": {}}, Mock()
        )
    fallback.assert_not_called()


def test_request_is_published_before_system_child_can_read_it(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = fixture.helper
    request = {"sid": fixture.journal["sid"], "environment": {}}
    helper._write(str(fixture.root), "request.json", request)
    monkeypatch.setattr(
        helper, "_launch", Mock(side_effect=helper._LaunchDenied("denied"))
    )

    def _system(*_args: Any) -> int:
        actual = helper._read(str(fixture.root), "request.json")
        assert actual == request and actual["worker_sid"] == "S-1-5-18"
        return 456

    monkeypatch.setattr(helper, "_launch_system", _system)
    helper._launch_owned(
        "command",
        str(fixture.root),
        request,
        lambda: helper._replace_request(str(fixture.root), "request.json", request),
    )


def test_system_worker_keeps_original_caller_polling_and_cleanup_ownership(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = fixture.helper
    request = {
        "sid": fixture.journal["sid"],
        "worker_sid": "S-1-5-18",
        "nonce": fixture.journal["nonce"],
        "environment": dict(os.environ),
        "options": {},
    }
    helper._write(str(fixture.root), "request.json", request)
    fixture.state.process = fixture.journal["worker"]
    monkeypatch.setattr(helper, "_sid", lambda _pid: "S-1-5-18")
    monkeypatch.setattr(helper.sys, "argv", ["worker.py", str(fixture.root)])
    monkeypatch.setattr(
        helper.updates,
        "run",
        lambda _options, emit, _cancelled, _log: emit(
            "exit", {"changed": False, "failed": False}
        ),
    )
    helper.main()
    state = helper._read(str(fixture.root), "state.json")
    assert state["worker_sid"] == "S-1-5-18" and state["finished"] is True
    monkeypatch.setattr(helper, "_sid", lambda _pid: fixture.journal["sid"])
    assert helper.poll(fixture.options)["output"][-1]["task"] == "exit"
    fixture.state.process = None
    assert helper.cancel(fixture.options) == {"changed": False}
    assert not fixture.root.exists()


@pytest.mark.parametrize(
    "outcome",
    [
        "success",
        "token-error",
        "impersonation-error",
        "not-impersonated",
        "rejected",
        "ambiguous",
        "impersonation-restore-error",
        "token-restore-error",
    ],
)
def test_system_wmi_launch_keeps_exact_input_and_bounds_identity_lifetime(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    helper = fixture.helper
    tokens = ModuleType("fallback_tokens")
    security = object()
    token = ctypes.c_void_p(42)
    events = []

    @contextmanager
    def _tokens(*args: Any) -> Any:
        assert args == ("NT AUTHORITY\\SYSTEM", None, "Service")
        events.append("acquire")
        if outcome == "token-error":
            raise OSError("no accessible SYSTEM token")
        try:
            yield [token]
        finally:
            events.append("close")
        if outcome == "token-restore-error":
            raise OSError("privilege restoration failed")

    @contextmanager
    def _impersonation(actual_security: Any, actual_token: Any) -> Any:
        assert actual_security is security and actual_token is token
        events.append("impersonate")
        if outcome == "impersonation-error":
            raise OSError("impersonation denied")
        try:
            yield outcome != "not-impersonated"
        finally:
            events.append("revert")
        if outcome == "impersonation-restore-error":
            raise OSError("thread identity restoration failed")

    def _launch(*args: Any, **arguments: Any) -> int:
        assert events == ["acquire", "impersonate"]
        assert args == ("exact command", "owned-root", environment)
        assert args[2] is environment
        assert arguments == {"dynamic_cloaking": True}
        if outcome == "rejected":
            raise helper._LaunchDenied("native ReturnValue 2")
        if outcome == "ambiguous":
            raise OSError("unknown dispatch outcome")
        return 123

    setattr(tokens, "_libraries", Mock(return_value=(security, None, None)))
    setattr(tokens, "logon_tokens", _tokens)
    setattr(tokens, "_impersonation", _impersonation)
    monkeypatch.setitem(sys.modules, "legacy_windows_runas_token", tokens)
    launch = Mock(side_effect=_launch)
    monkeypatch.setattr(helper, "_launch", launch)
    environment = {"USERNAME": "caller", "EXACT": "λ %PATH%"}
    if outcome == "success":
        assert helper._launch_system("exact command", "owned-root", environment) == 123
    else:
        with pytest.raises(OSError) as error:
            helper._launch_system("exact command", "owned-root", environment)
        assert isinstance(error.value, helper._LaunchDenied) is (
            outcome
            in ("token-error", "impersonation-error", "not-impersonated", "rejected")
        )
    if outcome in ("token-error", "impersonation-error", "not-impersonated"):
        launch.assert_not_called()
    else:
        launch.assert_called_once()
    assert events[-1] == ("acquire" if outcome == "token-error" else "close")
