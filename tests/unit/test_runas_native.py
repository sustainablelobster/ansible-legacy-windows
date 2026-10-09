"""Exercise native runas launch choices, binary stdin and handle ownership."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Private helpers expose the native execution/recovery boundaries under test.
# pylint: disable=protected-access

import ctypes
import io
import json
import sys
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="native")
def native_runas(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Import Windows helpers with isolated substitutes for native imports.

    :param monkeypatch: Scoped module cache and executable/environment values.
    :returns: Process and token helpers without loading a Windows DLL.
    """
    account = ModuleType("legacy_windows_account")
    monkeypatch.setitem(sys.modules, "legacy_windows_account", account)
    monkeypatch.setitem(sys.modules, "msvcrt", ModuleType("msvcrt"))
    directory = ROOT / "plugins/module_utils"
    s4u = load_module(directory / "legacy_windows_s4u.py", "tested_runas_s4u")
    monkeypatch.setitem(sys.modules, "legacy_windows_s4u", s4u)
    token = load_module(
        directory / "legacy_windows_runas_token.py", "tested_runas_token"
    )
    monkeypatch.setitem(sys.modules, "legacy_windows_runas_token", token)
    process = load_module(directory / "legacy_windows_runas.py", "tested_runas_process")
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    monkeypatch.setattr(
        sys, "getwindowsversion", lambda: SimpleNamespace(major=6), raising=False
    )
    return SimpleNamespace(process=process, token=token, s4u=s4u)


@pytest.mark.parametrize(
    "user,sid,kind,expected",
    [
        ("local-user", None, "Interactive", ("local-user", ".", 2)),
        ("DOMAIN\\user", None, "Batch", ("user", "DOMAIN", 4)),
        ("user@example.test", None, "Network", ("user@example.test", None, 3)),
        ("ignored", "S-1-5-19", "Interactive", ("LocalService", "NT AUTHORITY", 5)),
        ("ignored", "S-1-5-20", "Batch", ("NetworkService", "NT AUTHORITY", 5)),
    ],
)
def test_credentials_preserve_local_domain_upn_and_service_accounts(
    native: Any, user: str, sid: str | None, kind: str, expected: tuple[Any, ...]
) -> None:
    assert native.token._credentials(user, sid, kind) == expected


@pytest.mark.parametrize(
    "flags,expected",
    [
        ("None", 0),
        ("WithProfile", 1),
        ("NetCredentialsOnly", 2),
        ("WithProfile, None", 1),
    ],
)
def test_core_canonical_logon_flags(native: Any, flags: str, expected: int) -> None:
    assert native.process._logon_flags(flags) == expected


@pytest.mark.parametrize("flags", ["", "with_profile", "WithProfile, Unknown"])
def test_unknown_flags_do_not_silently_change_logon(native: Any, flags: str) -> None:
    with pytest.raises(ValueError, match="Invalid runas logon flag"):
        native.process._logon_flags(flags)


@pytest.mark.parametrize("previous", [None, 200])
def test_task_acl_preserves_null_dacl_but_grants_access_for_allocated_dacl(
    native: Any, monkeypatch: pytest.MonkeyPatch, previous: int | None
) -> None:
    process = native.process
    monkeypatch.setattr(process.account, "sid_bytes", lambda sid: b"sid", raising=False)

    def _query(*args: Any) -> int:
        ctypes.cast(args[5], ctypes.POINTER(ctypes.c_void_p))[0] = previous
        ctypes.cast(args[7], ctypes.POINTER(ctypes.c_void_p))[0] = 100
        return 0

    def _grant(count: int, access: Any, old: Any, revised: Any) -> int:
        assert count == 1 and old.value == 200
        entry = ctypes.cast(access, ctypes.POINTER(process._ExplicitAccess)).contents
        assert (entry.permissions, entry.mode, entry.inheritance) == (0x1200A9, 1, 3)
        ctypes.cast(revised, ctypes.POINTER(ctypes.c_void_p))[0] = 300
        return 0

    security = SimpleNamespace(
        GetNamedSecurityInfoW=Mock(side_effect=_query),
        SetEntriesInAclW=Mock(side_effect=_grant),
        SetNamedSecurityInfoW=Mock(return_value=0),
    )
    kernel = SimpleNamespace(LocalFree=Mock())
    process._grant_task_read(security, kernel, "owned-directory", "requested-sid")
    if previous is None:
        security.SetEntriesInAclW.assert_not_called()
        security.SetNamedSecurityInfoW.assert_not_called()
        assert [call.args[0].value for call in kernel.LocalFree.call_args_list] == [100]
    else:
        security.SetEntriesInAclW.assert_called_once()
        assert security.SetNamedSecurityInfoW.call_args.args[5].value == 300
        assert [call.args[0].value for call in kernel.LocalFree.call_args_list] == [
            300,
            100,
        ]


def test_worker_forwards_read_ahead_binary_input(
    native: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    command = '"python.exe" task.py'
    task_input = b"\x00\xff\n" + bytes(range(256)) * 50
    stdin = io.TextIOWrapper(
        io.BytesIO(json.dumps(command).encode() + b"\n" + task_input)
    )
    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "argv", ["wrapper.py", "--worker"])
    child = Mock(returncode=7)
    context = Mock()
    context.__enter__ = Mock(return_value=child)
    context.__exit__ = Mock(return_value=False)
    popen = Mock(return_value=context)
    monkeypatch.setattr(native.process.subprocess, "Popen", popen)
    assert native.process._main() == 7
    popen.assert_called_once_with(
        command, shell=True, stdin=native.process.subprocess.PIPE
    )
    child.communicate.assert_called_once_with(task_input)


@pytest.mark.parametrize("token_kind", [1, 2])
def test_linked_token_uses_fixed_buffer_and_keeps_only_primary_tokens(
    native: Any, monkeypatch: pytest.MonkeyPatch, token_kind: int
) -> None:
    token = native.token
    monkeypatch.setattr(
        sys, "getwindowsversion", lambda: SimpleNamespace(major=6), raising=False
    )
    statistics = ctypes.create_string_buffer(56)
    ctypes.c_int.from_buffer(statistics, 24).value = token_kind
    information = Mock(
        side_effect=[ctypes.create_string_buffer(b"\x03\x00\x00\x00"), statistics]
    )
    monkeypatch.setattr(token, "_information", information)

    def _linked_query(
        handle: Any, kind: int, buffer: Any, size: int, length: Any
    ) -> bool:
        assert handle.value == 42 and kind == 19
        assert size == ctypes.sizeof(ctypes.c_void_p)
        ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0] = 99
        ctypes.cast(length, ctypes.POINTER(ctypes.c_uint32))[0] = size
        return True

    security = SimpleNamespace(GetTokenInformation=Mock(side_effect=_linked_query))
    kernel = SimpleNamespace(CloseHandle=Mock())
    linked = token._linked_token(security, kernel, ctypes.c_void_p(42))
    assert [call.args[2] for call in information.call_args_list] == [18, 10]
    if token_kind == 1:
        assert linked.value == 99
        kernel.CloseHandle.assert_not_called()
    else:
        assert linked is None
        assert kernel.CloseHandle.call_args.args[0].value == 99


@pytest.mark.parametrize("modern", [False, True])
def test_launch_uses_short_worker_and_never_exposes_password(
    native: Any, modern: bool
) -> None:
    security = SimpleNamespace(
        CreateProcessWithLogonW=Mock(return_value=True),
        CreateProcessAsUserW=Mock(return_value=True),
    )
    if modern:
        security.CreateProcessWithTokenW = Mock(return_value=True)
    request = {
        "username": "DOMAIN\\user",
        "password": "test-secret",
        "logon_type": "Interactive",
        "logon_flags": "WithProfile",
        "command": "long command " * 1000,
    }
    process, startup = native.process._ProcessInfo(), native.process._StartupInfo()
    assert native.process._launch(
        security, ctypes.c_void_p(42), request, startup, process
    )
    operation = (
        security.CreateProcessWithTokenW if modern else security.CreateProcessWithLogonW
    )
    args = operation.call_args.args
    command = next(arg.value for arg in args if isinstance(arg, ctypes.Array))
    assert len(command) < 1024 and "--worker" in command
    assert "test-secret" not in command and "long command" not in command
    if not modern:
        assert args[:4] == ("user", "DOMAIN", "test-secret", 1)
    security.CreateProcessAsUserW.assert_not_called()


@pytest.mark.parametrize("exported", [False, True])
def test_legacy_token_launch_uses_explicit_user_environment(
    native: Any, monkeypatch: pytest.MonkeyPatch, exported: bool
) -> None:
    security = SimpleNamespace(CreateProcessAsUserW=Mock(return_value=True))
    monkeypatch.setattr(sys, "getwindowsversion", lambda: SimpleNamespace(major=5))
    if exported:
        security.CreateProcessWithTokenW = Mock(
            side_effect=AssertionError(
                "The unsupported legacy export must not be called"
            )
        )
    request = {
        "username": "NT AUTHORITY\\SYSTEM",
        "password": None,
        "logon_type": "Service",
        "logon_flags": "WithProfile",
    }
    environment = ctypes.c_void_p(123)
    assert native.process._launch(
        security,
        ctypes.c_void_p(42),
        request,
        native.process._StartupInfo(),
        native.process._ProcessInfo(),
        environment,
    )
    args = security.CreateProcessAsUserW.call_args.args
    assert args[5] is True and args[6] == 0x400 and args[7] is environment


@pytest.mark.parametrize("flags", ["None", "WithProfile"])
@pytest.mark.parametrize("child_fails", [False, True])
def test_legacy_profile_and_environment_lifetime_encloses_child_execution(
    native: Any,
    monkeypatch: pytest.MonkeyPatch,
    flags: str,
    child_fails: bool,
) -> None:
    events = []
    process = native.process

    def _load(token: Any, profile: Any) -> bool:
        assert token.value == 42
        details = ctypes.cast(profile, ctypes.POINTER(process._ProfileInfo)).contents
        assert details.size == ctypes.sizeof(process._ProfileInfo)
        assert details.flags == 1 and details.username == "SYSTEM"
        details.profile = 99
        events.append("load")
        return True

    def _environment(block: Any, token: Any, inherit: bool) -> bool:
        assert token.value == 42 and inherit is False
        ctypes.cast(block, ctypes.POINTER(ctypes.c_void_p))[0] = 123
        events.append("environment")
        return True

    def _unload(token: Any, profile: Any) -> bool:
        assert token.value == 42 and profile == 99
        events.append("unload")
        return True

    def _destroy(block: Any) -> bool:
        assert block.value == 123
        events.append("destroy")
        return True

    userenv = SimpleNamespace(
        LoadUserProfileW=Mock(side_effect=_load),
        UnloadUserProfile=Mock(side_effect=_unload),
        CreateEnvironmentBlock=Mock(side_effect=_environment),
        DestroyEnvironmentBlock=Mock(side_effect=_destroy),
    )
    monkeypatch.setattr(ctypes, "WinDLL", Mock(return_value=userenv), raising=False)
    request = {
        "username": "NT AUTHORITY\\SYSTEM",
        "password": None,
        "logon_type": "Service",
        "logon_flags": flags,
    }
    try:
        with process._legacy_environment(
            SimpleNamespace(), ctypes.c_void_p(42), request
        ) as block:
            assert block.value == 123
            events.append("child")
            if child_fails:
                raise RuntimeError("child failed")
    except RuntimeError as error:
        assert child_fails and str(error) == "child failed"
    assert events == (
        ["load", "environment", "child", "destroy", "unload"]
        if flags == "WithProfile"
        else ["environment", "child", "destroy"]
    )


def test_legacy_netcredentials_token_mode_fails_before_loading_profile(
    native: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = Mock()
    monkeypatch.setattr(ctypes, "WinDLL", library, raising=False)
    request = {
        "password": None,
        "logon_type": "NewCredentials",
        "logon_flags": "NetCredentialsOnly",
    }
    with pytest.raises(ValueError, match="cannot use NetCredentialsOnly"):
        with native.process._legacy_environment(SimpleNamespace(), None, request):
            pytest.fail("unsupported mode yielded a launch environment")
    library.assert_not_called()
