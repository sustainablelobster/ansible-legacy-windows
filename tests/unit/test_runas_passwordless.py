"""Exercise passwordless token selection, S4U buffers and native ownership."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Private helpers expose the native logon and token lifetime boundaries.
# pylint: disable=protected-access

import ctypes
import sys
from contextlib import ExitStack, contextmanager, nullcontext
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module, native_error


@pytest.fixture(name="native")
def native_helpers(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Import the target helpers without opening workstation Windows DLLs.

    :param monkeypatch: Scoped import and native-error replacements.
    :returns: Account, token and LSA helpers under test.
    """
    account = ModuleType("legacy_windows_account")
    monkeypatch.setitem(sys.modules, "legacy_windows_account", account)
    directory = ROOT / "legacy_windows/plugins/module_utils"
    s4u = load_module(directory / "legacy_windows_s4u.py", "tested_passwordless_s4u")
    monkeypatch.setitem(sys.modules, "legacy_windows_s4u", s4u)
    token = load_module(
        directory / "legacy_windows_runas_token.py", "tested_passwordless_token"
    )

    def _error(code: int, description: str | None = None) -> OSError:
        result = native_error(code)
        if description:
            result.strerror = description
        return result

    monkeypatch.setattr(ctypes, "WinError", _error, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5, raising=False)
    return SimpleNamespace(account=account, token=token, s4u=s4u)


@pytest.mark.parametrize("password", [None, "", "password"])
@pytest.mark.parametrize("existing", [False, True])
def test_absent_password_reuses_or_s4u_but_empty_password_uses_logon(
    native: Any, monkeypatch: pytest.MonkeyPatch, password: str | None, existing: bool
) -> None:
    def _logon(*args: Any) -> bool:
        assert args[2] == password
        args[-1]._obj.value = 99
        return True

    security, kernel, processes = (
        SimpleNamespace(LogonUserW=Mock(side_effect=_logon)),
        SimpleNamespace(CloseHandle=Mock()),
        object(),
    )
    reused = Mock(return_value=ctypes.c_void_p(99) if existing else None)
    s4u = Mock(return_value=ctypes.c_void_p(99))
    monkeypatch.setattr(native.token, "_user_token", reused)
    monkeypatch.setattr(native.s4u, "logon_token", s4u)
    monkeypatch.setattr(
        native.token, "_linked_token", lambda *_args: ctypes.c_void_p(100)
    )
    request = {
        "username": "fixture",
        "sid": "S-1-5-21-1-2-3-1000",
        "password": password,
        "logon_type": "Interactive",
    }
    with ExitStack() as lifetime:
        result = native.token._requested_tokens(
            security, kernel, processes, lifetime, request, ctypes.c_void_p(1)
        )
        assert [handle.value for handle in result] == [100, 99]
        kernel.CloseHandle.assert_not_called()
    assert [call.args[0].value for call in kernel.CloseHandle.call_args_list] == [
        100,
        99,
    ]
    if password is None:
        reused.assert_called_once_with(security, kernel, processes, request["sid"])
        security.LogonUserW.assert_not_called()
        if existing:
            s4u.assert_not_called()
        else:
            s4u.assert_called_once_with(request["sid"], "Interactive")
    else:
        reused.assert_not_called()
        s4u.assert_not_called()
        security.LogonUserW.assert_called_once()


def test_passwordless_never_uses_caller_when_system_impersonation_unavailable(
    native: Any,
) -> None:
    request = {
        "username": "fixture",
        "sid": "S-1-5-21-1-2-3-1000",
        "password": None,
        "logon_type": "Interactive",
    }
    security = SimpleNamespace(LogonUserW=Mock())
    with ExitStack() as lifetime, pytest.raises(
        ValueError, match="requires an accessible SYSTEM token"
    ):
        native.token._requested_tokens(
            security, object(), object(), lifetime, request, None
        )
    security.LogonUserW.assert_not_called()


def test_newcredentials_does_not_use_passwordless_account_reuse(
    native: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _logon(*args: Any) -> bool:
        assert args[:5] == ("fixture", ".", None, 9, 0)
        args[-1]._obj.value = 42
        return True

    security = SimpleNamespace(LogonUserW=Mock(side_effect=_logon))
    kernel = SimpleNamespace(CloseHandle=Mock())
    monkeypatch.setattr(native.token, "_linked_token", lambda *_args: None)
    reused = Mock()
    monkeypatch.setattr(native.token, "_user_token", reused)
    request = {
        "username": "fixture",
        "sid": None,
        "password": None,
        "logon_type": "NewCredentials",
    }
    with ExitStack() as lifetime:
        assert (
            native.token._requested_tokens(
                security, kernel, None, lifetime, request, None
            )[0].value
            == 42
        )
    reused.assert_not_called()


@pytest.mark.parametrize("username,domain", [("fixture", "HOST"), ("λ😀", "LAB😀")])
def test_s4u_authentication_strings_are_contiguous_counted_utf16(
    native: Any, username: str, domain: str
) -> None:
    helper = native.s4u
    buffer = helper._authentication_buffer(username, domain)
    value = helper._S4ULogon.from_buffer(buffer)
    assert (value.message_type, value.flags) == (12, 0)
    assert value.username.buffer == ctypes.addressof(buffer) + ctypes.sizeof(value)
    assert value.domain.buffer == value.username.buffer + value.username.length
    assert (
        ctypes.string_at(value.username.buffer, value.username.length).decode(
            "utf-16-le"
        )
        == username
    )
    assert (
        ctypes.string_at(value.domain.buffer, value.domain.length).decode("utf-16-le")
        == domain
    )
    assert value.username.maximum_length == value.username.length
    assert value.domain.maximum_length == value.domain.length
    assert ctypes.sizeof(buffer) == ctypes.sizeof(value) + len(
        (username + domain).encode("utf-16-le")
    )


@pytest.mark.parametrize("domain_account", [False, True])
@pytest.mark.parametrize(
    "logon_type,kind", [("Interactive", 4), ("Batch", 4), ("Network", 3)]
)
@pytest.mark.parametrize("failure", [None, "register", "lookup", "logon"])
# The independent account, logon-type and failure dimensions expose native paths.
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def test_s4u_package_kind_error_and_handle_recovery(
    native: Any,
    monkeypatch: pytest.MonkeyPatch,
    domain_account: bool,
    logon_type: str,
    kind: int,
    failure: str | None,
) -> None:
    helper = native.s4u
    monkeypatch.setenv("COMPUTERNAME", "HOST")
    monkeypatch.setattr(
        native.account,
        "sid_to_name",
        lambda _sid: ("DOMAIN" if domain_account else "HOST") + "\\fixture",
        raising=False,
    )

    def _register(origin: Any, handle: Any, _mode: Any) -> int:
        assert (
            ctypes.string_at(origin._obj.buffer, origin._obj.length)
            == b"legacy_windows"
        )
        if failure == "register":
            return 0xC0000022
        handle._obj.value = 10
        return 0

    def _lookup(handle: Any, package: Any, package_id: Any) -> int:
        assert handle.value == 10
        assert ctypes.string_at(package._obj.buffer, package._obj.length) == (
            b"Kerberos" if domain_account else b"MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"
        )
        package_id._obj.value = 7
        return 0xC000006D if failure == "lookup" else 0

    def _logon(*args: Any) -> int:
        assert args[2] == kind and args[3].value == 7 and args[6] is None
        source = args[7]._obj
        assert source.name == b"legacy" and source.identifier.low == 1
        authentication = helper._S4ULogon.from_buffer(args[4])
        assert authentication.message_type == 12 and args[5] == ctypes.sizeof(args[4])
        args[8]._obj.value, args[11]._obj.value = 20, 30
        if failure == "logon":
            args[13]._obj.value = 0xC0000072
            return 0xC000006E
        return 0

    def _allocate(identifier: Any) -> bool:
        identifier._obj.low = 1
        return True

    library = SimpleNamespace(
        LsaRegisterLogonProcess=Mock(side_effect=_register),
        LsaLookupAuthenticationPackage=Mock(side_effect=_lookup),
        LsaLogonUser=Mock(side_effect=_logon),
        LsaFreeReturnBuffer=Mock(),
        LsaDeregisterLogonProcess=Mock(),
    )
    security = SimpleNamespace(
        AllocateLocallyUniqueId=Mock(side_effect=_allocate),
        LsaNtStatusToWinError=Mock(return_value=1385),
    )
    kernel = SimpleNamespace(CloseHandle=Mock())
    monkeypatch.setattr(helper, "_libraries", lambda: (library, security, kernel))
    if failure:
        with pytest.raises(OSError, match="failed") as error:
            helper.logon_token("requested-sid", logon_type)
        if failure == "logon":
            assert "substatus 0xc0000072" in str(error.value)
    else:
        assert helper.logon_token("requested-sid", logon_type).value == 30
    assert library.LsaDeregisterLogonProcess.call_count == (failure != "register")
    assert library.LsaFreeReturnBuffer.call_count == (failure in (None, "logon"))
    assert kernel.CloseHandle.call_count == (failure == "logon")


@pytest.mark.parametrize(
    "status,returned_size,expected",
    [(5, None, None), (0, 4, None), (0, None, 3), (0, None, 4)],
)
def test_session_query_does_not_assume_unreadable_tokens_are_eligible(
    native: Any,
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    returned_size: int | None,
    expected: int | None,
) -> None:
    helper = native.s4u
    data = helper._SessionData(
        size=returned_size or ctypes.sizeof(helper._SessionData),
        logon_type=expected or 4,
    )

    def _query(identifier: Any, pointer: Any) -> int:
        assert identifier._obj.low == 42
        pointer._obj.value = ctypes.addressof(data)
        return status

    library = SimpleNamespace(
        LsaGetLogonSessionData=Mock(side_effect=_query), LsaFreeReturnBuffer=Mock()
    )
    monkeypatch.setattr(helper, "_libraries", lambda: (library, None, None))
    assert helper.session_logon_type(bytes(helper._Luid(42, 0))) == expected
    library.LsaFreeReturnBuffer.assert_called_once()


@pytest.mark.parametrize("system", [False, True])
def test_token_selection_closes_sources_and_keeps_matching_primary_token(
    native: Any, monkeypatch: pytest.MonkeyPatch, system: bool
) -> None:
    helper = native.token
    candidates = iter([None, 5, 3, 8])
    monkeypatch.setattr(helper, "_process_ids", lambda _processes: [1, 2, 3, 4])
    monkeypatch.setattr(
        helper, "_candidate_privileges", lambda *_args: next(candidates)
    )
    closed: list[int] = []

    def _open(process: int, access: int, token: Any) -> bool:
        assert access == 0xF
        token._obj.value = process + 10
        return True

    # Mirror DuplicateTokenEx's fixed native signature in the ownership probe.
    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def _duplicate(
        token: Any, access: int, attributes: Any, level: int, kind: int, result: Any
    ) -> bool:
        assert (access, attributes, level, kind) == (0x02000000, None, 2, 1)
        result._obj.value = token.value + 10
        return True

    security = SimpleNamespace(
        OpenProcessToken=Mock(side_effect=_open),
        DuplicateTokenEx=Mock(side_effect=_duplicate),
    )

    def _close(handle: Any) -> None:
        value = handle if isinstance(handle, int) else handle.value
        assert value is not None
        closed.append(value)

    kernel = SimpleNamespace(
        OpenProcess=Mock(side_effect=lambda _access, _inherit, pid: pid),
        CloseHandle=Mock(side_effect=_close),
    )
    result = helper._user_token(
        security, kernel, object(), "requested-sid", system=system
    )
    assert result.value == (24 if system else 22)
    assert closed == ([11, 1, 12, 2, 13, 3, 22, 14, 4] if system else [11, 1, 12, 2])
    assert result.value not in closed


@pytest.mark.parametrize("logon_type", [None, 3, 2, 4])
@pytest.mark.parametrize(
    "system,has_tcb", [(False, False), (True, False), (True, True)]
)
def test_candidate_requires_correct_sid_eligible_logon_and_system_tcb(
    native: Any,
    monkeypatch: pytest.MonkeyPatch,
    logon_type: int | None,
    system: bool,
    has_tcb: bool,
) -> None:
    helper = native.token
    user = ctypes.create_string_buffer(ctypes.sizeof(ctypes.c_void_p))
    ctypes.c_void_p.from_buffer(user).value = 99
    statistics = ctypes.create_string_buffer(56)
    privileges = ctypes.create_string_buffer(4)
    ctypes.c_uint32.from_buffer(privileges).value = 7
    monkeypatch.setattr(
        helper, "_information", Mock(side_effect=[user, statistics, privileges])
    )
    monkeypatch.setattr(
        native.account,
        "sid_to_string",
        lambda pointer: "requested-sid" if pointer == 99 else "other",
        raising=False,
    )
    monkeypatch.setattr(native.s4u, "session_logon_type", lambda identifier: logon_type)
    monkeypatch.setattr(helper, "_has_privilege", lambda *_args: has_tcb)
    assert helper._candidate_privileges(
        object(), object(), "requested-sid", system
    ) == (7 if logon_type not in (None, 3) and (not system or has_tcb) else None)


@pytest.mark.parametrize(
    "major,sid,password,existing,expected",
    [
        (5, "S-1-5-18", None, False, True),
        (5, "S-1-5-19", None, False, True),
        (5, "named-sid", None, False, True),
        (5, "named-sid", "secret", False, False),
        (5, "S-1-5-18", None, True, False),
        (6, "S-1-5-18", None, False, True),
    ],
)
# Each independent requested identity and capability determines the fallback.
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def test_temporary_system_fallback_only_for_required_missing_tokens(
    native: Any,
    monkeypatch: pytest.MonkeyPatch,
    major: int,
    sid: str,
    password: str | None,
    existing: bool,
    expected: bool,
) -> None:
    def _open(_process: Any, _access: Any, output: Any) -> bool:
        output._obj.value = 1
        return True

    security = SimpleNamespace(OpenProcessToken=Mock(side_effect=_open))
    kernel = SimpleNamespace(GetCurrentProcess=lambda: 7, CloseHandle=Mock())
    monkeypatch.setattr(native.token, "_libraries", lambda: (security, kernel, None))
    monkeypatch.setattr(
        native.account, "account_name_to_sid", lambda _name: sid, raising=False
    )
    monkeypatch.setattr(native.token, "_privilege", lambda *_args: nullcontext())
    monkeypatch.setattr(
        native.token,
        "_system_token",
        lambda *_args: ctypes.c_void_p(2) if existing else None,
    )
    monkeypatch.setattr(
        native.token,
        "_impersonation",
        lambda _security, system: nullcontext(bool(system)),
    )
    requested = Mock(return_value=[ctypes.c_void_p(3)])
    monkeypatch.setattr(native.token, "_requested_tokens", requested)
    monkeypatch.setattr(
        sys, "getwindowsversion", lambda: SimpleNamespace(major=major), raising=False
    )
    fallback = SimpleNamespace(acquire_token=Mock(return_value=ctypes.c_void_p(2)))
    monkeypatch.setitem(sys.modules, "legacy_windows_system_token", fallback)
    with native.token.logon_tokens("requested", password, "Interactive") as tokens:
        assert tokens[0].value == 3
    assert fallback.acquire_token.call_count == expected
    closed = [call.args[0].value for call in kernel.CloseHandle.call_args_list]
    assert closed == ([2, 1] if existing or expected else [1])


@pytest.mark.parametrize(
    "major,password,system,impersonated",
    [
        (5, None, True, True),
        (5, "secret", True, False),
        (5, "secret", False, False),
        (6, None, True, False),
    ],
)
# These dimensions distinguish native launch APIs and requested identities.
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def test_legacy_token_launch_scopes_existing_system_privileges(
    native: Any,
    monkeypatch: pytest.MonkeyPatch,
    major: int,
    password: str | None,
    system: bool,
    impersonated: bool,
) -> None:
    state: list[str] = []
    privileges: list[tuple[int, str]] = []

    @contextmanager
    def _impersonation(_security: Any, token: Any) -> Any:
        assert token.value == 2
        state.append("SYSTEM")
        try:
            yield True
        finally:
            state.pop()

    def _privilege(_security: Any, token: Any, name: str) -> Any:
        privileges.append((token.value, name))
        return nullcontext()

    monkeypatch.setattr(native.token, "_impersonation", _impersonation)
    monkeypatch.setattr(native.token, "_privilege", _privilege)
    monkeypatch.setattr(
        sys, "getwindowsversion", lambda: SimpleNamespace(major=major), raising=False
    )
    with pytest.raises(ValueError, match="task failure"):
        with native.token._launch_privileges(
            None,
            ctypes.c_void_p(1),
            ctypes.c_void_p(2) if system else None,
            {"password": password, "logon_type": "Interactive"},
        ):
            assert state == (["SYSTEM"] if impersonated else [])
            raise ValueError("task failure")
    assert not state
    assert privileges == (
        [
            (2 if impersonated else 1, name)
            for name in (
                "SeAssignPrimaryTokenPrivilege",
                "SeIncreaseQuotaPrivilege",
                "SeBackupPrivilege",
                "SeRestorePrivilege",
            )
        ]
        if major < 6
        else []
    )
