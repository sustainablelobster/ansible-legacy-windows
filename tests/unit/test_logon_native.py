"""Exercise LSA result shaping and ownership without claiming Windows execution."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native ABI records are deliberately inspected at this test boundary.
# pylint: disable=protected-access

import ctypes
import datetime
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module

SECOND = 10000000
FILETIME_EPOCH = 504911232000000000
MAX_TICKS = 3155378975999999999
ACCESS_DENIED = 0xC0000022
OBJECT_NAME_NOT_FOUND = 0xC0000034
ACCOUNT = {
    "sid": "S-1-5-21-1-2-3-1001",
    "account_name": "operator",
    "domain_name": "HOST",
    "type": "User",
}


@pytest.fixture(name="helper")
def logon_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the target helper with its sibling imports available.

    :param monkeypatch: Scoped import-path changes.
    :returns: Fresh helper imported by the developer Python runtime.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    return load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_logon.py",
        "tested_logon",
    )


@pytest.fixture(name="libraries")
def native_libraries(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> SimpleNamespace:
    """Substitute native calls while retaining the configured ctypes signatures.

    :param helper: Fresh target helper.
    :param monkeypatch: Scoped native substitutions.
    :returns: Fake LSA libraries and retained native allocations.
    """
    native = SimpleNamespace(
        security=Mock(), sessions=Mock(), allocations=[], freed=[], closed=[]
    )
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        helper.ctypes,
        "WinDLL",
        {"advapi32": native.security, "secur32": native.sessions}.__getitem__,
        raising=False,
    )
    monkeypatch.setattr(
        helper.ctypes,
        "WinError",
        OSError,
        raising=False,
    )
    monkeypatch.setattr(
        helper.account, "describe_sid", Mock(return_value=ACCOUNT.copy())
    )
    monkeypatch.setattr(helper.account, "sid_bytes", lambda sid: sid.encode("ascii"))
    native.security.LsaNtStatusToWinError.return_value = 5
    native.security.LsaFreeMemory.side_effect = lambda pointer: native.freed.append(
        pointer.value
    )
    native.sessions.LsaFreeReturnBuffer.side_effect = (
        lambda pointer: native.freed.append(pointer.value)
    )
    native.security.LsaClose.side_effect = lambda pointer: native.closed.append(
        pointer.value
    )
    native.security.LsaOpenPolicy.side_effect = (
        lambda _system, _attributes, _access, pointer: _pointer(pointer, 99)
    )
    return native


def _pointer(destination: Any, address: int) -> int:
    ctypes.cast(destination, ctypes.POINTER(ctypes.c_void_p)).contents.value = address
    return 0


def _count(destination: Any, value: int) -> None:
    assert isinstance(destination._obj, ctypes.c_uint32)
    ctypes.cast(destination, ctypes.POINTER(ctypes.c_uint32)).contents.value = value


def _session(helper: ModuleType, identifier: int = 42) -> Any:
    value = helper._SessionData()
    value.size = ctypes.sizeof(value)
    value.logon_id.low = identifier & 0xFFFFFFFF
    value.logon_id.high = identifier >> 32
    value.sid = 0x1234
    value.logon_type = 3
    value.buffers = []
    for field, text in (
        ("username", "ignored username"),
        ("login_domain", "HOST"),
        ("authentication_package", "Negotiate"),
        ("logon_server", "SERVER"),
        ("dns_domain_name", ""),
    ):
        buffer = ctypes.create_unicode_buffer(text)
        value.buffers.append(buffer)
        target = getattr(value, field)
        target.buffer = ctypes.addressof(buffer)
        # The pinned module reads through NUL, even when Length differs.
        target.length = 2
        target.maximum_length = 2
    return value


def _enumeration(
    helper: ModuleType,
    native: SimpleNamespace,
    entries: list[tuple[int, int, Any]],
) -> None:
    identifiers = (helper._Luid * len(entries))()
    for index, (identifier, _status, _record) in enumerate(entries):
        identifiers[index].low = identifier & 0xFFFFFFFF
        identifiers[index].high = identifier >> 32
    native.allocations.append(identifiers)

    def _enumerate(count: Any, pointer: Any) -> int:
        _count(count, len(entries))
        return _pointer(pointer, ctypes.addressof(identifiers))

    def _read(identifier: Any, pointer: Any) -> int:
        current = ctypes.cast(identifier, ctypes.POINTER(helper._Luid)).contents
        number = ((current.high & 0xFFFFFFFF) << 32) | current.low
        for listed, status, record in entries:
            if listed == number:
                if record is not None:
                    _pointer(pointer, ctypes.addressof(record))
                return status
        raise AssertionError("Read an unlisted session")

    native.sessions.LsaEnumerateLogonSessions.side_effect = _enumerate
    native.sessions.LsaGetLogonSessionData.side_effect = _read


def test_session_copies_public_fields_before_freeing_all_buffers(
    helper: ModuleType, libraries: SimpleNamespace
) -> None:
    other, current = _session(helper, 40), _session(helper)
    current.user_flags = 0x3C000 | 0x100
    _enumeration(
        helper, libraries, [(40, 0, other), (41, ACCESS_DENIED, None), (42, 0, current)]
    )
    warnings: list[str] = []

    result = helper.logon_session(42, warnings)

    assert result == {
        "logon_id": 42,
        "account": ACCOUNT,
        "login_domain": "HOST",
        "authentication_package": "Negotiate",
        "logon_type": "Network",
        "login_time": None,
        "logon_server": "SERVER",
        "dns_domain_name": "",
        "upn": None,
        "user_flags": [
            "Optimized",
            "Winlogon",
            "Pkinit",
            # Preserve the pinned upstream enum's misspelling in its public output.
            "Not optmized",  # codespell:ignore optmized
        ],
    }
    assert not warnings
    helper.account.describe_sid.assert_called_once_with(0x1234)
    assert libraries.freed == [
        ctypes.addressof(other),
        ctypes.addressof(current),
        ctypes.addressof(libraries.allocations[0]),
    ]


@pytest.mark.parametrize(
    ("logon_type", "name"), [(99, "99"), (0x80000000, "-2147483648")]
)
def test_session_matches_returned_luid_and_signed_undefined_logon_type(
    helper: ModuleType, libraries: SimpleNamespace, logon_type: int, name: str
) -> None:
    identifier = 0xFEDCBA9876543210
    current = _session(helper, identifier)
    current.logon_type = logon_type
    _enumeration(helper, libraries, [(42, 0, current)])

    result = helper.logon_session(identifier, [])

    assert result["logon_id"] == identifier
    assert result["logon_type"] == name


def test_legacy_session_size_excludes_user_flags_without_reading_beyond_buffer(
    helper: ModuleType, libraries: SimpleNamespace
) -> None:
    current = _session(helper)
    current.size = helper._SessionData.user_flags.offset
    current.user_flags = 0x3C000
    truncated = ctypes.create_string_buffer(
        bytes(current)[: current.size], current.size
    )
    _enumeration(helper, libraries, [(42, 0, truncated)])
    warnings: list[str] = []

    result = helper.logon_session(42, warnings)

    assert result["account"] == ACCOUNT
    assert result["user_flags"] is None
    assert len(warnings) == 1 and "user_flags" in warnings[0]
    assert "UserFlags" in warnings[0]
    assert libraries.freed[0] == ctypes.addressof(truncated)


@pytest.mark.parametrize("missing", ["id", "base", "pointer"])
def test_incomplete_native_session_fails_and_releases_allocations(
    helper: ModuleType, libraries: SimpleNamespace, missing: str
) -> None:
    current = _session(helper)
    if missing == "id":
        current.size = 4
    elif missing == "base":
        current.size = helper._SessionData.upn.offset
    _enumeration(
        helper, libraries, [(42, 0, None if missing == "pointer" else current)]
    )

    with pytest.raises(ValueError, match="missing|no session data"):
        helper.logon_session(42, [])

    expected = [] if missing == "pointer" else [ctypes.addressof(current)]
    assert libraries.freed == expected + [ctypes.addressof(libraries.allocations[0])]


@pytest.mark.parametrize("entries", [[], [(42, ACCESS_DENIED, None)]])
def test_missing_or_unreadable_current_session_is_not_invented(
    helper: ModuleType, libraries: SimpleNamespace, entries: Any
) -> None:
    _enumeration(helper, libraries, entries)

    with pytest.raises(
        ValueError, match="Could not find the data for logon session 42"
    ):
        helper.logon_session(42, [])

    assert libraries.freed == [ctypes.addressof(libraries.allocations[0])]


def test_unrelated_session_failure_is_preserved_and_later_call_recovers(
    helper: ModuleType, libraries: SimpleNamespace
) -> None:
    other, current = _session(helper, 40), _session(helper)
    _enumeration(helper, libraries, [(40, 0xC000000D, other), (42, 0, current)])

    with pytest.raises(OSError, match="LsaGetLogonSessionData") as failed:
        helper.logon_session(42, [])

    assert failed.value.errno == 5
    assert ctypes.addressof(other) in libraries.freed
    assert ctypes.addressof(current) not in libraries.freed
    _enumeration(helper, libraries, [(42, 0, current)])
    assert helper.logon_session(42, [])["account"] == ACCOUNT
    assert ctypes.addressof(current) in libraries.freed


def test_enumeration_failure_closes_its_returned_allocation(
    helper: ModuleType, libraries: SimpleNamespace
) -> None:
    def _failed(count: Any, pointer: Any) -> int:
        _count(count, 0)
        _pointer(pointer, 123)
        return ACCESS_DENIED

    libraries.sessions.LsaEnumerateLogonSessions.side_effect = _failed

    with pytest.raises(OSError, match="LsaEnumerateLogonSessions"):
        helper.logon_session(42, [])

    assert libraries.freed == [123]
    libraries.sessions.LsaGetLogonSessionData.assert_not_called()


def test_sid_conversion_failure_frees_both_session_and_enumeration(
    helper: ModuleType, libraries: SimpleNamespace
) -> None:
    current = _session(helper)
    _enumeration(helper, libraries, [(42, 0, current)])
    helper.account.describe_sid.side_effect = OSError(1337, "invalid SID")

    with pytest.raises(OSError, match="invalid SID"):
        helper.logon_session(42, [])

    assert libraries.freed == [
        ctypes.addressof(current),
        ctypes.addressof(libraries.allocations[0]),
    ]


@pytest.mark.parametrize(
    ("offset", "suffix"), [(345, "+05:45"), (-210, "-03:30"), (0, "+00:00")]
)
def test_login_time_keeps_seven_digits_and_local_offset(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, offset: int, suffix: str
) -> None:
    date = datetime.date(2026, 9, 29)
    local_ticks = (date.toordinal() - 1) * 86400 * SECOND + 45296 * SECOND + 1234567
    filetime = local_ticks - FILETIME_EPOCH - offset * 60 * SECOND
    monkeypatch.setattr(
        helper.native_time,
        "local_ticks_to_file_time",
        lambda _ticks: MAX_TICKS - FILETIME_EPOCH,
    )
    convert = Mock(return_value=local_ticks)
    monkeypatch.setattr(helper.native_time, "file_time_to_local_ticks", convert)

    assert helper._login_time(filetime) == "2026-09-29T12:34:56.1234567" + suffix
    convert.assert_called_once_with(filetime)


def test_login_time_zero_and_local_maximum_preserve_upstream_bounds(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    # DateTime.MaxValue.ToFileTime is smaller than UTC maximum east of UTC.
    maximum = MAX_TICKS - FILETIME_EPOCH - 60 * 60 * SECOND
    limit = Mock(return_value=maximum)
    convert = Mock(return_value=MAX_TICKS)
    monkeypatch.setattr(helper.native_time, "local_ticks_to_file_time", limit)
    monkeypatch.setattr(helper.native_time, "file_time_to_local_ticks", convert)

    assert helper._login_time(0) is None
    limit.assert_not_called()
    assert helper._login_time(maximum + 1) is None
    convert.assert_not_called()
    assert helper._login_time(maximum) == "9999-12-31T23:59:59.9999999+01:00"
    limit.assert_called_with(MAX_TICKS)


def _rights(
    native: SimpleNamespace, helper: ModuleType, entries: dict[str, Any]
) -> None:
    def _read(policy: Any, sid: Any, pointer: Any, count: Any) -> int:
        assert policy.value == 99
        values = entries[ctypes.string_at(sid).decode("ascii")]
        if isinstance(values, int):
            return values
        strings = [ctypes.create_unicode_buffer(value) for value in values]
        records = (helper._UnicodeString * len(strings))()
        for record, string in zip(records, strings):
            record.buffer = ctypes.addressof(string)
        native.allocations.extend(strings + [records])
        _count(count, len(strings))
        return _pointer(pointer, ctypes.addressof(records))

    native.security.LsaEnumerateAccountRights.side_effect = _read


def test_rights_keep_first_occurrence_case_and_native_order(
    helper: ModuleType, libraries: SimpleNamespace
) -> None:
    _rights(
        libraries,
        helper,
        {
            "S-1-5-32-544": [
                "SeBackupPrivilege",
                "SeNetworkLogonRight",
                "SelogonRight",
                "SeDenyBatchLogonRight",
            ],
            "S-1-5-11": OBJECT_NAME_NOT_FOUND,
            "S-1-5-5-1-2": [
                "SeNetworkLogonRight",
                "SeInteractiveLogonRight",
                "SeNETWORKLogonRight",
            ],
        },
    )

    result = helper.logon_rights(["S-1-5-32-544", "S-1-5-11", "S-1-5-5-1-2"])

    assert result == [
        "SeNetworkLogonRight",
        "SeDenyBatchLogonRight",
        "SeInteractiveLogonRight",
        "SeNETWORKLogonRight",
    ]
    assert len(libraries.freed) == 2
    assert libraries.closed == [99]
    system, attributes, access, _pointer_out = (
        libraries.security.LsaOpenPolicy.call_args.args
    )
    assert system is None
    assert access == 0x800
    value = ctypes.cast(attributes, ctypes.POINTER(helper._ObjectAttributes)).contents
    assert value.length == ctypes.sizeof(value)
    assert not value.root_directory and not value.security_descriptor


def test_rights_access_denial_is_not_silently_empty_and_policy_closes(
    helper: ModuleType, libraries: SimpleNamespace
) -> None:
    _rights(libraries, helper, {"S-1-5-11": ACCESS_DENIED})

    with pytest.raises(OSError, match="LsaEnumerateAccountRights"):
        helper.logon_rights(["S-1-5-11"])

    assert libraries.closed == [99]
    assert not libraries.freed
    _rights(libraries, helper, {"S-1-5-11": ["SeNetworkLogonRight"]})
    assert helper.logon_rights(["S-1-5-11"]) == ["SeNetworkLogonRight"]
    assert libraries.closed == [99, 99]


def test_failed_rights_call_frees_returned_allocation_and_closes_policy(
    helper: ModuleType, libraries: SimpleNamespace
) -> None:
    def _failed(_policy: Any, _sid: Any, pointer: Any, _count_out: Any) -> int:
        _pointer(pointer, 123)
        return ACCESS_DENIED

    libraries.security.LsaEnumerateAccountRights.side_effect = _failed

    with pytest.raises(OSError, match="LsaEnumerateAccountRights"):
        helper.logon_rights(["S-1-5-11"])

    assert libraries.freed == [123]
    assert libraries.closed == [99]


def test_failed_policy_open_closes_returned_handle_and_does_not_query_rights(
    helper: ModuleType, libraries: SimpleNamespace
) -> None:
    def _failed(_system: Any, _attributes: Any, _access: Any, pointer: Any) -> int:
        _pointer(pointer, 99)
        return ACCESS_DENIED

    libraries.security.LsaOpenPolicy.side_effect = _failed

    with pytest.raises(OSError, match="LsaOpenPolicy"):
        helper.logon_rights(["S-1-5-11"])

    libraries.security.LsaEnumerateAccountRights.assert_not_called()
    assert libraries.closed == [99]


def test_sid_parse_failure_closes_policy(
    helper: ModuleType, libraries: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        helper.account, "sid_bytes", Mock(side_effect=OSError(1337, "invalid SID"))
    )

    with pytest.raises(OSError, match="invalid SID"):
        helper.logon_rights(["invalid"])

    assert libraries.closed == [99]
    libraries.security.LsaEnumerateAccountRights.assert_not_called()


def test_native_layout_and_count_widths_match_windows_abi(
    helper: ModuleType, libraries: SimpleNamespace
) -> None:
    helper._security()
    helper._sessions()
    assert libraries.sessions.LsaEnumerateLogonSessions.argtypes[0] == ctypes.POINTER(
        ctypes.c_uint32
    )
    assert libraries.security.LsaEnumerateAccountRights.argtypes[-1] == ctypes.POINTER(
        ctypes.c_uint32
    )
    assert helper._SessionData.logon_id.offset == 4
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        assert helper._SessionData.login_time.offset == 80
        assert helper._SessionData.user_flags.offset == 136
        assert ctypes.sizeof(helper._UnicodeString) == 16
    else:
        assert helper._SessionData.login_time.offset == 48
        assert helper._SessionData.user_flags.offset == 80
        assert ctypes.sizeof(helper._UnicodeString) == 8


def test_non_windows_queries_fail_explicitly(helper: ModuleType) -> None:
    with pytest.raises(ValueError, match="require a Windows target"):
        helper.logon_session(42, [])
    with pytest.raises(ValueError, match="require a Windows target"):
        helper.logon_rights([])
