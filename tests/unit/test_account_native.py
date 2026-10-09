"""Exercise account API buffers and ownership without contacting Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes expose output pointers and allocations for cleanup assertions.
# pylint: disable=protected-access

import ctypes
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module, native_error


@pytest.fixture(name="helper")
def account_helper() -> ModuleType:
    """Import the account helper without loading native Windows libraries.

    :returns: Isolated target helper module.
    """
    return load_module(
        ROOT / "plugins/module_utils/legacy_windows_account.py", "tested_account_native"
    )


@pytest.mark.parametrize(
    "kind,expected",
    [
        (1, "User"),
        (2, "Group"),
        (3, "Domain"),
        (4, "Alias"),
        (5, "WellKnownGroup"),
        (6, "DeletedAccount"),
        (7, "Invalid"),
        (8, "Unknown"),
        (9, "Computer"),
        (10, "Label"),
        (11, "Logon"),
        (12, "12"),
        (-1, "-1"),
    ],
)
def test_identity_description_retains_all_sid_types_and_separate_names(
    helper: ModuleType, native: Mock, kind: int, expected: str
) -> None:
    borrowed = ctypes.addressof(native.sid_buffer)

    # The callback mirrors all seven native LookupAccountSidW arguments.
    def _lookup(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        system: Any,
        pointer: Any,
        name: Any,
        name_size: Any,
        domain: Any,
        domain_size: Any,
        sid_type: Any,
    ) -> int:
        assert system is None and pointer == borrowed
        if name is None:
            name_size._obj.value = 3
            domain_size._obj.value = 2
            native.error = 122
            return 0
        name.value, domain.value = "雪人", "域"
        sid_type._obj.value = kind
        return 1

    native.advapi.LookupAccountSidW.side_effect = _lookup
    assert helper.describe_sid(borrowed) == {
        "sid": native.canonical,
        "account_name": "雪人",
        "domain_name": "域",
        "type": expected,
    }
    assert native.released == [ctypes.addressof(native.text_buffers[0])]
    assert native.advapi.LookupAccountSidW.call_count == 2


@pytest.mark.parametrize("code", [1332, 1789])
@pytest.mark.parametrize("logon", [False, True])
def test_identity_description_preserves_unmapped_and_logon_sid_fallbacks(
    helper: ModuleType, native: Mock, code: int, logon: bool
) -> None:
    native.canonical = "S-1-5-5-123-456" if logon else "S-1-5-999999999"
    native.error = code
    native.advapi.LookupAccountSidW.return_value = 0
    assert helper.describe_sid(ctypes.addressof(native.sid_buffer)) == {
        "sid": native.canonical,
        "account_name": "LogonSessionId_123-456" if logon else None,
        "domain_name": "NT AUTHORITY" if logon else None,
        "type": "Logon" if logon else "Unknown",
    }
    assert native.released == [ctypes.addressof(native.text_buffers[0])]


@pytest.mark.parametrize("code", [5, 8, 87])
def test_identity_lookup_failure_releases_only_owned_memory_and_recovers(
    helper: ModuleType, native: Mock, code: int
) -> None:
    native.error = code
    native.advapi.LookupAccountSidW.return_value = 0
    with pytest.raises(OSError) as failure:
        helper.describe_sid(ctypes.addressof(native.sid_buffer))
    assert failure.value.errno == code
    assert native.released == [ctypes.addressof(native.text_buffers[0])]
    native.error = 1332
    assert helper.describe_sid(ctypes.addressof(native.sid_buffer))["type"] == "Unknown"
    assert native.released == [ctypes.addressof(value) for value in native.text_buffers]


def test_identity_description_retains_successful_empty_names(
    helper: ModuleType, native: Mock
) -> None:
    native.advapi.LookupAccountSidW.return_value = 1
    assert helper.describe_sid(ctypes.addressof(native.sid_buffer)) == {
        "sid": native.canonical,
        "account_name": "",
        "domain_name": "",
        "type": "0",
    }


@pytest.fixture(name="native")
def native_accounts(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Mock:
    """Provide inspectable SID allocations and native error results.

    :param helper: Isolated account helper.
    :param monkeypatch: Scoped Windows replacements.
    :returns: Mock exposing native libraries, SID buffers, and released addresses.
    """
    native = Mock()
    native.error = 0
    native.parse_success = True
    native.parse_error = 1337
    native.parse_allocates = True
    native.text_success = True
    native.text_allocates = True
    native.canonical = "S-1-1-0"
    native.binary = b"\x01\x01\0\0\0\0\0\x01\0\0\0\0"
    native.sid_buffer = ctypes.create_string_buffer(native.binary)
    native.text_buffers = []
    native.released = []
    native.netapi.NetUserEnum.return_value = 0
    native.netapi.NetApiBufferFree.return_value = 0

    def _parse(_value: str, pointer: Any) -> int:
        if native.parse_allocates:
            pointer._obj.value = ctypes.addressof(native.sid_buffer)
        if not native.parse_success:
            native.error = native.parse_error
        return int(native.parse_success)

    def _text(_sid: Any, pointer: Any) -> int:
        if native.text_allocates:
            buffer = ctypes.create_unicode_buffer(native.canonical)
            native.text_buffers.append(buffer)
            ctypes.cast(pointer, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(
                buffer
            )
        if not native.text_success:
            native.error = 8
        return int(native.text_success)

    native.advapi.ConvertStringSidToSidW.side_effect = _parse
    native.advapi.ConvertSidToStringSidW.side_effect = _text
    native.advapi.GetLengthSid.return_value = len(native.binary)
    native.advapi.IsValidSid.return_value = 1
    native.kernel.LocalFree.side_effect = lambda pointer: native.released.append(
        pointer.value
    )
    monkeypatch.setattr(
        helper, "os", SimpleNamespace(name="nt", environ={"COMPUTERNAME": "FIXTURE"})
    )
    monkeypatch.setattr(
        ctypes,
        "WinDLL",
        lambda name, **_kwargs: {
            "advapi32": native.advapi,
            "kernel32": native.kernel,
            "netapi32": native.netapi,
        }[name],
        raising=False,
    )
    monkeypatch.setattr(ctypes, "get_last_error", lambda: native.error, raising=False)
    monkeypatch.setattr(ctypes, "WinError", native_error, raising=False)
    return native


@pytest.mark.parametrize("operation", ["name_to_sid", "parse_sid"])
@pytest.mark.parametrize(
    "value,canonical",
    [
        ("BA", "S-1-5-32-544"),
        ("ba", "S-1-5-32-544"),
        ("WD", "S-1-1-0"),
        ("S-1-1-0", "S-1-1-0"),
        ("S-01-01-000", "S-1-1-0"),
        ("S-1-5-999999999", "S-1-5-999999999"),
    ],
)
def test_sid_inputs_use_native_canonicalization_and_release_both_allocations(
    helper: ModuleType, native: Mock, operation: str, value: str, canonical: str
) -> None:
    native.canonical = canonical
    assert getattr(helper, operation)(value) == canonical
    assert native.advapi.ConvertStringSidToSidW.call_args.args[0] == value
    native.advapi.LookupAccountNameW.assert_not_called()
    assert native.released == [
        ctypes.addressof(native.text_buffers[0]),
        ctypes.addressof(native.sid_buffer),
    ]


@pytest.mark.parametrize(
    "operation", ["name_to_sid", "parse_sid", "sid_to_name", "sid_to_string"]
)
@pytest.mark.parametrize(
    "native_sid,expected",
    [
        ("S-1-0x100000000-0", "S-1-4294967296-0"),
        ("S-1-0xffffffffffff-4294967295", "S-1-281474976710655-4294967295"),
        ("S-1-4294967295-0", "S-1-4294967295-0"),
    ],
)
def test_sid_output_uses_decimal_authority_and_retains_native_parser_results(
    helper: ModuleType, native: Mock, operation: str, native_sid: str, expected: str
) -> None:
    native.canonical = native_sid
    native.error = 1332
    native.advapi.LookupAccountSidW.return_value = 0
    borrowed = ctypes.c_void_p(ctypes.addressof(native.sid_buffer))
    value = borrowed if operation == "sid_to_string" else "S-1-4294967296-0"
    assert getattr(helper, operation)(value) == expected
    released = [ctypes.addressof(native.text_buffers[0])]
    if operation != "sid_to_string":
        released.append(ctypes.addressof(native.sid_buffer))
        assert native.advapi.ConvertStringSidToSidW.call_args.args[0] == value
    assert native.released == released


@pytest.mark.parametrize("code", [5, 8, 87])
@pytest.mark.parametrize("allocated", [False, True])
@pytest.mark.parametrize("operation", ["name_to_sid", "parse_sid"])
def test_non_sid_parse_errors_never_fall_back_to_account_lookup(
    helper: ModuleType, native: Mock, code: int, allocated: bool, operation: str
) -> None:
    native.parse_success = False
    native.parse_error = code
    native.parse_allocates = allocated
    with pytest.raises(OSError) as failure:
        getattr(helper, operation)("name")
    assert failure.value.errno == code
    native.advapi.LookupAccountNameW.assert_not_called()
    assert native.released == (
        [ctypes.addressof(native.sid_buffer)] if allocated else []
    )


@pytest.mark.parametrize("allocated", [False, True])
@pytest.mark.parametrize("operation", ["name_to_sid", "parse_sid"])
def test_sid_string_conversion_failure_frees_every_allocation(
    helper: ModuleType, native: Mock, allocated: bool, operation: str
) -> None:
    native.text_success = False
    native.text_allocates = allocated
    with pytest.raises(OSError) as failure:
        getattr(helper, operation)("S-1-1-0")
    assert failure.value.errno == 8
    expected = [ctypes.addressof(native.sid_buffer)]
    if allocated:
        expected.insert(0, ctypes.addressof(native.text_buffers[0]))
    assert native.released == expected
    native.advapi.LookupAccountNameW.assert_not_called()


@pytest.mark.parametrize("operation", ["name_to_sid", "parse_sid"])
def test_output_conversion_invalid_sid_error_does_not_trigger_account_lookup(
    helper: ModuleType, native: Mock, operation: str
) -> None:
    def _invalid_sid(_sid: Any, _pointer: Any) -> int:
        native.error = 1337
        return 0

    native.advapi.ConvertSidToStringSidW.side_effect = _invalid_sid
    with pytest.raises(OSError) as failure:
        getattr(helper, operation)("S-1-1-0")
    assert failure.value.errno == 1337
    assert native.released == [ctypes.addressof(native.sid_buffer)]
    native.advapi.LookupAccountNameW.assert_not_called()


def test_invalid_binary_sid_falls_back_after_releasing_the_parse_buffer(
    helper: ModuleType, native: Mock
) -> None:
    native.advapi.IsValidSid.return_value = 0

    def _lookup(*arguments: Any) -> int:
        assert native.released == [ctypes.addressof(native.sid_buffer)]
        assert arguments[1] == "S-2-1-0"
        native.error = 1332
        return 0

    native.advapi.LookupAccountNameW.side_effect = _lookup
    with pytest.raises(OSError) as failure:
        helper.name_to_sid("S-2-1-0")
    assert failure.value.errno == 1332
    native.advapi.ConvertSidToStringSidW.assert_not_called()


@pytest.mark.parametrize(
    "name,expected",
    [
        ("user", "user"),
        (r".\user", r"FIXTURE\user"),
        (r"DOMAIN\user", r"DOMAIN\user"),
        (r"DOMAIN\user\part", r"DOMAIN\user\part"),
        (r"\user", "user"),
        ("user@example.test", "user@example.test"),
        ("S-malformed", "S-malformed"),
    ],
)
def test_invalid_sid_uses_normalized_name_and_retries_growing_buffers(
    helper: ModuleType, native: Mock, name: str, expected: str
) -> None:
    native.parse_success = False
    native.parse_allocates = False
    capacities = []

    def _lookup(*arguments: Any) -> int:
        system, account, sid, sid_size, domain, domain_size, kind = arguments
        assert system is None
        assert account == expected
        capacities.append((sid_size._obj.value, domain_size._obj.value))
        if len(capacities) < 3:
            if len(capacities) == 1:
                assert sid is None and domain is None
            else:
                assert ctypes.sizeof(sid) == 12
                assert len(domain) == 4
            sid_size._obj.value = 12 if len(capacities) == 1 else 24
            domain_size._obj.value = 4 if len(capacities) == 1 else 16
            native.error = 122
            return 0
        assert ctypes.sizeof(sid) == 24
        assert len(domain) == 16
        sid.raw = native.binary + b"\0" * 12
        domain.value = "FIXTURE"
        kind._obj.value = 1
        return 1

    native.advapi.LookupAccountNameW.side_effect = _lookup
    assert helper.name_to_sid(name) == "S-1-1-0"
    assert capacities == [(0, 0), (12, 4), (24, 16)]
    assert native.released == [ctypes.addressof(native.text_buffers[0])]


@pytest.mark.parametrize(
    "name,expected_name",
    [
        ("BA", "BA"),
        ("WD", "WD"),
        ("S-1-1-0", "S-1-1-0"),
        ("Administrators", "Administrators"),
        (r".\BA", r"FIXTURE\BA"),
        (r"MACHINE\BA", r"MACHINE\BA"),
    ],
)
@pytest.mark.parametrize(
    "sid_output",
    [
        ("S-1-5-21-41-42-43-1001", "S-1-5-21-41-42-43-1001"),
        ("S-1-0x100000000-0", "S-1-4294967296-0"),
    ],
)
def test_account_only_lookup_preserves_actual_names_and_canonicalizes_results(
    helper: ModuleType,
    native: Mock,
    name: str,
    expected_name: str,
    sid_output: tuple[str, str],
) -> None:
    native_sid, expected_sid = sid_output
    native.canonical = native_sid

    def _lookup(*arguments: Any) -> int:
        assert arguments[0] is None
        assert arguments[1] == expected_name
        if arguments[2] is None:
            arguments[3]._obj.value = len(native.binary)
            arguments[5]._obj.value = 1
            native.error = 122
            return 0
        arguments[2].raw = native.binary
        arguments[4].value = ""
        arguments[6]._obj.value = 4
        return 1

    native.advapi.LookupAccountNameW.side_effect = _lookup
    assert helper.account_name_to_sid(name) == expected_sid
    native.advapi.ConvertStringSidToSidW.assert_not_called()
    native.advapi.IsValidSid.assert_not_called()
    assert native.released == [ctypes.addressof(native.text_buffers[0])]


@pytest.mark.parametrize("operation", ["name_to_sid", "account_name_to_sid"])
@pytest.mark.parametrize("name", ["", "\\", ".\\", "DOMAIN\\"])
def test_empty_account_fails_before_native_lookup(
    helper: ModuleType, native: Mock, operation: str, name: str
) -> None:
    native.parse_success = False
    native.parse_allocates = False
    with pytest.raises(ValueError, match="empty"):
        getattr(helper, operation)(name)
    native.advapi.LookupAccountNameW.assert_not_called()


@pytest.mark.parametrize("operation", ["name_to_sid", "account_name_to_sid"])
@pytest.mark.parametrize(
    "name",
    [
        "Administrator\0suffix",
        "DOMAIN\\Administrator\0suffix",
        "DOMAIN\0suffix\\Administrator",
        ".\\Administrator\0suffix",
        "\0",
    ],
)
def test_account_lookup_rejects_embedded_nul_without_translating_a_prefix(
    helper: ModuleType, native: Mock, operation: str, name: str
) -> None:
    native.parse_success = False
    with pytest.raises(OSError) as failure:
        getattr(helper, operation)(name)
    assert failure.value.errno == 87
    native.advapi.LookupAccountNameW.assert_not_called()
    if operation == "name_to_sid":
        assert native.advapi.ConvertStringSidToSidW.call_args.args[0] == name
        assert native.released == [ctypes.addressof(native.sid_buffer)]
    else:
        native.advapi.ConvertStringSidToSidW.assert_not_called()
        assert native.released == []


@pytest.mark.parametrize("name", ["WD\0suffix", "S-1-1-0\0suffix"])
@pytest.mark.parametrize("operation", ["name_to_sid", "parse_sid"])
def test_sid_parser_success_precedes_account_nul_validation(
    helper: ModuleType, native: Mock, name: str, operation: str
) -> None:
    assert getattr(helper, operation)(name) == "S-1-1-0"
    assert native.advapi.ConvertStringSidToSidW.call_args.args[0] == name
    native.advapi.LookupAccountNameW.assert_not_called()
    assert native.released == [
        ctypes.addressof(native.text_buffers[0]),
        ctypes.addressof(native.sid_buffer),
    ]


@pytest.mark.parametrize(
    "name,reason",
    [
        ("a" * 513, "Account name"),
        ("\U0001f600" * 257, "Account name"),
        ("DOMAIN\\" + "a" * 257, "Account name"),
        ("DOMAIN\\" + "\U0001f600" * 129, "Account name"),
        ("d" * 256 + "\\user", "Account domain"),
        ("\U0001f600" * 128 + "\\user", "Account domain"),
    ],
)
def test_account_constructor_limits_count_utf16_units(
    helper: ModuleType, native: Mock, name: str, reason: str
) -> None:
    native.parse_success = False
    with pytest.raises(ValueError, match=reason):
        helper.name_to_sid(name)
    native.advapi.LookupAccountNameW.assert_not_called()


@pytest.mark.parametrize(
    "name",
    ["a" * 512, "DOMAIN\\" + "a" * 256, "d" * 255 + "\\user"],
)
def test_account_constructor_accepts_boundary_lengths(
    helper: ModuleType, native: Mock, name: str
) -> None:
    native.parse_success = False
    native.advapi.LookupAccountNameW.return_value = 0
    native.advapi.LookupAccountNameW.side_effect = lambda *_args: setattr(
        native, "error", 1332
    )
    with pytest.raises(OSError) as failure:
        helper.name_to_sid(name)
    assert failure.value.errno == 1332
    assert native.advapi.LookupAccountNameW.call_args.args[1] == name


@pytest.mark.parametrize("code", [5, 87, 1332])
@pytest.mark.parametrize("after_probe", [False, True])
@pytest.mark.parametrize("operation", ["name_to_sid", "account_name_to_sid"])
def test_name_lookup_errors_propagate_without_fabricating_a_sid(
    helper: ModuleType, native: Mock, code: int, after_probe: bool, operation: str
) -> None:
    native.parse_success = False
    native.parse_allocates = False

    def _lookup(*arguments: Any) -> int:
        if after_probe and arguments[2] is None:
            arguments[3]._obj.value = 12
            arguments[5]._obj.value = 1
            native.error = 122
        else:
            native.error = code
        return 0

    native.advapi.LookupAccountNameW.side_effect = _lookup
    with pytest.raises(OSError) as failure:
        getattr(helper, operation)("unmapped")
    assert failure.value.errno == code
    native.advapi.ConvertSidToStringSidW.assert_not_called()
    assert native.released == []


@pytest.mark.parametrize(
    "domain,expected", [("BUILTIN", r"BUILTIN\Users"), ("", "Users")]
)
def test_sid_lookup_retries_both_growing_name_buffers_and_keeps_empty_domains(
    helper: ModuleType, native: Mock, domain: str, expected: str
) -> None:
    capacities = []

    def _lookup(*arguments: Any) -> int:
        system, pointer, name, name_size, domain_buffer, domain_size, kind = arguments
        assert system is None
        assert pointer.value == ctypes.addressof(native.sid_buffer)
        capacities.append((name_size._obj.value, domain_size._obj.value))
        if len(capacities) < 3:
            name_size._obj.value = 2 if len(capacities) == 1 else 6
            domain_size._obj.value = 0 if len(capacities) == 1 else len(domain) + 1
            native.error = 122
            return 0
        name.value = "Users"
        domain_buffer.value = domain
        kind._obj.value = 4
        return 1

    native.advapi.LookupAccountSidW.side_effect = _lookup
    assert helper.sid_to_name("S-1-1-0") == expected
    assert capacities == [(0, 0), (2, 1), (6, len(domain) + 1)]
    assert native.released == [ctypes.addressof(native.sid_buffer)]
    native.advapi.ConvertSidToStringSidW.assert_not_called()


@pytest.mark.parametrize("code", [5, 87, 1332])
@pytest.mark.parametrize("after_probe", [False, True])
def test_only_unmapped_sid_lookup_falls_back_to_canonical_text(
    helper: ModuleType, native: Mock, code: int, after_probe: bool
) -> None:
    native.canonical = "S-1-5-999999999"

    def _lookup(*arguments: Any) -> int:
        if after_probe and arguments[2] is None:
            arguments[3]._obj.value = 8
            arguments[5]._obj.value = 2
            native.error = 122
        else:
            native.error = code
        return 0

    native.advapi.LookupAccountSidW.side_effect = _lookup
    if code == 1332:
        assert helper.sid_to_name("S-01-05-999999999") == "S-1-5-999999999"
        assert native.released == [
            ctypes.addressof(native.text_buffers[0]),
            ctypes.addressof(native.sid_buffer),
        ]
    else:
        with pytest.raises(OSError) as failure:
            helper.sid_to_name("S-1-5-999999999")
        assert failure.value.errno == code
        assert native.released == [ctypes.addressof(native.sid_buffer)]
        native.advapi.ConvertSidToStringSidW.assert_not_called()


@pytest.mark.parametrize("operation", ["parse_sid", "sid_to_name", "sid_bytes"])
@pytest.mark.parametrize("allocated", [False, True])
def test_sid_operations_reject_invalid_text_and_release_partial_allocation(
    helper: ModuleType, native: Mock, operation: str, allocated: bool
) -> None:
    native.parse_success = False
    native.parse_allocates = allocated
    with pytest.raises(OSError) as failure:
        getattr(helper, operation)("invalid")
    assert failure.value.errno == 1337
    assert native.released == (
        [ctypes.addressof(native.sid_buffer)] if allocated else []
    )
    native.advapi.LookupAccountSidW.assert_not_called()
    native.advapi.LookupAccountNameW.assert_not_called()
    native.advapi.GetLengthSid.assert_not_called()


@pytest.mark.parametrize("operation", ["parse_sid", "sid_to_name", "sid_bytes"])
def test_sid_operations_validate_native_parse_success(
    helper: ModuleType, native: Mock, operation: str
) -> None:
    native.advapi.IsValidSid.return_value = 0
    with pytest.raises(OSError) as failure:
        getattr(helper, operation)("S-2-1-0")
    assert failure.value.errno == 1337
    assert native.released == [ctypes.addressof(native.sid_buffer)]
    native.advapi.LookupAccountSidW.assert_not_called()
    native.advapi.LookupAccountNameW.assert_not_called()
    native.advapi.GetLengthSid.assert_not_called()


@pytest.mark.parametrize("kind", range(1, 12))
@pytest.mark.parametrize("reverse", [False, True])
def test_only_account_sid_types_translate_in_either_direction(
    helper: ModuleType, native: Mock, kind: int, reverse: bool
) -> None:
    native.parse_success = reverse
    native.parse_allocates = reverse

    def _lookup(*arguments: Any) -> int:
        if arguments[2] is None:
            arguments[3]._obj.value = 12
            arguments[5]._obj.value = 8
            native.error = 122
            return 0
        if reverse:
            arguments[2].value = "account"
        arguments[4].value = "domain"
        arguments[6]._obj.value = kind
        return 1

    native.advapi.LookupAccountSidW.side_effect = _lookup
    native.advapi.LookupAccountNameW.side_effect = _lookup
    accepted = kind in (1, 2, 4, 5, 9)
    if reverse:
        expected = r"domain\account" if accepted else "S-1-1-0"
        assert helper.sid_to_name("S-1-1-0") == expected
        assert native.released[-1] == ctypes.addressof(native.sid_buffer)
    elif accepted:
        assert helper.name_to_sid("account") == "S-1-1-0"
    else:
        with pytest.raises(OSError) as failure:
            helper.name_to_sid("account")
        assert failure.value.errno == 1332
        native.advapi.ConvertSidToStringSidW.assert_not_called()


@pytest.mark.parametrize("success", [False, True])
def test_borrowed_sid_conversion_never_frees_the_borrowed_pointer(
    helper: ModuleType, native: Mock, success: bool
) -> None:
    native.text_success = success
    pointer = ctypes.c_void_p(ctypes.addressof(native.sid_buffer))
    if success:
        assert helper.sid_to_string(pointer) == "S-1-1-0"
    else:
        with pytest.raises(OSError) as failure:
            helper.sid_to_string(pointer)
        assert failure.value.errno == 8
    assert native.released == [ctypes.addressof(native.text_buffers[0])]
    native.advapi.ConvertStringSidToSidW.assert_not_called()


def test_binary_sid_is_copied_before_native_allocation_is_released(
    helper: ModuleType, native: Mock
) -> None:
    def _free(pointer: Any) -> None:
        native.released.append(pointer.value)
        ctypes.memset(pointer, 0, len(native.binary))

    native.kernel.LocalFree.side_effect = _free
    assert helper.sid_bytes("WD") == native.binary
    assert native.released == [ctypes.addressof(native.sid_buffer)]
    assert ctypes.string_at(native.sid_buffer, len(native.binary)) == b"\0" * 12
    native.advapi.ConvertSidToStringSidW.assert_not_called()


@pytest.mark.parametrize("unique", [False, True])
def test_sort_and_deduplication_use_native_collation_not_python_text_order(
    helper: ModuleType, native: Mock, unique: bool
) -> None:
    names = ["Zulu", "ä", "a", "A", "aa"]
    weights = {"Zulu": 3, "ä": 0, "a": 1, "A": 1, "aa": 2}

    def _compare(*arguments: Any) -> int:
        locale, flags, left, left_length, right, right_length = arguments
        assert (locale, flags) == (0x400, 0x08000001)
        assert left_length == len(left)
        assert right_length == len(right)
        return 2 + (weights[left] > weights[right]) - (weights[left] < weights[right])

    native.kernel.CompareStringW.side_effect = _compare
    expected = ["ä", "a", "aa", "Zulu"] if unique else ["ä", "a", "A", "aa", "Zulu"]
    assert helper.sort_names(names, unique=unique) == expected
    assert names == ["Zulu", "ä", "a", "A", "aa"]
    native.kernel.CompareStringW.assert_called()


@pytest.mark.parametrize("unique", [False, True])
@pytest.mark.parametrize("names", [[], ["user"]])
def test_empty_or_single_name_needs_no_native_comparison(
    helper: ModuleType, native: Mock, unique: bool, names: list[str]
) -> None:
    assert helper.sort_names(names, unique=unique) == names
    native.kernel.CompareStringW.assert_not_called()


def test_comparison_lengths_preserve_utf16_surrogates_and_embedded_nul(
    helper: ModuleType, native: Mock
) -> None:
    native.kernel.CompareStringW.return_value = 2
    names = ["\U0001f600\0x", "\ud800"]
    assert helper.sort_names(names) == names
    native.kernel.CompareStringW.assert_called_once_with(
        0x400, 0x08000001, "\ud800", 1, "\U0001f600\0x", 4
    )


@pytest.mark.parametrize("deduplication", [False, True])
def test_sorting_and_deduplication_propagate_comparison_errors(
    helper: ModuleType, native: Mock, deduplication: bool
) -> None:
    native.error = 87
    native.kernel.CompareStringW.side_effect = [2, 0] if deduplication else [0]
    with pytest.raises(OSError) as failure:
        helper.sort_names(["a", "A"], unique=deduplication)
    assert failure.value.errno == 87


def test_legacy_sort_retries_only_unsupported_flags_and_retains_native_order(
    helper: ModuleType, native: Mock
) -> None:
    native.error = 1004
    native.kernel.CompareStringW.side_effect = [0, 2, 2]
    assert helper.sort_names(["a", "A"], unique=True) == ["a"]
    assert [call.args[1] for call in native.kernel.CompareStringW.call_args_list] == [
        0x08000001,
        1,
        1,
    ]


@pytest.mark.parametrize("code", [5, 87, 1004])
def test_legacy_comparison_retry_failure_propagates_without_a_further_fallback(
    helper: ModuleType, native: Mock, code: int
) -> None:
    errors = iter([1004, code])

    def _compare(*_arguments: Any) -> int:
        native.error = next(errors)
        return 0

    native.kernel.CompareStringW.side_effect = _compare
    with pytest.raises(OSError) as failure:
        helper.sort_names(["a", "b"])
    assert failure.value.errno == code
    assert native.kernel.CompareStringW.call_count == 2


def test_local_users_copy_names_and_consume_all_pages_with_a_dword_resume(
    helper: ModuleType, native: Mock
) -> None:
    first_name = ctypes.create_unicode_buffer("Local_雪")
    pages = [
        (helper._UserInfo0 * 2)(
            (ctypes.cast(first_name, ctypes.c_wchar_p),), ("Guest",)
        ),
        (helper._UserInfo0 * 1)(("Last",)),
    ]
    observed = []
    resume = 0xFFFFFFFF

    def _enumerate(*arguments: Any) -> int:
        assert arguments[:3] == (None, 0, 2)
        buffer = arguments[3]
        count, total, context = arguments[5], arguments[6], arguments[7]
        assert arguments[4] == 0xFFFFFFFF
        assert isinstance(context._obj, ctypes.c_uint32)
        observed.append(context._obj.value)
        index = len(observed) - 1
        buffer._obj.value = ctypes.addressof(pages[index])
        count._obj.value = len(pages[index])
        # The total is only a hint, so it must not limit copied names or pages.
        total._obj.value = 1
        context._obj.value = resume
        return 234 if index == 0 else 0

    def _free(buffer: Any) -> int:
        if buffer.value == ctypes.addressof(pages[0]):
            first_name.value = "freed"
        return 0

    native.netapi.NetUserEnum.side_effect = _enumerate
    native.netapi.NetApiBufferFree.side_effect = _free
    assert helper.local_user_names() == ["Local_雪", "Guest", "Last"]
    assert observed == [0, resume]
    assert [
        call.args[0].value for call in native.netapi.NetApiBufferFree.call_args_list
    ] == [ctypes.addressof(page) for page in pages]
    native.advapi.LookupAccountNameW.assert_not_called()


@pytest.mark.parametrize("allocated", [False, True])
def test_empty_local_user_pages_continue_on_more_data_and_release_allocations(
    helper: ModuleType, native: Mock, allocated: bool
) -> None:
    page = (helper._UserInfo0 * 1)(("unused",))
    observed = []

    def _enumerate(*arguments: Any) -> int:
        buffer = arguments[3]
        count, total, context = arguments[5], arguments[6], arguments[7]
        observed.append(context._obj.value)
        if allocated:
            buffer._obj.value = ctypes.addressof(page)
        count._obj.value = 0
        total._obj.value = 5
        context._obj.value = 3
        return 234 if len(observed) == 1 else 0

    native.netapi.NetUserEnum.side_effect = _enumerate
    assert helper.local_user_names() == []
    assert observed == [0, 3]
    assert native.netapi.NetApiBufferFree.call_count == (2 if allocated else 0)


@pytest.mark.parametrize("code", [5, 87, 2123])
@pytest.mark.parametrize("allocated", [False, True])
@pytest.mark.parametrize("after_page", [False, True])
def test_local_user_errors_propagate_and_release_successful_and_failed_pages(
    helper: ModuleType, native: Mock, code: int, allocated: bool, after_page: bool
) -> None:
    page = (helper._UserInfo0 * 1)(("Local",))
    calls = []

    def _enumerate(*arguments: Any) -> int:
        buffer, count, context = arguments[3], arguments[5], arguments[7]
        calls.append(context._obj.value)
        if after_page and len(calls) == 1:
            buffer._obj.value = ctypes.addressof(page)
            count._obj.value = 1
            context._obj.value = 7
            return 234
        if allocated:
            buffer._obj.value = ctypes.addressof(page)
        return code

    native.netapi.NetUserEnum.side_effect = _enumerate
    with pytest.raises(OSError) as failure:
        helper.local_user_names()
    assert failure.value.errno == code
    assert calls == ([0, 7] if after_page else [0])
    assert native.netapi.NetApiBufferFree.call_count == int(after_page) + int(allocated)


def test_local_user_copy_failure_releases_the_native_page(
    helper: ModuleType, native: Mock, monkeypatch: pytest.MonkeyPatch
) -> None:
    page = (helper._UserInfo0 * 1)(("Local",))

    def _enumerate(*arguments: Any) -> int:
        arguments[3]._obj.value = ctypes.addressof(page)
        arguments[5]._obj.value = 1
        return 0

    native.netapi.NetUserEnum.side_effect = _enumerate
    monkeypatch.setattr(ctypes, "cast", Mock(side_effect=ValueError("copy failed")))
    with pytest.raises(ValueError, match="copy failed"):
        helper.local_user_names()
    assert native.netapi.NetApiBufferFree.call_args.args[0].value == ctypes.addressof(
        page
    )


def test_local_user_enumeration_requires_windows(helper: ModuleType) -> None:
    with pytest.raises(ValueError, match="Windows"):
        helper.local_user_names()


def test_local_user_structure_and_signature_use_native_pointer_and_dword_widths(
    helper: ModuleType, native: Mock
) -> None:
    assert ctypes.sizeof(helper._UserInfo0) == ctypes.sizeof(ctypes.c_void_p)
    assert helper._UserInfo0.name.offset == 0
    assert helper.local_user_names() == []
    assert native.netapi.NetUserEnum.argtypes == [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    assert native.netapi.NetUserEnum.restype is ctypes.c_uint32
    assert native.netapi.NetApiBufferFree.argtypes == [ctypes.c_void_p]
    assert native.netapi.NetApiBufferFree.restype is ctypes.c_uint32


@pytest.mark.parametrize(
    "operation,value",
    [
        ("name_to_sid", "name"),
        ("account_name_to_sid", "name"),
        ("parse_sid", "S-1-1-0"),
        ("sid_to_name", "S-1-1-0"),
        ("sid_to_string", 123),
        ("sid_bytes", "S-1-1-0"),
        ("sort_names", ["a", "b"]),
    ],
)
def test_account_operations_require_windows(
    helper: ModuleType, operation: str, value: Any
) -> None:
    with pytest.raises(ValueError, match="Windows"):
        getattr(helper, operation)(value)


def test_native_signatures_preserve_pointer_width_and_windows_integer_width(
    helper: ModuleType, native: Mock
) -> None:
    helper.sid_bytes("WD")
    assert native.advapi.ConvertStringSidToSidW.argtypes == [
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    assert native.advapi.ConvertSidToStringSidW.argtypes == [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_wchar_p),
    ]
    assert native.advapi.LookupAccountNameW.argtypes[2:4] == [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    assert native.advapi.LookupAccountSidW.argtypes[1] is ctypes.c_void_p
    assert native.advapi.GetLengthSid.restype is ctypes.c_uint32
    assert native.kernel.LocalFree.argtypes == [ctypes.c_void_p]
    assert native.kernel.LocalFree.restype is ctypes.c_void_p
    assert native.kernel.CompareStringW.restype is ctypes.c_int
