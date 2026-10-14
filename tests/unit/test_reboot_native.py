"""Exercise reboot indicators and native event reads without contacting Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes expose buffers and errors on the controller interpreter.
# pylint: disable=protected-access

import ctypes
import datetime
import json
import struct
import uuid
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module, native_error

REFERENCE = json.loads(
    (ROOT / "tests/fixtures/reboot_info_reference.json").read_text(encoding="utf-8")
)
BOOT = datetime.datetime(2026, 9, 29, 12)
PROPERTIES = [
    r"C:\synthetic.exe",
    "machine",
    "synthetic reason",
    "0x80040002",
    "restart",
    "",
    r"DOMAIN\user",
]


def _ticks(timestamp: datetime.datetime) -> int:
    delta = timestamp - datetime.datetime(1601, 1, 1)
    return ((delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds) * 10


@pytest.fixture(name="helper")
def reboot_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the target helper with portable native-error construction.

    :param monkeypatch: Scoped imports and ctypes substitutions.
    :returns: Isolated reboot helper.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    monkeypatch.setattr(ctypes, "WinError", native_error, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5, raising=False)
    helper = load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_reboot.py", "reboot"
    )
    monkeypatch.setattr(helper, "_account_domain_sid", lambda _pointer: None)
    return helper


@pytest.fixture(name="registry")
def registry_reads(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> SimpleNamespace:
    """Provide only read operations and track every opened registry handle.

    :param helper: Imported reboot helper.
    :param monkeypatch: Scoped native registry boundary.
    :returns: Keys, values, native calls, and opened handles.
    """
    values: dict[str, dict[str, Any]] = {}
    errors: dict[str, int] = {}
    opened: list[Mock] = []
    native = Mock(HKEY_LOCAL_MACHINE=1, KEY_READ=0x20019)

    def _open(hive: int, path: str, reserved: int, access: int) -> Mock:
        assert (hive, reserved, access) == (1, 0, 0x20019)
        if path in errors or path not in values:
            raise native_error(errors.get(path, 2))
        key = Mock(path=path)
        key.__enter__ = Mock(return_value=key)
        key.__exit__ = Mock(return_value=False)
        opened.append(key)
        return key

    def _read(key: Mock, name: str, expand: bool = False) -> tuple[Any, int]:
        assert expand is True
        return values[key.path].get(name), 1

    native.OpenKey.side_effect = _open
    native.QueryInfoKey.side_effect = lambda key: (0, len(values[key.path]), 0)
    native.EnumValue.side_effect = lambda key, index: (
        list(values[key.path])[index],
        None,
        1,
    )
    monkeypatch.setattr(helper, "winreg", native)
    monkeypatch.setattr(helper, "read_value", _read)
    monkeypatch.setattr(
        helper, "_same_name", lambda left, right: left.lower() == right.lower()
    )
    return SimpleNamespace(values=values, errors=errors, native=native, opened=opened)


def test_all_indicators_preserve_source_order_and_descriptions(
    helper: ModuleType, registry: SimpleNamespace
) -> None:
    registry.values.update(
        {
            helper._CBS: {},
            helper._WINDOWS_UPDATE: {},
            helper._SESSION_MANAGER: {"PendingFileRenameOperations": ["source", ""]},
            helper._COMPUTER_NAME + r"\ComputerName": {"ComputerName": "new"},
            helper._COMPUTER_NAME + r"\ActiveComputerName": {"ComputerName": "old"},
            helper._NETLOGON: {"JoinDomain": 0},
            helper._SERVER_MANAGER: {"RestartRequired": 1},
        }
    )
    assert helper.pending_reboot_reasons() == [
        {
            "source": "component_based_servicing",
            "description": "Component Based Servicing has a pending reboot.",
        },
        {
            "source": "windows_update",
            "description": "Windows Update has installed updates that require a reboot.",
        },
        {
            "source": "pending_file_rename",
            "description": "There are pending file rename operations that require a reboot.",
        },
        {
            "source": "pending_computer_rename",
            "description": "Computer name change pending from 'old' to 'new'.",
        },
        {
            "source": "domain_join",
            "description": "A domain join operation is pending and requires a reboot.",
        },
        {
            "source": "server_manager",
            "description": "Server Manager indicates a component change requires a reboot.",
        },
    ]
    assert len(registry.opened) == 7
    for handle in registry.opened:
        handle.__exit__.assert_called_once()


def test_absent_registry_state_has_no_reasons(
    helper: ModuleType, registry: SimpleNamespace
) -> None:
    assert helper.pending_reboot_reasons() == []
    assert len(registry.native.OpenKey.call_args_list) == 7


@pytest.mark.parametrize(
    "code,present", [(2, False), (3, False), (5, True), (1346, True), (1018, False)]
)
def test_key_presence_and_silent_property_access_are_distinct(
    helper: ModuleType, registry: SimpleNamespace, code: int, present: bool
) -> None:
    registry.errors[helper._CBS] = code
    registry.errors[helper._SESSION_MANAGER] = code
    result = helper.pending_reboot_reasons()
    assert [reason["source"] for reason in result] == (
        ["component_based_servicing"] if present else []
    )


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, False),
        ([], False),
        ([""], False),
        ([0], False),
        (["", ""], True),
        ([0, 0], True),
        (["file"], True),
        ("0", True),
        (0, False),
        (-1, True),
    ],
)
@pytest.mark.parametrize("indicator", ["file", "server"])
def test_registry_truthiness_matches_powershell(
    helper: ModuleType,
    registry: SimpleNamespace,
    value: Any,
    expected: bool,
    indicator: str,
) -> None:
    if indicator == "file":
        registry.values[helper._SESSION_MANAGER] = {
            "PendingFileRenameOperations": value
        }
    else:
        registry.values[helper._SERVER_MANAGER] = {"RestartRequired": value}
    assert bool(helper.pending_reboot_reasons()) is expected


@pytest.mark.parametrize("name", ["JoinDomain", "avoIdSPNSet"])
@pytest.mark.parametrize("value", [None, "", 0, [], 1])
def test_domain_join_depends_on_property_presence_not_value(
    helper: ModuleType, registry: SimpleNamespace, name: str, value: Any
) -> None:
    registry.values[helper._NETLOGON] = {name: value}
    assert helper.pending_reboot_reasons()[0]["source"] == "domain_join"


@pytest.mark.parametrize(
    "pending,active", [("host", "HOST"), ("", "host"), ("host", None)]
)
def test_computer_rename_requires_two_nonempty_different_names(
    helper: ModuleType, registry: SimpleNamespace, pending: Any, active: Any
) -> None:
    registry.values[helper._COMPUTER_NAME + r"\ComputerName"] = {
        "ComputerName": pending
    }
    registry.values[helper._COMPUTER_NAME + r"\ActiveComputerName"] = {
        "ComputerName": active
    }
    assert helper.pending_reboot_reasons() == []


def test_name_comparison_uses_invariant_case_insensitive_counted_utf16(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    kernel = Mock()
    kernel.CompareStringW.return_value = 2
    monkeypatch.setattr(ctypes, "WinDLL", Mock(return_value=kernel), raising=False)
    assert helper._same_name("\U00010000A\0", "\U00010000a\0") is True
    kernel.CompareStringW.assert_called_once_with(
        0x7F, 1, "\U00010000A\0", 4, "\U00010000a\0", 4
    )
    kernel.CompareStringW.return_value = 0
    with pytest.raises(OSError):
        helper._same_name("a", "b")


@pytest.mark.parametrize("case", REFERENCE["reason_cases"])
def test_reason_code_matches_recorded_powershell(
    helper: ModuleType, case: dict[str, Any]
) -> None:
    actual = helper._reason_code(case["input"])
    assert actual == case["output"]
    assert type(actual) is type(case["output"])


@pytest.mark.parametrize(
    "value,expected",
    [
        (True, 1),
        (1.5, 2),
        (2.5, 2),
        (2**63, 2**63),
        ("9223372036854775807.0", "9223372036854775807.0"),
        ("1e999", "1e999"),
        ("\x1c42", "\x1c42"),
    ],
)
def test_reason_conversion_preserves_failed_values(
    helper: ModuleType, value: Any, expected: Any
) -> None:
    assert helper._reason_code(value) == expected


@pytest.mark.parametrize("case", REFERENCE["events"])
def test_event_result_matches_recorded_assignment_shape(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, case: dict[str, Any]
) -> None:
    offsets = {
        "older": -3000000001,
        "threshold": -3000000000,
        "recent": -600000000,
        "future": 600000000,
    }
    event: Any = (_ticks(BOOT) + offsets.get(case["id"], 0), PROPERTIES)
    if case["id"] == "absent":
        event = None
    elif case["id"] == "null_time":
        event = (None, PROPERTIES)
    elif case["id"] == "zero_properties":
        event = (_ticks(BOOT), [])
    elif case["id"] == "four_properties":
        event = (_ticks(BOOT), PROPERTIES[:4])
    monkeypatch.setattr(helper, "_event_api", object)
    monkeypatch.setattr(helper, "_modern_event", lambda _library, _cutoff: event)
    if case["failed"]:
        with pytest.raises(
            RuntimeError, match='Cannot find an overload for "Warn"'
        ) as failed:
            helper.recent_reboot(BOOT)
        assert str(failed.value) == case["message"]
    else:
        assert helper.recent_reboot(BOOT) == json.loads(case["raw_json"])["details"]


def test_microseconds_and_event_ticks_are_not_rounded_at_cutoff(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    boot = BOOT.replace(microsecond=123456)
    cutoff = _ticks(boot) - 3000000000
    monkeypatch.setattr(helper, "_event_api", lambda: None)
    for ticks, included in [(cutoff - 1, False), (cutoff, True), (cutoff + 1, True)]:
        monkeypatch.setattr(
            helper, "_classic_event", Mock(return_value=(ticks, PROPERTIES[:6]))
        )
        result = helper.recent_reboot(boot)
        assert bool(result) is included
        if included:
            assert result["event_time"] == "2026-09-29T11:55:00Z"
            assert result["initiated_by"] is None


@pytest.fixture(name="modern")
def modern_event_library(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Mock:
    """Provide an event handle while leaving native cleanup observable.

    :param helper: Imported reboot helper.
    :param monkeypatch: Scoped modern API boundary.
    :returns: Fake event library with a valid latest event.
    """
    library = Mock()
    library.EvtQuery.return_value = 11

    def _next(
        _query: int, count: int, event: Any, _timeout: int, _flags: int, returned: Any
    ) -> int:
        assert count == 1
        ctypes.cast(event, ctypes.POINTER(ctypes.c_void_p))[0] = 22
        ctypes.cast(returned, ctypes.POINTER(ctypes.c_uint32))[0] = 1
        return 1

    library.EvtNext.side_effect = _next
    monkeypatch.setattr(helper, "_event_api", lambda: library)
    monkeypatch.setattr(
        helper,
        "_render_values",
        lambda _library, _event, kind: _ticks(BOOT) if kind == 1 else PROPERTIES,
    )
    return library


def test_modern_query_is_latest_system_id_only_and_closes_handles(
    helper: ModuleType, modern: Mock
) -> None:
    assert helper.recent_reboot(BOOT)["reason_code"] == 2147745794
    modern.EvtQuery.assert_called_once_with(
        None, "System", "*[System[(EventID=1074)]]", 0x1201
    )
    assert [
        (
            call.args[0].value
            if isinstance(call.args[0], ctypes.c_void_p)
            else call.args[0]
        )
        for call in modern.EvtClose.call_args_list
    ] == [22, 11]


def test_old_modern_event_does_not_read_its_properties(
    helper: ModuleType, modern: Mock, monkeypatch: pytest.MonkeyPatch
) -> None:
    render = Mock(return_value=_ticks(BOOT) - 3000000001)
    monkeypatch.setattr(helper, "_render_values", render)
    assert helper.recent_reboot(BOOT) == {}
    assert render.call_count == 1
    assert modern.EvtClose.call_count == 2


def test_modern_property_failure_is_fatal_but_handles_are_closed(
    helper: ModuleType, modern: Mock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper, "_render_values", Mock(side_effect=native_error(5)))
    with pytest.raises(RuntimeError, match="argument count"):
        helper.recent_reboot(BOOT)
    assert modern.EvtClose.call_count == 2


def test_modern_no_events_and_suppressed_iteration_error(
    helper: ModuleType, modern: Mock, monkeypatch: pytest.MonkeyPatch
) -> None:
    modern.EvtNext.side_effect = [0, 0]
    monkeypatch.setattr(ctypes, "get_last_error", Mock(side_effect=[5, 259]))
    assert helper.recent_reboot(BOOT) == {}
    modern.EvtClose.assert_called_once_with(11)


def test_modern_open_failure_does_not_close_unopened_handle(
    helper: ModuleType, modern: Mock
) -> None:
    modern.EvtQuery.return_value = None
    with pytest.raises(RuntimeError, match="argument count"):
        helper.recent_reboot(BOOT)
    modern.EvtClose.assert_not_called()


def test_modern_variant_buffer_copies_nullable_strings_and_closes_context(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = Mock()
    library.EvtCreateRenderContext.return_value = 33
    string = ctypes.create_unicode_buffer("value")
    variants = (helper._EventVariant * 3)()
    variants[0].type = 1
    variants[0].value.pointer = ctypes.addressof(string)
    variants[1].type = 0
    variants[2].type = 10
    variants[2].value.unsigned = 2**64 - 1

    def _render(
        _context: int,
        _event: int,
        _flags: int,
        size: int,
        buffer: Any,
        used: Any,
        count: Any,
    ) -> int:
        ctypes.cast(used, ctypes.POINTER(ctypes.c_uint32))[0] = ctypes.sizeof(variants)
        ctypes.cast(count, ctypes.POINTER(ctypes.c_uint32))[0] = 3
        if not size:
            return 0
        ctypes.memmove(buffer, variants, ctypes.sizeof(variants))
        return 1

    library.EvtRender.side_effect = _render
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 122)
    assert helper._render_values(library, 22, 2) == ["value", None, 2**64 - 1]
    library.EvtClose.assert_called_once_with(33)
    assert ctypes.sizeof(helper._EventVariant) == 16


def test_empty_user_properties_render_success_without_a_buffer(
    helper: ModuleType,
) -> None:
    library = Mock()
    library.EvtCreateRenderContext.return_value = 33
    library.EvtRender.return_value = 1
    assert helper._render_values(library, 22, 2) == []
    library.EvtClose.assert_called_once_with(33)


def _record(event_id: int, generated: int, properties: list[str]) -> bytes:
    strings = ("\0".join(properties) + ("\0" if properties else "")).encode("utf-16-le")
    length = 56 + len(strings) + 4
    header = struct.pack(
        "<6L4H6L",
        length,
        0,
        1,
        generated,
        generated + 10,
        event_id,
        4,
        len(properties),
        0,
        0,
        0,
        56,
        0,
        0,
        0,
        0,
    )
    return header + strings + struct.pack("<L", length)


def test_classic_record_uses_low_event_id_and_generated_time(
    helper: ModuleType,
) -> None:
    data = (
        _record(6005, 1000, [])
        + _record(0x80000432, 900, PROPERTIES[:6])
        + _record(1074, 800, ["older"])
    )
    assert helper._classic_record(data, 0) == (
        (11644473600 + 900) * 10000000,
        PROPERTIES[:6],
    )


@pytest.mark.parametrize("data", [b"short", struct.pack("<L", 9999) + b"\0" * 52])
def test_classic_record_rejects_truncated_buffers(
    helper: ModuleType, data: bytes
) -> None:
    with pytest.raises(ValueError):
        helper._classic_record(data, 0)


def test_old_classic_event_does_not_decode_malformed_insertions(
    helper: ModuleType,
) -> None:
    record = bytearray(_record(1074, 1, ["x"]))
    struct.pack_into("<L", record, 36, 9999)
    assert helper._classic_record(bytes(record), 2**63)[1] == []
    with pytest.raises(ValueError, match="offset"):
        helper._classic_record(bytes(record), 0)


@pytest.mark.parametrize("failure", [None, "eof", "read", "open"])
def test_classic_reader_resizes_scans_and_closes_on_all_paths(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    library = Mock()
    library.OpenEventLogW.return_value = None if failure == "open" else 44
    rows = [_record(6005, 1, []), _record(1074, 2, PROPERTIES)]
    calls = 0
    error = 5

    # The substitute keeps the native seven-argument ReadEventLogW contract.
    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def _read(
        log: int,
        flags: int,
        offset: int,
        buffer: Any,
        size: int,
        read: Any,
        needed: Any,
    ) -> int:
        nonlocal calls, error
        assert (log, flags, offset) == (44, 9, 0)
        calls += 1
        if calls == 1:
            error = 122
            ctypes.cast(needed, ctypes.POINTER(ctypes.c_uint32))[0] = 70000
            return 0
        assert size == 70000
        if failure:
            error = 38 if failure == "eof" else 5
            return 0
        row = rows.pop(0)
        ctypes.memmove(buffer, row, len(row))
        ctypes.cast(read, ctypes.POINTER(ctypes.c_uint32))[0] = len(row)
        return 1

    library.ReadEventLogW.side_effect = _read
    monkeypatch.setattr(helper, "_classic_api", lambda: library)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: error)
    if failure in ("read", "open"):
        with pytest.raises(OSError):
            helper._classic_event(0)
    elif failure == "eof":
        assert helper._classic_event(0) is None
    else:
        assert helper._classic_event(0)[1] == PROPERTIES
        assert calls == 3
    if failure == "open":
        library.CloseEventLog.assert_not_called()
    else:
        library.CloseEventLog.assert_called_once_with(44)


def test_missing_modern_dll_selects_classic_api_only_for_module_not_found(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    loader = Mock(side_effect=native_error(126))
    monkeypatch.setattr(ctypes, "WinDLL", loader, raising=False)
    assert helper._event_api() is None
    loader.side_effect = native_error(5)
    with pytest.raises(OSError):
        helper._event_api()


def test_native_function_signatures_preserve_handles_and_dword_widths(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = Mock()
    monkeypatch.setattr(ctypes, "WinDLL", Mock(return_value=library), raising=False)
    assert helper._event_api() is library
    assert helper._classic_api() is library
    assert library.EvtQuery.restype is ctypes.c_void_p
    assert library.OpenEventLogW.restype is ctypes.c_void_p
    assert library.EvtRender.argtypes[-1] is ctypes.POINTER(ctypes.c_uint32)
    assert library.ReadEventLogW.argtypes[1] is ctypes.c_uint32


def _variant(helper: ModuleType, kind: int, value: Any) -> Any:
    variant = helper._EventVariant()
    variant.type = kind
    buffer: Any
    if kind in (1, 2):
        buffer = (
            ctypes.create_unicode_buffer(value)
            if kind == 1
            else ctypes.create_string_buffer(value)
        )
    elif kind in (14, 15, 19):
        buffer = ctypes.create_string_buffer(value)
        variant.count = len(value)
    elif kind & 0x80:
        base_kind = kind & 0x7F
        variant.count = len(value)
        if base_kind == 1:
            buffer = (ctypes.c_wchar_p * len(value))(*value)
        elif base_kind == 15:
            buffer = ctypes.create_string_buffer(b"".join(value))
        else:
            number_type = (
                ctypes.c_uint64 if base_kind == 17 else helper._EVENT_NUMBERS[base_kind]
            )
            buffer = (number_type * len(value))(*value)
    else:
        number_type = (
            ctypes.c_uint64
            if kind == 17
            else helper._EVENT_NUMBERS.get(kind, ctypes.c_uint64)
        )
        number_type.from_buffer(variant.value).value = value
        return variant
    variant.value.pointer = ctypes.addressof(buffer)
    variant.keepalive = buffer
    return variant


@pytest.mark.parametrize("case", REFERENCE["typed_cases"])
def test_typed_properties_preserve_reference_json_and_reason_pipeline_shape(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, case: dict[str, Any]
) -> None:
    guid = uuid.UUID("01234567-89ab-cdef-0123-456789abcdef").bytes_le
    date = _ticks(BOOT.replace(microsecond=125000))
    cases = {
        "null": (0, 0),
        "string": (1, "Text 雪"),
        "byte": (4, 255),
        "sbyte": (7, -1),
        "uint16": (6, 65535),
        "int32": (7, -2147483648),
        "uint64": (10, 2**64 - 1),
        "single": (11, 1.25),
        "double": (12, 1.25),
        "boolean": (13, 1),
        "binary": (14, b"\0\xff"),
        "empty_binary": (14, b""),
        "guid": (15, guid),
        "size_t": (16, 17),
        "datetime": (17, date),
        "sid": (19, b"\x01\x01\0\0\0\0\0\x05\x12\0\0\0"),
        "string_array": (129, ["a", "b"]),
        "int32_array": (135, [1, 2]),
        "single_int32_array": (135, [17]),
        "boolean_array": (141, [1, 0]),
        "guid_array": (143, [guid]),
        "datetime_array": (145, [date]),
    }
    variant = _variant(helper, *cases[case["id"]])
    value = helper._variant_value(variant)
    monkeypatch.setattr(helper, "_event_api", object)
    monkeypatch.setattr(
        helper, "_modern_event", lambda _library, _cutoff: (_ticks(BOOT), [value] * 7)
    )
    assert helper.recent_reboot(BOOT) == json.loads(case["raw_json"])["details"]


@pytest.mark.parametrize(
    "kind,value,expected",
    [
        (3, -1, 255),
        (5, -32768, 0),
        (20, -1, -1),
        (148, [-1], [4294967295]),
        (131, [-1], [-1]),
        (133, [-32768], [-32768]),
    ],
)
def test_signed_numeric_variant_widths(
    helper: ModuleType, kind: int, value: Any, expected: Any
) -> None:
    assert helper._variant_value(_variant(helper, kind, value)) == expected


@pytest.mark.parametrize(
    "kind,expected",
    [
        (0, None),
        (1, ""),
        (2, ""),
        (14, []),
        (15, "00000000-0000-0000-0000-000000000000"),
        (19, None),
        (129, []),
        (135, []),
        (143, []),
        (145, []),
    ],
)
def test_null_native_property_pointers_keep_type_specific_values(
    helper: ModuleType, kind: int, expected: Any
) -> None:
    variant = helper._EventVariant()
    variant.type = kind
    assert helper._variant_value(variant) == expected


@pytest.mark.parametrize("kind", [128, 142, 144, 147, 163, 35, 127])
def test_framework_rejected_variant_kinds_are_rejected(
    helper: ModuleType, kind: int
) -> None:
    variant = helper._EventVariant()
    variant.type = kind
    with pytest.raises(ValueError):
        helper._variant_value(variant)


def test_system_time_property_uses_local_to_utc_conversion(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    buffer = ctypes.create_string_buffer(
        struct.pack("<8H", 2026, 9, 2, 29, 12, 0, 0, 125)
    )
    convert = Mock(return_value=_ticks(BOOT.replace(microsecond=125000)))
    monkeypatch.setattr(helper, "local_ticks_to_file_time", convert)
    variant = helper._EventVariant()
    variant.type = 18
    variant.value.pointer = ctypes.addressof(buffer)
    assert helper._variant_value(variant) == "/Date(1790683200125)/"
    expected = _ticks(BOOT.replace(microsecond=125000)) + 504911232000000000
    convert.assert_called_once_with(expected)


@pytest.mark.parametrize(
    "offset,expected", [(-10001, -1), (-9999, 0), (9999, 0), (10001, 1)]
)
def test_datetime_json_milliseconds_truncate_toward_zero(
    helper: ModuleType, offset: int, expected: int
) -> None:
    assert helper._json_date(116444736000000000 + offset) == f"/Date({expected})/"


@pytest.mark.parametrize("case", REFERENCE["native_variant_cases"]["variants"])
def test_numeric_decoder_matches_framework_reflection(
    helper: ModuleType, case: dict[str, Any]
) -> None:
    cases = {
        "sbyte_ff": (3, -1),
        "int16_ffff": (5, -1),
        "int16_0100": (5, 256),
        "hex32_ffffffff": (20, -1),
        "size_t_17": (16, 17),
    }
    actual = helper._variant_value(_variant(helper, *cases[case["id"]]))
    assert actual == json.loads(case["raw_json"])["value"]


@pytest.mark.parametrize("case", REFERENCE["native_variant_cases"]["sids"])
def test_account_domain_sid_preserves_depth_limited_json_chain(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, case: dict[str, Any]
) -> None:
    parts = [int(value) for value in case["sid"].split("-")[1:]]
    data = bytes([parts[0], len(parts) - 2]) + parts[1].to_bytes(6, "big")
    data += struct.pack(f"<{len(parts) - 2}L", *parts[2:])
    monkeypatch.setattr(
        helper, "_account_domain_sid", lambda _pointer: (24, "S-1-5-21-1-2-3")
    )
    value = helper._variant_value(_variant(helper, 19, data))
    expected = json.loads(case["raw_json"])["last_reboot"]["details"]
    assert value == expected["process"]
    assert helper._reason_code(value) == expected["reason_code"]


@pytest.mark.parametrize("error", [0, 1257, 5])
def test_native_domain_sid_read_distinguishes_non_account_sid(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, error: int
) -> None:
    # Load the original native boundary, not the portable fixture substitute.
    original = load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_reboot.py",
        "native_sid",
    )
    domain = b"\x01\x04\0\0\0\0\0\x05" + struct.pack("<4L", 21, 1, 2, 3)
    library = Mock()

    def _domain(_pointer: int, buffer: Any, size: Any) -> int:
        assert ctypes.cast(size, ctypes.POINTER(ctypes.c_uint32))[0] == 68
        ctypes.memmove(buffer, domain, len(domain))
        return 0 if error else 1

    library.GetWindowsAccountDomainSid.side_effect = _domain
    monkeypatch.setattr(ctypes, "WinDLL", Mock(return_value=library), raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: error)
    if error == 5:
        with pytest.raises(OSError):
            original._account_domain_sid(1)
    else:
        assert original._account_domain_sid(1) == (
            None if error else (24, "S-1-5-21-1-2-3")
        )
    assert helper._sid_object(None) is None
