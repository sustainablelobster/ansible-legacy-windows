"""Exercise native Config2 decoding and the approved unsupported-field policy."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes expose structures and borrowed pointers without Windows access.
# pylint: disable=protected-access

import ctypes
import json
import struct
import uuid
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module

TRIGGER_CASES = json.loads(
    (ROOT / "tests/fixtures/service_info_trigger_data.json").read_text(encoding="utf-8")
)["cases"]
SERIALIZATION = json.loads(
    (ROOT / "tests/fixtures/service_info_serialization.json").read_text(
        encoding="utf-8"
    )
)
MODERN_FIELDS = [
    "start_mode",
    "failure_actions_on_non_crash_failure",
    "sid_info",
    "required_privileges",
    "pre_shutdown_timeout_ms",
    "triggers",
    "preferred_node",
    "launch_protection",
]


@pytest.fixture(name="helper")
def config_helper() -> ModuleType:
    """Load Config2 decoding without loading Windows libraries.

    :returns: Isolated configuration helper.
    """
    return load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_service_config.py",
        "tested_service_config",
    )


@pytest.fixture(name="native")
def native_configuration(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> SimpleNamespace:
    """Provide valid buffers and configurable native read errors.

    :param helper: Imported configuration helper.
    :param monkeypatch: Scoped Windows last-error substitution.
    :returns: Library, level records, and per-level error overrides.
    """
    library = Mock()
    errors: dict[int, int] = {}
    last_error = Mock(return_value=122)
    privileges = ctypes.create_string_buffer(
        "SeBackupPrivilege\0SeRestorePrivilege\0\0".encode("utf-16-le")
    )
    records = {
        1: helper._Description("description"),
        2: helper._FailureActions(30, None, "recover", 0, None),
        3: ctypes.c_uint32(1),
        4: ctypes.c_uint32(1),
        5: ctypes.c_uint32(3),
        6: ctypes.cast(privileges, ctypes.c_void_p),
        7: ctypes.c_uint32(180000),
        8: helper._Triggers(0, None, None),
        9: ctypes.c_uint16(17),
        12: ctypes.c_uint32(3),
    }

    def _query(_service: int, level: int, buffer: Any, size: int, needed: Any) -> int:
        if level in errors:
            last_error.return_value = errors[level]
            return 0
        record = records[level]
        required = ctypes.sizeof(record)
        ctypes.cast(needed, ctypes.POINTER(ctypes.c_uint32))[0] = required
        if size < required:
            last_error.return_value = 122
            return 0
        ctypes.memmove(buffer, ctypes.byref(record), required)
        return 1

    library.QueryServiceConfig2W.side_effect = _query
    monkeypatch.setattr(ctypes, "get_last_error", last_error, raising=False)
    return SimpleNamespace(
        library=library, records=records, errors=errors, last_error=last_error
    )


def _data_item(helper: ModuleType, kind: int, data: bytes) -> Any:
    buffer = ctypes.create_string_buffer(data)
    return helper._TriggerData(kind, len(data), ctypes.cast(buffer, ctypes.c_void_p))


def _trigger(
    helper: ModuleType, kind: int, action: int, guid: str, items: list[Any]
) -> Any:
    guid_buffer = ctypes.create_string_buffer(uuid.UUID(guid).bytes_le)
    return helper._Trigger(
        kind,
        action,
        ctypes.cast(guid_buffer, ctypes.c_void_p),
        len(items),
        (helper._TriggerData * len(items))(*items),
    )


def test_reads_all_config2_fields_and_copies_privileges(
    helper: ModuleType, native: SimpleNamespace
) -> None:
    warnings: list[str] = []
    result = helper.query_config(native.library, 202, "service", "auto", warnings)
    assert result == {
        "description": "description",
        "failure_actions": [],
        "failure_command": "recover",
        "failure_reboot_msg": None,
        "failure_reset_period_sec": 30,
        "start_mode": "delayed",
        "failure_actions_on_non_crash_failure": True,
        "sid_info": "restricted",
        "required_privileges": ["SeBackupPrivilege", "SeRestorePrivilege"],
        "pre_shutdown_timeout_ms": 180000,
        "triggers": [],
        "preferred_node": 17,
        "launch_protection": "antimalware_light",
    }
    assert not warnings
    ctypes.memset(native.records[6], 0, 2)
    assert result["required_privileges"] == ["SeBackupPrivilege", "SeRestorePrivilege"]
    assert {
        entry.args[0] for entry in native.library.QueryServiceConfig2W.call_args_list
    } == {202}


@pytest.mark.parametrize("empty", [None, ""])
def test_nullable_and_empty_config2_strings_remain_distinct(
    helper: ModuleType, native: SimpleNamespace, empty: str | None
) -> None:
    native.records[1].description = empty
    native.records[2].command = empty
    native.records[2].reboot_message = empty
    result = helper.query_config(native.library, 202, "service", "auto", [])
    assert result["description"] == empty
    assert result["failure_command"] == empty
    assert result["failure_reboot_msg"] == empty
    assert result["failure_actions"] == []


@pytest.mark.parametrize("observation", SERIALIZATION["switches"])
def test_failure_action_types_match_recorded_reference_serialization(
    helper: ModuleType, native: SimpleNamespace, observation: dict[str, Any]
) -> None:
    actions = (helper._FailureAction * 1)((observation["input"], 0))
    native.records[2].count = 1
    native.records[2].actions = actions
    result = helper.query_config(native.library, 202, "service", "auto", [])
    assert result["failure_actions"] == [
        {
            "type": observation["inline"]["type"],
            "delay_ms": 0,
        }
    ]


@pytest.mark.parametrize("mode", ["boot", "system", "manual", "disabled", {}])
def test_nonautomatic_start_never_queries_delayed_start(
    helper: ModuleType, native: SimpleNamespace, mode: str | dict[str, str]
) -> None:
    native.errors[3] = 124
    warnings: list[str] = []
    result = helper.query_config(native.library, 202, "service", mode, warnings)
    assert result["start_mode"] == mode
    assert 3 not in [
        entry.args[1] for entry in native.library.QueryServiceConfig2W.call_args_list
    ]
    assert not warnings


def test_all_unsupported_modern_fields_are_null_with_one_ordered_warning(
    helper: ModuleType, native: SimpleNamespace
) -> None:
    native.errors.update({level: 124 for level in (3, 4, 5, 6, 7, 8, 9, 12)})
    expected = helper.query_config(native.library, 202, "service", "auto", [])
    for _ in range(2):
        warnings: list[str] = []
        result = helper.query_config(native.library, 202, "service", "auto", warnings)
        assert result == expected
        assert {field: result[field] for field in MODERN_FIELDS} == dict.fromkeys(
            MODERN_FIELDS
        )
        assert result["description"] == "description"
        assert result["failure_command"] == "recover"
        assert warnings == [
            "Service 'service': fields "
            + ", ".join(MODERN_FIELDS)
            + " are unavailable (Windows error 124); returning null for those fields."
            + " Automatic and delayed automatic start cannot be distinguished."
        ]
    native.errors.clear()
    recovered_warnings: list[str] = []
    assert (
        helper.query_config(native.library, 202, "service", "auto", recovered_warnings)[
            "start_mode"
        ]
        == "delayed"
    )
    assert not recovered_warnings


@pytest.mark.parametrize("mode", ["manual", "disabled", "boot", "system"])
def test_unsupported_modern_fields_do_not_erase_known_start_mode(
    helper: ModuleType, native: SimpleNamespace, mode: str
) -> None:
    native.errors.update({level: 124 for level in (3, 4, 5, 6, 7, 8, 9, 12)})
    warnings: list[str] = []
    assert (
        helper.query_config(native.library, 202, "service", mode, warnings)[
            "start_mode"
        ]
        == mode
    )
    assert "start_mode" not in warnings[0]
    assert "cannot be distinguished" not in warnings[0]


@pytest.mark.parametrize(
    ("level", "field", "expected"),
    [
        (3, "start_mode", {}),
        (4, "failure_actions_on_non_crash_failure", None),
        (6, "required_privileges", None),
        (7, "pre_shutdown_timeout_ms", None),
        (8, "triggers", []),
        (9, "preferred_node", None),
        (12, "launch_protection", "none"),
    ],
)
def test_other_getter_failures_keep_reference_shapes_without_unsupported_warning(
    helper: ModuleType, native: SimpleNamespace, level: int, field: str, expected: Any
) -> None:
    baseline = helper.query_config(native.library, 202, "service", "auto", [])
    native.errors[level] = 5
    warnings: list[str] = []
    result = helper.query_config(native.library, 202, "service", "auto", warnings)
    assert result == dict(baseline, **{field: expected})
    assert not warnings
    native.errors.clear()
    assert helper.query_config(native.library, 202, "service", "auto", []) == baseline


def test_preferred_node_error87_is_normal_null_without_warning(
    helper: ModuleType, native: SimpleNamespace
) -> None:
    native.errors[9] = 87
    warnings: list[str] = []
    assert (
        helper.query_config(native.library, 202, "service", "auto", warnings)[
            "preferred_node"
        ]
        is None
    )
    assert not warnings


@pytest.mark.parametrize("code", [2, 5, 87])
def test_sid_failure_is_fatal_unless_the_level_is_unsupported(
    helper: ModuleType, native: SimpleNamespace, code: int
) -> None:
    native.errors[5] = code
    warnings: list[str] = []
    with pytest.raises(
        ValueError, match="cannot call a method on a null-valued expression"
    ):
        helper.query_config(native.library, 202, "service", "auto", warnings)
    assert not warnings


@pytest.mark.parametrize("value", [0, 1, 3, 99, 0xFFFFFFFF])
def test_sid_type_names_and_unknown_numeric_values(
    helper: ModuleType, native: SimpleNamespace, value: int
) -> None:
    native.records[5].value = value
    result = helper.query_config(native.library, 202, "service", "auto", [])
    assert result["sid_info"] == {0: "none", 1: "unrestricted", 3: "restricted"}.get(
        value, str(value)
    )


@pytest.mark.parametrize("value", [0, 1, 2, 3, 99])
def test_launch_protection_names_and_unknown_switch_values(
    helper: ModuleType, native: SimpleNamespace, value: int
) -> None:
    native.records[12].value = value
    result = helper.query_config(native.library, 202, "service", "auto", [])
    assert result["launch_protection"] == {
        0: "none",
        1: "windows",
        2: "windows_light",
        3: "antimalware_light",
    }.get(value, {})


@pytest.mark.parametrize("value", [0, 1, 2, 0xFFFFFFFF])
def test_native_bool_fields_treat_any_nonzero_dword_as_true(
    helper: ModuleType, native: SimpleNamespace, value: int
) -> None:
    native.records[3].value = value
    native.records[4].value = value
    result = helper.query_config(native.library, 202, "service", "auto", [])
    assert result["start_mode"] == ("delayed" if value else "auto")
    assert result["failure_actions_on_non_crash_failure"] is bool(value)


@pytest.mark.parametrize(
    "case", TRIGGER_CASES, ids=[row["id"] for row in TRIGGER_CASES]
)
def test_trigger_item_decoding_matches_raw_reference(
    helper: ModuleType, case: dict[str, Any]
) -> None:
    item = _data_item(helper, case["type"], bytes(case["bytes"]))
    if case["accepted"]:
        decoded = helper._trigger_item(item)
        assert decoded["data"] == case["value"]
        assert decoded["type"] == {
            1: "binary",
            2: "string",
            3: "level",
            4: "keyword_any",
            5: "keyword_all",
        }.get(case["type"], {})
    else:
        with pytest.raises((ValueError, IndexError, struct.error)):
            helper._trigger_item(item)


@pytest.mark.parametrize("kind", [1, 2, 3, 4, 5, 6, 20, 99])
@pytest.mark.parametrize("action", [1, 2, 99])
def test_trigger_arrays_preserve_order_types_guid_endianness_and_data(
    helper: ModuleType, native: SimpleNamespace, kind: int, action: int
) -> None:
    guid = "bc90d167-9470-4139-a9ba-be0bbbf5b74d"
    first = _trigger(
        helper,
        kind,
        action,
        guid,
        [
            _data_item(helper, 1, b"\0\xff"),
            _data_item(helper, 2, "first\0second\0\0".encode("utf-16-le")),
        ],
    )
    second_guid = "01234567-89ab-cdef-0123-456789abcdef"
    second = _trigger(helper, 20, 2, second_guid, [])
    native.records[8] = helper._Triggers(2, (helper._Trigger * 2)(first, second), None)
    result = helper.query_config(native.library, 202, "service", "manual", [])[
        "triggers"
    ]
    assert result == [
        {
            "action": {1: "start_service", 2: "stop_service"}.get(action, {}),
            "type": {
                1: "device_interface_arrival",
                2: "ip_address_availability",
                3: "domain_join",
                4: "firewall_port_event",
                5: "group_policy",
                6: "network_endpoint",
                20: "custom",
            }.get(kind, {}),
            "sub_type": "rpc_interface_event",
            "sub_type_guid": guid,
            "data_items": [
                {"type": "binary", "data": "AP8="},
                {"type": "string", "data": ["first", "second"]},
            ],
        },
        {
            "action": "stop_service",
            "type": "custom",
            "sub_type": "custom",
            "sub_type_guid": second_guid,
            "data_items": [],
        },
    ]
    first.type = 999
    assert result[0]["type"] != "999"


@pytest.mark.parametrize(
    ("guid", "expected"),
    [
        ("1f81d131-3fac-4537-9e0c-7e7b0c2f4b55", "named_pipe_event"),
        ("1ce20aba-9851-4421-9430-1ddeb766e809", "domain_join"),
        ("ddaf516e-58c2-4866-9574-c3b615d42ea1", "domain_leave"),
        ("b7569e07-8421-4ee0-ad10-86915afdad09", "firewall_port_open"),
        ("a144ed38-8e12-4de4-9d96-e64740b1a524", "firewall_port_close"),
        ("659fcae6-5bdb-4da9-b1ff-ca2a178d46e0", "machine_policy_present"),
        ("54fb46c8-f089-464c-b1fd-59d1b62c3b50", "user_policy_present"),
        ("4f27f2de-14e2-430b-a549-7cd48cbc8245", "network_first_ip_arrival"),
        ("cc4ba62a-162e-4648-847a-b6bdf993e335", "network_last_ip_removal"),
    ],
)
def test_known_trigger_subtypes(
    helper: ModuleType, native: SimpleNamespace, guid: str, expected: str
) -> None:
    trigger = _trigger(helper, 1, 1, guid, [])
    native.records[8] = helper._Triggers(1, (helper._Trigger * 1)(trigger), None)
    assert (
        helper.query_config(native.library, 202, "service", "manual", [])["triggers"][
            0
        ]["sub_type"]
        == expected
    )


@pytest.mark.parametrize(
    "case",
    [row for row in TRIGGER_CASES if not row["accepted"]],
    ids=lambda row: row["id"],
)
def test_one_bad_item_discards_entire_trigger_getter_then_recovers(
    helper: ModuleType, native: SimpleNamespace, case: dict[str, Any]
) -> None:
    guid = "bc90d167-9470-4139-a9ba-be0bbbf5b74d"
    good = _trigger(helper, 6, 1, guid, [_data_item(helper, 1, b"ok")])
    bad = _trigger(
        helper, 6, 1, guid, [_data_item(helper, case["type"], bytes(case["bytes"]))]
    )
    native.records[8] = helper._Triggers(2, (helper._Trigger * 2)(good, bad), None)
    warnings: list[str] = []
    failed_getter = helper.query_config(
        native.library, 202, "service", "auto", warnings
    )
    assert failed_getter["triggers"] == []
    assert failed_getter["description"] == "description"
    assert not warnings
    native.records[8] = helper._Triggers(1, (helper._Trigger * 1)(good), None)
    assert (
        len(helper.query_config(native.library, 202, "service", "auto", [])["triggers"])
        == 1
    )


def test_native_structure_widths_do_not_assume_boolean_is_dword(
    helper: ModuleType,
) -> None:
    width = ctypes.sizeof(ctypes.c_void_p)
    assert ctypes.sizeof(helper._FailureAction) == 8
    assert ctypes.sizeof(helper._FailureActions) == (40 if width == 8 else 20)
    assert ctypes.sizeof(helper._TriggerData) == (16 if width == 8 else 12)
    assert ctypes.sizeof(helper._Trigger) == (32 if width == 8 else 20)
    assert ctypes.sizeof(helper._Triggers) == (24 if width == 8 else 12)


def test_query_buffer_retries_growth_and_preserves_error_code(
    helper: ModuleType, native: SimpleNamespace
) -> None:
    sizes = []

    def _query(_service: int, _level: int, buffer: Any, size: int, needed: Any) -> int:
        sizes.append(size)
        ctypes.cast(needed, ctypes.POINTER(ctypes.c_uint32))[0] = 8 * len(sizes)
        if len(sizes) < 3:
            native.last_error.return_value = 122
            return 0
        buffer[0] = b"x"
        return 1

    native.library.QueryServiceConfig2W.side_effect = _query
    buffer, error = helper._read_buffer(native.library, 202, 3)
    assert sizes == [0, 8, 16]
    assert buffer[0] == b"x"
    assert error == 0
