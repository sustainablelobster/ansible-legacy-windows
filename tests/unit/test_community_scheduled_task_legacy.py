"""Exercise Scheduler 1.0 definitions, persistence and fixed COM layouts."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Boundary substitutes exercise the actual backend planning and ABI records.
# pylint: disable=protected-access

import copy
import ctypes
from types import ModuleType, SimpleNamespace
from typing import Any, cast
from uuid import UUID

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module

_DIRECTORY = ROOT / "legacy_community_windows/plugins/module_utils"


# These small test doubles expose the native boundary, not public Python contracts.
# pylint: disable=missing-function-docstring,missing-return-doc
class _Task:
    def __init__(self, scheduler: "_Scheduler", name: str) -> None:
        self.scheduler = scheduler
        self.name = name
        self.strings = {19: "", 21: "", 31: "", 33: "", 35: "", 37: ""}
        self.numbers = {16: 0x41303, 17: 0x41303, 29: 0xC0, 39: 0x20, 43: 259200000}
        self.records: list[Any] = []
        self.operations: list[tuple[Any, ...]] = []

    def string(self, slot: int) -> str:
        return self.strings[slot]

    def set_string(self, slot: int, value: str) -> None:
        self.operations.append(("string", slot, value))
        self.strings[slot + 1] = value

    def number(self, slot: int) -> int:
        return self.numbers[slot]

    def set_number(self, slot: int, value: int) -> None:
        self.operations.append(("number", slot, value))
        self.numbers[slot + 1] = value

    def account(self, name: str, password: str | None) -> None:
        self.operations.append(("account", name, password))
        self.strings[31] = name

    def triggers(self) -> list[Any]:
        return self.records

    def set_triggers(self, records: list[Any]) -> None:
        self.operations.append(("triggers",))
        self.records = records

    def time(self, slot: int) -> str | None:
        return None if slot == 15 else "2030-01-01T09:00:00"

    def idle(self) -> tuple[int, int]:
        return 10, 60

    def save(self) -> None:
        self.scheduler.saved += 1
        self.scheduler.tasks[self.name] = self
        if self.scheduler.save_error:
            raise OSError("controlled persistence failure")


class _Scheduler:
    def __init__(self) -> None:
        self.tasks: dict[str, _Task] = {}
        self.created: list[str] = []
        self.deleted: list[str] = []
        self.saved = 0
        self.save_error = False

    def __enter__(self) -> "_Scheduler":
        return self

    def __exit__(self, *_arguments: Any) -> None:
        return None

    def names(self) -> list[str]:
        return list(self.tasks)

    def task(self, name: str, create: bool = False) -> _Task:
        if create:
            self.created.append(name)
            return _Task(self, name)
        result = copy.copy(self.tasks[name])
        result.strings = dict(result.strings)
        result.numbers = dict(result.numbers)
        result.operations = []
        return result

    def delete(self, name: str) -> None:
        self.deleted.append(name)
        del self.tasks[name]


# pylint: enable=missing-function-docstring,missing-return-doc


@pytest.fixture(name="backend")
def fixture_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[ModuleType, ModuleType, _Scheduler]:
    """Load public validation and native records behind an in-memory service.

    :param monkeypatch: Scoped dependency and native-service replacements.
    :returns: Backend, public validation module and in-memory service.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(str(_DIRECTORY))
    common = load_module(
        _DIRECTORY / "legacy_community_windows_scheduled_task.py",
        "tested_legacy_common",
    )
    module = load_module(
        _DIRECTORY / "legacy_community_windows_scheduled_task_legacy.py",
        "tested_legacy_tasks",
    )
    scheduler = _Scheduler()
    monkeypatch.setattr(module, "LegacyScheduler", lambda: scheduler)
    sids = {
        "system": "S-1-5-18",
        "nt authority\\system": "S-1-5-18",
        "local service": "S-1-5-19",
        "network service": "S-1-5-20",
        "test\\user": "S-1-5-21-1-1000",
    }
    monkeypatch.setattr(
        module.account, "name_to_sid", lambda value: sids[value.lower()]
    )
    monkeypatch.setattr(
        module.account,
        "sid_to_name",
        lambda value: "NT AUTHORITY\\SYSTEM" if value == "S-1-5-18" else "TEST\\user",
    )
    return module, common, scheduler


def _options(common: ModuleType, **values: Any) -> dict[str, Any]:
    arguments = {
        "name": "legacy-task",
        "actions": [
            {"path": "C:\\Python34\\python.exe", "arguments": "-c print('雪')"}
        ],
        "username": "SYSTEM",
        "logon_type": "service_account",
        "description": "Café 雪",
        "execution_time_limit": "PT5M",
        "enabled": True,
        "triggers": [
            {
                "type": "daily",
                "start_boundary": "2030-01-01T09:00:00",
                "days_interval": 1,
            }
        ],
    }
    arguments.update(values)
    return cast(dict[str, Any], common.parameters(arguments))


@pytest.mark.parametrize("name", ["legacy-task", "legacy-task.v5r", "legacy-task.job"])
def test_create_repeat_update_preserve_and_delete(
    backend: tuple[ModuleType, ModuleType, _Scheduler],
    name: str,
) -> None:
    module, common, scheduler = backend
    options = _options(common, name=name)
    assert module.manage_legacy(options) == {"changed": True}
    task = scheduler.tasks[name]
    assert task.strings[31] == ""
    assert task.strings[19] == "Café 雪"
    assert task.numbers[43] == 300000
    assert task.records[0].data.daily.days_interval == 1
    assert module.manage_legacy(options) == {"changed": False}
    stat = module.stat_legacy("\\", name)
    assert stat["task_exists"] is True
    assert name in stat["folder_task_names"]
    update = common.parameters({"name": name.upper(), "description": "updated"})
    assert module.manage_legacy(update) == {"changed": True}
    assert scheduler.tasks[name].strings[33] == options["actions"][0]["path"]
    assert scheduler.tasks[name].strings[19] == "updated"
    assert module.manage_legacy(update) == {"changed": False}
    absent = common.parameters({"name": name, "state": "absent"})
    assert module.manage_legacy(absent) == {"changed": True}
    assert module.manage_legacy(absent) == {"changed": False}
    assert module.stat_legacy("\\", name)["task_exists"] is False
    assert scheduler.saved == 2


def test_check_mode_never_constructs_saves_or_deletes(
    backend: tuple[ModuleType, ModuleType, _Scheduler],
) -> None:
    module, common, scheduler = backend
    options = _options(common)
    assert module.manage_legacy(options, True, True)["changed"] is True
    assert scheduler.created == []
    module.manage_legacy(options)
    before = dict(scheduler.tasks["legacy-task"].strings)
    assert (
        module.manage_legacy(_options(common, description="preview"), True)["changed"]
        is True
    )
    assert scheduler.tasks["legacy-task"].strings == before
    assert (
        module.manage_legacy(
            common.parameters({"name": "legacy-task", "state": "absent"}), True
        )["changed"]
        is True
    )
    assert scheduler.saved == 1
    assert scheduler.deleted == []


@pytest.mark.parametrize("field", ["arguments", "description", "author"])
def test_case_only_edits_preserve_requested_text(
    backend: tuple[ModuleType, ModuleType, _Scheduler], field: str
) -> None:
    module, common, scheduler = backend
    initial = _options(common, description="TOKEN", author="TOKEN")
    initial["actions"][0]["arguments"] = "-c print('TOKEN')"
    module.manage_legacy(initial)
    update = copy.deepcopy(initial)
    if field == "arguments":
        update["actions"][0][field] = "-c print('token')"
    else:
        update[field] = "token"
    assert module.manage_legacy(update)["changed"] is True
    slot = {"arguments": 35, "description": 19, "author": 21}[field]
    expected = "-c print('token')" if field == "arguments" else "token"
    assert scheduler.tasks["legacy-task"].strings[slot] == expected
    assert module.manage_legacy(update)["changed"] is False


@pytest.mark.parametrize(
    "values, message",
    [
        ({"path": "\\folder"}, "folders"),
        ({"actions": [{"path": "one"}, {"path": "two"}]}, "multiple actions"),
        ({"source": "source"}, "source"),
        ({"group": "TEST", "username": None, "logon_type": "group"}, "group"),
        ({"run_level": "limited"}, "limited"),
        ({"logon_type": "s4u", "password": "private"}, "s4u"),
        ({"allow_demand_start": False}, "allow_demand_start"),
        ({"allow_hard_terminate": False}, "allow_hard_terminate"),
        ({"restart_count": 1}, "restart_count"),
        ({"restart_interval": "PT1M"}, "restart_interval"),
        ({"run_only_if_network_available": True}, "network"),
        ({"compatibility": 2}, "compatibility"),
        ({"priority": 7}, "priority"),
        ({"execution_time_limit": "P50D"}, "49-day"),
        (
            {"triggers": [{"type": "event", "subscription": "<QueryList/>"}]},
            "trigger type event",
        ),
        (
            {"triggers": [{"type": "time", "start_boundary": "2030-01-01T09:00:01"}]},
            "minute precision",
        ),
        (
            {"triggers": [{"type": "time", "start_boundary": "2030-01-01T09:00:00Z"}]},
            "timezone",
        ),
        ({"triggers": [{"type": "boot", "delay": "PT1M"}]}, "trigger delay"),
        ({"triggers": [{"type": "logon", "user_id": "TEST\\user"}]}, "user_id"),
        (
            {
                "triggers": [
                    {
                        "type": "daily",
                        "start_boundary": "2030-01-01T09:00:00",
                        "repetition": {"interval": "PT15S", "duration": "PT1H"},
                    }
                ]
            },
            "whole-minute",
        ),
    ],
)
def test_unavailable_features_fail_before_mutation(
    backend: tuple[ModuleType, ModuleType, _Scheduler],
    values: dict[str, Any],
    message: str,
) -> None:
    module, common, scheduler = backend
    with pytest.raises(ValueError, match=message):
        module.manage_legacy(_options(common, **values))
    assert scheduler.created == []
    assert scheduler.saved == 0


def test_empty_collections_clear_but_none_preserves(
    backend: tuple[ModuleType, ModuleType, _Scheduler],
) -> None:
    module, common, scheduler = backend
    module.manage_legacy(_options(common))
    assert (
        module.manage_legacy(common.parameters({"name": "legacy-task"}))["changed"]
        is False
    )
    clear = common.parameters({"name": "legacy-task", "actions": [], "triggers": []})
    assert module.manage_legacy(clear)["changed"] is True
    assert scheduler.tasks["legacy-task"].strings[33] == ""
    assert scheduler.tasks["legacy-task"].records == []
    assert module.manage_legacy(clear)["changed"] is False


def test_missing_create_action_is_actionable(
    backend: tuple[ModuleType, ModuleType, _Scheduler],
) -> None:
    module, common, scheduler = backend
    with pytest.raises(ValueError, match="cannot create a task with no actions"):
        module.manage_legacy(common.parameters({"name": "legacy-task"}))
    assert scheduler.created == []


def test_failed_creation_cleans_job_file_and_propagates(
    backend: tuple[ModuleType, ModuleType, _Scheduler],
) -> None:
    module, common, scheduler = backend
    scheduler.save_error = True
    with pytest.raises(OSError, match="controlled persistence failure"):
        module.manage_legacy(_options(common))
    assert scheduler.tasks == {}
    assert scheduler.deleted == ["legacy-task"]


def test_existing_save_failure_does_not_delete_task(
    backend: tuple[ModuleType, ModuleType, _Scheduler],
) -> None:
    module, common, scheduler = backend
    module.manage_legacy(_options(common))
    scheduler.save_error = True
    with pytest.raises(OSError, match="controlled persistence failure"):
        module.manage_legacy(_options(common, description="new"))
    assert "legacy-task" in scheduler.tasks
    assert scheduler.deleted == []


def test_interactive_flags_precede_null_password_credentials(
    backend: tuple[ModuleType, ModuleType, _Scheduler],
) -> None:
    module, common, scheduler = backend
    module.manage_legacy(
        _options(common, username="TEST\\user", logon_type="interactive_token")
    )
    operations = scheduler.tasks["legacy-task"].operations
    assert operations[-1] == ("account", "TEST\\user", None)
    assert scheduler.tasks["legacy-task"].numbers[29] & 0x2000


def test_stored_password_credentials_survive_metadata_update(
    backend: tuple[ModuleType, ModuleType, _Scheduler],
) -> None:
    module, common, scheduler = backend
    module.manage_legacy(
        _options(
            common, username="TEST\\user", logon_type="password", password="private"
        )
    )
    repeated = _options(
        common, username="TEST\\user", logon_type="password", password=None
    )
    assert module.manage_legacy(repeated)["changed"] is False
    repeated["description"] = "new"
    assert module.manage_legacy(repeated)["changed"] is True
    assert all(
        item[0] != "account" for item in scheduler.tasks["legacy-task"].operations
    )


def test_password_updates_respect_flag_and_do_not_leak_diff(
    backend: tuple[ModuleType, ModuleType, _Scheduler],
) -> None:
    module, common, _scheduler = backend
    options = _options(
        common, username="TEST\\user", logon_type="password", password="private"
    )
    module.manage_legacy(options)
    assert module.manage_legacy(options)["changed"] is True
    options["update_password"] = False
    assert module.manage_legacy(options)["changed"] is False
    options["update_password"] = True
    result = module.manage_legacy(options, True, True)
    assert "private" not in str(result)


def test_stat_reports_real_values_and_unavailable_nulls(
    backend: tuple[ModuleType, ModuleType, _Scheduler],
) -> None:
    module, common, _scheduler = backend
    module.manage_legacy(_options(common))
    result = module.stat_legacy("\\", "LEGACY-TASK")
    assert result["task_exists"] is True
    assert result["folder_task_names"] == ["legacy-task"]
    assert result["principal"]["logon_type"] == "TASK_LOGON_SERVICE_ACCOUNT"
    assert result["principal"]["run_level"] is None
    assert result["registration_info"]["description"] == "Café 雪"
    assert result["settings"]["execution_time_limit"] == "PT300S"
    assert result["triggers"][0]["type"] == "TASK_TRIGGER_DAILY"
    assert result["state"]["last_task_result"] == 0x41303
    assert result["state"]["last_run_time"] is None
    assert result["state"]["number_of_missed_runs"] is None
    assert result["warnings"]


def test_missing_folder_or_task_facts_do_not_invent_fields(
    backend: tuple[ModuleType, ModuleType, _Scheduler],
) -> None:
    module, _common, _scheduler = backend
    assert module.stat_legacy("\\folder", "task") == {
        "changed": False,
        "folder_exists": False,
        "task_exists": False,
    }
    result = module.stat_legacy("\\")
    assert result == {
        "changed": False,
        "folder_exists": True,
        "folder_task_names": [],
        "folder_task_count": 0,
    }


@pytest.mark.parametrize(
    "entry, fields",
    [
        (
            {"type": "weekly", "days_of_week": "monday,friday", "weeks_interval": 2},
            {"weeks_interval": 2, "days_of_week": "monday,friday"},
        ),
        (
            {
                "type": "monthly",
                "days_of_month": "1,31",
                "months_of_year": "january,december",
            },
            {"days_of_month": "1,31", "months_of_year": "january,december"},
        ),
        (
            {
                "type": "monthlydow",
                "weeks_of_month": "3",
                "days_of_week": "tuesday",
                "months_of_year": "march",
            },
            {
                "weeks_of_month": "3",
                "days_of_week": "tuesday",
                "months_of_year": "march",
            },
        ),
        (
            {
                "type": "monthlydow",
                "run_on_last_week_of_month": True,
                "days_of_week": "sunday",
            },
            {"weeks_of_month": "", "run_on_last_week_of_month": True},
        ),
    ],
)
def test_calendar_trigger_masks_roundtrip(
    backend: tuple[ModuleType, ModuleType, _Scheduler],
    entry: dict[str, Any],
    fields: dict[str, Any],
) -> None:
    module, common, _scheduler = backend
    entry = dict(entry, start_boundary="2030-01-01T09:00:00")
    module.manage_legacy(_options(common, triggers=[entry]))
    stat = module.stat_legacy("\\", "legacy-task")["triggers"][0]
    for key, value in fields.items():
        assert stat[key] == value
    assert module.manage_legacy(_options(common, triggers=[entry]))["changed"] is False


def test_repetition_and_trigger_enable_state_roundtrip(
    backend: tuple[ModuleType, ModuleType, _Scheduler],
) -> None:
    module, common, _scheduler = backend
    trigger = {
        "type": "daily",
        "start_boundary": "2030-01-01T09:00:00",
        "enabled": False,
        "repetition": {
            "interval": "PT5M",
            "duration": "PT1H",
            "stop_at_duration_end": True,
        },
    }
    module.manage_legacy(_options(common, triggers=[trigger]))
    stat = module.stat_legacy("\\", "legacy-task")["triggers"][0]
    assert stat["enabled"] is False
    assert stat["repetition"] == {
        "interval": "PT300S",
        "duration": "PT3600S",
        "stop_at_duration_end": True,
    }


def test_trigger_abi_has_sdk_size_and_offsets(
    backend: tuple[ModuleType, ModuleType, _Scheduler],
) -> None:
    module, _common, _scheduler = backend
    assert ctypes.sizeof(module.Trigger) == 48
    assert module.Trigger.duration.offset == 20
    assert module.Trigger.kind.offset == 32
    assert module.Trigger.data.offset == 36
    assert module.Trigger.reserved2.offset == 44


def test_native_exit_code_retains_never_run_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(HELPER.parent))
    native = load_module(
        _DIRECTORY / "legacy_community_windows_scheduled_task_legacy_native.py",
        "tested_legacy_native",
    )
    monkeypatch.setattr(native, "_call", lambda *_arguments: 0x41303)
    task = object.__new__(native.LegacyTask)
    task.pointer = ctypes.c_void_p(1)
    assert task.number(17) == 0x41303


def _native(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.syspath_prepend(str(HELPER.parent))
    return load_module(
        _DIRECTORY / "legacy_community_windows_scheduled_task_legacy_native.py",
        "tested_legacy_native_boundary",
    )


def _pointer(output: Any, value: int) -> None:
    ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p)).contents.value = value


def test_native_save_uses_ipersistfile_and_releases_interface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = _native(monkeypatch)
    operations: list[tuple[Any, ...]] = []
    released: list[Any] = []

    def _invoke(pointer: Any, slot: int, _types: Any, *values: Any) -> int:
        operations.append((pointer, slot, values))
        if slot == 0:
            identifier = UUID(bytes_le=ctypes.string_at(values[0], 16))
            assert str(identifier) == "0000010b-0000-0000-c000-000000000046"
            _pointer(values[1], 200)
        return 0

    monkeypatch.setattr(native, "_call", _invoke)
    monkeypatch.setattr(native, "_release", released.append)
    task = object.__new__(native.LegacyTask)
    task.pointer = ctypes.c_void_p(100)
    task.save()
    assert operations[1][1:] == (6, (None, 1))
    assert released[0].value == 200


def test_native_trigger_interfaces_release_after_read_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = _native(monkeypatch)
    released: list[Any] = []

    def _invoke(_pointer_value: Any, slot: int, _types: Any, *values: Any) -> int:
        if slot == 5:
            ctypes.cast(values[0], ctypes.POINTER(ctypes.c_uint16)).contents.value = 1
        elif slot == 6:
            assert values[0] == 0
            _pointer(values[1], 200)
        elif slot == 4:
            assert (
                ctypes.cast(values[0], ctypes.POINTER(native.Trigger)).contents.size
                == 48
            )
            raise OSError("controlled native trigger read failure")
        return 0

    monkeypatch.setattr(native, "_call", _invoke)
    monkeypatch.setattr(native, "_release", released.append)
    task = object.__new__(native.LegacyTask)
    task.pointer = ctypes.c_void_p(100)
    with pytest.raises(OSError, match="trigger read failure"):
        task.triggers()
    assert released[0].value == 200


@pytest.mark.parametrize(
    "name", ["Unicode-雪", "task.with.dots", "task.job", "task.JOB"]
)
def test_native_new_task_uses_documented_class_interface_and_slot(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    native = _native(monkeypatch)
    operations: list[tuple[Any, ...]] = []

    def _invoke(_pointer_value: Any, slot: int, _types: Any, *values: Any) -> int:
        operations.append((slot, values))
        assert values[0] == name + ".job"
        assert (
            str(UUID(bytes_le=ctypes.string_at(values[1], 16)))
            == "148bd520-a2ab-11ce-b11f-00aa00530503"
        )
        assert (
            str(UUID(bytes_le=ctypes.string_at(values[2], 16)))
            == "148bd524-a2ab-11ce-b11f-00aa00530503"
        )
        _pointer(values[3], 200)
        return 0

    monkeypatch.setattr(native, "_call", _invoke)
    monkeypatch.setattr(native, "LegacyTask", lambda _owner, pointer: pointer.value)
    scheduler = native.LegacyScheduler()
    assert scheduler.task(name, create=True) == 200
    assert operations[0][0] == 8


@pytest.mark.parametrize(
    "name", ["Unicode-雪", "task.with.dots", "task.job", "task.JOB"]
)
def test_native_activation_and_deletion_preserve_public_dotted_name(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    native = _native(monkeypatch)
    operations: list[int] = []

    def _invoke(_pointer_value: Any, slot: int, _types: Any, *values: Any) -> int:
        operations.append(slot)
        assert values[0] == name + ".job"
        if slot == 6:
            assert (
                str(UUID(bytes_le=ctypes.string_at(values[1], 16)))
                == "148bd524-a2ab-11ce-b11f-00aa00530503"
            )
            _pointer(values[2], 200)
        return 0

    monkeypatch.setattr(native, "_call", _invoke)
    monkeypatch.setattr(native, "LegacyTask", lambda _owner, pointer: pointer.value)
    scheduler = native.LegacyScheduler()
    assert scheduler.task(name) == 200
    scheduler.delete(name)
    assert operations == [6, 7]


@pytest.mark.parametrize(
    "name", ["Unicode-雪", "task.with.dots", "task.job", "task.JOB"]
)
def test_native_enumeration_strips_only_the_storage_suffix(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
) -> None:
    native = _native(monkeypatch)
    stored_name = ctypes.create_unicode_buffer(name + ".job")
    names = (ctypes.c_void_p * 1)(ctypes.addressof(stored_name))
    freed: list[Any] = []
    released: list[Any] = []

    def _invoke(_pointer_value: Any, slot: int, _types: Any, *values: Any) -> int:
        if slot == 5:
            _pointer(values[0], 200)
            return 0
        assert slot == 3
        _pointer(values[1], ctypes.addressof(names))
        ctypes.cast(values[2], ctypes.POINTER(ctypes.c_uint32)).contents.value = 1
        return 1

    monkeypatch.setattr(native, "_call", _invoke)
    monkeypatch.setattr(native, "_release", released.append)
    scheduler = native.LegacyScheduler()
    scheduler.ole32 = SimpleNamespace(CoTaskMemFree=freed.append)
    assert scheduler.names() == [name]
    assert len(freed) == 2
    assert released[0].value == 200


def test_native_task_time_preserves_local_components_and_absent_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = _native(monkeypatch)

    def _invoke(_pointer_value: Any, slot: int, _types: Any, *values: Any) -> int:
        if slot == 9:
            value = ctypes.cast(values[0], ctypes.POINTER(native._SystemTime)).contents
            value.year, value.month, value.day = 2030, 7, 15
            value.hour, value.minute, value.second = 9, 10, 11
            return 0
        return 0x41303

    monkeypatch.setattr(native, "_call", _invoke)
    task = object.__new__(native.LegacyTask)
    task.pointer = ctypes.c_void_p(100)
    assert task.time(9) == "2030-07-15T09:10:11"
    assert task.time(15) is None
