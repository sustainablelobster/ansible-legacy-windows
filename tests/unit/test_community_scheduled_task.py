"""Exercise task definitions, lifecycle and information at the native boundary."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Native-boundary substitutes retain actual argument validation and task logic.
# pylint: disable=protected-access

import copy
import sys
from types import ModuleType
from typing import Any
from unittest.mock import patch
from xml.sax.saxutils import escape

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module


# These private doubles mirror native Automation methods; the lifecycle tests
# specify their contract without documenting a second public object API.
# pylint: disable=missing-function-docstring,missing-return-doc,too-few-public-methods
class _Object:
    def __init__(self, values: dict[str, Any] | None = None) -> None:
        self.values = values or {}

    def get(self, name: str) -> Any:
        return self.values.get(name)

    def put(self, name: str, value: Any) -> None:
        self.values[name] = value

    def properties(self) -> dict[str, Any]:
        return dict(self.values)


class _Collection:
    def __init__(self, actions: bool = False) -> None:
        self.actions = actions
        self.values: list[Any] = []

    def items(self) -> list[Any]:
        return list(self.values)

    def get(self, name: str) -> int:
        assert name == "Count"
        return len(self.values)

    def call(self, name: str, *arguments: Any) -> Any:
        if name == "Clear":
            self.values.clear()
            return None
        assert name == "Create"
        values = {"Type": arguments[0], "Id": None}
        if self.actions:
            values.update(Path=None, Arguments=None, WorkingDirectory=None)
        else:
            values.update(
                Enabled=True,
                StartBoundary=None,
                EndBoundary=None,
                ExecutionTimeLimit=None,
                Repetition=_Object(
                    {"Interval": None, "Duration": None, "StopAtDurationEnd": False}
                ),
                DaysInterval=1,
                WeeksInterval=1,
                DaysOfWeek=0,
                DaysOfMonth=0,
                MonthsOfYear=4095,
                WeeksOfMonth=0,
                RunOnLastWeekOfMonth=False,
                RunOnLastDayOfMonth=False,
                RandomDelay=None,
                Delay=None,
                Subscription=None,
                UserId=None,
                StateChange=1,
            )
        result = _Object(values)
        self.values.append(result)
        return result


class _Definition(_Object):
    def get(self, name: str) -> Any:
        if name != "XmlText":
            return super().get(name)
        principal = self.values["Principal"].values
        identities = "".join(
            f"<{key}>{escape(principal[key])}</{key}>"
            for key in ("UserId", "GroupId")
            if principal[key]
        )
        return (
            '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
            "<Principals><Principal>" + identities + "</Principal></Principals></Task>"
        )


class _Folder:
    def __init__(self, scheduler: "_Scheduler", path: str) -> None:
        self.scheduler = scheduler
        self.path = path
        self.tasks: dict[str, _Object] = {}

    def call(self, name: str, *arguments: Any) -> Any:
        if name in ("GetTasks", "GetFolders"):
            collection = _Collection()
            collection.values = list(self.tasks.values()) if name == "GetTasks" else []
            return collection
        if name == "CreateFolder":
            folder = _Folder(self.scheduler, arguments[0])
            self.scheduler.folders[arguments[0]] = folder
            return folder
        if name == "DeleteFolder":
            del self.scheduler.folders[arguments[0]]
            return None
        if name == "DeleteTask":
            del self.tasks[arguments[0]]
            return None
        assert name == "RegisterTaskDefinition"
        self.scheduler.registrations.append(arguments)
        task_name, definition, flags, _user, _password, _logon_type = arguments
        if self.scheduler.registration_error:
            raise OSError("controlled scheduler registration failure")
        if flags != 1:
            task = _Object(
                {
                    "Name": task_name,
                    "Definition": copy.deepcopy(definition),
                    "State": 3,
                    "LastRunTime": "1899-12-30T00:00:00",
                    "LastTaskResult": 0,
                    "NextRunTime": "2030-01-01T00:00:00",
                    "NumberOfMissedRuns": 0,
                }
            )
            self.tasks[task_name] = task
            return task
        return None


class _Scheduler:
    def __init__(self, settings: dict[str, str]) -> None:
        self.service = self
        self.settings = settings
        self.folders = {"\\": _Folder(self, "\\")}
        self.registrations: list[tuple[Any, ...]] = []
        self.registration_error = False

    def __enter__(self) -> "_Scheduler":
        return self

    def __exit__(self, *_arguments: object) -> None:
        return None

    def call(self, name: str, *arguments: Any) -> Any:
        if name == "GetFolder":
            if arguments[0] not in self.folders:
                error = OSError("folder not found")
                setattr(error, "hresult", 0x80070002)
                raise error
            return self.folders[arguments[0]]
        assert name == "NewTask"
        return _Definition(
            {
                "Principal": _Object(
                    {
                        "DisplayName": None,
                        "UserId": None,
                        "GroupId": None,
                        "LogonType": 0,
                        "RunLevel": 0,
                        "Id": None,
                    }
                ),
                "RegistrationInfo": _Object(
                    {
                        name: None
                        for name in (
                            "Author",
                            "Date",
                            "Description",
                            "Source",
                            "Version",
                        )
                    }
                ),
                "Settings": _Object({name: None for name in self.settings.values()}),
                "Actions": _Collection(actions=True),
                "Triggers": _Collection(),
            }
        )


# pylint: enable=missing-function-docstring,missing-return-doc,too-few-public-methods


@pytest.fixture(name="payload")
def scheduled_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[ModuleType, ModuleType, _Scheduler]:
    """Load task frontends with actual validation and isolated native state.

    :param monkeypatch: Scoped imports and native-boundary substitutions.
    :returns: Task helper, information helper and their shared native substitute.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(
        str(ROOT / "legacy_community_windows/plugins/module_utils")
    )
    load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_scheduled_task.py",
        "tested_community_scheduled_task",
    )
    load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_scheduled_task_stat.py",
        "tested_community_scheduled_task_stat",
    )
    helper = sys.modules["legacy_community_windows_scheduled_task"]
    facts = sys.modules["legacy_community_windows_scheduled_task_stat"]
    scheduler = _Scheduler(helper.SETTINGS)
    monkeypatch.setattr(helper, "TaskScheduler", lambda: scheduler)
    monkeypatch.setattr(facts, "TaskScheduler", lambda: scheduler)
    identities = {
        "SYSTEM": "S-1-5-18",
        "NT AUTHORITY\\SYSTEM": "S-1-5-18",
        "HOST\\Administrator": "S-1-5-21-1-500",
        "Administrator": "S-1-5-21-1-500",
    }
    monkeypatch.setattr(
        helper.account, "name_to_sid", lambda name: identities.get(name, name)
    )
    monkeypatch.setattr(
        helper.account,
        "sid_to_name",
        lambda sid: {
            "S-1-5-18": "NT AUTHORITY\\SYSTEM",
            "S-1-5-21-1-500": "HOST\\Administrator",
        }.get(sid, sid),
    )
    monkeypatch.setattr(helper, "_current_account", lambda: "HOST\\Administrator")
    monkeypatch.setattr(helper, "require_running_service", lambda: None)
    return helper, facts, scheduler


def _apply(
    payload: tuple[ModuleType, ModuleType, _Scheduler], **options: Any
) -> dict[str, Any]:
    helper, _facts, _scheduler = payload
    check_mode, diff_mode = options.pop("check", False), options.pop("diff", False)
    result: dict[str, Any] = helper.manage(
        helper.parameters({"name": "Fixture", **options}), check_mode, diff_mode
    )
    return result


def _definition(
    payload: tuple[ModuleType, ModuleType, _Scheduler], path: str = "\\"
) -> _Definition:
    result: _Definition = payload[2].folders[path].tasks["Fixture"].get("Definition")
    return result


def test_create_query_repeat_update_and_remove(
    payload: tuple[ModuleType, ModuleType, _Scheduler],
) -> None:
    options = {
        "actions": [{"path": "cmd.exe", "arguments": "/c echo marker"}],
        "triggers": [{"type": "daily", "start_boundary": "2030-01-01T09:00:00"}],
        "username": "SYSTEM",
        "logon_type": "service_account",
        "description": "Café 雪",
    }
    assert _apply(payload, **options)["changed"] is True
    assert _apply(payload, **options)["changed"] is False
    result = payload[1].inspect("\\", "Fixture")
    assert result["task_exists"] is True
    assert result["folder_task_names"] == ["Fixture"]
    assert result["principal"]["user_id"] == "NT AUTHORITY\\SYSTEM"
    assert result["principal"]["logon_type"] == "TASK_LOGON_SERVICE_ACCOUNT"
    assert result["actions"][0]["type"] == "TASK_ACTION_EXEC"
    assert result["triggers"][0]["type"] == "TASK_TRIGGER_DAILY"
    assert _apply(payload, description="updated")["changed"] is True
    assert _apply(payload, state="absent")["changed"] is True
    assert _apply(payload, state="absent")["changed"] is False


def test_check_mode_validates_without_creating_folder_or_task(
    payload: tuple[ModuleType, ModuleType, _Scheduler],
) -> None:
    result = _apply(
        payload, path="\\Private", actions=[{"path": "cmd.exe"}], check=True, diff=True
    )
    assert result["changed"] is True
    assert "\\Private" not in payload[2].folders
    assert not payload[2].folders["\\"].tasks
    assert len(payload[2].registrations) == 1
    assert payload[2].registrations[0][2] == 1


def test_creating_folder_validates_definition_before_mutation(
    payload: tuple[ModuleType, ModuleType, _Scheduler],
) -> None:
    payload[2].registration_error = True
    with pytest.raises(OSError, match="controlled scheduler registration failure"):
        _apply(payload, path="\\Private", actions=[{"path": "cmd.exe"}])
    assert "\\Private" not in payload[2].folders


@pytest.mark.parametrize("check_mode", [False, True])
def test_stopped_service_fails_before_native_registration_or_folder_changes(
    payload: tuple[ModuleType, ModuleType, _Scheduler],
    monkeypatch: pytest.MonkeyPatch,
    check_mode: bool,
) -> None:
    def _stopped() -> None:
        raise OSError("Task Scheduler service must be running")

    monkeypatch.setattr(payload[0], "require_running_service", _stopped)
    with pytest.raises(OSError, match="must be running"):
        _apply(
            payload, path="\\Private", actions=[{"path": "cmd.exe"}], check=check_mode
        )
    assert not payload[2].registrations
    assert "\\Private" not in payload[2].folders


def test_folder_lifecycle_and_read_only_missing_facts(
    payload: tuple[ModuleType, ModuleType, _Scheduler],
) -> None:
    assert payload[1].inspect("\\Missing", "Fixture") == {
        "changed": False,
        "folder_exists": False,
        "task_exists": False,
    }
    _apply(payload, path="Private", actions=[{"path": "cmd.exe"}])
    assert "\\Private" in payload[2].folders
    assert payload[1].inspect("\\Private")["folder_task_count"] == 1
    _apply(payload, path="Private", state="absent")
    assert "\\Private" not in payload[2].folders


def test_ordered_actions_preserve_omitted_optional_values(
    payload: tuple[ModuleType, ModuleType, _Scheduler],
) -> None:
    _apply(
        payload,
        actions=[
            {
                "path": "first.exe",
                "arguments": "retained",
                "working_directory": "C:\\Work",
            },
            {"path": "second.exe"},
        ],
    )
    assert (
        _apply(payload, actions=[{"path": "first.exe"}, {"path": "second.exe"}])[
            "changed"
        ]
        is False
    )
    assert (
        _apply(payload, actions=[{"path": "second.exe"}, {"path": "first.exe"}])[
            "changed"
        ]
        is True
    )
    action = _definition(payload).get("Actions").items()[0]
    assert action.get("Path") == "second.exe"
    assert action.get("Arguments") == "retained"
    assert action.get("WorkingDirectory") == "C:\\Work"


def test_trigger_masks_repetition_and_omitted_values_are_idempotent(
    payload: tuple[ModuleType, ModuleType, _Scheduler],
) -> None:
    trigger = {
        "type": "weekly",
        "days_of_week": ["monday", "FRIDAY"],
        "start_boundary": "2030-01-01T09:00:00",
        "weeks_interval": 2,
        "repetition": {
            "interval": "PT1M",
            "duration": "PT1H",
            "stop_at_duration_end": True,
        },
    }
    _apply(payload, actions=[{"path": "cmd.exe"}], triggers=[trigger])
    assert _apply(payload, triggers=[trigger])["changed"] is False
    changed = dict(trigger, weeks_interval=3)
    assert _apply(payload, triggers=[changed])["changed"] is True
    result = payload[1].inspect("\\", "Fixture")
    assert result["triggers"][0]["days_of_week"] == "monday,friday"
    assert result["triggers"][0]["repetition"]["interval"] == "PT1M"


def test_password_updates_follow_update_password_contract(
    payload: tuple[ModuleType, ModuleType, _Scheduler],
) -> None:
    _apply(
        payload,
        actions=[{"path": "cmd.exe"}],
        username="Administrator",
        logon_type="password",
        password="fixture secret",
        update_password=False,
    )
    assert (
        _apply(payload, password="fixture secret", update_password=False)["changed"]
        is False
    )
    assert _apply(payload, password="fixture secret")["changed"] is True
    assert payload[2].registrations[-1][4] == "fixture secret"
    _apply(payload, description="changed without password")
    assert payload[2].registrations[-1][3:] == (None, None, None)


@pytest.mark.parametrize(
    "options,message",
    [
        ({"name": "bad/name"}, "Invalid task name"),
        ({"username": "user", "group": "group"}, "can not be set"),
        ({"logon_type": "s4u"}, "password must be set"),
        ({"logon_type": "group"}, "group must be set"),
        ({"actions": [{}]}, "action entry"),
        ({"actions": "not-list"}, "actions must be a list"),
        ({"triggers": [{}]}, "valid type"),
        ({"triggers": [{"type": "weekly"}]}, "requires days_of_week"),
        ({"triggers": [{"type": "daily", "start_boundary": "invalid"}]}, "YYYY-MM-DD"),
        (
            {"triggers": [{"type": "daily", "start_boundary": "2030-02-30T00:00:00"}]},
            "invalid date",
        ),
        ({"triggers": [{"type": "boot", "delay": "invalid"}]}, "XML duration"),
        (
            {
                "triggers": [
                    {
                        "type": "logon",
                        "repetition": {"interval": "PT2H", "duration": "PT1H"},
                    }
                ]
            },
            "less than or equal",
        ),
        (
            {
                "triggers": [
                    {
                        "type": "monthly",
                        "start_boundary": "2030-01-01T00:00:00",
                        "days_of_month": "32",
                    }
                ]
            },
            "Invalid days_of_month",
        ),
    ],
)
def test_invalid_options_fail_without_registering(
    payload: tuple[ModuleType, ModuleType, _Scheduler],
    options: dict[str, Any],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _apply(payload, **options)
    assert not payload[2].registrations


def test_no_actions_cannot_create_task(
    payload: tuple[ModuleType, ModuleType, _Scheduler],
) -> None:
    with pytest.raises(ValueError, match="cannot create a task with no actions"):
        _apply(payload)
    assert not payload[2].registrations


def test_absence_check_mode_preserves_task(
    payload: tuple[ModuleType, ModuleType, _Scheduler],
) -> None:
    _apply(payload, actions=[{"path": "cmd.exe"}])
    assert _apply(payload, state="absent", check=True)["changed"] is True
    assert payload[1].inspect("\\", "Fixture")["task_exists"] is True


@pytest.mark.parametrize(
    "kind,fields",
    [
        ("event", {"subscription": "<QueryList/>"}),
        ("time", {"start_boundary": "2030-01-01T09:00:00"}),
        ("daily", {"start_boundary": "2030-01-01T09:00:00", "days_interval": 2}),
        (
            "weekly",
            {"start_boundary": "2030-01-01T09:00:00", "days_of_week": "monday,friday"},
        ),
        (
            "monthly",
            {
                "start_boundary": "2030-01-01T09:00:00",
                "days_of_month": "1,31",
                "months_of_year": "january,december",
            },
        ),
        (
            "monthlydow",
            {
                "start_boundary": "2030-01-01T09:00:00",
                "days_of_week": "sunday",
                "weeks_of_month": "1,4",
                "run_on_last_week_of_month": True,
            },
        ),
        ("idle", {}),
        ("registration", {"delay": "PT1M"}),
        ("boot", {"delay": "PT1M"}),
        ("logon", {"user_id": "Administrator"}),
        ("session_state_change", {"state_change": "session_unlock"}),
    ],
)
def test_every_released_trigger_kind_is_built_and_repeated(
    payload: tuple[ModuleType, ModuleType, _Scheduler],
    kind: str,
    fields: dict[str, Any],
) -> None:
    options = {"actions": [{"path": "cmd.exe"}], "triggers": [{"type": kind, **fields}]}
    assert _apply(payload, **options)["changed"] is True
    assert _apply(payload, **options)["changed"] is False
    facts = payload[1].inspect("\\", "Fixture")
    assert facts["triggers"][0]["type"] == "TASK_TRIGGER_" + kind.upper()


def test_sid_identity_comparison_does_not_repeat_domain_name_changes(
    payload: tuple[ModuleType, ModuleType, _Scheduler],
) -> None:
    _apply(payload, actions=[{"path": "cmd.exe"}], username="Administrator")
    assert _apply(payload, username="HOST\\Administrator")["changed"] is False


@pytest.mark.parametrize("field", ["arguments", "description", "subscription"])
def test_case_only_edits_are_applied_and_then_idempotent(
    payload: tuple[ModuleType, ModuleType, _Scheduler], field: str
) -> None:
    options: dict[str, Any] = {
        "actions": [{"path": "python.exe", "arguments": "-c print('TOKEN')"}],
        "description": "TOKEN",
        "triggers": [
            {"type": "event", "subscription": "<QueryList><!--TOKEN--></QueryList>"}
        ],
    }
    assert _apply(payload, **options)["changed"] is True
    desired = copy.deepcopy(options)
    if field == "arguments":
        desired["actions"][0][field] = "-c print('token')"
    elif field == "subscription":
        desired["triggers"][0][field] = "<QueryList><!--token--></QueryList>"
    else:
        desired[field] = "token"
    assert _apply(payload, **desired)["changed"] is True
    definition = _definition(payload)
    if field == "description":
        assert definition.get("RegistrationInfo").get("Description") == "token"
    else:
        collection = "Actions" if field == "arguments" else "Triggers"
        native_name = "Arguments" if field == "arguments" else "Subscription"
        assert (
            definition.get(collection).items()[0].get(native_name)
            == desired[collection.lower()][0][field]
        )
    assert _apply(payload, **desired)["changed"] is False


def test_logon_type_output_is_canonical_despite_input_alias_iteration(
    payload: tuple[ModuleType, ModuleType, _Scheduler],
) -> None:
    _apply(payload, actions=[{"path": "python.exe"}])
    _definition(payload).get("Principal").put("LogonType", 6)
    # Python 3.4 dictionary iteration may visit the accepted alias first.
    with patch.dict(
        payload[0].LOGON_TYPES,
        {"token_or_password": 6, "interactive_token_or_password": 6},
        clear=True,
    ):
        assert payload[1].inspect("\\", "Fixture")["principal"]["logon_type"] == (
            "TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD"
        )
