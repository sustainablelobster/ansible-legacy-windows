# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read native scheduler properties in the released information interface."""

import re

import legacy_windows_account as account  # pylint: disable=import-error
from legacy_community_windows_scheduled_task import (  # pylint: disable=import-error
    DAYS,
    MONTHS,
    SESSION_CHANGES,
    TRIGGER_TYPES,
    _find_folder,
)
from legacy_community_windows_scheduled_task_native import (  # pylint: disable=import-error
    TaskScheduler,
    TaskSchedulerUnavailable,
)


def _snake(name):
    return re.sub(
        r"([a-z0-9])([A-Z])", r"\1_\2", re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    ).lower()


def _enum(values, value, prefix):
    name = next((name for name, number in values.items() if number == value), None)
    return prefix + name.upper() if name is not None else str(value)


# Each return corresponds to one native property representation. Keeping these
# explicit is clearer than a registry of callbacks for unrelated scalar types.
def _value(name, value, section):  # pylint: disable=too-many-return-statements
    if hasattr(value, "properties"):
        return _properties(value, section)
    masks = {
        "DaysOfWeek": DAYS,
        "DaysOfMonth": tuple(str(day) for day in range(1, 32)),
        "WeeksOfMonth": ("1", "2", "3", "4"),
        "MonthsOfYear": MONTHS,
    }
    if name in masks:
        return ",".join(
            text for index, text in enumerate(masks[name]) if value & (1 << index)
        )
    if name == "Type":
        if section == "actions":
            return _enum(
                {"exec": 0, "com_handler": 5, "send_email": 6, "show_message": 7},
                value,
                "TASK_ACTION_",
            )
        if section == "triggers":
            return _enum(TRIGGER_TYPES, value, "TASK_TRIGGER_")
    if name == "RunLevel":
        return {0: "TASK_RUNLEVEL_LUA", 1: "TASK_RUNLEVEL_HIGHEST"}.get(
            value, str(value)
        )
    if name == "LogonType":
        return {
            0: "TASK_LOGON_NONE",
            1: "TASK_LOGON_PASSWORD",
            2: "TASK_LOGON_S4U",
            3: "TASK_LOGON_INTERACTIVE_TOKEN",
            4: "TASK_LOGON_GROUP",
            5: "TASK_LOGON_SERVICE_ACCOUNT",
            6: "TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD",
        }.get(value, str(value))
    if name in ("UserId", "GroupId") and value:
        return account.sid_to_name(account.name_to_sid(value))
    return value


def _properties(target, section):
    result = {}
    for name, value in target.properties().items():
        result[_snake(name)] = _value(name, value, section)
        if name == "StateChange":
            result["state_change_str"] = (
                _enum(SESSION_CHANGES, value, "TASK_") if value else None
            )
    return result


def _stat_modern(scheduler, path, name):
    result = {"changed": False, "folder_exists": False}
    folder = _find_folder(scheduler.service, path)
    if folder is None:
        if name is not None:
            result["task_exists"] = False
        return result
    result["folder_exists"] = True
    tasks = folder.call("GetTasks", 1).items()
    result["folder_task_names"] = [task.get("Name") for task in tasks]
    result["folder_task_count"] = len(tasks)
    if name is None:
        return result
    selected = next(
        (task for task in tasks if task.get("Name").lower() == name.lower()), None
    )
    result["task_exists"] = selected is not None
    if selected is None:
        return result
    result["state"] = {
        "last_run_time": selected.get("LastRunTime"),
        "last_task_result": selected.get("LastTaskResult"),
        "next_run_time": selected.get("NextRunTime"),
        "number_of_missed_runs": selected.get("NumberOfMissedRuns"),
        "status": _enum(
            {"unknown": 0, "disabled": 1, "queued": 2, "ready": 3, "running": 4},
            selected.get("State"),
            "TASK_STATE_",
        ),
    }
    definition = selected.get("Definition")
    for section, property_name in (
        ("principal", "Principal"),
        ("registration_info", "RegistrationInfo"),
        ("settings", "Settings"),
    ):
        result[section] = _properties(definition.get(property_name), section)
    for section, property_name in (("actions", "Actions"), ("triggers", "Triggers")):
        result[section] = [
            _properties(value, section)
            for value in definition.get(property_name).items()
        ]
    return result


def inspect(path, name=None):
    """Read a folder and optional task using the installed native scheduler.

    :param str path: Task folder path.
    :param name: Task name, or None to read only the folder.
    :type name: str or None
    :returns: Released folder/task existence and native definition/state fields.
    :rtype: dict
    :raises OSError: Native scheduler access or account resolution fails.
    :raises ValueError: A native property value cannot be represented.
    """
    try:
        with TaskScheduler() as scheduler:
            return _stat_modern(scheduler, path, name)
    except TaskSchedulerUnavailable:
        from legacy_community_windows_scheduled_task_legacy import (  # pylint: disable=import-outside-toplevel,import-error
            stat_legacy,
        )

        return stat_legacy(path, name)
