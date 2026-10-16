# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage definitions representable by the native Task Scheduler 1.0 service."""

import ctypes
import datetime

import legacy_windows_account as account  # pylint: disable=import-error
from legacy_community_windows_scheduled_task_legacy_native import (  # pylint: disable=import-error
    LegacyScheduler,
    Trigger,
)

_KINDS = {
    "time": 0,
    "daily": 1,
    "weekly": 2,
    "monthly": 3,
    "monthlydow": 4,
    "idle": 5,
    "boot": 6,
    "logon": 7,
}
_FLAGS = {
    "enabled": (0x4, True),
    "hidden": (0x200, False),
    "run_only_if_idle": (0x10, False),
    "disallow_start_if_on_batteries": (0x40, False),
    "stop_if_going_on_batteries": (0x80, False),
    "wake_to_run": (0x1000, False),
}
_PRIORITIES = {0: 0x100, 1: 0x80, 4: 0x20, 5: 0x20, 6: 0x20, 9: 0x40, 10: 0x40}
_STRING_PROPERTIES = {"description": (19, 18), "author": (21, 20)}


def _unsupported(feature):
    raise ValueError(
        "The installed Task Scheduler 1.0 service cannot represent {0}; "
        "use a scheduler with that capability or omit this option.".format(feature)
    )


def _duration(value):
    # Lazy import avoids a cycle: the public manager selects this backend.
    from legacy_community_windows_scheduled_task import (  # pylint: disable=import-outside-toplevel,import-error
        duration_seconds,
    )

    return duration_seconds(value)


def _minutes(value, field):
    seconds = _duration(value)
    if seconds % 60 or seconds / 60 > 0xFFFFFFFF:
        _unsupported(field + " outside whole-minute, 32-bit limits")
    return int(seconds / 60)


def _timeout(value):
    seconds = _duration(value)
    if not seconds:
        return 0xFFFFFFFF
    milliseconds = seconds * 1000
    if milliseconds != int(milliseconds) or milliseconds >= 0xFFFFFFFF:
        _unsupported(
            "execution_time_limit outside millisecond precision and the 49-day native limit"
        )
    return int(milliseconds)


def _validate(options):
    if options["path"] != "\\":
        _unsupported("task folders other than the root path \\")
    actions = options.get("actions")
    if actions is not None and len(actions) > 1:
        _unsupported("multiple actions in one task")
    for name in ("group", "display_name", "date", "source", "version"):
        if options.get(name) is not None:
            _unsupported(name)
    for name, fixed in (
        ("allow_demand_start", True),
        ("allow_hard_terminate", True),
        ("run_only_if_network_available", False),
        ("start_when_available", False),
        ("multiple_instances", 2),
        ("restart_count", 0),
        ("compatibility", 1),
    ):
        if options.get(name) is not None and options[name] != fixed:
            _unsupported("{0}={1}".format(name, options[name]))
    for name in ("restart_interval", "delete_expired_task_after"):
        value = options.get(name)
        if value is not None and _duration(value):
            _unsupported(name)
    if options.get("run_level") == "limited":
        _unsupported("run_level=limited (restricted UAC tokens)")
    if options.get("logon_type") not in (
        None,
        "password",
        "interactive_token",
        "service_account",
    ):
        _unsupported("logon_type=" + options["logon_type"])
    if options.get("priority") is not None and options["priority"] not in _PRIORITIES:
        _unsupported(
            "priority={0}; supported legacy values are {1}".format(
                options["priority"],
                ", ".join(str(value) for value in sorted(_PRIORITIES)),
            )
        )
    if options.get("execution_time_limit") is not None:
        _timeout(options["execution_time_limit"])


def _boundary(value, field):
    if len(value) != 19:
        _unsupported(field + " with a timezone offset or fractional seconds")
    stamp = datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")
    if stamp.second or (field == "end_boundary" and (stamp.hour or stamp.minute)):
        _unsupported(
            field + " below the scheduler's minute precision"
            if field != "end_boundary"
            else "end_boundary with a time of day (legacy end boundaries are dates)"
        )
    return stamp


def _new_trigger():
    result = Trigger()
    result.size = ctypes.sizeof(result)
    today = datetime.date.today()
    result.begin_year, result.begin_month, result.begin_day = (
        today.year,
        today.month,
        today.day,
    )
    return result


def _validate_trigger(entry):
    if entry["type"] not in _KINDS:
        _unsupported("trigger type " + entry["type"])
    for name in ("delay", "random_delay", "execution_time_limit"):
        if entry.get(name) is not None and _duration(entry[name]):
            _unsupported("trigger " + name)
    if entry.get("user_id"):
        _unsupported("logon trigger user_id; the legacy trigger runs for any logon")
    if entry.get("run_on_last_day_of_month"):
        _unsupported("run_on_last_day_of_month")


def _trigger(entry, previous=None):
    _validate_trigger(entry)
    kind = entry["type"]
    result = (
        Trigger.from_buffer_copy(bytes(previous))
        if previous is not None and previous.kind == _KINDS[kind]
        else _new_trigger()
    )
    result.kind = _KINDS[kind]
    if entry.get("start_boundary") is not None:
        stamp = _boundary(entry["start_boundary"], "start_boundary")
        result.begin_year, result.begin_month, result.begin_day = (
            stamp.year,
            stamp.month,
            stamp.day,
        )
        result.hour, result.minute = stamp.hour, stamp.minute
    if entry.get("end_boundary") is not None:
        stamp = _boundary(entry["end_boundary"], "end_boundary")
        result.end_year, result.end_month, result.end_day = (
            stamp.year,
            stamp.month,
            stamp.day,
        )
        result.flags |= 1
    if entry.get("enabled") is not None:
        result.flags = result.flags & ~4 if entry["enabled"] else result.flags | 4
    repetition = entry.get("repetition")
    if repetition is not None:
        for name in ("interval", "duration"):
            if repetition.get(name) is not None:
                setattr(
                    result,
                    name,
                    _minutes(repetition[name], "trigger repetition " + name),
                )
        if repetition.get("stop_at_duration_end") is not None:
            result.flags = (
                result.flags | 2
                if repetition["stop_at_duration_end"]
                else result.flags & ~2
            )
    if result.interval and result.duration <= result.interval:
        _unsupported("trigger repetition without a duration greater than its interval")
    _calendar(entry, result)
    return result


def _calendar(entry, result):
    kind = entry["type"]
    if kind == "daily":
        result.data.daily.days_interval = _word(
            entry.get("days_interval", result.data.daily.days_interval or 1),
            "days_interval",
            365,
        )
    elif kind == "weekly":
        result.data.weekly.weeks_interval = _word(
            entry.get("weeks_interval", result.data.weekly.weeks_interval or 1),
            "weeks_interval",
            52,
        )
        result.data.weekly.days = entry.get("days_of_week") or result.data.weekly.days
    elif kind == "monthly":
        result.data.monthly.days = (
            entry.get("days_of_month") or result.data.monthly.days
        )
        result.data.monthly.months = (
            entry.get("months_of_year") or result.data.monthly.months or 4095
        )
    elif kind == "monthlydow":
        weeks = entry.get("weeks_of_month")
        if entry.get("run_on_last_week_of_month"):
            if weeks:
                _unsupported(
                    "combining selected weeks_of_month with run_on_last_week_of_month"
                )
            week = 5
        elif weeks:
            if weeks & (weeks - 1):
                _unsupported(
                    "more than one weeks_of_month value in one monthlydow trigger; "
                    "use one trigger for each week"
                )
            week = weeks.bit_length()
        else:
            week = result.data.monthly_day.week or 1
        result.data.monthly_day.week = week
        result.data.monthly_day.days = (
            entry.get("days_of_week") or result.data.monthly_day.days
        )
        result.data.monthly_day.months = (
            entry.get("months_of_year") or result.data.monthly_day.months or 4095
        )
        if not result.data.monthly_day.days:
            raise ValueError("A legacy monthlydow trigger requires days_of_week")


def _word(value, name, maximum):
    if value is None or not 1 <= value <= maximum:
        raise ValueError("{0} must be between 1 and {1}".format(name, maximum))
    return value


def _triggers(entries, previous):
    return [
        _trigger(entry, previous[index] if index < len(previous) else None)
        for index, entry in enumerate(entries)
    ]


def _flags(options, current):
    result = current
    for name, (mask, inverse) in _FLAGS.items():
        requested = options.get(name)
        if requested is not None:
            result = result | mask if bool(requested) != inverse else result & ~mask
    if options.get("logon_type") == "interactive_token":
        result |= 0x2000
    elif options.get("logon_type") in ("password", "service_account"):
        result &= ~0x2000
    if options.get("delete_expired_task_after") is not None:
        result |= 2
    return result


def _same_account(left, right):
    return account.name_to_sid(left or "SYSTEM") == account.name_to_sid(
        right or "SYSTEM"
    )


def _credentials(options, task, creating):
    previous = None if creating else task.string(31)
    requested = options.get("username")
    if requested is None:
        if creating:
            from legacy_community_windows_scheduled_task import (  # pylint: disable=import-outside-toplevel,import-error
                _current_account,
            )

            requested = _current_account()
        else:
            requested = previous
    sid = account.name_to_sid(requested or "SYSTEM")
    if options.get("logon_type") == "service_account" and sid != "S-1-5-18":
        _unsupported("service_account other than SYSTEM")
    if sid in ("S-1-5-19", "S-1-5-20"):
        _unsupported("LOCAL SERVICE or NETWORK SERVICE as task accounts")
    requested = "" if sid == "S-1-5-18" else requested
    changed = creating or not _same_account(requested, previous)
    password = options.get("password")
    password_change = password is not None and options.get("update_password", True)
    logon = options.get("logon_type")
    flags = _flags(options, 0 if creating else task.number(29))
    if creating and logon is None and sid != "S-1-5-18":
        flags |= 0x2000
    if sid == "S-1-5-18":
        if logon in ("password", "interactive_token"):
            _unsupported("logon_type=" + logon + " for SYSTEM; use service_account")
        password = None
    old_interactive = not creating and task.number(29) & 0x2000
    needs_credentials = changed or password_change or old_interactive
    if (
        sid != "S-1-5-18"
        and needs_credentials
        and not flags & 0x2000
        and password is None
    ):
        raise ValueError(
            "password is required when configuring a legacy task account "
            "without interactive_token logon"
        )
    return requested, password, changed or password_change, flags


def _changes(task, options, creating):
    changes = []
    account_name, password, account_changed, flags = _credentials(
        options, task, creating
    )
    if account_changed:
        changes.append(("account", account_name, password))
    if flags != (0 if creating else task.number(29)):
        changes.append(("number", 28, flags))
    for name, (getter, setter) in _STRING_PROPERTIES.items():
        requested = options.get(name)
        if requested is not None and (creating or requested != task.string(getter)):
            changes.append(("string", setter, requested))
    changes.extend(_action_changes(task, options.get("actions"), creating))
    for name, getter, setter, convert in (
        ("execution_time_limit", 43, 42, _timeout),
        ("priority", 39, 38, lambda value: _PRIORITIES[value]),
    ):
        if options.get(name) is not None:
            requested = convert(options[name])
            if creating or task.number(getter) != requested:
                changes.append(("number", setter, requested))
    if options.get("triggers") is not None:
        previous = [] if creating else task.triggers()
        triggers = _triggers(options["triggers"], previous)
        if [bytes(value) for value in triggers] != [bytes(value) for value in previous]:
            changes.append(("triggers", triggers))
    if options.get("password") is not None and changes and not account_changed:
        changes.append(("account", account_name, password))
    return changes


def _action_changes(task, actions, creating):
    changes = []
    if actions is not None:
        action = (
            actions[0]
            if actions
            else {"path": "", "arguments": "", "working_directory": ""}
        )
        for name, getter, setter in (
            ("path", 33, 32),
            ("arguments", 35, 34),
            ("working_directory", 37, 36),
        ):
            requested = action.get(name)
            if requested is not None and (creating or requested != task.string(getter)):
                changes.append(("string", setter, requested))
    return changes


def _apply(scheduler, task, options, changes, creating):
    if creating:
        task = scheduler.task(options["name"], create=True)
    try:
        # Set flags before credentials: interactive accounts allow a null password.
        for change in sorted(changes, key=lambda change: change[0] == "account"):
            if change[0] == "string":
                task.set_string(change[1], change[2])
            elif change[0] == "number":
                value = change[2]
                if creating and change[1] == 28:
                    # Preserve native default flags for options the caller omitted.
                    value = _flags(options, task.number(29))
                    if change[2] & 0x2000:
                        value |= 0x2000
                task.set_number(change[1], value)
            elif change[0] == "triggers":
                task.set_triggers(change[1])
            else:
                task.account(change[1], change[2])
        task.save()
    except OSError:
        # Server 2003 can create a .job file even when credential validation fails.
        if creating and any(
            name.lower() == options["name"].lower() for name in scheduler.names()
        ):
            scheduler.delete(options["name"])
        raise


def _delete(scheduler, existing, check_mode, diff_mode):
    result = {"changed": existing is not None}
    if diff_mode:
        result["diff"] = {}
    if existing is not None:
        if not check_mode:
            scheduler.delete(existing)
        if diff_mode:
            result["diff"]["prepared"] = "-[Task]\n-\\" + existing
    return result


def manage_legacy(options, check_mode=False, diff_mode=False):
    """Apply the released interface to a native Scheduler 1.0 task definition.

    :param dict options: Typed options from the public scheduled-task validator.
    :param bool check_mode: Predict changes without saving task definitions.
    :param bool diff_mode: Return a prepared summary without credentials.
    :returns: Ansible change and optional diff fields.
    :rtype: dict
    :raises ValueError: Requested features cannot be represented by this service.
    :raises OSError: Native task access, credentials, or persistence fails.
    """
    if options["state"] != "absent":
        _validate(options)
    elif options["path"] != "\\":
        return {"changed": False}
    with LegacyScheduler() as scheduler:
        existing = next(
            (
                name
                for name in scheduler.names()
                if name.lower() == options["name"].lower()
            ),
            None,
        )
        result = {"changed": False}
        if diff_mode:
            result["diff"] = {}
        if options["state"] == "absent":
            return _delete(scheduler, existing, check_mode, diff_mode)
        creating = existing is None
        if creating and not options.get("actions"):
            raise ValueError(
                "cannot create a task with no actions, set at least one action "
                "with a path to an executable"
            )
        task = None if creating else scheduler.task(existing)
        changes = _changes(task, options, creating)
        result["changed"] = creating or bool(changes)
        if not result["changed"]:
            return result
        if diff_mode:
            result["diff"]["prepared"] = (
                ("+[Task]\n" if creating else "[Task]\n")
                + "\\"
                + options["name"]
                + "\n"
                + "\n".join(
                    "+"
                    + (
                        "triggers"
                        if change[0] == "triggers"
                        else (
                            "account"
                            if change[0] == "account"
                            else "property " + str(change[1])
                        )
                    )
                    for change in changes
                )
            )
        if check_mode:
            return result
        _apply(scheduler, task, options, changes, creating)
        return result


def _mask(value, names):
    return ",".join(name for index, name in enumerate(names) if value & (1 << index))


def _iso_duration(seconds):
    return "PT{0:g}S".format(seconds)


def _trigger_stat(value):
    from legacy_community_windows_scheduled_task import (  # pylint: disable=import-outside-toplevel,import-error
        DAYS,
        MONTHS,
    )

    name = next(name for name, kind in _KINDS.items() if kind == value.kind)
    result = {
        "id": None,
        "type": "TASK_TRIGGER_" + name.upper(),
        "enabled": not bool(value.flags & 4),
        "start_boundary": "{0:04d}-{1:02d}-{2:02d}T{3:02d}:{4:02d}:00".format(
            value.begin_year,
            value.begin_month,
            value.begin_day,
            value.hour,
            value.minute,
        ),
        "end_boundary": (
            "{0:04d}-{1:02d}-{2:02d}T00:00:00".format(
                value.end_year, value.end_month, value.end_day
            )
            if value.flags & 1
            else None
        ),
        "execution_time_limit": None,
        "repetition": {
            "interval": _iso_duration(value.interval * 60) if value.interval else None,
            "duration": _iso_duration(value.duration * 60) if value.duration else None,
            "stop_at_duration_end": bool(value.flags & 2),
        },
    }
    if name == "daily":
        result["days_interval"] = value.data.daily.days_interval
    elif name == "weekly":
        result.update(
            weeks_interval=value.data.weekly.weeks_interval,
            days_of_week=_mask(value.data.weekly.days, DAYS),
        )
    elif name == "monthly":
        result.update(
            days_of_month=_mask(
                value.data.monthly.days, tuple(str(day) for day in range(1, 32))
            ),
            months_of_year=_mask(value.data.monthly.months, MONTHS),
            run_on_last_day_of_month=False,
        )
    elif name == "monthlydow":
        result.update(
            days_of_week=_mask(value.data.monthly_day.days, DAYS),
            months_of_year=_mask(value.data.monthly_day.months, MONTHS),
            weeks_of_month=(
                str(value.data.monthly_day.week)
                if value.data.monthly_day.week != 5
                else ""
            ),
            run_on_last_week_of_month=value.data.monthly_day.week == 5,
        )
    if name in ("time", "daily", "weekly", "monthly", "monthlydow"):
        result["random_delay"] = None
    if name in ("boot", "logon"):
        result["delay"] = None
    if name == "logon":
        result["user_id"] = None
    return result


def _task_stat(task):
    flags = task.number(29)
    username = task.string(31)
    system = not username or account.name_to_sid(username) == "S-1-5-18"
    idle, wait = task.idle()
    settings = {
        "allow_demand_start": True,
        "allow_hard_terminate": True,
        "compatibility": 1,
        "delete_expired_task_after": "PT0S" if flags & 2 else None,
        "disallow_start_on_remote_app_session": None,
        "execution_time_limit": (
            "PT0S"
            if task.number(43) == 0xFFFFFFFF
            else _iso_duration(task.number(43) / 1000)
        ),
        "idle_settings": {
            "idle_duration": _iso_duration(idle * 60),
            "wait_timeout": _iso_duration(wait * 60),
            "stop_on_idle_end": bool(flags & 0x20),
            "restart_on_idle": bool(flags & 0x800),
        },
        "maintenance_settings": None,
        "multiple_instances": 2,
        "network_settings": None,
        "priority": {0x100: 0, 0x80: 1, 0x20: 5, 0x40: 10}.get(task.number(39)),
        "restart_count": None,
        "restart_interval": None,
        "run_only_if_network_available": None,
        "start_when_available": None,
        "use_unified_scheduling_engine": None,
        "volatile": None,
    }
    for name, (mask, inverse) in _FLAGS.items():
        settings[name] = bool(flags & mask) != inverse
    status = task.number(16)
    result = {
        "actions": [
            {
                "id": None,
                "type": "TASK_ACTION_EXEC",
                "path": task.string(33),
                "arguments": task.string(35) or None,
                "working_directory": task.string(37) or None,
            }
        ],
        "principal": {
            "display_name": None,
            "group_id": None,
            "id": None,
            "run_level": None,
            "user_id": account.sid_to_name(account.name_to_sid(username or "SYSTEM")),
            "logon_type": (
                "TASK_LOGON_SERVICE_ACCOUNT"
                if system
                else (
                    "TASK_LOGON_INTERACTIVE_TOKEN"
                    if flags & 0x2000
                    else "TASK_LOGON_PASSWORD"
                )
            ),
        },
        "registration_info": {
            "author": task.string(21) or None,
            "date": None,
            "description": task.string(19) or None,
            "documentation": None,
            "security_descriptor": None,
            "source": None,
            "uri": None,
            "version": None,
        },
        "settings": settings,
        "triggers": [_trigger_stat(value) for value in task.triggers()],
        "state": {
            "last_run_time": task.time(15),
            "next_run_time": task.time(9),
            "last_task_result": task.number(17),
            "number_of_missed_runs": None,
            "status": (
                "TASK_STATE_DISABLED"
                if flags & 4
                else {
                    0x41300: "TASK_STATE_READY",
                    0x41301: "TASK_STATE_RUNNING",
                    0x41302: "TASK_STATE_DISABLED",
                    0x41303: "TASK_STATE_READY",
                    0x41304: "TASK_STATE_READY",
                    0x41305: "TASK_STATE_READY",
                    0x41306: "TASK_STATE_READY",
                    0x41307: "TASK_STATE_READY",
                    0x41308: "TASK_STATE_READY",
                }.get(status, "TASK_STATE_UNKNOWN")
            ),
        },
        "warnings": [
            "Task Scheduler 1.0 does not expose Task Scheduler 2.0 principal/registration "
            "identifiers, run levels, newer settings, per-trigger identifiers/time limits, "
            "or missed-run counts; unavailable fields are null. Legacy trigger boundaries "
            "have minute/date precision and priority values identify native process classes."
        ],
    }
    return result


def stat_legacy(path, name=None):
    """Read folder and task facts from the installed Scheduler 1.0 service.

    :param str path: Public task folder path.
    :param name: Optional task name without a .job suffix.
    :type name: str or None
    :returns: Native task facts, with nulls and warnings for unavailable fields.
    :rtype: dict
    :raises OSError: Native scheduler or account lookup fails.
    """
    result = {"changed": False, "folder_exists": path.strip("\\") == ""}
    if name is not None:
        result["task_exists"] = False
    if not result["folder_exists"]:
        return result
    with LegacyScheduler() as scheduler:
        names = scheduler.names()
        result.update(folder_task_names=names, folder_task_count=len(names))
        if name is None:
            return result
        selected = next((item for item in names if item.lower() == name.lower()), None)
        if selected is not None:
            result["task_exists"] = True
            result.update(_task_stat(scheduler.task(selected)))
        return result
