# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Validate and manage the released scheduled-task interface through native APIs."""

import ctypes
import datetime
import re
from xml.etree import ElementTree

import legacy_windows_account as account  # pylint: disable=import-error
from legacy_community_windows_scheduled_task_native import (  # pylint: disable=import-error
    TaskScheduler,
    TaskSchedulerUnavailable,
    require_running_service,
)
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_dictionary,
    as_string,
)

TRIGGER_TYPES = {
    "event": 0,
    "time": 1,
    "daily": 2,
    "weekly": 3,
    "monthly": 4,
    "monthlydow": 5,
    "idle": 6,
    "registration": 7,
    "boot": 8,
    "logon": 9,
    "session_state_change": 11,
}
LOGON_TYPES = {
    "none": 0,
    "password": 1,
    "s4u": 2,
    "interactive_token": 3,
    "group": 4,
    "service_account": 5,
    "interactive_token_or_password": 6,
    "token_or_password": 6,
}
SESSION_CHANGES = {
    "console_connect": 1,
    "console_disconnect": 2,
    "remote_connect": 3,
    "remote_disconnect": 4,
    "session_lock": 7,
    "session_unlock": 8,
}
DAYS = ("sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday")
MONTHS = (
    "january",
    "february",
    "march",
    "april",
    "may",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
)
BOOLEAN_OPTIONS = (
    "allow_demand_start",
    "allow_hard_terminate",
    "disallow_start_if_on_batteries",
    "enabled",
    "hidden",
    "run_only_if_idle",
    "run_only_if_network_available",
    "start_when_available",
    "stop_if_going_on_batteries",
    "wake_to_run",
)
INTEGER_OPTIONS = ("compatibility", "multiple_instances", "priority", "restart_count")
STRING_OPTIONS = (
    "display_name",
    "group",
    "logon_type",
    "run_level",
    "username",
    "password",
    "author",
    "date",
    "description",
    "source",
    "version",
    "delete_expired_task_after",
    "execution_time_limit",
    "restart_interval",
)
SETTINGS = {
    name: "".join(part.title() for part in name.split("_"))
    for name in BOOLEAN_OPTIONS
    + INTEGER_OPTIONS
    + (
        "delete_expired_task_after",
        "execution_time_limit",
        "restart_interval",
    )
}
_TRIGGER_BASE = (
    "enabled",
    "end_boundary",
    "execution_time_limit",
    "start_boundary",
    "repetition",
)
_TRIGGER_OPTIONAL = {
    "boot": ("delay",),
    "daily": ("days_interval", "random_delay"),
    "event": ("delay", "subscription"),
    "idle": (),
    "logon": ("delay", "user_id"),
    "monthlydow": (
        "days_of_week",
        "months_of_year",
        "random_delay",
        "weeks_of_month",
        "run_on_last_week_of_month",
    ),
    "monthly": (
        "days_of_month",
        "months_of_year",
        "random_delay",
        "run_on_last_day_of_month",
    ),
    "registration": ("delay",),
    "time": ("random_delay",),
    "weekly": ("days_of_week", "random_delay", "weeks_interval"),
    "session_state_change": ("delay", "state_change", "user_id"),
}
_TRIGGER_REQUIRED = {
    "daily": ("start_boundary",),
    "event": ("subscription",),
    "monthlydow": ("start_boundary",),
    "monthly": ("days_of_month", "start_boundary"),
    "time": ("start_boundary",),
    "weekly": ("days_of_week", "start_boundary"),
}
PARAMETERS = (
    (
        "name",
        "path",
        "state",
        "actions",
        "triggers",
        "user",
        "runlevel",
        "update_password",
    )
    + BOOLEAN_OPTIONS
    + INTEGER_OPTIONS
    + STRING_OPTIONS
)


def _integer(value, name):
    if value is None:
        return None
    try:
        result = int(round(value)) if isinstance(value, float) else int(value)
    except (ValueError, TypeError, OverflowError) as error:
        raise ValueError(name + " must be an integer") from error
    if not -(2**31) <= result < 2**31:
        raise ValueError(name + " must fit in a signed 32-bit integer")
    return result


def duration_seconds(value):
    """Read a nonnegative XML duration for native scheduler validation.

    :param str value: ISO 8601 duration accepted by the public task interface.
    :returns: Duration in seconds, with XML's 365-day years and 30-day months.
    :rtype: float
    :raises ValueError: The duration is invalid or negative.
    """
    found = re.match(
        r"\AP(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?\Z",
        value,
    )
    if found is None or not any(found.groups()) or value.endswith("T"):
        raise ValueError("Task duration must use the XML duration format: " + value)
    return sum(
        float(number or 0) * multiplier
        for number, multiplier in zip(
            found.groups(), (31536000, 2592000, 86400, 3600, 60, 1)
        )
    )


def _boundary(value, name):
    value = as_string(value, name)
    if value is None:
        return None
    if not re.match(
        r"\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)?\Z", value
    ):
        raise ValueError(
            "trigger option '{0}' must use YYYY-MM-DDThh:mm:ss: {1}".format(name, value)
        )
    try:
        datetime.datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError as error:
        raise ValueError(
            "trigger option '{0}' contains an invalid date: {1}".format(name, value)
        ) from error
    return value


def _mask(value, names, name):
    if value is None:
        return None
    values = (
        value.split(",")
        if isinstance(value, str)
        else value if isinstance(value, list) else [value]
    )
    result = 0
    for item in values:
        text = str(item).strip().lower()
        if text not in names:
            raise ValueError("Invalid {0} value: {1}".format(name, text))
        result |= 1 << names.index(text)
    return result or None


def _trigger_fields(trigger):
    for name in ("start_boundary", "end_boundary"):
        if name in trigger:
            trigger[name] = _boundary(trigger[name], name)
    for name in ("delay", "random_delay", "execution_time_limit"):
        if trigger.get(name) is not None:
            trigger[name] = as_string(trigger[name], name)
            duration_seconds(trigger[name])
    for name in ("enabled", "run_on_last_week_of_month", "run_on_last_day_of_month"):
        if trigger.get(name) is not None:
            trigger[name] = as_bool(trigger[name], name)
    for name in ("days_interval", "weeks_interval"):
        if name in trigger:
            trigger[name] = _integer(trigger[name], name)


def _repetition(value):
    repetition = as_dictionary(value, "repetition")
    for name in ("interval", "duration"):
        if repetition.get(name) is not None:
            repetition[name] = as_string(repetition[name], name)
            duration_seconds(repetition[name])
    if repetition.get("stop_at_duration_end") is not None:
        repetition["stop_at_duration_end"] = as_bool(
            repetition["stop_at_duration_end"], "stop_at_duration_end"
        )
    if (
        repetition.get("interval")
        and repetition.get("duration")
        and duration_seconds(repetition["interval"])
        > duration_seconds(repetition["duration"])
    ):
        raise ValueError(
            "trigger repetition interval must be less than or equal to duration"
        )
    return repetition


def _trigger(entry):
    trigger = as_dictionary(entry, "trigger")
    if not trigger or trigger.get("type") not in TRIGGER_TYPES:
        raise ValueError(
            "A trigger must contain a valid type: " + ", ".join(sorted(TRIGGER_TYPES))
        )
    trigger = dict(trigger)
    kind = trigger["type"]
    for name in _TRIGGER_REQUIRED.get(kind, ()):
        if name not in trigger or trigger[name] is None:
            raise ValueError("Trigger type {0} requires {1}".format(kind, name))
    _trigger_fields(trigger)
    for name, names in (
        ("days_of_week", DAYS),
        ("months_of_year", MONTHS),
        ("days_of_month", tuple(str(day) for day in range(1, 32))),
        ("weeks_of_month", ("1", "2", "3", "4")),
    ):
        if name in trigger:
            trigger[name] = _mask(trigger[name], names, name)
    if trigger.get("state_change") is not None:
        if trigger["state_change"] not in SESSION_CHANGES:
            raise ValueError(
                "Invalid trigger state_change: " + str(trigger["state_change"])
            )
        trigger["state_change"] = SESSION_CHANGES[trigger["state_change"]]
    if trigger.get("repetition") is not None:
        trigger["repetition"] = _repetition(trigger["repetition"])
    return trigger


def _triggers(values):
    if values is None:
        return None
    if not isinstance(values, list):
        raise ValueError("triggers must be a list of dictionaries")
    return [_trigger(entry) for entry in values]


def _principal_parameters(arguments, result):
    result["username"] = as_string(
        arguments.get("username", arguments.get("user")), "username"
    )
    result["run_level"] = as_string(
        arguments.get("run_level", arguments.get("runlevel")), "run_level"
    )
    for name, choices in (
        ("run_level", (None, "limited", "highest")),
        ("logon_type", (None,) + tuple(LOGON_TYPES)),
    ):
        if result[name] not in choices:
            raise ValueError("Invalid value for " + name + ": " + str(result[name]))
    if result["username"] is not None and result["group"] is not None:
        raise ValueError("username and group can not be set at the same time")
    if result["logon_type"] == "s4u" and result["password"] is None:
        raise ValueError("password must be set when logon_type=s4u")
    if result["logon_type"] == "group" and result["group"] is None:
        raise ValueError("group must be set when logon_type=group")


def _actions(values):
    if values is None:
        return None
    if not isinstance(values, list):
        raise ValueError("actions must be a list of dictionaries")
    result = []
    for entry in values:
        action = as_dictionary(entry, "action")
        if action is None or "path" not in action:
            raise ValueError("action entry must contain the key 'path'")
        result.append(
            {
                name: as_string(action.get(name), name)
                for name in ("path", "arguments", "working_directory")
                if name in action
            }
        )
    return result


def parameters(arguments):
    """Normalize released task options without touching Windows resources.

    :param dict arguments: Public module arguments and controller flags.
    :returns: Typed options shared by native scheduler backends.
    :rtype: dict
    :raises ValueError: Names, choices, nested actions, or triggers are invalid.
    """
    result = {name: as_string(arguments.get(name), name) for name in STRING_OPTIONS}
    _principal_parameters(arguments, result)
    result["name"] = as_string(arguments.get("name"), "name")
    if not result["name"]:
        raise ValueError("Missing required argument: name")
    if re.search(r'[\\/:*?"<>|]', result["name"]):
        raise ValueError("Invalid task name: " + result["name"])
    path = as_string(arguments.get("path", "\\"), "path") or "\\"
    result["path"] = "\\" + path.strip("\\") if path.strip("\\") else "\\"
    result["state"] = as_string(arguments.get("state", "present"), "state")
    if result["state"] not in ("present", "absent"):
        raise ValueError("Invalid value for state: " + str(result["state"]))
    for name in BOOLEAN_OPTIONS:
        result[name] = (
            as_bool(arguments[name], name) if arguments.get(name) is not None else None
        )
    for name in INTEGER_OPTIONS:
        result[name] = _integer(arguments.get(name), name)
    for name in (
        "execution_time_limit",
        "delete_expired_task_after",
        "restart_interval",
    ):
        if result[name] is not None:
            duration_seconds(result[name])
    result["update_password"] = as_bool(
        arguments.get("update_password", True), "update_password"
    )
    result["actions"] = _actions(arguments.get("actions"))
    result["triggers"] = _triggers(arguments.get("triggers"))
    return result


def _current_account():
    security = ctypes.WinDLL("secur32", use_last_error=True)
    security.GetUserNameExW.argtypes = [
        ctypes.c_int,
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    security.GetUserNameExW.restype = ctypes.c_int
    length = ctypes.c_uint32(32768)
    buffer = ctypes.create_unicode_buffer(length.value)
    if not security.GetUserNameExW(2, buffer, ctypes.byref(length)):
        raise ctypes.WinError(ctypes.get_last_error())
    return buffer.value


def _identity(value):
    return account.sid_to_name(account.name_to_sid(value)) if value else value


def _same(left, right):
    if left is None and right == "" or right is None and left == "":
        return True
    return left == right


def _set_properties(target, values, changes, prefix):
    for name, requested in values.items():
        if requested is not None and not _same(target.get(name), requested):
            target.put(name, requested)
            changes.append(prefix + "." + name)


def _repetition_values(previous, requested):
    repetition = previous.get("Repetition") if previous else None
    values, different = {}, False
    for field, name in (
        ("interval", "Interval"),
        ("duration", "Duration"),
        ("stop_at_duration_end", "StopAtDurationEnd"),
    ):
        current = repetition.get(name) if repetition else None
        desired = (requested or {}).get(field)
        values[name] = current if desired is None else desired
        if desired is not None and not _same(current, desired):
            different = True
    return values, different


def _collection_values(entry, previous, name):
    values, different = {}, previous is None
    allowed = (
        ("path", "arguments", "working_directory")
        if name == "Actions"
        else _TRIGGER_BASE + _TRIGGER_OPTIONAL[entry["type"]]
    )
    for argument in allowed:
        property_name = "".join(part.title() for part in argument.split("_"))
        if argument == "repetition":
            values[property_name], changed = _repetition_values(
                previous, entry.get("repetition")
            )
            different = different or changed
            continue
        requested = entry.get(argument)
        if requested is not None:
            if previous is None or not _same(previous.get(property_name), requested):
                different = True
            values[property_name] = requested
        elif previous:
            values[property_name] = previous.get(property_name)
    return values, different


def _collection_snapshots(existing, name, entries):
    snapshots = []
    different = len(existing) != len(entries)
    for index, entry in enumerate(entries):
        kind = 0 if name == "Actions" else TRIGGER_TYPES[entry["type"]]
        previous = (
            existing[index]
            if index < len(existing) and existing[index].get("Type") == kind
            else None
        )
        values, changed = _collection_values(entry, previous, name)
        different = different or changed
        snapshots.append((kind, values))
    return snapshots, different


def _collection(definition, name, entries, changes):
    if entries is None:
        return
    collection = definition.get(name)
    snapshots, different = _collection_snapshots(collection.items(), name, entries)
    if not different:
        return
    collection.call("Clear")
    for kind, values in snapshots:
        target = collection.call("Create", kind)
        repetition = values.pop("Repetition", None)
        _set_properties(target, values, [], name)
        if repetition:
            _set_properties(target.get("Repetition"), repetition, [], "Repetition")
    changes.append(name)


def _find_folder(service, path):
    try:
        return service.call("GetFolder", path)
    except OSError as error:
        if getattr(error, "hresult", None) in (0x80070002, 0x80070003):
            return None
        raise


def _find_task(folder, name):
    if folder is None:
        return None
    return next(
        (
            task
            for task in folder.call("GetTasks", 1).items()
            if task.get("Name").lower() == name.lower()
        ),
        None,
    )


def _update_principal_identity(definition, principal, username, group, changes):
    namespace = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"
    xml = ElementTree.fromstring(definition.get("XmlText"))
    name, other = ("UserId", "GroupId") if username else ("GroupId", "UserId")
    desired = username or group
    existing_node = xml.find(
        namespace + "Principals/" + namespace + "Principal/" + namespace + name
    )
    existing = existing_node.text if existing_node is not None else None
    if existing is None or account.name_to_sid(existing) != account.name_to_sid(
        desired
    ):
        if principal.get(other):
            principal.put(other, None)
        principal.put(name, desired)
        changes.append("Principal." + name)


def _configure_principal(definition, options, creating, changes):
    principal = definition.get("Principal")
    username = _identity(options["username"])
    group = _identity(options["group"])
    principal_values = {
        "DisplayName": options["display_name"],
        "RunLevel": (
            None
            if options["run_level"] is None
            else int(options["run_level"] == "highest")
        ),
    }
    if creating:
        if group:
            principal.put("GroupId", group)
        else:
            principal.put("UserId", username or _current_account())
        principal_values["LogonType"] = (
            4
            if group
            else (
                5
                if username
                and account.name_to_sid(username)
                in ("S-1-5-18", "S-1-5-19", "S-1-5-20")
                else 3
            )
        )
    elif username or group:
        _update_principal_identity(definition, principal, username, group, changes)
    if options["logon_type"] is not None:
        principal_values["LogonType"] = LOGON_TYPES[options["logon_type"]]
    elif group:
        principal_values["LogonType"] = LOGON_TYPES["group"]
    if options["logon_type"] == "service_account" and (
        not username
        or account.name_to_sid(username) not in ("S-1-5-18", "S-1-5-19", "S-1-5-20")
    ):
        raise ValueError(
            "username must be SYSTEM, LOCAL SERVICE or NETWORK SERVICE "
            "when logon_type=service_account"
        )
    _set_properties(principal, principal_values, changes, "Principal")
    return principal


# The registration call has six distinct inputs: retaining their names is
# clearer than hiding scheduler objects and security state in an options bundle.
def _register_modern(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    service, folder, definition, options, credentials, check_mode
):
    require_running_service()
    user, password, logon_type = credentials
    created_folder = False
    validated = False
    if folder is None:
        folder = service.call("GetFolder", "\\")
        folder.call(
            "RegisterTaskDefinition",
            options["name"],
            definition,
            1,
            user,
            password,
            logon_type,
        )
        validated = True
        if not check_mode:
            folder = folder.call("CreateFolder", options["path"], None)
            created_folder = True
    try:
        if not check_mode or not validated:
            folder.call(
                "RegisterTaskDefinition",
                options["name"],
                definition,
                1 if check_mode else 6,
                user,
                password,
                logon_type,
            )
    except OSError:
        if (
            created_folder
            and folder.call("GetTasks", 1).get("Count") == 0
            and folder.call("GetFolders", 0).get("Count") == 0
        ):
            service.call("GetFolder", "\\").call("DeleteFolder", options["path"], 0)
        raise


def _registration_credentials(principal, options, creating, password_change):
    if not creating and not password_change:
        # Null credentials inherit the task's stored credentials rather than
        # replacing them with a missing password during an unrelated update.
        return None, None, None
    user = principal.get("GroupId") or principal.get("UserId")
    password = options["password"] if creating or password_change else None
    logon_type = principal.get("LogonType")
    return user, password, logon_type


def _remove_modern(service, folder, options, check_mode, result):
    result["changed"] = True
    if not check_mode:
        folder.call("DeleteTask", options["name"], 0)
        if (
            options["path"] != "\\"
            and folder.call("GetTasks", 1).get("Count") == 0
            and folder.call("GetFolders", 0).get("Count") == 0
        ):
            service.call("GetFolder", "\\").call("DeleteFolder", options["path"], 0)
    if "diff" in result:
        result["diff"]["prepared"] = (
            "-[Task]\n-" + options["path"].rstrip("\\") + "\\" + options["name"]
        )


def _manage_modern(scheduler, options, check_mode, diff_mode):
    service = scheduler.service
    folder = _find_folder(service, options["path"])
    task = _find_task(folder, options["name"])
    result = {"changed": False}
    if diff_mode:
        result["diff"] = {}
    if options["state"] == "absent":
        if task:
            _remove_modern(service, folder, options, check_mode, result)
        return result
    creating = task is None
    if creating and not options["actions"]:
        raise ValueError(
            "cannot create a task with no actions, set at least one action "
            "with a path to an executable"
        )
    definition = service.call("NewTask", 0) if creating else task.get("Definition")
    changes = []
    _collection(definition, "Actions", options["actions"], changes)
    _collection(definition, "Triggers", options["triggers"], changes)
    principal = _configure_principal(definition, options, creating, changes)
    _set_properties(
        definition.get("RegistrationInfo"),
        {
            name.title(): options[name]
            for name in ("author", "date", "description", "source", "version")
        },
        changes,
        "RegistrationInfo",
    )
    _set_properties(
        definition.get("Settings"),
        {property_name: options[name] for name, property_name in SETTINGS.items()},
        changes,
        "Settings",
    )
    password_change = options["password"] is not None and (
        options["update_password"] or bool(changes)
    )
    result["changed"] = creating or bool(changes) or password_change
    if not result["changed"]:
        return result
    _register_modern(
        service,
        folder,
        definition,
        options,
        _registration_credentials(principal, options, creating, password_change),
        check_mode,
    )
    if diff_mode:
        result["diff"]["prepared"] = (
            ("+[Task]\n" if creating else "[Task]\n")
            + options["path"].rstrip("\\")
            + "\\"
            + options["name"]
            + "\n"
            + "\n".join("+" + change for change in changes)
        )
    return result


def manage(options, check_mode=False, diff_mode=False):
    """Manage a task using the installed native scheduler's capabilities.

    :param dict options: Validated task interface arguments.
    :param bool check_mode: Validate and predict without changing tasks or folders.
    :param bool diff_mode: Include a prepared task/property change summary.
    :returns: Ansible changed and optional diff fields.
    :rtype: dict
    :raises OSError: Native scheduler operations or account lookup fail.
    :raises ValueError: The requested definition cannot be represented.
    """
    try:
        with TaskScheduler() as scheduler:
            return _manage_modern(scheduler, options, check_mode, diff_mode)
    except TaskSchedulerUnavailable:
        # The legacy backend is staged explicitly, not discovered as a transport.
        from legacy_community_windows_scheduled_task_legacy import (  # pylint: disable=import-outside-toplevel,import-error
            manage_legacy,
        )

        return manage_legacy(options, check_mode, diff_mode)
