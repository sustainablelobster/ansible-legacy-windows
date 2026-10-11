#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage Windows services with Python and the native service manager."""

# WANT_JSON

import legacy_windows_account as account  # pylint: disable=import-error
import legacy_windows_environment as environment  # pylint: disable=import-error
import legacy_windows_service as service  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_dictionary,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

# Ansible interfaces must be self-contained; repeated option/return text is
# interface documentation, not duplicated execution logic.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_service
short_description: Configure and control Windows services
description:
  - Creates, configures, controls, and removes services through native Windows APIs.
  - Configuration changes are ordered, not transactional. A later failure can
    leave earlier changes in place; inspect and correct the reported failure.
options:
  name:
    description: Literal service key or display name; the key is used for creation.
    type: str
    required: true
  path:
    description:
      - Executable command line, required when creating a service.
      - Windows environment references are expanded on the target.
    type: str
  state:
    description: Desired state. C(restarted) always restarts an existing service.
    type: str
    choices: [absent, paused, started, stopped, restarted]
  start_mode:
    description:
      - Startup configuration. New services initially use C(auto).
      - Before Windows Vista / Server 2008, C(auto), C(manual), and C(disabled)
        use the basic service configuration. C(delayed) is rejected before writes.
    type: str
    choices: [auto, delayed, disabled, manual]
  display_name:
    description: Display label. Omission or an empty string preserves an existing label.
    type: str
  description:
    description: Service description. Omission preserves the existing value.
    type: str
  username:
    description: Service account. New services initially run as C(LocalSystem).
    type: str
  password:
    description: Account password. Supply O(username) with this option.
    type: str
  update_password:
    description:
      - C(always) writes a supplied nonempty password; Windows does not expose
        a readable password for comparison.
      - Omission behaves as C(on_create); an account change also updates a
        supplied nonempty password.
    type: str
    choices: [always, on_create]
  desktop_interact:
    description: Set the interactive flag, which requires the SYSTEM account.
    type: bool
    default: false
  service_type:
    description: Native Win32 service process type.
    type: str
    choices: [win32_own_process, win32_share_process, user_own_process, user_share_process]
  dependencies:
    description:
      - Service keys or C(+group) names, interpreted using O(dependency_action).
      - An empty replacement list preserves native dependencies, matching the
        pinned runtime; its returned diff still reports the requested empty list.
    type: list
    elements: str
  dependency_action:
    description: Replace, add to, or remove from the existing dependency list.
    type: str
    choices: [set, add, remove]
    default: set
  force_dependent_services:
    description: Stop dependent services when stopping or restarting this service.
    type: bool
    default: false
  error_control:
    description: Native startup failure severity.
    type: str
    choices: [critical, ignore, normal, severe]
  load_order_group:
    description: Startup group. An empty string removes group membership.
    type: str
  failure_actions:
    description: Ordered recovery actions; an empty list removes all actions.
    type: list
    elements: dict
    suboptions:
      type:
        description: Recovery operation.
        type: str
        required: true
        choices: [none, reboot, restart, run_command]
      delay_ms:
        description: Delay before the action, as an unsigned 32-bit millisecond count.
        type: raw
        aliases: [delay]
        default: 0
  failure_actions_on_non_crash_failure:
    description: Apply recovery actions to nonzero service-reported exit codes.
    type: bool
  failure_command:
    description: Command used by C(run_command) recovery actions.
    type: str
  failure_reboot_msg:
    description: Message used by C(reboot) recovery actions.
    type: str
  failure_reset_period_sec:
    description: Unsigned 32-bit recovery counter reset period in seconds.
    type: raw
    aliases: [failure_reset_period]
  pre_shutdown_timeout_ms:
    description: Unsigned 32-bit pre-shutdown timeout in milliseconds.
    type: raw
    aliases: [pre_shutdown_timeout]
  required_privileges:
    description: Required privilege names. Omission preserves; an empty list clears.
    type: list
    elements: str
  sid_info:
    description: Native service SID restriction policy.
    type: str
    choices: [none, restricted, unrestricted]
notes:
  - Requires service manager permissions for the requested operation.
  - Unsupported modern configuration reads return null with warnings. Requested
    setters are not silently emulated when the operating system rejects them.
  - Check mode predicts requested changes without creating or controlling services.
    Its creation defaults differ from the values returned after real creation.
  - A named-account change with a supplied nonempty password writes both together,
    so the Service Control Manager can validate the new credentials.
  - Passwords are masked in invocation data and excluded from readable diffs.
  - JSON numeric fractions in time counts round to nearest even before unsigned
    32-bit range validation. Exact lowercase aliases take precedence over canonical
    values. Nested aliases expand before input key case is normalized.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Start an existing service
  sustainablelobster.legacy_windows.win_service:
    name: example-service
    state: started

- name: Create a service with a quoted executable path
  sustainablelobster.legacy_windows.win_service:
    name: example-service
    path: '"C:\Program Files\Example\service.exe"'
    start_mode: manual
"""

RETURN = r"""
exists:
  description: Whether the service exists after the requested operation.
  returned: success
  type: bool
name:
  description: Resolved service key.
  returned: when the service exists
  type: str
state:
  description: Service state, using the legacy spelling C(running).
  returned: when the service exists
  type: str
display_name:
  description: Service display label.
  returned: when the service exists
  type: str
path:
  description: Executable command line.
  returned: when the service exists
  type: str
description:
  description: Service description, or null.
  returned: when the service exists
  type: str
start_mode:
  description: Startup mode. Pre-Vista Windows reports its basic SCM startup mode.
  returned: when the service exists
  type: str
username:
  description: Service account, with SYSTEM returned as C(LocalSystem).
  returned: when the service exists
  type: str
desktop_interact:
  description: Interactive flag.
  returned: when the service exists
  type: bool
dependencies:
  description: Ordered dependencies.
  returned: when the service exists
  type: list
  elements: str
depended_by:
  description: Keys of services dependent on this service.
  returned: when the service exists
  type: list
  elements: str
can_pause_and_continue:
  description: Currently accepted pause/continue control, or null for predicted creation.
  returned: when the service exists
  type: bool
"""
# pylint: enable=duplicate-code

_MODULE = "sustainablelobster.legacy_windows.win_service"
_DEFAULTS = dict.fromkeys(
    (
        "dependencies",
        "description",
        "display_name",
        "error_control",
        "failure_actions",
        "failure_actions_on_non_crash_failure",
        "failure_command",
        "failure_reboot_msg",
        "failure_reset_period_sec",
        "load_order_group",
        "name",
        "password",
        "path",
        "pre_shutdown_timeout_ms",
        "required_privileges",
        "service_type",
        "sid_info",
        "start_mode",
        "state",
        "update_password",
        "username",
    )
)
_DEFAULTS.update(
    dependency_action="set", desktop_interact=False, force_dependent_services=False
)
_ALIASES = {
    "failure_reset_period": "failure_reset_period_sec",
    "pre_shutdown_timeout": "pre_shutdown_timeout_ms",
}
_CHOICES = {
    "dependency_action": ("add", "remove", "set"),
    "error_control": ("critical", "ignore", "normal", "severe"),
    "service_type": (
        "win32_own_process",
        "win32_share_process",
        "user_own_process",
        "user_share_process",
    ),
    "sid_info": ("none", "restricted", "unrestricted"),
    "start_mode": ("auto", "delayed", "disabled", "manual"),
    "state": ("started", "stopped", "restarted", "absent", "paused"),
    "update_password": ("always", "on_create"),
}
_TYPE_VALUES = {
    "win32_own_process": 0x10,
    "win32_share_process": 0x20,
    "user_own_process": 0x50,
    "user_share_process": 0x60,
}
_ERROR_VALUES = {"ignore": 0, "normal": 1, "severe": 2, "critical": 3}


def _choice(value, name, choices):
    if value is not None:
        for item in choices:
            if environment.values_equal(value, item):
                return item
        raise ValueError(
            "value of {0} must be one of: {1}. Got no match for: {2}".format(
                name, ", ".join(choices), value
            )
        )
    return value


def _uint32(value, name):
    if value is None:
        return None
    try:
        if isinstance(value, float):
            # The pinned UInt32 binder rounds JSON numeric fractions to nearest even.
            number = int(round(value))
        elif isinstance(value, str) and value.lower().startswith("0x"):
            number = int(value, 0)
        else:
            number = int(value)
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError(
            "Expected an unsigned 32-bit integer for " + name + "."
        ) from error
    if number < 0 or number > 0xFFFFFFFF:
        raise ValueError("Expected an unsigned 32-bit integer for " + name + ".")
    return number


class _ActionKeyCollision(ValueError):
    """A nested duplicate rejected before service result initialization."""


def _actions(value):
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValueError("Expected a list for failure_actions.")
    result = []
    for item in value:
        dictionary_string = isinstance(item, str)
        entry = as_dictionary(item, "failure_actions")
        original_keys = {}
        for key in entry:
            lower = key.lower()
            if lower in original_keys:
                if dictionary_string:
                    # String entries reach the original binder as PSObjects,
                    # not JSON dictionaries inspected by its exec wrapper.
                    raise _ActionKeyCollision(
                        "Unhandled exception while executing module: Exception "
                        'calling "Create" with "2" argument(s): '
                        '"System.Management.Automation.PSObject cannot be '
                        'converted to a dict"'
                    )
                raise _ActionKeyCollision(
                    "failure during exec_wrapper: Cannot convert the JSON string "
                    "because a dictionary that was converted from the string "
                    "contains the duplicated keys '{0}' and '{1}'.".format(
                        original_keys[lower], key
                    )
                )
            original_keys[lower] = key
        entry = dict(entry)
        # The nested binder expands only the exact lowercase alias before
        # normalizing keys. A supplied Delay remains public but supplies no value.
        if "delay" in entry:
            entry["delay_ms"] = entry["delay"]
        for key in list(entry):
            lower = key.lower()
            if key != lower:
                value = entry.pop(key)
                if lower in entry:
                    raise _ActionKeyCollision(
                        "Unhandled exception while executing module: Exception "
                        'calling "Create" with "2" argument(s): "An item with the '
                        'same key has already been added."'
                    )
                entry[lower] = value
        if "type" not in entry:
            raise ValueError(
                "missing required arguments: type found in failure_actions"
            )
        unknown = set(entry) - {"type", "delay_ms", "delay"}
        if unknown:
            raise ValueError(
                "Unsupported failure_actions parameters: " + ", ".join(sorted(unknown))
            )
        entry["type"] = as_string(entry["type"], "type")
        _choice(entry["type"], "type", ("none", "reboot", "restart", "run_command"))
        # Basic keeps aliases in the public binding and lets them override
        # canonical values before converting only the canonical field.
        entry["delay_ms"] = _uint32(entry.get("delay_ms", 0), "delay_ms")
        result.append(entry)
    return result


def _native_actions(actions):
    return [
        {"type": action["type"].lower(), "delay_ms": action["delay_ms"]}
        for action in actions
    ]


def _parameters(arguments):
    arguments = dict(arguments)
    for alias, name in _ALIASES.items():
        if alias in arguments:
            arguments[name] = arguments[alias]
    unknown = sorted(
        key
        for key in arguments
        if key not in _DEFAULTS
        and key not in _ALIASES
        and not key.startswith("_ansible_")
    )
    if unknown and not as_bool(
        arguments.get("_ansible_ignore_unknown_opts", False),
        "_ansible_ignore_unknown_opts",
    ):
        raise ValueError(
            (
                "Unsupported parameters for ({0}) module: {1}. "
                "Supported parameters include: {2}"
            ).format(_MODULE, ", ".join(unknown), ", ".join(sorted(_DEFAULTS)))
        )
    if "name" not in arguments:
        raise ValueError("missing required arguments: name")
    if arguments.get("password") is not None and "username" not in arguments:
        raise ValueError("missing parameter(s) required by 'password': username")
    result = {}
    for name, default in _DEFAULTS.items():
        value = arguments.get(name, default)
        if name in (
            "desktop_interact",
            "force_dependent_services",
            "failure_actions_on_non_crash_failure",
        ):
            result[name] = None if value is None else as_bool(value, name)
        elif name in ("dependencies", "required_privileges"):
            result[name] = None if value is None else as_string_list(value, name)
        elif name in ("failure_reset_period_sec", "pre_shutdown_timeout_ms"):
            result[name] = _uint32(value, name)
        elif name == "failure_actions":
            result[name] = _actions(value)
        else:
            result[name] = as_string(value, name)
    for name, choices in _CHOICES.items():
        _choice(result[name], name, choices)
    result.update({alias: arguments[alias] for alias in _ALIASES if alias in arguments})
    return result


def _sid(name):
    if environment.values_equal(name, "LocalSystem"):
        return "S-1-5-18"
    return account.name_to_sid(name)


def _diff(record):
    result = {
        name: value
        for name, value in record.items()
        if not name.startswith("_") and name != "username"
    }
    if not record["_service_type"] & 3:
        result.update(
            username=(
                account.sid_to_name(_sid(record["username"]))
                if record["username"]
                else None
            ),
            password="REDACTED",
        )
    return result


def _write(result, check_mode, function, *arguments, **keywords):
    if not check_mode:
        function(*arguments, **keywords)
    result["changed"] = True


def _account(parameters, record, after, result, check_mode):
    if record["_service_type"] & 3:
        return
    if not record["username"]:
        after.update(username=parameters["username"] or "", password="REDACTED")
        return
    actual = _sid(record["username"])
    desired = _sid(parameters["username"]) if parameters["username"] else actual
    after.update(username=account.sid_to_name(desired), password="REDACTED")
    update = (parameters["update_password"] or "").lower() == "always"
    if desired != actual:
        if desired != "S-1-5-18":
            # Account changes perform this earlier type setter even when it
            # needs no write; its fields remain visible on a later failure.
            after.update(desktop_interact=False, service_type=record["service_type"])
            if record["desktop_interact"]:
                _write(
                    result,
                    check_mode,
                    service.change,
                    record["name"],
                    service_type=record["_service_type"] & ~0x100,
                )
                record["_service_type"] &= ~0x100
        username = (
            "LocalSystem" if desired == "S-1-5-18" else account.sid_to_name(desired)
        )
        password = (
            ""
            if desired in ("S-1-5-18", "S-1-5-19", "S-1-5-20") or username.endswith("$")
            else None
        )
        combined_password = password is None and bool(parameters["password"])
        if combined_password:
            # Legacy SCM validates a new named account during this write; a
            # username-only write can fail before the later password setter.
            password = parameters["password"]
            after["password"] = "CHANGED REDACTED"
        _write(
            result,
            check_mode,
            service.change,
            record["name"],
            username=username,
            password=password,
        )
        update = not combined_password
    if update and parameters["password"]:
        after["password"] = "CHANGED REDACTED"
        _write(
            result,
            check_mode,
            service.change,
            record["name"],
            password=parameters["password"],
        )


def _dependencies(old, requested, action):
    if requested is None:
        return old
    added = (
        [] if action == "remove" else [value for value in requested if value not in old]
    )
    removed = (
        []
        if action == "add"
        else (
            [value for value in old if value in requested]
            if action == "remove"
            else [value for value in old if value not in requested]
        )
    )
    result = [value for value in old if value not in removed]
    for value in added:
        if value not in result:
            result.append(value)
    return result


def _description_and_label(parameters, record, after, result, check_mode):
    name = record["name"]
    for field in ("description", "display_name", "error_control"):
        value = parameters[field]
        if value is None or (field != "description" and not value):
            after[field] = record[field]
            continue
        after[field] = value
        compare = value or None if field == "description" else value
        equal = (
            compare.lower() == record[field].lower()
            if field == "error_control"
            else compare == record[field]
        )
        if not equal:
            if field == "description":
                _write(result, check_mode, service.set_extended, name, field, value)
            else:
                native = (
                    _ERROR_VALUES[value.lower()] if field == "error_control" else value
                )
                _write(result, check_mode, service.change, name, **{field: native})


def _failure_configuration(parameters, record, after, result, check_mode):
    name = record["name"]
    flag = parameters["failure_actions_on_non_crash_failure"]
    after["failure_actions_on_non_crash_failure"] = record[
        "failure_actions_on_non_crash_failure"
    ]
    if flag is not None:
        # The pinned implementation leaves this diff entry null on a requested write.
        after["failure_actions_on_non_crash_failure"] = None
        if flag != record["failure_actions_on_non_crash_failure"]:
            _write(
                result,
                check_mode,
                service.set_extended,
                name,
                "failure_actions_on_non_crash_failure",
                flag,
            )
    failures = {}
    for field in (
        "failure_actions",
        "failure_command",
        "failure_reboot_msg",
        "failure_reset_period_sec",
    ):
        value = parameters[field]
        after[field] = record[field] if value is None else value
        if value is not None:
            compare = (
                _native_actions(value)
                if field == "failure_actions"
                else (
                    value or None
                    if field in ("failure_command", "failure_reboot_msg")
                    else value
                )
            )
            if compare != record[field]:
                failures[field] = compare if field == "failure_actions" else value
    if failures:
        actions = failures.get("failure_actions")
        period = failures.get("failure_reset_period_sec")
        if period is not None and actions is None:
            if not record["failure_actions"]:
                raise ValueError(
                    "Cannot set FailureAction ResetPeriod without explicit Actions "
                    "and no existing Actions"
                )
            failures["failure_actions"] = record["failure_actions"]
        elif actions is not None and period is None:
            failures["failure_reset_period_sec"] = record["failure_reset_period_sec"]
        try:
            _write(
                result,
                check_mode,
                service.set_extended,
                name,
                "failures",
                failures,
                access=16 if parameters["failure_actions"] else 0,
            )
        except OSError as error:
            # ctypes.WinError supplies this member on the Windows target.
            message = (
                "Failed to change service config ({0}, Win32ErrorCode {1} - 0x{1:08X})"
            ).format(
                error.strerror.rstrip(" .\r\n"),
                error.winerror,  # pylint: disable=no-member
            )
            _unhandled_failure(
                result, 'Exception setting "FailureActions": "' + message + '"'
            )


def _remaining_configuration(parameters, record, after, result, check_mode):
    name = record["name"]
    for field in (
        "load_order_group",
        "path",
        "pre_shutdown_timeout_ms",
        "required_privileges",
        "sid_info",
        "start_mode",
    ):
        value = parameters[field]
        if value is None or (field in ("path", "sid_info", "start_mode") and not value):
            after[field] = record[field]
            continue
        after[field] = value
        equal = (
            record[field] is not None and set(value) == set(record[field])
            if field == "required_privileges"
            else (
                value.lower() == (record[field] or "").lower()
                if field in ("sid_info", "start_mode")
                else value == record[field]
            )
        )
        if equal:
            continue
        if field in ("load_order_group", "path"):
            _write(result, check_mode, service.change, name, **{field: value})
        elif field == "start_mode":
            if not check_mode:
                service.change(
                    name,
                    start_type={"auto": 2, "delayed": 2, "manual": 3, "disabled": 4}[
                        value.lower()
                    ],
                )
                if service.supports_delayed_start():
                    service.set_extended(name, "delayed", value.lower() == "delayed")
            result["changed"] = True
        else:
            native = (
                {"none": 0, "unrestricted": 1, "restricted": 3}[value.lower()]
                if field == "sid_info"
                else value
            )
            _write(result, check_mode, service.set_extended, name, field, native)


def _service_type(parameters, record, after, result, check_mode):
    name = record["name"]
    kind = (parameters["service_type"] or "").lower()
    after["service_type"] = kind or record["service_type"]
    desired_type = _TYPE_VALUES[kind] if kind else record["_service_type"]
    interactive = parameters["desktop_interact"]
    after["desktop_interact"] = interactive
    if interactive:
        if _sid(parameters["username"] or record["username"]) != "S-1-5-18":
            raise ValueError(
                "Can only set 'desktop_interact' to true when 'username' equals 'SYSTEM'"
            )
        desired_type |= 0x100
    else:
        desired_type &= ~0x100
    if desired_type != record["_service_type"]:
        _write(result, check_mode, service.change, name, service_type=desired_type)


def _service_state(parameters, record, after, result, check_mode):
    name = record["name"]
    state = parameters["state"]
    after["state"] = state or record["state"]
    if state:
        state = state.lower()
        if state == "restarted" or state != record["state"]:
            if state == "paused" and not record["_controls"] & 2:
                raise ValueError(
                    "failed to pause service {0}: The service does not support pausing".format(
                        name
                    )
                )
            try:
                _write(
                    result,
                    check_mode,
                    service.control,
                    name,
                    state,
                    parameters["force_dependent_services"],
                )
            except OSError as error:
                # ctypes.WinError supplies this member on the Windows target.
                code = error.winerror  # pylint: disable=no-member
                if state in ("stopped", "restarted") and code == 1051:
                    _unhandled_failure(
                        result,
                        "Cannot stop service '{0} ({1})' because it has dependent "
                        "services. It can only be stopped if the Force flag is set.".format(
                            record["display_name"], name
                        ),
                    )
                raise


def _unhandled_failure(result, message):
    # The pinned outer exception boundary discards its partial result, even
    # when earlier setters have written. Native observations must show those writes.
    result.clear()
    result["changed"] = False
    raise RuntimeError("Unhandled exception while executing module: " + message)


def _configure(parameters, record, after, result, check_mode):
    _account(parameters, record, after, result, check_mode)
    dependencies = _dependencies(
        record["dependencies"],
        parameters["dependencies"],
        parameters["dependency_action"].lower(),
    )
    after["dependencies"] = dependencies
    if dependencies != record["dependencies"]:
        _write(
            result,
            check_mode,
            service.change,
            record["name"],
            dependencies=dependencies,
        )
    _description_and_label(parameters, record, after, result, check_mode)
    _failure_configuration(parameters, record, after, result, check_mode)
    _remaining_configuration(parameters, record, after, result, check_mode)
    _service_type(parameters, record, after, result, check_mode)
    _service_state(parameters, record, after, result, check_mode)


def _predicted_creation(parameters):
    result = {
        name: parameters[name]
        for name in (
            "name",
            "dependencies",
            "description",
            "desktop_interact",
            "display_name",
            "error_control",
            "failure_actions",
            "failure_command",
            "failure_reboot_msg",
            "failure_reset_period_sec",
            "load_order_group",
            "path",
            "pre_shutdown_timeout_ms",
            "required_privileges",
            "service_type",
            "sid_info",
            "start_mode",
            "state",
        )
    }
    for name in (
        "display_name",
        "error_control",
        "service_type",
        "sid_info",
        "start_mode",
        "state",
    ):
        result[name] = result[name] or ""
    result["failure_actions_on_non_crash_failure"] = None
    return result


# Keeping creation, absence, and check-mode branches together makes the public
# service-existence contract visible without introducing a second state model.
def _manage(parameters, result, check_mode):  # pylint: disable=too-many-branches
    # Expanded paths and creation-only password policy are working values,
    # not changes to the argument dictionary returned in invocation data.
    parameters = dict(parameters)
    if (
        parameters["start_mode"] or ""
    ).lower() == "delayed" and not service.supports_delayed_start():
        raise ValueError(
            "start_mode=delayed is not supported before Windows Vista / Server 2008."
        )
    parameters["path"] = service.expand_path(parameters["path"])
    name = service.resolve_name(parameters["name"])
    warnings = []
    access = 0x10000 if (parameters["state"] or "").lower() == "absent" else 2
    if parameters["failure_actions"]:
        access |= 16
    record = service.read(name, warnings, access) if name is not None else None
    before = _diff(record) if record is not None else ""
    diff = {"before": before, "after": ""}
    if "diff" in result:
        result["diff"] = diff
    if warnings:
        result["warnings"] = warnings
    if (parameters["state"] or "").lower() == "absent":
        if record is not None:
            if not check_mode:
                service.control(name, "stopped", parameters["force_dependent_services"])
                service.remove(name)
            result["changed"] = True
        return
    created = record is None
    if created:
        parameters["update_password"] = "always"
        mutate = any(
            parameters[key] is not None
            for key in _DEFAULTS
            if key
            not in (
                "name",
                "dependency_action",
                "desktop_interact",
                "force_dependent_services",
                "update_password",
            )
        )
        mutate = (
            mutate
            or parameters["dependency_action"].lower() != "set"
            or parameters["desktop_interact"]
        )
        if not mutate:
            return
        if parameters["path"] is None:
            raise ValueError(
                "Service '{0}' is not installed, need to set 'path' to create a new service".format(
                    parameters["name"]
                )
            )
        if check_mode:
            after = _predicted_creation(parameters)
            result["changed"] = True
        else:
            service.create(parameters["name"], parameters["path"])
            result["changed"] = True
            name = parameters["name"]
            record = service.read(name, warnings)
            if warnings:
                result["warnings"] = warnings
            after = {"name": name}
    else:
        after = {"name": name}
    diff["after"] = after
    if record is not None:
        _configure(parameters, record, after, result, check_mode)
    current = service.read(name, []) if record is not None else None
    _legacy_result(after, current, result)


def _legacy_result(after, current, result):
    result["exists"] = True
    for key in (
        "name",
        "dependencies",
        "description",
        "desktop_interact",
        "display_name",
        "path",
        "start_mode",
        "username",
    ):
        result[key] = after.get(key)
    if result["username"] and _sid(result["username"]) == "S-1-5-18":
        result["username"] = "LocalSystem"
    state = after["state"].replace("_", "")
    result["state"] = "running" if state.lower() in ("started", "restarted") else state
    result["can_pause_and_continue"] = (
        bool(current["_controls"] & 2) if current is not None else None
    )
    result["depended_by"] = current["_dependents"] if current is not None else []


def _redact(value, password):
    if not password:
        return value
    if isinstance(value, dict):
        return {key: _redact(item, password) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item, password) for item in value]
    if isinstance(value, str):
        return (
            "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
            if value == password
            else value.replace(password, "********")
        )
    return value


def _response():
    arguments = read_arguments(
        dict(_DEFAULTS, **dict.fromkeys(_ALIASES)), _MODULE, allow_unknown=True
    )
    result = {"changed": False, "exists": False}
    parameters = None
    password = as_string(arguments.get("password"), "password")
    try:
        parameters = _parameters(arguments)
        if as_bool(arguments.get("_ansible_diff", False), "_ansible_diff"):
            result["diff"] = {"before": "", "after": ""}
        _manage(
            parameters,
            result,
            as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
        )
    except _ActionKeyCollision as error:
        # These pinned wrapper/binder failures precede initialized service
        # fields and invocation data, unlike ordinary payload validation.
        return _redact(
            {
                "changed": False,
                "failed": True,
                "msg": str(error),
                "exception": "(traceback unavailable)",
            },
            password,
        )
    except Exception as error:  # pylint: disable=broad-exception-caught
        result.update(failed=True, msg=str(error), exception="(traceback unavailable)")
    if as_bool(
        arguments.get("_ansible_inject_invocation", False), "_ansible_inject_invocation"
    ):
        result["invocation"] = {
            "module_args": (
                parameters
                if parameters is not None
                else {
                    key: value
                    for key, value in arguments.items()
                    if not key.startswith("_ansible_")
                }
            )
        }
    return _redact(result, password)


def main():
    """Emit one Ansible JSON result, with passwords masked on failures too.

    :raises SystemExit: After emitting the protocol response.
    """
    run_module(_response)


# Each independently staged payload needs its own executable entry guard.
# pylint: disable=duplicate-code
if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
