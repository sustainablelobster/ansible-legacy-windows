# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate script arguments and protect declared secrets in failure messages."""

from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_dictionary,
    as_string,
    as_string_list,
)
from legacy_windows_powershell_engine import (  # pylint: disable=import-error
    invoke_script,
)

_TEXT_OPTIONS = ("chdir", "creates", "executable", "path", "removes", "script")


def _depth(value):
    # Keep this released Hashtable argument diagnostic with its public binder;
    # DSC has a different private Dictionary diagnostic and null behavior.
    # pylint: disable=duplicate-code
    if value is None:
        return 0
    if isinstance(value, str):
        kind = "String"
    elif isinstance(value, bool):
        kind = "Boolean"
    elif isinstance(value, float):
        kind = "Double" if "e" in repr(value) else "Decimal"
    elif isinstance(value, int):
        if -(2**31) <= value < 2**31:
            kind = "Int32"
        elif -(2**63) <= value < 2**63:
            kind = "Int64"
        else:
            kind = (
                "Decimal" if abs(value) <= 79228162514264337593543950335 else "Double"
            )
    elif isinstance(value, list):
        kind = "Object[]"
    else:
        kind = "Collections.Hashtable"
    text = as_string(value, "depth").lstrip(" \t\r\n\v\f")
    text = text.rstrip("\x00").rstrip(" \t\r\n\v\f")
    digits = text[1:] if text.startswith(("+", "-")) else text
    detail = "Input string was not in a correct format."
    if digits and all(character in "0123456789" for character in digits):
        converted = int(text)
        if -(2**31) <= converted < 2**31:
            return converted
        detail = "Value was either too large or too small for an Int32."
    raise ValueError(
        "argument for depth is of type System.{0} and we were unable to convert to int: {1}".format(
            kind, detail
        )
    )


def _sensitive(values):
    if values is None:
        return []
    if not isinstance(values, list):
        raise ValueError("Expected a list for sensitive_parameters.")
    result = []
    for item in values:
        item = as_dictionary(item, "sensitive_parameters")
        if item is None:
            raise ValueError(
                "missing required arguments: name found in sensitive_parameters"
            )
        item = {key.lower(): value for key, value in item.items()}
        if "name" not in item:
            raise ValueError(
                "missing required arguments: name found in sensitive_parameters"
            )
        unsupported = sorted(set(item) - {"name", "value", "username", "password"})
        if unsupported:
            raise ValueError(
                "Unsupported parameters for (ansible.windows.win_powershell) module: "
                + ", ".join(unsupported)
                + " found in sensitive_parameters. Supported parameters include: "
                "name, password, username, value"
            )
        if "value" in item:
            for conflict in ("username", "password"):
                if conflict in item:
                    raise ValueError(
                        "parameters are mutually exclusive: value, "
                        + conflict
                        + " found in sensitive_parameters"
                    )
        if ("username" in item) != ("password" in item):
            raise ValueError(
                "parameters are required together: username, password"
                + " found in sensitive_parameters"
            )
        result.append({key: as_string(value, key) for key, value in item.items()})
    return result


def _redact(value, secrets):
    if isinstance(value, str):
        if value in secrets:
            return "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
        for secret in sorted(secrets, key=len, reverse=True):
            value = value.replace(secret, "********")
        return value
    if isinstance(value, list):
        return [_redact(item, secrets) for item in value]
    if isinstance(value, dict):
        return {key: _redact(item, secrets) for key, item in value.items()}
    if isinstance(value, (bool, int, float)):
        text = as_string(value, "sensitive result")
        if any(secret in text for secret in secrets):
            return "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
    return value


def execute_script(arguments):
    """Invoke the explicit engine with source-exact failure-message protection.

    :param arguments: Flat Ansible JSON options and controller flags.
    :type arguments: dict
    :returns: Complete structured script result.
    :rtype: dict
    :raises ValueError: If script options or sensitive parameters are invalid.
    :raises OSError: If the selected installed PowerShell engine is unavailable.
    """
    if "script" in arguments and "path" in arguments:
        raise ValueError("parameters are mutually exclusive: path, script")
    if "script" not in arguments and "path" not in arguments:
        raise ValueError("one of the following is required: path, script")
    request = {key: as_string(arguments.get(key), key) for key in _TEXT_OPTIONS}
    request["remote_src"] = as_bool(arguments.get("remote_src", False), "remote_src")
    request["arguments"] = as_string_list(arguments.get("arguments"), "arguments")
    request["parameters"] = as_dictionary(arguments.get("parameters"), "parameters")
    request["check_mode"] = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    request["diff_mode"] = as_bool(
        arguments.get("_ansible_diff", False), "_ansible_diff"
    )
    request["verbosity"] = arguments.get("_ansible_verbosity", 0)
    request["depth"] = _depth(arguments.get("depth", 2))
    request["error_action"] = as_string(
        arguments.get("error_action", "continue"), "error_action"
    )
    if request["error_action"] is not None and request["error_action"].lower() not in (
        "continue",
        "stop",
        "silently_continue",
    ):
        raise ValueError(
            "value of error_action must be one of: silently_continue, continue, stop."
            " Got no match for: " + str(request["error_action"])
        )
    request["sensitive_parameters"] = _sensitive(arguments.get("sensitive_parameters"))
    secrets = {
        item[key]
        for item in request["sensitive_parameters"]
        for key in ("value", "password")
        if item.get(key)
    }
    try:
        result = invoke_script(request)
        # Basic hides declared secrets from invocation and FailJson messages,
        # not from arbitrary fields the caller deliberately writes or returns.
        if "msg" in result:
            result["msg"] = _redact(result["msg"], secrets)
        return result
    except (OSError, UnicodeError, ValueError) as error:
        if not secrets:
            raise
        return _redact({"changed": False, "failed": True, "msg": str(error)}, secrets)
