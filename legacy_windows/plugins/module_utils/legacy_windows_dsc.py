"""Validate dynamic resource arguments and invoke the classic DSC engine."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ctypes

from legacy_windows_dsc_engine import engine_request  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_dictionary,
    as_string,
    as_string_list,
)


def _option_names(entry):
    name = "Key" if entry["name"] == "key" else entry["name"]
    if entry.get("reference") == "MSFT_Credential":
        return [name + "_username", name + "_password"]
    return [name]


def _boolean(value, name):
    try:
        return as_bool(value, name)
    except ValueError as error:
        type_name = (
            "System.String"
            if isinstance(value, str)
            else "System." + type(value).__name__
        )
        raise ValueError(
            "argument for {0} is of type {1} and we were unable to convert to bool: "
            "The value '{2}' is not a valid boolean. Valid booleans include: "
            "y, yes, on, 1, true, t, 1.0, n, no, off, 0, false, f, 0.0".format(
                name, type_name, value
            )
        ) from error


def _integer_kind(value):
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
        elif abs(value) <= 79228162514264337593543950335:
            kind = "Decimal"
        else:
            kind = "Double"
    elif isinstance(value, list):
        kind = "Object[]"
    else:
        kind = "Collections.Generic.Dictionary`2[System.String,System.Object]"
    return "System." + kind


def _integer(value, name):
    # Basic parses signed decimal text, not Python's Boolean conversion or float
    # truncation. Int32.Parse permits ASCII whitespace and trailing nulls.
    text = as_string(value, name).lstrip(" \t\r\n\v\f")
    text = text.rstrip("\x00").rstrip(" \t\r\n\v\f")
    digits = text[1:] if text.startswith(("+", "-")) else text
    detail = "Input string was not in a correct format."
    if digits and all(character in "0123456789" for character in digits):
        converted = int(text)
        if -(2**31) <= converted < 2**31:
            return converted
        detail = "Value was either too large or too small for an Int32."
    raise ValueError(
        "argument for {0} is of type {1} and we were unable to convert to int: {2}".format(
            name, _integer_kind(value), detail
        )
    )


def _ordinal_equal(left, right):
    if all(ord(character) < 128 for character in left + right):
        return left.lower() == right.lower()
    # Python casefold expands characters such as sharp S, unlike the source's
    # OrdinalIgnoreCase comparer. Use Windows' ordinal comparison for Unicode.
    compare = ctypes.WinDLL("kernel32", use_last_error=True).CompareStringOrdinal
    compare.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_int,
    ]
    compare.restype = ctypes.c_int
    result = compare(
        left,
        len(left.encode("utf-16-le", "surrogatepass")) // 2,
        right,
        len(right.encode("utf-16-le", "surrogatepass")) // 2,
        True,
    )
    if not result:
        raise ctypes.WinError(ctypes.get_last_error())
    return result == 2


def _check_choices(result, entry):
    choices = entry.get("choices")
    if not choices:
        return
    texts = [as_string(choice, entry["name"]) for choice in choices]
    values = result if isinstance(result, list) else [result]
    invalid = []
    for value in values:
        text = as_string(value, entry["name"])
        if not any(_ordinal_equal(text, choice) for choice in texts + invalid):
            invalid.append(text)
    if invalid:
        raise ValueError(
            "value of {0} must be {1}: {2}. Got no match for: {3}".format(
                entry["name"],
                "one or more of" if isinstance(result, list) else "one of",
                ", ".join(texts),
                ", ".join(invalid),
            )
        )


def _scalar(value, entry):
    kind = entry["type"]
    name = entry["name"]
    if kind == "Boolean":
        return _boolean(value, name)
    if kind == "String" or entry.get("reference") == "MSFT_Credential":
        return as_string(value, name)
    if kind in ("Instance", "Reference"):
        return as_dictionary(value, name)
    if kind == "SInt32":
        return _integer(value, name)
    if kind == "Real32":
        try:
            return float(value)
        except (TypeError, ValueError) as error:
            raise ValueError(
                "argument for {0} cannot be converted to float".format(name)
            ) from error
    # DSC's explicit engine adapter converts the remaining CIM scalar types.
    return value


def _value(value, entry):
    if value is None:
        return None
    if entry.get("reference") == "MSFT_KeyValuePair":
        return as_dictionary(value, entry["name"])
    kind = entry["type"]
    if kind.endswith("Array"):
        if kind == "StringArray":
            result = as_string_list(value, entry["name"])
        else:
            items = (
                value
                if isinstance(value, list)
                else (value.split(",") if isinstance(value, str) else [value])
            )
            scalar = dict(entry, type=kind[:-5])
            result = [_scalar(item, scalar) for item in items]
    else:
        result = _scalar(value, entry)
    if entry.get("properties"):
        if isinstance(result, list):
            result = [
                _properties(item, entry["properties"], base=False) for item in result
            ]
        else:
            result = _properties(result, entry["properties"], base=False)
    _check_choices(result, entry)
    return result


def _required_properties(supplied, options, schema):
    missing = sorted(
        name
        for name, entry in options.items()
        if entry["required"] and supplied.get(name) is None
    )
    if missing:
        raise ValueError("missing required arguments: " + ", ".join(missing))
    for entry in schema:
        names = _option_names(entry)
        if len(names) == 2:
            present = [supplied.get(name) is not None for name in names]
            if any(present) and not all(present):
                raise ValueError(
                    "parameters are required together: " + ", ".join(names)
                )


def _properties(arguments, schema, base=True):
    options = {}
    canonical = {}
    for entry in schema:
        for name in _option_names(entry):
            options[name] = entry
            canonical[name.lower()] = name
        if entry["name"] == "Name":
            canonical["item_name"] = "Name"
    if base:
        canonical.update(
            {"resource_name": "resource_name", "module_version": "module_version"}
        )
    supplied = {}
    unknown = []
    for key, value in arguments.items():
        if key.startswith("_ansible_"):
            continue
        name = canonical.get(key.lower())
        if name is None:
            unknown.append(key)
        else:
            supplied[name] = value
    if unknown:
        supported = sorted(
            set(options) | ({"module_version", "resource_name"} if base else set())
        )
        raise ValueError(
            "Unsupported parameters for (ansible.windows.win_dsc) module: {0}. "
            "Supported parameters include: {1}".format(
                ", ".join(sorted(unknown)), ", ".join(supported)
            )
        )
    _required_properties(supplied, options, schema)
    return {
        name: _value(
            value,
            (
                dict(options[name], name=name, type="String")
                if options[name].get("reference") == "MSFT_Credential"
                else options[name]
            ),
        )
        for name, value in supplied.items()
        if name in options and value is not None
    }


def _redact(value, passwords):
    if isinstance(value, str):
        for password in passwords:
            if password:
                value = value.replace(password, "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER")
        return value
    if isinstance(value, list):
        return [_redact(item, passwords) for item in value]
    if isinstance(value, dict):
        return {key: _redact(item, passwords) for key, item in value.items()}
    return value


def _credential_passwords(arguments, schema):
    values = {name.lower(): value for name, value in arguments.items()}
    passwords = []
    for entry in schema:
        name = entry["name"].lower()
        if entry.get("reference") == "MSFT_Credential":
            value = values.get(name + "_password")
            if value is not None:
                passwords.append(as_string(value, name + "_password"))
        elif entry.get("properties") and values.get(name) is not None:
            value = values[name]
            items = value if isinstance(value, list) else [value]
            for item in items:
                passwords.extend(
                    _credential_passwords(
                        as_dictionary(item, name), entry["properties"]
                    )
                )
    return passwords


def configure_resource(arguments, request=engine_request):
    """Test and, outside check mode, set one schema-discovered DSC resource.

    :param dict arguments: Ansible arguments, including dynamic DSC properties.
    :param callable request: Installed DSC engine adapter.
    :returns: Released-style result, preserving early and method failure fields.
    :rtype: dict
    """
    result = {"changed": False}
    discovery = request({"operation": "discover", "arguments": arguments})
    if discovery.get("error"):
        result.update(failed=True, msg=discovery["error"])
        return result
    passwords = _credential_passwords(arguments, discovery["properties"])
    try:
        properties = _properties(arguments, discovery["properties"])
    except ValueError as error:
        result.update(failed=True, msg=str(error))
        return _redact(result, passwords)
    result.update(module_version=discovery["module_version"], reboot_required=False)
    for method in ("Test", "Set"):
        response = request(
            {
                "operation": "invoke",
                "invocation": discovery["invocation"],
                "schema": discovery["properties"],
                "properties": properties,
                "method": method,
            }
        )
        if response.get("warnings"):
            result.setdefault("warnings", []).extend(response["warnings"])
        if arguments.get("_ansible_verbosity", 0) >= 3:
            result["verbose_" + method.lower()] = response.get("verbose", [])
        if response.get("error"):
            result.update(failed=True, msg=response["error"])
            return _redact(result, passwords)
        output = response.get("result", [])
        if method == "Set":
            result["reboot_required"] = (
                output[0].get("RebootRequired") if output else None
            )
            result["changed"] = True
        elif output and output[0].get("InDesiredState") is True:
            break
        elif as_bool(
            arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
        ):
            result["changed"] = True
            break
    return _redact(result, passwords)
