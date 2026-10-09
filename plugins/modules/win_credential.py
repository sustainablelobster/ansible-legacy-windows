#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage named credentials with the native Windows credential store."""

# WANT_JSON

import base64
import binascii

import legacy_windows_credential as credential  # pylint: disable=import-error
import legacy_windows_environment as environment  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    DOTNET_WHITESPACE,
    as_bool,
    as_dictionary,
    as_string,
    read_arguments,
    run_module,
)

# Ansible interfaces must be self-contained; repeated option/return text is
# interface documentation, not duplicated execution logic.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_credential
short_description: Manage named Windows Credential Manager entries
description:
  - Creates, updates, and removes password or certificate credentials for the
    executing Windows user through native APIs.
options:
  name:
    description: Target name, combined with O(type) to identify one credential.
    type: str
    required: true
  type:
    description: Credential category and authentication mechanism.
    type: str
    required: true
    choices: [domain_password, domain_certificate, generic_password, generic_certificate]
  state:
    description: Whether the named credential should exist.
    type: str
    choices: [absent, present]
    default: present
  username:
    description:
      - Account name for password credentials; required when O(state=present).
      - For certificate credentials, supply the thumbprint of a certificate in
        the executing user's CurrentUser\My certificate store.
    type: str
  secret:
    description:
      - Password or certificate PIN. Omitted values preserve an existing secret.
      - A new credential without this option has an empty secret.
    type: str
  secret_format:
    description: Interpret O(secret) as UTF-16LE text or base64-encoded bytes.
    type: str
    choices: [base64, text]
    default: text
  update_secret:
    description:
      - Select whether an existing secret should be compared and updated.
      - C(always) reports a change when Windows does not expose a readable secret.
    type: str
    choices: [always, on_create]
    default: always
  persistence:
    description: Persist locally for the user or permit domain roaming.
    type: str
    choices: [enterprise, local]
    default: local
  alias:
    description: Optional target alias. Omission clears an existing alias.
    type: str
  comment:
    description: Optional case-sensitive comment. Omission clears an existing comment.
    type: str
  attributes:
    description:
      - Ordered application attributes. Omission preserves existing attributes;
        an empty list removes them. Duplicate names are allowed.
    type: list
    elements: dict
    suboptions:
      name:
        description: Attribute keyword.
        type: str
        required: true
      data:
        description: Attribute value; text uses UTF-8, matching the pinned implementation.
        type: str
      data_format:
        description: Interpret the value as text or base64-encoded bytes.
        type: str
        choices: [base64, text]
        default: text
notes:
  - The executing logon session must have access to the user's credential store.
    Upstream recommends become when the connection's logon session lacks access.
  - Secret values are omitted from diffs. Other diff fields can coincide with a secret.
  - Check-mode attribute diffs contain supplied values; real diffs contain base64 bytes.
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Store an application credential
  sustainablelobster.legacy_windows.win_credential:
    name: example-application
    type: generic_password
    username: application-user
    secret: '{{ application_password }}'

- name: Remove the application credential
  sustainablelobster.legacy_windows.win_credential:
    name: example-application
    type: generic_password
    state: absent
"""

RETURN = """
---
"""
# pylint: enable=duplicate-code

_MODULE = "sustainablelobster.legacy_windows.win_credential"
_DEFAULTS = {
    "alias": None,
    "attributes": None,
    "comment": None,
    "name": None,
    "persistence": "local",
    "secret": None,
    "secret_format": "text",
    "state": "present",
    "type": None,
    "update_secret": "always",
    "username": None,
}
_CHOICES = {
    "persistence": ("enterprise", "local"),
    "secret_format": ("base64", "text"),
    "state": ("absent", "present"),
    "type": (
        "domain_password",
        "domain_certificate",
        "generic_password",
        "generic_certificate",
    ),
    "update_secret": ("always", "on_create"),
}
_TYPES = {
    "generic_password": 1,
    "domain_password": 2,
    "domain_certificate": 3,
    "generic_certificate": 5,
}
_TYPE_NAMES = {
    1: "Generic",
    2: "DomainPassword",
    3: "DomainCertificate",
    5: "GenericCertificate",
}
_PERSIST_NAMES = {1: "Session", 2: "LocalMachine", 3: "Enterprise"}


def _choice(value, name, choices):
    if value is not None and not any(
        environment.values_equal(value, item) for item in choices
    ):
        # Choice failures use the same public argument-validation envelope.
        # pylint: disable=duplicate-code
        raise ValueError(
            "value of {0} must be one of: {1}. Got no match for: {2}".format(
                name, ", ".join(choices), value
            )
        )
        # pylint: enable=duplicate-code
    return value


def _attributes(value):
    if value is None:
        return None
    if isinstance(value, str):
        value = [entry.strip(DOTNET_WHITESPACE) for entry in value.split(",")]
    elif isinstance(value, int) and not isinstance(value, bool):
        value = [value]
    if not isinstance(value, list):
        raise ValueError("Expected a list for attributes.")
    result = []
    for entry in value:
        entry = as_dictionary(entry, "attributes")
        if entry is None:
            raise ValueError("attributes must not contain null entries.")
        entry = {key.lower(): item for key, item in entry.items()}
        unknown = sorted(set(entry) - {"name", "data", "data_format"})
        if unknown:
            raise ValueError(
                "Unsupported parameters for ({0}) module: {1} found in attributes. "
                "Supported parameters include: data, data_format, name".format(
                    _MODULE, ", ".join(unknown)
                )
            )
        if "name" not in entry:
            raise ValueError("missing required arguments: name found in attributes")
        data_format = as_string(entry.get("data_format", "text"), "data_format")
        result.append(
            {
                "name": as_string(entry["name"], "name"),
                "data": as_string(entry.get("data"), "data"),
                "data_format": _choice(data_format, "data_format", ("base64", "text")),
            }
        )
    return result


def _parameters(arguments):
    unknown = sorted(
        key
        for key in arguments
        if key not in _DEFAULTS and not key.startswith("_ansible_")
    )
    # Each module validates its own option set and core's ignore-unknown flag.
    # pylint: disable=duplicate-code
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
    # pylint: enable=duplicate-code
    missing = [name for name in ("name", "type") if name not in arguments]
    if missing:
        raise ValueError("missing required arguments: " + ", ".join(missing))
    result = {
        name: as_string(arguments.get(name, default), name)
        for name, default in _DEFAULTS.items()
        if name != "attributes"
    }
    for name, choices in _CHOICES.items():
        _choice(result[name], name, choices)
    if (
        environment.values_equal(result["state"], "present")
        and "username" not in arguments
    ):
        raise ValueError(
            "state is present but all of the following are missing: username"
        )
    result["attributes"] = _attributes(arguments.get("attributes"))
    return result


def _bytes(value, data_format, encoding):
    if value is None:
        return None
    if environment.values_equal(data_format, "base64"):
        text = value.translate({ord(character): None for character in " \t\r\n"})
        # Python 3.4 accepts excess padding that FromBase64String rejects.
        if len(text) % 4:
            raise binascii.Error("Invalid length for a Base-64 char array or string.")
        try:
            return base64.b64decode(text.encode("ascii"), validate=True)
        except (UnicodeError, binascii.Error) as error:
            raise ValueError("The input is not a valid Base-64 string.") from error
    # Decode UTF-16 code units to preserve pairs and replace lone surrogates
    # with U+FFFD, matching the pinned .NET encoders rather than Python's '?'.
    text = value.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace")
    return text.encode(encoding)


def _encoded(value):
    return base64.b64encode(value).decode("ascii") if value is not None else None


def _converted_attributes(attributes):
    return [
        {
            "name": entry["name"],
            "data": _bytes(entry["data"], entry["data_format"], "utf-8"),
            "flags": 0,
        }
        for entry in attributes
    ]


def _diff(record):
    return {
        "name": record["name"],
        "type": _TYPE_NAMES.get(record["type"], str(record["type"])),
        "alias": record["alias"],
        "comment": record["comment"],
        "persistence": _PERSIST_NAMES.get(
            record["persistence"], str(record["persistence"])
        ),
        "username": record["username"],
        "attributes": [
            {"name": entry["name"], "data": _encoded(entry["data"])}
            for entry in record["attributes"]
        ],
    }


def _update(existing, parameters, secret, persistence):
    changed = False
    for name in ("comment", "alias", "username"):
        equal = (
            existing[name] == parameters[name]
            if name == "comment"
            else environment.values_equal(existing[name], parameters[name])
        )
        if not equal:
            existing[name], changed = parameters[name], True
    if existing["persistence"] != persistence:
        existing["persistence"], changed = persistence, True
    if parameters["attributes"] is not None:
        requested = _converted_attributes(parameters["attributes"])
        old = existing["attributes"]
        equal = len(requested) == len(old) and all(
            left["name"] == right["name"]
            and environment.values_equal(
                _encoded(left["data"]) or "", _encoded(right["data"]) or ""
            )
            for left, right in zip(requested, old)
        )
        if not equal:
            existing["attributes"], changed = requested, True
    preserve = secret is None
    if preserve:
        existing["secret"] = None
    elif environment.values_equal(parameters["update_secret"], "always") and (
        not existing["secret"]
        or not environment.values_equal(_encoded(secret), _encoded(existing["secret"]))
    ):
        existing["secret"], changed = secret, True
    return changed, preserve


def _certificate_username(parameters, kind):
    username = parameters["username"]
    if kind in (3, 5) and username is not None:
        username = username.upper().replace(" ", "").replace("-", "")
        parameters["username"] = username
        if not credential.certificate_exists(username):
            raise ValueError(
                "Failed to find certificate with the thumbprint "
                + username
                + " in the CurrentUser\\My store"
            )
    return username


def _manage(parameters, result, check_mode):
    parameters = dict(parameters)
    diff = {"before": "", "after": ""}
    if "diff" in result:
        result["diff"] = diff
    name, type_name = parameters["name"], parameters["type"]
    kind = _TYPES.get(type_name.lower() if type_name else None, 0)
    username = _certificate_username(parameters, kind)
    secret = _bytes(parameters["secret"], parameters["secret_format"], "utf-16-le")
    persistence = (
        3 if environment.values_equal(parameters["persistence"], "enterprise") else 2
    )
    existing = credential.read(name, kind)
    if existing is not None:
        diff["before"] = _diff(existing)
    if environment.values_equal(parameters["state"], "absent"):
        if existing is not None:
            if not check_mode:
                credential.delete(existing["name"], existing["type"])
            result["changed"] = True
        return
    if existing is None:
        record = {
            "name": name,
            "type": kind,
            "persistence": persistence,
            "alias": parameters["alias"] or None,
            "comment": parameters["comment"] or None,
            "username": username,
            "secret": secret,
            "attributes": _converted_attributes(parameters["attributes"] or []),
        }
        if not check_mode:
            credential.write(record, False)
        result["changed"] = True
    else:
        changed, preserve = _update(existing, parameters, secret, persistence)
        if changed and not check_mode:
            credential.write(existing, preserve)
        result["changed"] = changed
    if check_mode:
        diff["after"] = {
            "name": name,
            "type": _TYPE_NAMES.get(kind, str(kind)),
            "alias": parameters["alias"],
            "comment": parameters["comment"],
            "persistence": _PERSIST_NAMES[persistence],
            "username": username,
            "attributes": parameters["attributes"],
        }
    else:
        diff["after"] = _diff(credential.read(name, kind))


def _hide_secret(value, secret):
    if not secret:
        return value
    if isinstance(value, dict):
        return {key: _hide_secret(entry, secret) for key, entry in value.items()}
    if isinstance(value, list):
        return [_hide_secret(entry, secret) for entry in value]
    if isinstance(value, str):
        return (
            "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
            if value == secret
            else value.replace(secret, "********")
        )
    if value is not None and secret in as_string(value, "secret redaction"):
        return "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
    return value


def _response():
    arguments = read_arguments(_DEFAULTS, _MODULE, allow_unknown=True)
    secret = as_string(arguments.get("secret"), "secret")
    result = {"changed": False}
    parameters = None
    try:
        # This dispatch binds core check/diff flags, not credential operations.
        # pylint: disable=duplicate-code
        parameters = _parameters(arguments)
        if as_bool(arguments.get("_ansible_diff", False), "_ansible_diff"):
            result["diff"] = {"before": "", "after": ""}
        _manage(
            parameters,
            result,
            as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
        )
        # pylint: enable=duplicate-code
    except Exception as error:  # pylint: disable=broad-exception-caught
        message = str(error)
        if isinstance(error, binascii.Error):
            # The measured upstream conversion exception omits the pending diff.
            result.pop("diff", None)
            message = (
                "Unhandled exception while executing module: Exception calling "
                '"FromBase64String" with "1" argument(s): "{0}"'
            ).format(message)
        result.update(
            failed=True,
            msg=_hide_secret(message, secret),
            exception="(traceback unavailable)",
        )
    if as_bool(
        arguments.get("_ansible_inject_invocation", False), "_ansible_inject_invocation"
    ):
        # Invocation reports validated arguments or excludes core's private flags.
        # pylint: disable=duplicate-code
        invocation = (
            parameters
            if parameters is not None
            else {
                key: value
                for key, value in arguments.items()
                if not key.startswith("_ansible_")
            }
        )
        # pylint: enable=duplicate-code
        invocation = dict(invocation)
        if "secret" in invocation:
            invocation["secret"] = secret
        result["invocation"] = {"module_args": _hide_secret(invocation, secret)}
    return result


def main():
    """Read one Ansible request and emit results with scoped secret redaction.

    :raises SystemExit: After emitting the success or failure response.
    """
    run_module(_response)


# Each independently staged payload needs its own executable entry guard.
# pylint: disable=duplicate-code
if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
