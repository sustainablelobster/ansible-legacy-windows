#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2026 sustainablelobster
# Copyright: (c) 2017, Jordan Borean <jborean93@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Configure and verify installed local security policy using secedit.exe."""

# WANT_JSON

import codecs
import os
import re
import subprocess
import tempfile

try:
    import winreg
except ImportError:
    winreg = None

from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)
from legacy_windows_text import decode_bytes  # pylint: disable=import-error

DOCUMENTATION = r"""
---
module: win_security_policy
short_description: Change local security policy settings
description:
- Allows you to set the local security policies that are configured by
  SecEdit.exe.
options:
  section:
    description:
    - The ini section the key exists in.
    - If the section does not exist then the module will return an error.
    - Example sections to use are 'Account Policies', 'Local Policies',
      'Event Log', 'Restricted Groups', 'System Services', 'Registry' and
      'File System'
    - If wanting to edit the C(Privilege Rights) section, use the
      M(sustainablelobster.legacy_windows.win_user_right) module instead.
    type: str
    required: yes
  key:
    description:
    - The ini key of the section or policy name to modify.
    - The module will return an error if this key is invalid.
    type: str
    required: yes
  value:
    description:
    - The value for the ini key or policy name.
    - If the key takes in a boolean value then 0 = False and 1 = True.
    type: str
    required: yes
notes:
- Requires the installed C(secedit.exe) utility and permission to export and configure local security policy.
- Imports contain only the requested policy and the required INF headers, avoiding reapplication of unrelated exported settings.
- Check mode exports current policy into disposable files but does not configure it. Native command failures include their return code and captured output;
  configuration logs are returned whenever a configuration command ran.
- This module uses the SecEdit.exe tool to configure the values, more details
  of the areas and keys that can be configured can be found here
  U(https://msdn.microsoft.com/en-us/library/bb742512.aspx).
- If you are in a domain environment these policies may be set by a GPO policy,
  this module can temporarily change these values but the GPO will override
  it if the value differs.
- You can also run C(SecEdit.exe /export /cfg C:\temp\output.ini) to view the
  current policies set on your system.
- When assigning user rights, use the M(sustainablelobster.legacy_windows.win_user_right) module instead.
seealso:
- module: sustainablelobster.legacy_windows.win_user_right
author:
- sustainablelobster
- Jordan Borean (@jborean93)
"""

EXAMPLES = r"""
- name: Change the guest account name
  sustainablelobster.legacy_community_windows.win_security_policy:
    section: System Access
    key: NewGuestName
    value: Guest Account

- name: Set the maximum password age
  sustainablelobster.legacy_community_windows.win_security_policy:
    section: System Access
    key: MaximumPasswordAge
    value: 15

- name: Do not store passwords using reversible encryption
  sustainablelobster.legacy_community_windows.win_security_policy:
    section: System Access
    key: ClearTextPassword
    value: 0

- name: Enable system events
  sustainablelobster.legacy_community_windows.win_security_policy:
    section: Event Audit
    key: AuditSystemEvents
    value: 1
"""

RETURN = r"""
rc:
  description: The return code after a failure when running SecEdit.exe.
  returned: failure with secedit calls
  type: int
  sample: -1
stdout:
  description: The output of the STDOUT buffer after a failure when running
    SecEdit.exe.
  returned: failure with secedit calls
  type: str
  sample: check log for error details
stderr:
  description: The output of the STDERR buffer after a failure when running
    SecEdit.exe.
  returned: failure with secedit calls
  type: str
  sample: failed to import security policy
import_log:
  description: The log of the SecEdit.exe /configure job that configured the
    local policies. This is used for debugging purposes on failures.
  returned: secedit.exe /import run and change occurred
  type: str
  sample: Completed 6 percent (0/15) \tProcess Privilege Rights area.
key:
  description: The key in the section passed to the module to modify.
  returned: success
  type: str
  sample: NewGuestName
section:
  description: The section passed to the module to modify.
  returned: success
  type: str
  sample: System Access
value:
  description: The value passed to the module to modify to.
  returned: success
  type: str
  sample: Guest Account
"""


def _read_text(path):
    if not os.path.isfile(path):
        return ""
    with open(path, "rb") as stream:
        return decode_bytes(stream.read(), "mbcs" if os.name == "nt" else "cp1252")


def _invoke(executable, arguments, temporary):
    descriptor, log_path = tempfile.mkstemp(
        prefix="secedit-", suffix=".log", dir=temporary
    )
    os.close(descriptor)
    with subprocess.Popen(
        [executable] + arguments + ["/log", log_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        stdout, stderr = process.communicate()
    return {
        "rc": process.returncode,
        "stdout": decode_bytes(stdout, "mbcs" if os.name == "nt" else "cp1252"),
        "stderr": decode_bytes(stderr, "mbcs" if os.name == "nt" else "cp1252"),
        "log": "\n".join(_read_text(log_path).splitlines()).strip(),
    }


def _parse(text):
    sections = {}
    current = None
    for line in text.splitlines():
        if line.startswith(";"):
            continue
        section = re.match(r"^\[(.+)\]", line)
        if section:
            current = sections.setdefault(section.group(1), {})
            continue
        entry = re.match(r"(.+?)\s*=(.*)", line)
        if current is not None and entry:
            value = entry.group(2).strip()
            if re.match(r"^\d+$", value):
                value = int(value)
            elif len(value) >= 2 and value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            current[entry.group(1).strip()] = value
    return sections


def _matching_key(values, requested):
    return next((key for key in values if key.lower() == requested.lower()), None)


def _equal(current, desired):
    if isinstance(current, int) and not isinstance(current, bool):
        try:
            return current == int(
                desired, 16 if desired.lower().startswith("0x") else 10
            )
        except ValueError:
            return False
    return current == desired


def _export(executable, temporary):
    path = os.path.join(temporary, "export.inf")
    with open(path, "wb") as stream:
        stream.write(codecs.BOM_UTF16_LE + "\r\n".encode("utf-16-le"))
    command = _invoke(executable, ["/export", "/cfg", path, "/quiet"], temporary)
    sections = _parse(_read_text(path))
    return sections, command


def _failure(result, message, command=None):
    result.update(failed=True, msg=message)
    if command is not None:
        result.update({name: command[name] for name in ("rc", "stdout", "stderr")})
    return result


def _trim_legal_notice():
    if winreg is None:
        return
    path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            path,
            0,
            winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE,
        ) as key:
            try:
                value, kind = winreg.QueryValueEx(key, "LegalNoticeText")
            except FileNotFoundError:
                return
            if isinstance(value, str) and value.endswith("\0"):
                winreg.SetValueEx(key, "LegalNoticeText", 0, kind, value.rstrip("\0"))
    except FileNotFoundError:
        return


def _verify(result, sections, section, key, value):
    actual_section = _matching_key(sections, section)
    actual = sections.get(actual_section, {})
    actual_key = _matching_key(actual, key)
    if actual_key is None:
        if value == "":
            return result
        return _failure(
            result,
            "The key '{0}' in section '{1}' is not a valid key, cannot set this value".format(
                key, section
            ),
        )
    if not _equal(actual[actual_key], value):
        return _failure(
            result,
            (
                "Failed to change the value for key '{0}' in section '{1}', "
                "the value is still {2}"
            ).format(key, section, actual[actual_key]),
        )
    return result


def _arguments(arguments):
    for name in ("section", "key", "value"):
        if arguments.get(name) is None:
            raise ValueError("Missing required argument: " + name)
    section = as_string(arguments["section"], "section")
    key = as_string(arguments["key"], "key")
    value = as_string(arguments["value"], "value")
    if not section or not key:
        raise ValueError("section and key must not be empty")
    if (
        any(character in section + key + value for character in "\r\n")
        or "]" in section
        or "=" in key
    ):
        raise ValueError("arguments must identify a single security policy entry")
    return section, key, value


def _write_policy(temporary, section, key, value):
    path = os.path.join(temporary, "policy.inf")
    content = (
        '[Unicode]\r\nUnicode=yes\r\n[Version]\r\nsignature="$CHICAGO$"\r\n'
        "Revision=1\r\n[{0}]\r\n{1} = {2}\r\n"
    ).format(section, key, value)
    with open(path, "wb") as stream:
        stream.write(codecs.BOM_UTF16_LE + content.encode("utf-16-le"))
    return path


def _apply(executable, temporary, result, native_section, native_key):
    value = as_string(result["value"], "value")
    path = _write_policy(temporary, native_section, native_key, value)
    command = _invoke(
        executable,
        [
            "/configure",
            "/db",
            os.path.join(temporary, "policy.sdb"),
            "/cfg",
            path,
            "/quiet",
        ],
        temporary,
    )
    result["import_log"] = command["log"]
    if command["rc"]:
        return _failure(result, "Failed to import secedit.ini file", command)
    legal_notice_key = (
        r"MACHINE\Software\Microsoft\Windows\CurrentVersion"
        r"\Policies\System\LegalNoticeText"
    )
    if (
        native_section.lower() == "registry values"
        and native_key.lower() == legal_notice_key.lower()
    ):
        try:
            _trim_legal_notice()
        except OSError as error:
            return _failure(
                result,
                "Failed to normalize LegalNoticeText after import: " + str(error),
            )
    verified, command = _export(executable, temporary)
    if command["rc"] or not verified:
        return _failure(
            result, "Failed to export security policy for verification", command
        )
    return _verify(result, verified, result["section"], result["key"], value)


def _configure(arguments):
    section, key, value = _arguments(arguments)
    result = {
        "changed": False,
        "section": section,
        "key": key,
        "value": arguments["value"],
    }
    if section.lower() == "privilege rights":
        result["warnings"] = [
            "Using this module to edit rights and privileges is error-prone, "
            "use the sustainablelobster.legacy_windows.win_user_right module instead"
        ]
    diff_mode = as_bool(arguments.get("_ansible_diff", False), "_ansible_diff")
    check_mode = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    if diff_mode:
        result["diff"] = {}
    executable = os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"), "System32", "secedit.exe"
    )
    if not os.path.isfile(executable):
        raise ValueError(
            "Local security policy requires the installed secedit.exe utility"
        )
    with tempfile.TemporaryDirectory(prefix="legacy-security-policy-") as temporary:
        sections, command = _export(executable, temporary)
        if command["rc"] or not sections:
            return _failure(result, "Failed to export secedit.ini file", command)
        current_section = _matching_key(sections, section)
        if current_section is None:
            return _failure(
                result,
                "The section '{0}' does not exist in SecEdit.exe output ini".format(
                    section
                ),
            )
        values = sections[current_section]
        current_key = _matching_key(values, key)
        if current_key is None and value == "":
            return result
        if current_key is not None and _equal(values[current_key], value):
            return result
        result["changed"] = True
        if diff_mode:
            previous = (
                "-{0} = {1}\n".format(key, values[current_key])
                if current_key is not None
                else ""
            )
            result["diff"]["prepared"] = "[{0}]\n{1}+{2} = {3}".format(
                section, previous, key, value
            )
        if check_mode:
            return result
        return _apply(
            executable, temporary, result, current_section, current_key or key
        )


def main():
    """Read a WANT_JSON request and configure a verified security policy."""
    run_module(
        lambda: _configure(
            read_arguments(
                ("section", "key", "value"),
                "sustainablelobster.legacy_community_windows.win_security_policy",
                allow_unknown=True,
            )
        )
    )


if __name__ == "__main__":
    main()
