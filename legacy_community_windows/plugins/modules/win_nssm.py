#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2015, George Frank <george@georgefrank.net>
# Copyright: (c) 2015, Adam Keech <akeech@chathamfinancial.com>
# Copyright: (c) 2015, Hans-Joachim Kliemeck <git@kliemeck.de>
# Copyright: (c) 2019, Kevin Subileau (@ksubileau)
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage services using the installed NSSM executable and native Windows APIs."""

# WANT_JSON

import collections
import os
import subprocess

# The action stages these shared Python3.4-compatible native helpers.
import legacy_windows_account as accounts  # pylint: disable=import-error
import legacy_windows_service as services  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_dictionary,
    as_path,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)
from legacy_windows_process import run_command  # pylint: disable=import-error

DOCUMENTATION = r"""
---
module: win_nssm
short_description: Install a service using NSSM
description:
    - Install a Windows service using the NSSM wrapper.
    - NSSM is a service helper which doesn't suck. See U(https://nssm.cc/) for more information.
requirements:
    - "nssm >= 2.24.0 # (install via M(chocolatey.chocolatey.win_chocolatey)) C(win_chocolatey: name=nssm)"
options:
  name:
    description:
      - Name of the service to operate on.
    type: str
    required: true
  state:
    description:
      - State of the service on the system.
    type: str
    choices: [ absent, present, started, stopped, restarted ]
    default: present
  application:
    description:
      - The application binary to run as a service
      - Required when I(state) is C(present), C(started), C(stopped), or C(restarted).
    type: path
  executable:
    description:
    - The location of the NSSM utility (in case it is not located in your PATH).
    type: path
    default: nssm.exe
  description:
    description:
      - The description to set for the service.
    type: str
  display_name:
    description:
      - The display name to set for the service.
    type: str
  working_directory:
    description:
      - The working directory to run the service executable from (defaults to the directory containing the application binary)
    type: path
    aliases: [ app_directory, chdir ]
  stdout_file:
    description:
      - Path to receive output.
    type: path
  stderr_file:
    description:
      - Path to receive error output.
    type: path
  arguments:
    description:
      - Parameters to be passed to the application when it starts.
      - This can be either a simple string or a list.
    aliases: [ app_parameters_free_form ]
    type: str
  dependencies:
    description:
      - Service dependencies that has to be started to trigger startup, separated by comma.
    type: list
    elements: str
  username:
    description:
      - User to be used for service startup.
      - Group managed service accounts must end with C($).
      - Before C(1.8.0), this parameter was just C(user).
    type: str
    aliases:
    - user
  password:
    description:
      - Password to be used for service startup.
      - This is not required for the well known service accounts and group managed service accounts.
    type: str
  start_mode:
    description:
      - If C(auto) is selected, the service will start at boot.
      - C(delayed) causes a delayed but automatic start after boot.
      - C(manual) means that the service will start only when another service needs it.
      - C(disabled) means that the service will stay off, regardless if it is needed or not.
    type: str
    choices: [ auto, delayed, disabled, manual ]
    default: auto
  app_environment:
    description:
      - Key/Value pairs which will be added to the environment of the service application.
    type: dict
    version_added: '1.0.0'
  app_rotate_bytes:
    description:
      - NSSM will not rotate any file which is smaller than the configured number of bytes.
    type: int
    default: 104858
  app_rotate_online:
    description:
      - If set to 1, nssm can rotate files which grow to the configured file size limit while the service is running.
    type: int
    choices:
      - 0
      - 1
    default: 0
  app_stop_method_console:
    description:
      - Time to wait after sending Control-C.
    type: int
  app_stop_method_skip:
    description:
      - To disable service shutdown methods, set to the sum of one or more of the numbers
      - 1 - Don't send Control-C to the console.
      - 2 - Don't send WM_CLOSE to windows.
      - 4 - Don't send WM_QUIT to threads.
      - 8 - Don't call TerminateProcess().
    type: int
    choices:
      - 1
      - 2
      - 3
      - 4
      - 5
      - 6
      - 7
      - 8
      - 9
      - 10
      - 11
      - 12
      - 13
      - 14
      - 15
seealso:
  - module: sustainablelobster.legacy_windows.win_service
notes:
  - The service will NOT be started after its creation when C(state=present).
  - Once the service is created, you can use the M(sustainablelobster.legacy_windows.win_service) module to start it or configure
    some additional properties, such as its startup type, dependencies, service account, and so on.
author:
  - Adam Keech (@smadam813)
  - George Frank (@georgefrank)
  - Hans-Joachim Kliemeck (@h0nIg)
  - Michael Wild (@themiwi)
  - Kevin Subileau (@ksubileau)
  - Shachaf Goldstein (@Shachaf92)
"""

EXAMPLES = r"""
- name: Install the foo service
  sustainablelobster.legacy_community_windows.win_nssm:
    name: foo
    application: C:\windows\foo.exe

# This will yield the following command: C:\windows\foo.exe bar "true"
- name: Install the Consul service with a list of parameters
  sustainablelobster.legacy_community_windows.win_nssm:
    name: Consul
    application: C:\consul\consul.exe
    arguments:
      - agent
      - -config-dir=C:\consul\config

# This is strictly equivalent to the previous example
- name: Install the Consul service with an arbitrary string of parameters
  sustainablelobster.legacy_community_windows.win_nssm:
    name: Consul
    application: C:\consul\consul.exe
    arguments: agent -config-dir=C:\consul\config


# Install the foo service, and then configure and start it with win_service
- name: Install the foo service, redirecting stdout and stderr to the same file
  sustainablelobster.legacy_community_windows.win_nssm:
    name: foo
    application: C:\windows\foo.exe
    stdout_file: C:\windows\foo.log
    stderr_file: C:\windows\foo.log

- name: Configure and start the foo service using win_service
  sustainablelobster.legacy_windows.win_service:
    name: foo
    dependencies: [adf, tcpip]
    username: foouser
    password: secret
    start_mode: manual
    state: started

- name: Install a script based service and define custom environment variables
  sustainablelobster.legacy_community_windows.win_nssm:
    name: <ServiceName>
    application: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
    arguments:
      - <path-to-script>
      - <script arg>
    app_environment:
      AUTH_TOKEN: <token value>
      SERVER_URL: https://example.com
      PATH: "<path-prepends>;{{ ansible_env.PATH }};<path-appends>"

- name: Remove the foo service
  sustainablelobster.legacy_community_windows.win_nssm:
    name: foo
    state: absent
"""

_MODES = {
    "auto": "SERVICE_AUTO_START",
    "delayed": "SERVICE_DELAYED_AUTO_START",
    "manual": "SERVICE_DEMAND_START",
    "disabled": "SERVICE_DISABLED",
}
_PATHS = {
    "application": (),
    "working_directory": ("app_directory", "chdir"),
    "stdout_file": (),
    "stderr_file": (),
}
_INTEGERS = {
    "app_rotate_bytes": 104858,
    "app_rotate_online": 0,
    "app_stop_method_console": None,
    "app_stop_method_skip": None,
}
_PARAMETERS = (
    "name",
    "state",
    "display_name",
    "description",
    "application",
    "working_directory",
    "app_directory",
    "chdir",
    "arguments",
    "app_parameters_free_form",
    "stdout_file",
    "stderr_file",
    "executable",
    "app_environment",
    "app_rotate_bytes",
    "app_rotate_online",
    "app_stop_method_console",
    "app_stop_method_skip",
    "start_mode",
    "dependencies",
    "username",
    "user",
    "password",
)


class _ToolFailure(Exception):
    """Stop a failed vendor operation while retaining its public diagnostics."""


def _integer(value, name):
    if value is None:
        return None
    try:
        number = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(name + " must be a 32-bit integer.") from error
    if number < -2147483648 or number > 2147483647:
        raise ValueError(name + " must be a 32-bit integer.")
    return number


def _account(value):
    if value.lower() == "localsystem":
        return "LocalSystem"
    sid = accounts.name_to_sid(value)
    return "LocalSystem" if sid == "S-1-5-18" else accounts.sid_to_name(sid)


def _application_settings(values):
    if not values["application"]:
        raise ValueError(
            "The application parameter must be defined when the state is not absent."
        )
    if not os.path.isfile(values["application"]):
        raise ValueError("The application specified does not exist on the host.")
    if values["working_directory"] is None:
        values["working_directory"] = os.path.dirname(
            os.path.abspath(values["application"])
        )
    if values["start_mode"] == "delayed" and not services.supports_delayed_start():
        raise ValueError(
            "Delayed automatic startup is unavailable on this Windows service manager."
        )
    if values["username"]:
        values["username"] = _account(values["username"])
        sid = (
            "S-1-5-18"
            if values["username"] == "LocalSystem"
            else accounts.name_to_sid(values["username"])
        )
        if sid in ("S-1-5-18", "S-1-5-19", "S-1-5-20"):
            values["password"] = ""
        elif values["username"].endswith("$"):
            values["password"] = "gsma_password"
        elif not values["password"]:
            raise ValueError(
                "A password is required for the requested service account."
            )


def _settings(arguments):
    values = dict(arguments)
    for name in ("name", "display_name", "description", "password"):
        values[name] = as_string(arguments.get(name), name)
    if not values["name"]:
        raise ValueError("name is required.")
    values["state"] = as_string(arguments.get("state", "present"), "state").lower()
    if values["state"] not in ("present", "absent", "started", "stopped", "restarted"):
        raise ValueError("Unsupported state: " + values["state"])
    values["start_mode"] = as_string(
        arguments.get("start_mode", "auto"), "start_mode"
    ).lower()
    if values["start_mode"] not in _MODES:
        raise ValueError("Unsupported start_mode: " + values["start_mode"])
    values["executable"] = as_path(
        arguments.get("executable", "nssm.exe"), "executable"
    )
    for name, aliases in _PATHS.items():
        value = arguments.get(name)
        if name not in arguments:
            for alias in aliases:
                if alias in arguments:
                    value = arguments[alias]
                    break
        values[name] = as_path(value, name)
    for name, default in _INTEGERS.items():
        values[name] = _integer(arguments.get(name, default), name)
    if values["app_rotate_online"] not in (0, 1):
        raise ValueError("app_rotate_online must be 0 or 1.")
    if values["app_stop_method_skip"] is not None and values[
        "app_stop_method_skip"
    ] not in range(1, 16):
        raise ValueError("app_stop_method_skip must be between 1 and 15.")
    values["arguments"] = arguments.get(
        "arguments", arguments.get("app_parameters_free_form")
    )
    values["dependencies"] = as_string_list(
        arguments.get("dependencies"), "dependencies"
    )
    values["app_environment"] = as_dictionary(
        arguments.get("app_environment"), "app_environment"
    )
    values["username"] = as_string(
        arguments.get("username", arguments.get("user")), "username"
    )
    if values["state"] != "absent":
        _application_settings(values)
    values["_ansible_check_mode"] = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    values["_ansible_diff"] = as_bool(
        arguments.get("_ansible_diff", False), "_ansible_diff"
    )
    return values


# One public operation applies a concrete request; individual vendor steps stay private.
class _NssmService:  # pylint: disable=too-few-public-methods
    """Apply one concrete service request, recording changed fields and safe diffs."""

    def __init__(self, values):
        self.values = values
        self.result = {"changed": False}
        self.diff = ""

    def _redact(self, text):
        password = self.values["password"]
        if password:
            for secret in (subprocess.list2cmdline([password]), password):
                text = text.replace(secret, "*PASSWORD_REPLACED*")
        return text

    def _invoke(self, *options):
        command = subprocess.list2cmdline([self.values["executable"]] + list(options))
        response = run_command(
            self.values["executable"],
            command,
            # Official NSSM2.24 writes BOM-less UTF-16LE to redirected streams.
            {"chdir": None, "stdin": None, "output_encoding_override": "utf-16-le"},
        )
        if response["rc"] != 0 or "stdout" not in response:
            self.result.update(
                failed=True,
                nssm_error_cmd=self._redact(command),
                nssm_error_log=self._redact(response.get("stderr", "")),
                msg="NSSM {0} failed for service '{1}'.".format(
                    options[0], self.values["name"]
                ),
            )
            raise _ToolFailure()
        return response["stdout"]

    def _changed(self, reason):
        self.result.update(changed=True, changed_by=reason)

    def _update(self, parameter, values):
        if values is None:
            return
        if not isinstance(values, list):
            values = [as_string(values, parameter)]
        expected = [as_string(value, parameter) for value in values if value != ""]
        actual = [
            line
            for line in self._invoke("get", self.values["name"], parameter).splitlines()
            if line
        ]
        if parameter == "ObjectName":
            equal = (
                bool(actual)
                and _account(actual[0]).casefold() == _account(expected[0]).casefold()
            )
        else:
            equal = collections.Counter(
                value.casefold() for value in actual
            ) == collections.Counter(value.casefold() for value in expected)
        if equal:
            return
        if not self.values["_ansible_check_mode"]:
            if expected:
                self._invoke("set", self.values["name"], parameter, *expected)
            else:
                self._invoke("reset", self.values["name"], parameter)
        self.diff += "-{0} = {1}\n+{0} = {2}\n".format(
            parameter,
            ", ".join(actual),
            self._redact(", ".join(expected)),
        )
        self._changed(parameter)

    def _configure(self):
        values = self.values
        for parameter, argument in (
            ("Application", "application"),
            ("DisplayName", "display_name"),
            ("Description", "description"),
            ("AppDirectory", "working_directory"),
        ):
            self._update(parameter, values[argument])
        arguments = values["arguments"]
        if arguments is not None:
            if isinstance(arguments, list):
                arguments = subprocess.list2cmdline(
                    [as_string(value, "arguments") for value in arguments]
                )
            else:
                arguments = as_string(arguments, "arguments")
            self.result["nssm_app_parameters"] = values["arguments"]
            self.result["nssm_single_line_app_parameters"] = arguments
            self._update("AppParameters", arguments)
        self._update("AppStdout", values["stdout_file"])
        self._update("AppStderr", values["stderr_file"])
        environment = values["app_environment"]
        if environment is not None:
            self._update(
                "AppEnvironmentExtra",
                [
                    key + "=" + as_string(environment[key], "app_environment")
                    for key in sorted(environment, key=str.casefold)
                ],
            )
        for parameter, value in (
            ("AppStdoutCreationDisposition", 2),
            ("AppStderrCreationDisposition", 2),
            ("AppRotateFiles", 1),
            ("AppRotateOnline", values["app_rotate_online"]),
            ("AppRotateSeconds", 86400),
            ("AppRotateBytes", values["app_rotate_bytes"]),
            ("DependOnService", values["dependencies"]),
        ):
            self._update(parameter, value)
        if values["username"]:
            self._update("ObjectName", [values["username"], values["password"]])
        self._update("Start", _MODES[values["start_mode"]])

    def _state(self, desired):
        state = self._invoke("status", self.values["name"])
        changed = (
            ("SERVICE_RUNNING" not in state)
            if desired == "started"
            else ("SERVICE_STOPPED" not in state)
        )
        if not changed:
            return
        if not self.values["_ansible_check_mode"]:
            if desired == "stopped" or "SERVICE_STOPPED" not in state:
                self._invoke("stop", self.values["name"])
            if desired == "started":
                self._invoke("start", self.values["name"])
        self._changed("start_service" if desired == "started" else "stop_service")

    def _apply(self):
        values = self.values
        exists = services.resolve_name(values["name"]) is not None
        if values["state"] == "absent":
            if exists:
                if not values["_ansible_check_mode"]:
                    self._state("stopped")
                    self._invoke("remove", values["name"], "confirm")
                self.diff = "-[" + values["name"] + "]"
                self._changed("remove_service")
            return
        if not exists:
            if not values["_ansible_check_mode"]:
                self._invoke("install", values["name"], values["application"])
                exists = True
            self._changed("install_service")
        self.diff = (
            ("" if exists and not self.result["changed"] else "+")
            + "["
            + values["name"]
            + "]\n"
        )
        if not exists:
            return
        self._configure()
        if values["state"] in ("stopped", "restarted"):
            self._state("stopped")
        if values["state"] in ("started", "restarted"):
            self._state("started")
        self._update("AppStopMethodConsole", values["app_stop_method_console"])
        self._update("AppStopMethodSkip", values["app_stop_method_skip"])

    def run(self):
        """Apply the request while preserving diagnostics after partial failure.

        :returns: Changed state, requested diff and any vendor failure details.
        :rtype: dict
        """
        try:
            self._apply()
        except _ToolFailure:
            return self.result
        if self.values["_ansible_diff"] and self.result["changed"]:
            self.result["diff"] = {"prepared": self.diff}
        return self.result


def _execute(arguments):
    return _NssmService(_settings(arguments)).run()


def main():
    """Read the module argument file and report the NSSM service operation."""
    run_module(
        lambda: _execute(
            read_arguments(
                _PARAMETERS,
                "sustainablelobster.legacy_community_windows.win_nssm",
                allow_unknown=True,
            )
        )
    )


if __name__ == "__main__":
    main()
