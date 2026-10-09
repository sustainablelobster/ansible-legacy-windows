# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Select and isolate native Windows fact collectors under Python 3.4.4."""

import json
import os
import subprocess
import sys
import time
import traceback

import legacy_windows_setup_native as native  # pylint: disable=import-error

_GROUPS = {
    "min": (
        "date_time",
        "distribution",
        "dns",
        "env",
        "local",
        "platform",
        "powershell_version",
        "user",
    ),
    "network": (
        "all_ipv4_addresses",
        "all_ipv6_addresses",
        "interfaces",
        "windows_domain",
        "winrm",
    ),
    "hardware": ("bios", "memory", "processor", "uptime", "virtual"),
    "external": ("facter",),
}
_ALL = set(subset for group in _GROUPS.values() for subset in group)
_COLLECTORS = (
    ("all_ipv4_addresses", "all_ipv6_addresses"),
    ("bios",),
    ("date_time",),
    ("distribution",),
    ("env",),
    ("facter",),
    ("interfaces",),
    ("local",),
    ("memory",),
    ("platform",),
    ("powershell_version",),
    ("processor",),
    ("uptime",),
    ("user",),
    ("windows_domain",),
    ("winrm",),
    ("virtual",),
)


def selected_subsets(requested, warnings):
    """Resolve upstream groups, exclusions and explicit inclusions.

    :param requested: Bound gather_subset list, or an explicit null.
    :type requested: list[str] or None
    :param warnings: Receives warnings for invalid positive selections.
    :type warnings: list[str]
    :returns: Set of selected named subsets. Exclusions are applied before
        explicit inclusions, regardless of argument order.
    :rtype: set[str]
    """
    excluded, explicit = set(), set()
    groups = dict(_GROUPS, all=_ALL)
    for item in requested or []:
        if item.startswith("!"):
            name = item[1:]
            if name.lower() == "all":
                excluded.update(_ALL.difference(_GROUPS["min"]))
            elif name.lower() in groups:
                excluded.update(groups[name.lower()])
            elif name in _ALL:
                excluded.add(name)
        elif item.lower() in groups:
            explicit.update(groups[item.lower()])
        elif item in _ALL:
            explicit.add(item)
        else:
            warnings.append("invalid value {0} specified in gather_subset".format(item))
    return _ALL.difference(excluded).union(explicit)


def _collect_process(name, parameters):
    request = json.dumps({"name": name, "parameters": parameters}).encode("utf-8")
    timeout = parameters["gather_timeout"] or 0
    version = native.windows_version()
    if (version.major, version.minor) < (6, 2) and native.collector_needs_detached():
        output, errors, returncode, timed_out = native.collect_detached(
            [sys.executable, os.path.abspath(__file__), "--collect-detached"],
            request,
            timeout,
        )
        if timed_out:
            return {
                "facts": {},
                "warnings": ["Failed to collect {0} due to timeout".format(name)],
            }
        if returncode:
            raise OSError(
                "Fact collector {0} failed: {1}".format(
                    name, errors.decode("utf-8", "replace").strip()
                )
            )
        return json.loads(output.decode("utf-8"))
    # Nested jobs were added in Windows 8. Older SSH job owners must permit
    # breakaway so this worker can have its own bounded descendant cleanup.
    creation_flags = 0x01000000 if (version.major, version.minor) < (6, 2) else 0
    # A new Python process provides a cancellable native/WMI operation. The
    # timeout owns only this child, not the connection or another collector.
    with subprocess.Popen(
        [sys.executable, os.path.abspath(__file__), "--collect"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=creation_flags,
    ) as process:
        timed_out = False
        try:
            # The private handle is the established Windows Popen process
            # identity. Assign before sending stdin, so no custom child starts
            # before its owned job is active.
            # pylint: disable-next=protected-access,no-member
            with native.owned_job(process._handle):
                try:
                    output, errors = process.communicate(request, timeout=timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    timed_out = True
            if timed_out:
                # Close the job first: descendants can otherwise keep inherited
                # pipe handles open and make reaping wait for their natural exit.
                process.communicate()
                return {
                    "facts": {},
                    "warnings": ["Failed to collect {0} due to timeout".format(name)],
                }
        except OSError:
            if process.poll() is None:
                process.kill()
            process.communicate()
            raise
        if process.returncode:
            raise OSError(
                "Fact collector {0} failed: {1}".format(
                    name, errors.decode("utf-8", "replace").strip()
                )
            )
    return json.loads(output.decode("utf-8"))


def read_facts(parameters, warnings):
    """Gather selected facts with independent cancellable collector timeouts.

    :param parameters: Bound public module arguments.
    :type parameters: dict
    :param warnings: Receives selection, platform and collector warnings.
    :type warnings: list[str]
    :returns: Fact dictionary with gather_subset and module_setup markers.
    :rtype: dict
    :raises OSError: The target is not Windows or a collector cannot start.
    :raises ValueError: The timeout cannot be represented by the native wait.
    """
    if os.name != "nt":
        raise OSError("Windows setup facts require a Windows target.")
    version = native.windows_version()
    if version.major < 10:
        warnings.append(
            "The Windows version '{0}.{1}' is no longer supported or tested by Ansible.".format(
                version.major, version.minor
            )
        )
    selected = selected_subsets(parameters["gather_subset"], warnings)
    timeout = parameters["gather_timeout"]
    if (
        timeout is not None
        and timeout < 0
        and any(selected.intersection(subsets) for subsets in _COLLECTORS)
    ):
        raise ValueError("gather_timeout cannot be negative when collecting facts.")
    facts = {"gather_subset": parameters["gather_subset"], "module_setup": True}
    if parameters["_measure_subset"]:
        facts["measure_info"] = {}
    for subsets in _COLLECTORS:
        if not selected.intersection(subsets):
            continue
        name = ", ".join(subsets)
        try:
            collected = _collect_process(name, parameters)
        except (OSError, ValueError) as error:
            warnings.append("Error when collecting {0} facts: {1}".format(name, error))
            continue
        facts.update(collected["facts"])
        warnings.extend(collected["warnings"])
        if parameters["_measure_subset"] and "elapsed" in collected:
            facts["measure_info"][name] = collected["elapsed"]
    return facts


def _collect_worker(request):
    facts, warnings = {}, []
    started = time.monotonic()
    try:
        native.collect(request["name"], request["parameters"], facts, warnings)
    except (OSError, ValueError, NotImplementedError) as error:
        warnings.append(
            "Error when collecting {0} facts: {1}".format(request["name"], error)
        )
    return {
        "facts": facts,
        "warnings": warnings,
        "elapsed": time.monotonic() - started,
    }


def _worker():
    request = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    sys.stdout.buffer.write(
        json.dumps(_collect_worker(request), ensure_ascii=True).encode("utf-8")
    )


def _detached_worker():
    event, request_path, output_path, error_path = sys.argv[2:]
    directory = os.path.dirname(request_path)
    if not os.path.basename(directory).startswith("legacy-windows-fact-collector-"):
        raise ValueError("Not an owned detached fact collector directory.")
    if [
        os.path.join(directory, name)
        for name in ("request.json", "output.json", "errors.txt")
    ] != [request_path, output_path, error_path]:
        raise ValueError(
            "Fact collector IPC paths do not belong to one owned directory."
        )
    native.await_collector_activation(event)
    with open(request_path, "rb") as stream:
        request = json.loads(stream.read().decode("utf-8"))
    with open(error_path, "x", encoding="utf-8") as errors:
        try:
            collected = _collect_worker(request)
            with open(output_path, "xb") as output:
                output.write(json.dumps(collected, ensure_ascii=True).encode("utf-8"))
        # Match a private pipe worker's stderr/exit behavior for unexpected
        # collector failures; the parent surfaces this traceback as its error.
        except Exception:  # pylint: disable=broad-exception-caught
            traceback.print_exc(file=errors)
            return 1
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--collect"]:
        _worker()
    elif sys.argv[1:2] == ["--collect-detached"]:
        sys.exit(_detached_worker())
    else:
        raise ValueError("Unknown fact collector worker arguments.")
