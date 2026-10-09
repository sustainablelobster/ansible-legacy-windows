"""Retain the measured pending-install service effect until snapshot recovery."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import os
import sys

_BASE = {}


def _service_effects(before, after, state):
    if len(before) != len(after):
        raise OSError("Servicing added or removed a protected service name.")
    effects = []
    for original, current in zip(before, after):
        expected = {key: value for key, value in original.items() if key != "State"}
        observed = {key: value for key, value in current.items() if key != "State"}
        if expected == observed:
            continue
        # Actual cumulative installation changed this one startup setting while
        # a reboot was pending. Retain both full rows, and require original
        # configuration literally AFTER rollback; do not call this restored.
        if (
            state == "installed"
            and expected == {"Name": "TrustedInstaller", "StartMode": "Manual"}
            and observed == {"Name": "TrustedInstaller", "StartMode": "Auto"}
        ):
            effects.append({"before": original, "current": current})
        else:
            raise OSError("Unqualified service configuration effect: " + repr(current))
    return effects


def _observe_servicing(workspace):
    journal = _BASE["_journal"](workspace)
    current, original = _BASE["_protected"](), journal["protected"]
    for field in ("registry", "python_executable", "network"):
        _BASE["_same"](current[field], original[field])
    effects = _service_effects(
        original["services"], current["services"], globals()["SERVICING_STATE"]
    )
    with open(os.path.join(workspace, "sentinel.bin"), "rb") as stream:
        if stream.read() != b"protected async sentinel\x00\xff":
            raise OSError("The protected servicing sentinel bytes changed.")
    processes = []
    for name in os.listdir(workspace):
        if name.startswith("job-") and name.endswith(".json"):
            identity = _BASE["_read"](os.path.join(workspace, name))["worker"]
            if identity:
                processes.append(
                    {"expected": identity, "actual": _BASE["_process"](identity["pid"])}
                )
    cache_path = os.path.join(workspace, "cache")
    return {
        "original_protected": original,
        "protected": current,
        "pending_install_service_effects": effects,
        # Preserve this servicing-specific journal independently of async tests.
        # pylint: disable=duplicate-code
        "service_state_changes": [
            {
                "name": before["Name"],
                "expected": before["State"],
                "actual": after["State"],
            }
            for before, after in zip(original["services"], current["services"])
            if before["State"] != after["State"]
        ],
        # pylint: enable=duplicate-code
        "processes": processes,
        "cache": sorted(os.listdir(cache_path)),
        "cache_records": {
            name: _BASE["_cache"](os.path.join(cache_path, name))
            for name in os.listdir(cache_path)
        },
        "staging": sorted(os.listdir(os.path.join(workspace, "staging"))),
    }


def main():
    """Run the exact journal/job helpers with the observed servicing qualification.

    :raises OSError: Runtime, workspace ownership or protected resources differ.
    """
    _BASE.update(
        {"__name__": "owned_servicing_async", "WMI_SOURCE": globals()["WMI_SOURCE"]}
    )
    # Reuse only the frozen fixture's existing journal/process/cache contracts;
    # no production helper or installed generic fixture is altered.
    exec(  # pylint: disable=exec-used
        compile(globals()["BASE_ASYNC_SOURCE"], "frozen_native_async.py", "exec"), _BASE
    )
    _BASE["_observe"] = _observe_servicing
    if sys.version_info[:3] != (3, 4, 4):
        raise OSError("The servicing fixture requires actual Python3.4.4.")
    workspace, operation = sys.argv[1:3]
    if not os.path.basename(workspace).startswith(
        "legacy-windows-native-async-updates-positive-"
    ):
        raise OSError("The exact positive servicing workspace is required.")
    operations = {
        "setup": _BASE["_setup"],
        "record": _BASE["_record_job"],
        "observe": _observe_servicing,
        "cleanup": _BASE["_cleanup"],
    }
    print(json.dumps(operations[operation](workspace), sort_keys=True))


if __name__ == "__main__":
    main()
