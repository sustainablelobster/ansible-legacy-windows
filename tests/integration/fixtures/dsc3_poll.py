"""Retain owned DSC caches while standard automatic polling consumes them."""

# SPDX-License-Identifier: GPL-3.0-or-later

import hashlib
import json
import os
import subprocess
import sys
import time
import traceback


def _namespace(source, name):
    namespace = {"__name__": name}
    for key in ("WMI_SOURCE", "BASE_SOURCE", "ASYNC_SOURCE"):
        namespace[key] = globals()[key]
    # Use the exact maintained cache, process and protection observers supplied
    # by the play; these are fixture dependencies, not target payload changes.
    exec(compile(source, name + ".py", "exec"), namespace)  # pylint: disable=exec-used
    return namespace


_UPDATES = _namespace(globals()["UPDATES_SOURCE"], "owned_dsc_poll_cache")
_DSC = _namespace(globals()["DSC_ASYNC_SOURCE"], "owned_dsc_poll_protection")
_BASE = _UPDATES["_BASE"]
_WMI = _UPDATES["_WMI"]


def _read(root, name):
    return _UPDATES["_read"](root, name)


def _write(root, name, value):
    _UPDATES["_write"](root, name, value)


def _closed(expected, actual):
    return not actual or actual["created"] != expected["created"] or not actual["alive"]


def _monitor(root):
    jobs, races = {}, []
    with _WMI["WmiConnection"]() as connection:
        _write(root, "poll-ready.json", _BASE["_process"](os.getpid()))
        deadline = time.monotonic() + 180
        while not os.path.exists(os.path.join(root, "poll-release.json")):
            assert time.monotonic() < deadline, "Owned DSC cache observer not released"
            _UPDATES["_poll_cache"](root, connection, jobs, races)
            time.sleep(0.005)
    _write(root, "poll-complete.json", {"jobs": jobs, "cache_races": races})


def _setup(root):
    protection = _DSC["_setup"](root)
    source = globals()["MONITOR_SOURCE"]
    path = os.path.join(root, "poll-monitor.py")
    with open(path, "x", encoding="utf-8") as stream:
        stream.write(source)
    # The accepted WMI launch creates an independent observer without inheriting
    # SSH pipes or changing the command runner's job/token behavior.
    command = subprocess.list2cmdline([sys.executable, "-B", path, root, "monitor"])
    with _WMI["WmiConnection"]() as connection:
        launched = connection.call_method(
            "Win32_Process",
            "Create",
            ["ReturnValue", "ProcessId"],
            {"CommandLine": command, "CurrentDirectory": root},
        )
    assert launched["ReturnValue"] == 0 and launched["ProcessId"], launched
    identity = _BASE["_process"](launched["ProcessId"])
    assert identity and identity["alive"]
    _write(root, "poll-identity.json", identity)
    deadline = time.monotonic() + 20
    while not os.path.exists(os.path.join(root, "poll-ready.json")):
        assert _BASE["_process"](identity["pid"]) == identity
        assert time.monotonic() < deadline, "Owned DSC observer did not become ready"
        time.sleep(0.05)
    assert _read(root, "poll-ready.json") == identity
    return {
        "protected": protection,
        "monitor": identity,
        "monitor_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
    }


def _observe(root):
    observed = _DSC["_observe"](root)
    path = os.path.join(root, "async-jobs.json")
    observed["observed_jobs"] = (
        _read(root, "async-jobs.json") if os.path.exists(path) else {}
    )
    observed["utc"] = time.time()
    return observed


def _stop(root):
    identity = _read(root, "poll-identity.json")
    _write(root, "poll-release.json", True)
    deadline = time.monotonic() + 35
    while True:
        actual = _BASE["_process"](identity["pid"])
        if _closed(identity, actual):
            break
        assert time.monotonic() < deadline, "Owned DSC observer still alive"
        time.sleep(0.05)
    if not os.path.exists(os.path.join(root, "poll-complete.json")):
        diagnostics = {"expected": identity, "actual": actual}
        for name in ("poll-error.log", "async-jobs.json"):
            path = os.path.join(root, name)
            if os.path.exists(path):
                with open(path, encoding="utf-8") as stream:
                    diagnostics[name] = stream.read()
            else:
                diagnostics[name] = None
        raise OSError("Owned DSC observer failed: " + json.dumps(diagnostics))
    result = _read(root, "poll-complete.json")
    result.update(monitor_identity=identity, monitor_final=actual, workers_closed=[])
    deadline = time.monotonic() + 35
    for job in result["jobs"].values():
        expected = job["worker"]["identity"]
        while True:
            actual = _BASE["_process"](expected["pid"])
            if _closed(expected, actual):
                break
            assert time.monotonic() < deadline, "Owned DSC watchdog still alive"
            time.sleep(0.05)
        result["workers_closed"].append({"expected": expected, "actual": actual})
    result["before_cleanup"] = _observe(root)
    result["recovery"] = _DSC["_cleanup"](root)
    return result


def main():
    """Run one owned automatic-poll observation on actual Windows Python3.4.4.

    :raises Exception: Preserve the original monitor traceback before re-raising.
    :raises AssertionError: If ownership, protection or process closure fails.
    """
    assert sys.version_info[:3] == (3, 4, 4)
    root, operation = sys.argv[1:3]
    assert os.path.basename(root).startswith("legacy-windows-dsc-")
    if operation == "monitor":
        try:
            _monitor(root)
        # Keep any original observer traceback before propagating its failure.
        except Exception:  # pylint: disable=broad-exception-caught
            with open(
                os.path.join(root, "poll-error.log"), "w", encoding="utf-8"
            ) as stream:
                stream.write(traceback.format_exc())
            raise
        return
    print(
        json.dumps(
            {"setup": _setup, "observe": _observe, "cleanup": _stop}[operation](root)
        )
    )


if __name__ == "__main__":
    main()
