"""Inspect only owned DSC async caches and await natural worker/engine exit."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import os
import re
import sys
import time

_ASYNC = {"__name__": "dsc3_async_observer", "WMI_SOURCE": globals()["WMI_SOURCE"]}
exec(  # pylint: disable=exec-used
    compile(globals()["ASYNC_SOURCE"], "dsc3_async_observer.py", "exec"), _ASYNC
)
_WMI = {"__name__": "dsc3_async_wmi"}
exec(  # pylint: disable=exec-used
    compile(globals()["WMI_SOURCE"], "dsc3_async_wmi.py", "exec"), _WMI
)


def _journal(root):
    journal = _ASYNC["_read"](os.path.join(root, "dsc3-async-journal.json"))
    assert journal["workspace"] == root
    return journal


def _persistent(protected):
    protected = dict(protected)
    protected["services"] = _ASYNC["_service_configuration"](protected["services"])
    return protected


def _setup(root):
    assert os.path.isfile(os.path.join(root, "dsc3-recovery.json"))
    assert os.path.isdir(os.path.join(root, "engine"))
    journal = {"workspace": root, "protected": _ASYNC["_protected"]()}
    _ASYNC["_write"](os.path.join(root, "dsc3-async-journal.json"), journal)
    for name in ("cache", "staging"):
        os.mkdir(os.path.join(root, name))
    return journal


def _jobs(root):
    jobs = []
    for name in sorted(os.listdir(os.path.join(root, "cache"))):
        assert re.match(r"^j[0-9]+\.[0-9]+$", name), name
        record = _ASYNC["_cache"](os.path.join(root, "cache", name))
        result = record["json"]
        assert result["ansible_job_id"] == name
        pid = result["ansible_async_watchdog_pid"]
        assert isinstance(pid, int) and not isinstance(pid, bool) and pid > 0
        jobs.append({"name": name, "cache": record, "process": _ASYNC["_process"](pid)})
    return jobs


def _engine_processes(root):
    engine = os.path.normcase(os.path.join(root, "engine")) + os.sep
    properties = [
        "ProcessId",
        "ParentProcessId",
        "CreationDate",
        "ExecutablePath",
        "CommandLine",
    ]
    with _WMI["WmiConnection"]() as connection:
        processes = connection.query("SELECT * FROM Win32_Process", properties)
    return [
        process
        for process in processes
        if process["ExecutablePath"]
        and os.path.normcase(process["ExecutablePath"]).startswith(engine)
    ]


def _observe(root):
    journal = _journal(root)
    protected = _ASYNC["_protected"]()
    _ASYNC["_same"](_persistent(journal["protected"]), _persistent(protected))
    return {
        "original_protected": journal["protected"],
        "protected": protected,
        "jobs": _jobs(root),
        "engine_processes": _engine_processes(root),
        "staging": sorted(os.listdir(os.path.join(root, "staging"))),
    }


def _cleanup(root):
    # An absent/dead cached PID proves its worker is no longer alive even if
    # another process reused the number. A live reused PID conservatively waits;
    # this fixture never terminates a process based only on a numeric PID.
    deadline = time.monotonic() + 35
    while True:
        observed = _observe(root)
        if not observed["engine_processes"] and all(
            job["cache"]["json"].get("finished")
            and (job["process"] is None or not job["process"]["alive"])
            for job in observed["jobs"]
        ):
            break
        assert time.monotonic() < deadline, "Retain workspace: owned jobs still alive"
        time.sleep(0.05)
    assert observed["staging"] == []
    for job in observed["jobs"]:
        os.remove(os.path.join(root, "cache", job["name"]))
    observed["restored"] = True
    observed["cache_after"] = sorted(os.listdir(os.path.join(root, "cache")))
    return observed


def main():
    """Observe the declared operation using actual Windows Python3.4.4.

    :raises AssertionError: If protection, cache shape or recovery fails.
    """
    assert sys.version_info[:3] == (3, 4, 4)
    root, operation = sys.argv[1:3]
    assert os.path.basename(root).startswith("legacy-windows-dsc-")
    print(
        json.dumps(
            {"setup": _setup, "observe": _observe, "cleanup": _cleanup}[operation](
                root
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
