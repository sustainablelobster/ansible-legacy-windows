"""Observe actual Updates backend identities without altering either provider."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import traceback
import winreg  # pylint: disable=import-error

_BASE = {"__name__": "updates_runas_protection", "WMI_SOURCE": globals()["WMI_SOURCE"]}
_WMI = {"__name__": "updates_runas_wmi"}
# Embed only the accepted, literal observation primitives supplied by the play.
# pylint: disable=exec-used
exec(compile(globals()["BASE_SOURCE"], "native_async.py", "exec"), _BASE)
exec(compile(globals()["WMI_SOURCE"], "legacy_windows_wmi.py", "exec"), _WMI)
# pylint: enable=exec-used


def _write(workspace, name, value):
    path = os.path.join(workspace, name)
    with open(path + ".next", "w", encoding="utf-8") as stream:
        json.dump(value, stream)
    os.replace(path + ".next", path)


def _read(workspace, name):
    with open(os.path.join(workspace, name), encoding="utf-8") as stream:
        return json.load(stream)


def _policy(path):
    # This independent Runas observer reads policy without the tested provider.
    # pylint: disable=duplicate-code
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        )
    except OSError as error:
        if error.winerror in (2, 3):  # pylint: disable=no-member
            return None
        raise
    # pylint: enable=duplicate-code
    with key:
        values = []
        for index in range(winreg.QueryInfoKey(key)[1]):
            name, value, kind = winreg.EnumValue(key, index)
            if isinstance(value, bytes):
                value = {"base64": base64.b64encode(value).decode("ascii")}
            values.append([name, value, kind])
        return sorted(values)


def _observe():
    protected = _BASE["_protected"]()
    policy = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    protected["updates_policy"] = _policy(policy)
    protected["updates_au_policy"] = _policy(policy + r"\AU")
    return {"python": list(sys.version_info[:3]), "protected": protected}


def _backend(command):
    if not command:
        return None
    if "legacy-windows-updates-" in command and "\\worker.py" in command:
        return "native"
    if (
        "import legacy_windows_updates_worker as worker;worker._supervised_main()"
        in command
        and re.search(r"\.updates-start-[0-9a-f]{32}\.json", command)
    ):
        return "native"
    # This exact plain-text stub identifies the released backend, not its
    # encoded frontend, a generic PowerShell instance or a guessed scheduler.
    if "Invoke-InProcessStub" in command and "ANSIBLE_BOOTSTRAP_ERROR:" in command:
        return "original"
    return None


def _poll_cache(workspace, connection, jobs, races):
    cache = os.path.join(workspace, "cache")
    changed = False
    for name in sorted(os.listdir(cache)):
        if not re.match(r"^j[0-9]+\.[0-9]+$", name):
            continue
        try:
            value = _BASE["_cache"](os.path.join(cache, name))
        except (FileNotFoundError, ValueError) as error:
            # Core may delete a completed cache while this read-only observer
            # opens it; retain the race rather than claiming a completed read.
            races.append({"cache": name, "error": repr(error)})
            continue
        body = value["json"]
        assert body["ansible_job_id"] == name and body["started"] is True
        assert body["results_file"] == os.path.join(cache, name)
        if name not in jobs:
            assert body["finished"] is False, "The startup cache was not observed"
            pid = body["ansible_async_watchdog_pid"]
            assert type(pid) is int and pid > 0  # pylint: disable=unidiomatic-typecheck
            identity = _BASE["_process"](pid)
            assert identity and identity["alive"]
            owner = connection.call_method(
                "Win32_Process.Handle='{0}'".format(pid),
                "GetOwnerSid",
                ["ReturnValue", "Sid"],
            )
            assert owner["ReturnValue"] == 0 and owner["Sid"]
            assert _BASE["_process"](pid) == identity
            jobs[name] = {
                "startup": value,
                "worker": {"identity": identity, "sid": owner["Sid"]},
                "started_at": time.time(),
            }
            changed = True
        if body["finished"] is True and jobs[name].get("completed") != value:
            jobs[name]["completed"] = value
            jobs[name]["completed_at"] = time.time()
            changed = True
    if changed:
        _write(workspace, "async-jobs.json", jobs)
    active = [name for name in jobs if "completed" not in jobs[name]]
    assert len(active) <= 1, "This owned fixture executes one Updates job at a time"
    return active[0] if active else None


def _poll_public(result, job, workspace):
    launch = job["startup"]["json"]
    for name in ("ansible_job_id", "ansible_async_watchdog_pid", "results_file"):
        _BASE["_same"](result[name], launch[name])
    assert launch["results_file"] == os.path.join(
        workspace, "cache", launch["ansible_job_id"]
    )
    assert result["started"] is True and result["finished"] is True
    worker = job["worker"]["identity"]
    assert worker["pid"] == launch["ansible_async_watchdog_pid"]
    assert worker["alive"] is True and worker["created"] > 0
    cache = job["completed"]
    _BASE["_same"](
        json.loads(base64.b64decode(cache["body_base64"]).decode("utf-8-sig")),
        cache["json"],
    )
    for name, value in cache["json"].items():
        if name not in ("invocation", "exception") and not name.startswith("_ansible_"):
            _BASE["_same"](value, result[name])
    metadata = {"invocation", "exception", "item", "ansible_loop_var"}
    public = {
        name: value
        for name, value in result.items()
        if name not in metadata and not name.startswith("_ansible_")
    }
    for name in ("ansible_job_id", "ansible_async_watchdog_pid", "results_file"):
        public[name] = "<independently validated owned {0}>".format(name)
    return public


def _retain_source_jobs(retained, results, jobs, identities):
    # Keep the original allocated paths and bytes. A healthy released cohort
    # can be retained only with its exact recorded resource/process closure.
    source_workspace = retained["workspace"]
    assert not os.path.exists(source_workspace)
    source = retained["observation"]
    assert source["cache_after"] == []
    for result in results:
        identifier = result["ansible_job_id"]
        assert identifier not in jobs
        job = source["jobs"][identifier]
        closed = [
            row
            for row in source["workers_closed"]
            if row["expected"] == job["worker"]["identity"]
        ]
        assert len(closed) == 1
        actual = closed[0]["actual"]
        assert (
            not actual
            or actual["created"] != closed[0]["expected"]["created"]
            or not actual["alive"]
        )
        records = [row for row in source["records"] if row.get("job_id") == identifier]
        assert len(records) == 1 and records[0]["side"] == "original"
        assert any(
            row["expected"] == records[0]["identity"]
            and (
                not row["actual"]
                or row["actual"]["created"] != row["expected"]["created"]
                or not row["actual"]["alive"]
            )
            for row in source["backends_closed"]
        )
        jobs[identifier] = job
        identities.extend(records)
    return source_workspace


def _compare_poll(workspace, pairs):
    jobs = _read(workspace, "async-jobs.json")
    identities = _read(workspace, "backend-identities.json")
    source_workspace = workspace
    if pairs.get("retained_original"):
        source_workspace = _retain_source_jobs(
            pairs["retained_original"], pairs["original"], jobs, identities
        )
    assert len(pairs["cases"]) == len(pairs["native"]) == len(pairs["original"]) == 4
    assert len(jobs) == len(identities) == 8
    used = set()
    for index, case in enumerate(pairs["cases"]):
        expected = (
            pairs["administrator_sid"]
            if case["actor"] == "administrator"
            else "S-1-5-18"
        )
        results = []
        for side in ("native", "original"):
            result = pairs[side][index]
            _BASE["_same"](result["item"], case)
            assert result["failed"] is True and result["hresult"] == -2145107951
            assert result["updates"] == result["filtered_updates"] == {}
            assert result["changed"] is False and result["rebooted"] is False
            identifier = result["ansible_job_id"]
            assert identifier not in used
            used.add(identifier)
            job = jobs[identifier]
            assert job["worker"]["sid"] == expected
            backend = [row for row in identities if row.get("job_id") == identifier]
            assert len(backend) == 1 and backend[0]["side"] == side
            assert backend[0]["sid"] == expected
            results.append(
                _poll_public(
                    result, job, source_workspace if side == "original" else workspace
                )
            )
        _BASE["_same"](*results)
    assert used == set(jobs)
    return {
        "whole_typed_public_pairs": 4,
        "startup_and_completed_cache_pairs": 4,
        "watchdog_and_backend_sid_birth_observations": 16,
    }


def _monitor(workspace):
    records, failures = [], []
    jobs, cache_races, active_job = {}, [], None
    polling = globals().get("POLL_ASYNC_CACHE", False)
    with _WMI["WmiConnection"]() as connection:
        _write(workspace, "monitor-ready.json", _BASE["_process"](os.getpid()))
        deadline = time.monotonic() + 300
        while not os.path.exists(os.path.join(workspace, "monitor-release")):
            if time.monotonic() >= deadline:
                raise OSError("Owned Updates identity monitor was not released.")
            if polling:
                active_job = (
                    _poll_cache(workspace, connection, jobs, cache_races) or active_job
                )
            rows = connection.query(
                "SELECT ProcessId,ParentProcessId,CommandLine,ExecutablePath "
                "FROM Win32_Process WHERE Name='python.exe' OR Name='powershell.exe'",
                ["ProcessId", "ParentProcessId", "CommandLine", "ExecutablePath"],
            )
            for row in rows:
                side = _backend(row["CommandLine"])
                if side is None:
                    continue
                identity = _BASE["_process"](row["ProcessId"])
                if not identity or not identity["alive"]:
                    continue
                if any(value["identity"] == identity for value in records):
                    continue
                owner = connection.call_method(
                    "Win32_Process.Handle='{0}'".format(row["ProcessId"]),
                    "GetOwnerSid",
                    ["ReturnValue", "Sid"],
                )
                current = _BASE["_process"](row["ProcessId"])
                if current != identity:
                    # A completed process is not proof of its earlier token.
                    failures.append(
                        {
                            "row": row,
                            "identity": identity,
                            "owner": owner,
                            "after": current,
                        }
                    )
                    continue
                if owner["ReturnValue"] != 0 or not owner["Sid"]:
                    raise OSError(
                        "Cannot query the live Updates backend SID: " + repr(owner)
                    )
                records.append(
                    {
                        "side": side,
                        "identity": identity,
                        "sid": owner["Sid"],
                        "process": row,
                        "time": time.time(),
                    }
                )
                if polling:
                    assert (
                        active_job is not None
                    ), "No owned startup cache identifies this backend"
                    records[-1]["job_id"] = active_job
                _write(workspace, "backend-identities.json", records)
            time.sleep(0.02)
    if polling:
        _write(
            workspace,
            "monitor-complete.json",
            {
                "records": records,
                "races": failures,
                "jobs": jobs,
                "cache_races": cache_races,
            },
        )
    else:
        _write(
            workspace, "monitor-complete.json", {"records": records, "races": failures}
        )


def _start(workspace):
    assert os.path.basename(workspace).startswith("legacy-windows-updates-runas-")
    source = globals()["MONITOR_SOURCE"]
    path = os.path.join(workspace, "monitor.py")
    with open(path, "x", encoding="utf-8") as stream:
        stream.write(source)
    # Use the existing native WMI provider to outlive the Runas command's job.
    # A subprocess BREAKAWAY launch failed with WinError5 on the actual guest;
    # the fixture does not change the production token/job runner to avoid it.
    command = subprocess.list2cmdline(
        [sys.executable, "-B", path, workspace, "monitor"]
    )
    # The birth-pinned monitor owns this launch, independently of Runas actions.
    # pylint: disable=duplicate-code
    with _WMI["WmiConnection"]() as connection:
        launched = connection.call_method(
            "Win32_Process",
            "Create",
            ["ReturnValue", "ProcessId"],
            {"CommandLine": command, "CurrentDirectory": workspace},
        )
        # pylint: enable=duplicate-code
        assert launched["ReturnValue"] == 0 and launched["ProcessId"], launched
        identity = _BASE["_process"](launched["ProcessId"])
        assert identity and identity["alive"]
        _write(workspace, "monitor-identity.json", identity)
        owners = [
            connection.call_method(
                "Win32_Process.Handle='{0}'".format(pid),
                "GetOwnerSid",
                ["ReturnValue", "Sid"],
            )
            for pid in (os.getpid(), launched["ProcessId"])
        ]
        assert all(owner["ReturnValue"] == 0 for owner in owners), owners
        assert [owner["Sid"] for owner in owners] == ["S-1-5-18"] * 2, owners
    deadline = time.monotonic() + 20
    while not os.path.exists(os.path.join(workspace, "monitor-ready.json")):
        current = _BASE["_process"](identity["pid"])
        if current != identity or time.monotonic() >= deadline:
            raise OSError("The owned Updates identity monitor did not become ready.")
        time.sleep(0.05)
    assert _read(workspace, "monitor-ready.json") == identity
    return {
        "identity": identity,
        "owners": owners,
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
    }


def _failed_monitor(workspace, identity, current):
    diagnostics = {"monitor_identity": identity, "monitor_final": current}
    for name in ("monitor-error.log", "async-jobs.json", "backend-identities.json"):
        try:
            with open(os.path.join(workspace, name), encoding="utf-8") as stream:
                diagnostics[name] = (
                    stream.read() if name.endswith(".log") else json.load(stream)
                )
        except FileNotFoundError:
            diagnostics[name] = None
    return diagnostics


def _stop(workspace):
    identity = _read(workspace, "monitor-identity.json")
    with open(
        os.path.join(workspace, "monitor-release"), "w", encoding="utf-8"
    ) as stream:
        stream.write("Release only the journaled Updates identity observer\n")
    deadline = time.monotonic() + 30
    while True:
        current = _BASE["_process"](identity["pid"])
        if (
            not current
            or current["created"] != identity["created"]
            or not current["alive"]
        ):
            break
        if time.monotonic() >= deadline:
            raise OSError(
                "The birth-identified Updates identity observer did not exit."
            )
        time.sleep(0.1)
    try:
        result = _read(workspace, "monitor-complete.json")
    except FileNotFoundError as error:
        # A crashed observer is still a failed gate. Keep its original traceback
        # and partial journals in the raw task before snapshot recovery erases them.
        raise OSError(
            "Owned Updates identity monitor failed: "
            + json.dumps(_failed_monitor(workspace, identity, current))
        ) from error
    closed = []
    for record in result["records"]:
        actual = _BASE["_process"](record["identity"]["pid"])
        assert (
            not actual
            or actual["created"] != record["identity"]["created"]
            or not actual["alive"]
        )
        closed.append({"expected": record["identity"], "actual": actual})
    result.update(
        monitor_identity=identity, monitor_final=current, backends_closed=closed
    )
    if globals().get("POLL_ASYNC_CACHE", False):
        workers = []
        for job in result["jobs"].values():
            expected = job["worker"]["identity"]
            actual = _BASE["_process"](expected["pid"])
            assert (
                not actual
                or actual["created"] != expected["created"]
                or not actual["alive"]
            )
            workers.append({"expected": expected, "actual": actual})
        cache = sorted(os.listdir(os.path.join(workspace, "cache")))
        assert cache == [], "Core did not automatically erase every completed cache"
        result.update(workers_closed=workers, cache_after=cache)
    return result


def main():
    """Observe one owned Runas fixture phase on actual Python3.4.4.

    :raises Exception: Preserve the original failed observer diagnostic.
    :raises ValueError: The requested observation phase is not recognized.
    """
    assert sys.version_info[:3] == (3, 4, 4)
    workspace, operation = sys.argv[1:3]
    if operation == "observe":
        result = _observe()
    elif operation == "start":
        result = _start(workspace)
    elif operation == "stop":
        result = _stop(workspace)
    elif operation == "compare-poll":
        result = _compare_poll(workspace, json.loads(sys.stdin.read()))
    elif operation == "monitor":
        try:
            _monitor(workspace)
        # Preserve any original monitor traceback in its owned diagnostic file
        # before re-raising the failure.
        except Exception:  # pylint: disable=broad-exception-caught
            with open(
                os.path.join(workspace, "monitor-error.log"), "w", encoding="utf-8"
            ) as stream:
                stream.write(traceback.format_exc())
            raise
        return
    else:
        raise ValueError("Unknown Updates Runas observation phase.")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
