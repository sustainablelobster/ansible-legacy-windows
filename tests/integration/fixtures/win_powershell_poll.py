"""Observe PowerShell caches and release only birth-pinned owned script engines."""

# SPDX-License-Identifier: GPL-3.0-or-later

import hashlib
import json
import os
import re
import subprocess
import sys
import time
import traceback


def _namespace(source):
    namespace = {"__name__": "owned_powershell_poll_dependencies"}
    for name in ("RESOURCE_SOURCE", "ASYNC_SOURCE", "WMI_SOURCE", "FILE_SCRIPT"):
        namespace[name] = globals()[name]
    # Execute only the literal accepted fixtures embedded by the playbook.
    # pylint: disable-next=exec-used
    exec(compile(source, "owned_poll_dependencies.py", "exec"), namespace)
    return namespace


_BASE = _namespace(globals()["POLL_BASE_SOURCE"])
_ASYNC, _WMI, _RESOURCE = (_BASE[name] for name in ("_ASYNC", "_WMI", "_RESOURCE"))


def _paths(root):
    return _BASE["_journal"](root)["jobs"]["poll-monitor"]


def _write(path, value):
    with open(path + ".next", "w", encoding="utf-8") as stream:
        json.dump(value, stream)
    os.replace(path + ".next", path)


def _read(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def _owner(connection, identity):
    result = connection.call_method(
        "Win32_Process.Handle='{0}'".format(identity["pid"]),
        "GetOwnerSid",
        ["ReturnValue", "Sid"],
    )
    assert result["ReturnValue"] == 0 and result["Sid"]
    assert _ASYNC["_process"](identity["pid"]) == identity
    return result["Sid"]


def _pin_engine(root, connection, job):
    paths = _BASE["_journal"](root)["jobs"][job["name"]]
    if not os.path.exists(paths["marker"]):
        return False
    with open(paths["marker"], encoding="ascii") as stream:
        value = stream.read()
    assert value and all(character in "0123456789" for character in value)
    launch = job["startup"]["json"]
    chain, pid = [], int(value)
    # Polling validates its own engine chain; the foreground fixture is separate.
    # pylint: disable=duplicate-code
    for _ in range(8):
        row = _BASE["_process_row"](connection, pid)
        row["sid"] = _owner(connection, row["identity"])
        assert not any(item["identity"]["pid"] == pid for item in chain)
        chain.append(row)
        if pid == launch["ansible_async_watchdog_pid"]:
            break
        pid = row["process"]["ParentProcessId"]
    assert chain[-1]["identity"] == job["worker"]["identity"]
    assert chain[0]["process"]["Name"].lower() == "powershell.exe"
    assert all(
        child["identity"]["created"] >= parent["identity"]["created"]
        for child, parent in zip(chain, chain[1:])
    )
    pin = {"launch": launch, "chain": chain, "paths": paths}
    with open(paths["pin"], "x", encoding="utf-8") as stream:
        json.dump(pin, stream)
        stream.flush()
        os.fsync(stream.fileno())
    # pylint: enable=duplicate-code
    job["pin"] = pin
    with open(paths["release"], "x", encoding="ascii") as stream:
        stream.write("release only the journal-owned birth-pinned engine")
    return True


def _capture(root, connection, jobs, races):
    changed = False
    for phase in ("native", "original"):
        cache = os.path.join(root, phase + "-cache")
        for identifier in sorted(os.listdir(cache)):
            if not re.match(r"^j[0-9]+\.[0-9]+$", identifier):
                # The accepted native writer atomically replaces its final jid
                # from jid.writer_pid.tmp. Retain this observed inventory; the
                # ordinary lifecycle still requires the entire cache empty.
                assert phase == "native" and re.match(
                    r"^j[0-9]+\.[0-9]+\.[0-9]+[.]tmp$", identifier
                ), identifier
                if not any(row.get("temporary") == identifier for row in races):
                    races.append(
                        {
                            "phase": phase,
                            "temporary": identifier,
                            "observed_at": time.time(),
                        }
                    )
                continue
            try:
                value = _ASYNC["_cache"](os.path.join(cache, identifier))
            except (FileNotFoundError, ValueError) as error:
                # Standard automatic polling can delete a completed cache while
                # this read-only observer opens it; retain the exact race.
                races.append(
                    {"phase": phase, "cache": identifier, "error": repr(error)}
                )
                continue
            body = value["json"]
            assert body["ansible_job_id"] == identifier and body["started"] is True
            assert body["results_file"] == os.path.join(cache, identifier)
            if identifier not in jobs:
                assert body["finished"] is False, "Startup cache was not observed"
                active = _BASE["_journal"](root)["active"]
                assert active["phase"] == phase
                pid = body["ansible_async_watchdog_pid"]
                # JSON Boolean/float values cannot identify a native process.
                # pylint: disable-next=unidiomatic-typecheck
                assert type(pid) is int and pid > 0
                identity = _ASYNC["_process"](pid)
                assert identity and identity["alive"]
                jobs[identifier] = {
                    "name": _BASE["_names"](active["index"], phase),
                    "phase": phase,
                    "startup": value,
                    "worker": {
                        "identity": identity,
                        "sid": _owner(connection, identity),
                    },
                    "started_at": time.time(),
                }
                changed = True
            job = jobs[identifier]
            if "pin" not in job:
                changed = _pin_engine(root, connection, job) or changed
            if body["finished"] is True and "completed" not in job:
                assert "pin" in job, "The engine was not observed alive"
                job["completed"], job["completed_at"] = value, time.time()
                changed = True
    if changed:
        _write(_paths(root)["state"], jobs)


def _monitor(root):
    paths, jobs, races = _paths(root), {}, []
    with _WMI["WmiConnection"]() as connection:
        identity = _ASYNC["_process"](os.getpid())
        _write(
            paths["ready"], {"identity": identity, "sid": _owner(connection, identity)}
        )
        deadline = time.monotonic() + 240
        while not os.path.exists(paths["release"]):
            assert time.monotonic() < deadline, "Owned cache observer was not released"
            _capture(root, connection, jobs, races)
            time.sleep(0.005)
    _write(paths["complete"], {"jobs": jobs, "cache_races": races})


def _setup(root):
    protected = _BASE["_setup"](root)
    paths = {
        key: os.path.join(root, "owned-jobs", "poll-" + name)
        for key, name in (
            ("marker", "monitor.py"),
            ("pin", "identity.json"),
            ("release", "release.json"),
            ("ready", "ready.json"),
            ("state", "state.json"),
            ("complete", "complete.json"),
            ("error", "error.log"),
            ("ready_next", "ready.json.next"),
            ("state_next", "state.json.next"),
            ("complete_next", "complete.json.next"),
            ("release_next", "release.json.next"),
        )
    }
    record = _BASE["_journal"](root)
    record["jobs"]["poll-monitor"] = paths
    _RESOURCE["_write"](root, record)
    source = globals()["MONITOR_SOURCE"]
    with open(paths["marker"], "x", encoding="utf-8") as stream:
        stream.write(source)
    command = subprocess.list2cmdline(
        [sys.executable, "-B", paths["marker"], root, "monitor"]
    )
    # The monitor needs its own WMI launch, not the production async launcher.
    # pylint: disable=duplicate-code
    with _WMI["WmiConnection"]() as connection:
        launched = connection.call_method(
            "Win32_Process",
            "Create",
            ["ReturnValue", "ProcessId"],
            {"CommandLine": command, "CurrentDirectory": root},
        )
        # pylint: enable=duplicate-code
        assert launched["ReturnValue"] == 0 and launched["ProcessId"], launched
        row = _BASE["_process_row"](connection, launched["ProcessId"])
        row["sid"] = _owner(connection, row["identity"])
    with open(paths["pin"], "x", encoding="utf-8") as stream:
        json.dump({"chain": [row]}, stream)
    deadline = time.monotonic() + 20
    while not os.path.isfile(paths["ready"]):
        assert _ASYNC["_process"](row["identity"]["pid"]) == row["identity"]
        assert time.monotonic() < deadline, "Owned observer never became ready"
        time.sleep(0.05)
    assert _read(paths["ready"]) == {"identity": row["identity"], "sid": row["sid"]}
    return {
        "protected": protected,
        "monitor": row,
        "monitor_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
    }


def _observe(root):
    state = _BASE["_observe"](root)
    state["epoch"] = time.time()
    path = _paths(root)["state"]
    state["observed_jobs"] = _read(path) if os.path.exists(path) else {}
    return state


def _prepare(root):
    _BASE["_prepare"](root)
    record = _BASE["_journal"](root)
    index, phase = int(sys.argv[3]), sys.argv[4]
    _BASE["_names"](index, phase)
    record["active"] = {"index": index, "phase": phase}
    _RESOURCE["_write"](root, record)
    return _observe(root)


def _cleanup(root):
    paths = _paths(root)
    _write(paths["release"], True)
    recovery = _BASE["_cleanup"](root)
    assert os.path.isfile(
        paths["complete"]
    ), "Retain the original observer error and journal"
    result = _read(paths["complete"])
    result["recovery"] = recovery
    result["monitor"] = _read(paths["pin"])["chain"][0]
    result["monitor_ready"] = _read(paths["ready"])
    return result


def main():
    """Run a bounded observer using the accepted resource and process lifecycle.

    :raises AssertionError: If a protected resource or live ownership differs.
    :raises Exception: Preserve an original monitor failure before propagating it.
    """
    assert sys.version_info[:3] == (3, 4, 4)
    root, operation = sys.argv[1:3]
    if operation == "monitor":
        try:
            _monitor(root)
        # Preserve the precise observer traceback; never infer successful exit.
        except Exception:  # pylint: disable=broad-exception-caught
            with open(_paths(root)["error"], "w", encoding="utf-8") as stream:
                stream.write(traceback.format_exc())
            raise
        return
    operations = {
        "setup": _setup,
        "prepare": _prepare,
        "observe": _observe,
        "cleanup": _cleanup,
        "finalize": _BASE["_finalize"],
    }
    print(json.dumps(operations[operation](root), sort_keys=True))


if __name__ == "__main__":
    main()
