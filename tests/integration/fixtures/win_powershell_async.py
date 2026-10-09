"""Pin live script engines and watchdogs before releasing owned async scripts."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import glob
import json
import os
import sys
import tempfile
import time


def _namespace(source):
    result = {"__name__": "owned_powershell_async_fixture"}
    result["WMI_SOURCE"] = globals()["WMI_SOURCE"]
    # Execute only literal maintained fixture/helper bytes embedded by vars.
    exec(  # pylint: disable=exec-used
        compile(source, "owned_powershell_async_fixture.py", "exec"), result
    )
    return result


_RESOURCE = _namespace(globals()["RESOURCE_SOURCE"])
_ASYNC = _namespace(globals()["ASYNC_SOURCE"])
_WMI = _namespace(globals()["WMI_SOURCE"])


def _names(index, phase):
    assert phase in ("native", "original") and index in range(4)
    return "{0}-{1}".format(index, phase)


def _resources(workspace):
    return os.path.join(workspace, "resources")


def _journal(workspace):
    return _RESOURCE["_read"](workspace)


def _job_paths(workspace, name):
    return {
        key: os.path.join(workspace, "owned-jobs", name + suffix)
        for key, suffix in (
            ("marker", ".pid"),
            ("release", ".release"),
            ("pin", ".json"),
        )
    }


def _setup(workspace):
    assert os.listdir(workspace) == []
    for name in (
        "resources",
        "native-cache",
        "original-cache",
        "staging",
        "owned-jobs",
    ):
        os.mkdir(os.path.join(workspace, name))
    _RESOURCE["_setup"](_resources(workspace))
    # This newly owned input is prepared before defining its protected baseline.
    script = os.path.join(_resources(workspace), "remote-script.ps1")
    with open(script, "wb") as stream:
        stream.write(globals()["FILE_SCRIPT"].encode("utf-8"))
    record = _RESOURCE["_read"](_resources(workspace))
    record["protected"]["remote-script.ps1"] = _RESOURCE["_file"](script)
    _RESOURCE["_write"](_resources(workspace), record)
    _RESOURCE["_write"](
        workspace,
        {
            "workspace": workspace,
            "machine": _ASYNC["_protected"](),
            "jobs": {
                _names(index, phase): _job_paths(workspace, _names(index, phase))
                for index in range(4)
                for phase in ("native", "original")
            },
        },
    )
    return _observe(workspace)


def _process_row(connection, pid):
    # A JSON Boolean or float is not a process identity, even when equal to an int.
    # pylint: disable-next=unidiomatic-typecheck
    assert type(pid) is int and pid > 0
    rows = connection.query(
        (
            "SELECT ProcessId,ParentProcessId,Name,ExecutablePath "
            "FROM Win32_Process WHERE ProcessId={0}"
        ).format(pid),
        ["ProcessId", "ParentProcessId", "Name", "ExecutablePath"],
    )
    assert len(rows) == 1 and rows[0]["ProcessId"] == pid
    identity = _ASYNC["_process"](pid)
    assert identity and identity["alive"] and identity["created"] > 0
    return {"identity": identity, "process": rows[0]}


def _pin(workspace):
    phase = sys.argv[4]
    paths = _journal(workspace)["jobs"][_names(int(sys.argv[3]), phase)]
    launch = json.loads(base64.b64decode(sys.argv[5]).decode("utf-8"))
    # Reject Boolean/float PIDs before a native lookup or owned release write.
    # pylint: disable-next=unidiomatic-typecheck
    assert type(launch["ansible_async_watchdog_pid"]) is int
    assert launch["ansible_async_watchdog_pid"] > 0
    cache = os.path.join(workspace, phase + "-cache")
    assert os.path.samefile(os.path.dirname(launch["results_file"]), cache)
    assert os.path.basename(launch["results_file"]) == launch["ansible_job_id"]
    deadline = time.monotonic() + 45
    while not os.path.isfile(paths["marker"]):
        assert time.monotonic() < deadline, "Script never recorded its engine PID"
        time.sleep(0.1)
    _RESOURCE["_file"](paths["marker"])
    with open(paths["marker"], encoding="ascii") as stream:
        value = stream.read()
    assert value and all(character in "0123456789" for character in value)
    engine_pid = int(value)
    chain = []
    with _WMI["WmiConnection"]() as connection:
        pid = engine_pid
        for _ in range(8):
            row = _process_row(connection, pid)
            assert not any(item["identity"]["pid"] == pid for item in chain)
            chain.append(row)
            if pid == launch["ansible_async_watchdog_pid"]:
                break
            pid = row["process"]["ParentProcessId"]
    assert chain[-1]["identity"]["pid"] == launch["ansible_async_watchdog_pid"]
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
    with open(paths["release"], "x", encoding="ascii") as stream:
        stream.write("release journal-owned engine")
    return pin


def _observe(workspace):
    record = _journal(workspace)
    assert set(os.listdir(workspace)) == {
        "resources",
        "native-cache",
        "original-cache",
        "staging",
        "owned-jobs",
        "journal.json",
    }
    allowed = {
        os.path.basename(path)
        for paths in record["jobs"].values()
        for path in paths.values()
    }
    assert set(os.listdir(os.path.join(workspace, "owned-jobs"))) <= allowed
    state = _RESOURCE["_observe"](_resources(workspace))
    state["machine"] = _ASYNC["_protected"]()
    before, after = record["machine"], state["machine"]
    for field in ("registry", "network", "python_executable"):
        _ASYNC["_same"](before[field], after[field])
    _ASYNC["_same"](
        _ASYNC["_service_configuration"](before["services"]),
        _ASYNC["_service_configuration"](after["services"]),
    )
    state["original_machine"] = before
    state["processes"] = []
    for paths in record["jobs"].values():
        if not os.path.isfile(paths["pin"]):
            continue
        with open(paths["pin"], encoding="utf-8") as stream:
            pin = json.load(stream)
        for row in pin["chain"]:
            expected = row["identity"]
            state["processes"].append(
                {"expected": expected, "actual": _ASYNC["_process"](expected["pid"])}
            )
    state["cache"] = {}
    for phase in ("native", "original"):
        directory = os.path.join(workspace, phase + "-cache")
        assert _RESOURCE["_file"](directory)["directory"]
        state["cache"][phase] = {
            name: _ASYNC["_cache"](os.path.join(directory, name))
            for name in os.listdir(directory)
        }
    state["staging"] = sorted(os.listdir(os.path.join(workspace, "staging")))
    state["engine_scratch"] = sorted(
        glob.glob(os.path.join(tempfile.gettempdir(), "legacy-windows-powershell-*"))
    )
    return state


def _prepare(workspace):
    _RESOURCE["_reset"](_resources(workspace))
    return _observe(workspace)


def _owned_alive(state):
    return any(
        row["actual"]
        and row["actual"]["created"] == row["expected"]["created"]
        and row["actual"]["alive"]
        for row in state["processes"]
    )


def _cleanup(workspace):
    deadline = time.monotonic() + 30
    state = _observe(workspace)
    while _owned_alive(state):
        if time.monotonic() >= deadline:
            raise ValueError(
                "Owned engine/watchdog remains alive; retain workspace and journal"
            )
        time.sleep(0.1)
        state = _observe(workspace)
    assert (
        not any(state["cache"].values())
        and not state["staging"]
        and not state["engine_scratch"]
    )
    _RESOURCE["_cleanup"](_resources(workspace))
    return {"restored": True, "state": _observe(workspace)}


def _finalize(workspace):
    _cleanup(workspace)
    _RESOURCE["_finalize"](_resources(workspace))
    record = _journal(workspace)
    for paths in record["jobs"].values():
        for path in paths.values():
            if os.path.exists(path):
                _RESOURCE["_file"](path)
                os.remove(path)
    for name in (
        "resources",
        "native-cache",
        "original-cache",
        "staging",
        "owned-jobs",
    ):
        os.rmdir(os.path.join(workspace, name))
    os.remove(os.path.join(workspace, "journal.json"))
    assert os.listdir(workspace) == []
    return {"finalized": True}


if __name__ == "__main__":
    assert sys.version_info[:3] == (3, 4, 4)
    _WORKSPACE, _OPERATION = sys.argv[1:3]
    assert os.path.basename(_WORKSPACE).startswith(
        "legacy-windows-win-powershell-async-"
    )
    assert os.path.samefile(os.path.dirname(_WORKSPACE), tempfile.gettempdir())
    _OPERATIONS = {
        "setup": _setup,
        "prepare": _prepare,
        "pin": _pin,
        "observe": _observe,
        "cleanup": _cleanup,
        "finalize": _finalize,
    }
    print(json.dumps(_OPERATIONS[_OPERATION](_WORKSPACE), sort_keys=True))
