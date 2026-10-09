"""Journal the async fixture's exact jobs, child identities and protected state."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import ctypes
import hashlib
import json
import os
import subprocess
import sys
import time

# Registry observations run only on actual Windows Python3.4.4.
import winreg  # pylint: disable=import-error


def _kernel():
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    api.OpenProcess.restype = ctypes.c_void_p
    api.GetProcessTimes.argtypes = [ctypes.c_void_p] + [
        ctypes.POINTER(ctypes.c_uint64)
    ] * 4
    api.GetProcessTimes.restype = ctypes.c_int
    api.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    api.WaitForSingleObject.restype = ctypes.c_uint32
    api.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    api.TerminateProcess.restype = ctypes.c_int
    api.CloseHandle.argtypes = [ctypes.c_void_p]
    api.CloseHandle.restype = ctypes.c_int
    return api


def _process(pid):
    api = _kernel()
    handle = api.OpenProcess(0x100400, False, pid)
    if not handle:
        if ctypes.get_last_error() == 87:
            return None
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        clocks = [ctypes.c_uint64() for _ in range(4)]
        assert api.GetProcessTimes(handle, *[ctypes.byref(clock) for clock in clocks])
        return {
            "pid": pid,
            "created": clocks[0].value,
            "alive": api.WaitForSingleObject(handle, 0) == 258,
        }
    finally:
        assert api.CloseHandle(handle)


def _protected():
    registry = []
    for key_path, value_name in (
        (r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName", "ComputerName"),
        (r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "Hostname"),
        (r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation", "Bias"),
        (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell"),
    ):
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            value, kind = winreg.QueryValueEx(key, value_name)
            if isinstance(value, bytes):
                value = {"base64": base64.b64encode(value).decode("ascii")}
            registry.append([key_path, value_name, value, kind])
    with open(sys.executable, "rb") as stream:
        executable = hashlib.sha256(stream.read()).hexdigest()
    # The controller supplies exactly the frozen maintained WMI helper bytes;
    # it is used for observations only, never copied into target production code.
    namespace = {"__name__": "owned_async_fixture_wmi"}
    # Embedding frozen WMI observations makes the stdin fixture independent of
    # the tested payload's staging imports; no production code is generated.
    exec(  # pylint: disable=exec-used
        compile(globals()["WMI_SOURCE"], "owned_async_fixture_wmi.py", "exec"),
        namespace,
    )
    with namespace["WmiConnection"]() as connection:
        services = connection.query(
            "SELECT Name,State,StartMode FROM Win32_Service",
            ["Name", "State", "StartMode"],
        )
        network = connection.query(
            "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True",
            [
                "Index",
                "IPAddress",
                "IPSubnet",
                "DefaultIPGateway",
                "DHCPEnabled",
                "DHCPServer",
                "DNSServerSearchOrder",
                "MACAddress",
            ],
        )
    return {
        "registry": registry,
        "python_executable": executable,
        "services": sorted(services, key=lambda value: value["Name"]),
        "network": sorted(network, key=lambda value: value["Index"]),
    }


def _read(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def _write(path, value):
    with open(path, "x", encoding="utf-8") as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())


def _journal(workspace):
    value = _read(os.path.join(workspace, "journal.json"))
    assert value["workspace"] == workspace
    return value


def _setup(workspace):
    assert os.listdir(workspace) == []
    protected = _protected()
    _write(
        os.path.join(workspace, "journal.json"),
        {"workspace": workspace, "protected": protected},
    )
    for name in ("cache", "staging"):
        os.mkdir(os.path.join(workspace, name))
    with open(os.path.join(workspace, "sentinel.bin"), "xb") as stream:
        stream.write(b"protected async sentinel\x00\xff")
    return {"protected": protected, "python": sys.version}


def _record_job(workspace, launch=None):
    if launch is None:
        launch = json.loads(base64.b64decode(sys.argv[3]).decode("utf-8"))
    record = {
        "launch": launch,
        "worker": _process(launch["ansible_async_watchdog_pid"]),
    }
    _write(os.path.join(workspace, "job-" + launch["ansible_job_id"] + ".json"), record)
    return record


def _record_running_job(workspace):
    # This owned Command payload executes while its watchdog waits. Read the
    # sole owned startup cache, then verify the worker is this module's parent
    # before recording its live handle-derived birth identity. No PID-only
    # post-completion lookup can establish that ownership after automatic poll.
    cache = os.path.join(workspace, "cache")
    names = os.listdir(cache)
    assert len(names) == 1
    launch = _cache(os.path.join(cache, names[0]))["json"]
    assert launch["ansible_job_id"] == names[0]
    assert launch["started"] is True and launch["finished"] is False
    namespace = {"__name__": "owned_async_worker_observation"}
    exec(  # pylint: disable=exec-used
        compile(globals()["WMI_SOURCE"], "owned_async_fixture_wmi.py", "exec"),
        namespace,
    )
    module_pid = os.getppid()
    with namespace["WmiConnection"]() as connection:
        parents = connection.query(
            "SELECT ParentProcessId FROM Win32_Process WHERE ProcessId={0}".format(
                module_pid
            ),
            ["ParentProcessId"],
        )
    assert len(parents) == 1
    assert parents[0]["ParentProcessId"] == launch["ansible_async_watchdog_pid"]
    record = _record_job(workspace, launch)
    worker = record["worker"]
    module, payload = _process(module_pid), _process(os.getpid())
    assert worker and module and payload
    assert worker["alive"] and module["alive"] and payload["alive"]
    assert worker["created"] <= module["created"] <= payload["created"]
    return {"recorded_live_worker": True}


def _payload(workspace):
    # The child records its own birth identity before sleeping. This avoids a
    # recycled-PID assumption during strict timeout inspection and recovery.
    program = (
        "import ctypes,json,os,sys,time\n"
        + globals()["PROCESS_SOURCE"]
        + "\n"
        + (
            "value=_process(os.getpid())\n"
            "with open(sys.argv[1], 'x') as stream:\n"
            "    json.dump(value,stream)\n"
            "time.sleep(90)\n"
        )
    )
    # The owned child must outlive launch to exercise descendant timeout
    # cleanup; a Popen context would wait for its90-second sleep.
    subprocess.Popen(  # pylint: disable=consider-using-with
        [sys.executable, "-c", program, os.path.join(workspace, "child.json")]
    )
    deadline = time.monotonic() + 10
    while not os.path.exists(os.path.join(workspace, "child.json")):
        assert time.monotonic() < deadline
        time.sleep(0.01)
    time.sleep(90)


def _record_then_timeout(workspace):
    _record_running_job(workspace)
    _payload(workspace)


def _cache(path):
    with open(path, "rb") as stream:
        body = stream.read()
    return {
        "body_base64": base64.b64encode(body).decode("ascii"),
        "json": json.loads(body.decode("utf-8-sig")),
    }


def _same(left, right):
    assert type(left) is type(right)
    if isinstance(left, dict):
        assert set(left) == set(right)
        for name in left:
            _same(left[name], right[name])
    elif isinstance(left, list):
        assert len(left) == len(right)
        for native, original in zip(left, right):
            _same(native, original)
    else:
        assert left == right


def _job_public(result, launch, workspace):
    result = dict(result)
    job_id = launch["ansible_job_id"]
    assert result["ansible_job_id"] == job_id
    assert result["ansible_async_watchdog_pid"] == launch["ansible_async_watchdog_pid"]
    # JSON booleans must not satisfy the public integer PID contract.
    # pylint: disable=unidiomatic-typecheck
    assert (
        type(result["ansible_async_watchdog_pid"]) is int
        and result["ansible_async_watchdog_pid"] > 0
    )
    assert result["results_file"] == launch["results_file"]
    assert os.path.basename(result["results_file"]) == job_id
    assert os.path.samefile(
        os.path.dirname(result["results_file"]), os.path.join(workspace, "cache")
    )
    result["ansible_job_id"] = "<job-id>"
    result["results_file"] = result["results_file"].replace(job_id, "<job-id>")
    result["ansible_async_watchdog_pid"] = "<watchdog-pid>"
    if "attempts" in result:
        # Preserve the exact JSON counter type; bool is an int subclass.
        assert type(result["attempts"]) is int and 1 <= result["attempts"] <= 30
        result["attempts"] = "<bounded-poll-attempts>"
    # pylint: enable=unidiomatic-typecheck
    # The established compatibility contract excludes these diagnostic wrappers,
    # not arbitrary public fields. All raw captures remain unchanged.
    result.pop("invocation", None)
    result.pop("exception", None)
    return result


def _compare(workspace):
    pair = json.loads(base64.b64decode(sys.argv[3]).decode("utf-8"))
    _same(
        _job_public(pair["native_launch"], pair["native_launch"], workspace),
        _job_public(pair["original_launch"], pair["original_launch"], workspace),
    )
    _same(
        _job_public(pair["native_status"], pair["native_launch"], workspace),
        _job_public(pair["original_status"], pair["original_launch"], workspace),
    )
    return {
        "complete_typed_public_equal": True,
        "qualified": [
            "ansible_job_id",
            "results_file",
            "ansible_async_watchdog_pid",
            "attempts",
        ],
    }


def _service_configuration(rows):
    return [
        {name: value for name, value in row.items() if name != "State"} for row in rows
    ]


def _observe(workspace):
    record = _journal(workspace)
    current = _protected()
    original = record["protected"]
    for field in ("registry", "python_executable", "network"):
        _same(current[field], original[field])
    # Unrelated background services can start/stop by design. Protect every
    # name/startup setting literally, retain complete runtime observations,
    # and verify only fixture-owned process lifetimes below.
    _same(
        _service_configuration(current["services"]),
        _service_configuration(original["services"]),
    )
    with open(os.path.join(workspace, "sentinel.bin"), "rb") as stream:
        assert stream.read() == b"protected async sentinel\x00\xff"
    processes = []
    for name in os.listdir(workspace):
        if name.startswith("job-") and name.endswith(".json"):
            identity = _read(os.path.join(workspace, name))["worker"]
            if identity:
                actual = _process(identity["pid"])
                processes.append({"expected": identity, "actual": actual})
        elif name == "child.json":
            identity = _read(os.path.join(workspace, name))
            processes.append(
                {"expected": identity, "actual": _process(identity["pid"])}
            )
    return {
        "original_protected": original,
        "protected": current,
        "service_state_changes": [
            {
                "name": before["Name"],
                "expected": before["State"],
                "actual": after["State"],
            }
            for before, after in zip(original["services"], current["services"])
            if before["State"] != after["State"]
        ],
        "processes": processes,
        "cache": sorted(os.listdir(os.path.join(workspace, "cache"))),
        "cache_records": {
            name: _cache(os.path.join(workspace, "cache", name))
            for name in os.listdir(os.path.join(workspace, "cache"))
        },
        "staging": sorted(os.listdir(os.path.join(workspace, "staging"))),
    }


def _cleanup(workspace):
    observed = _observe(workspace)
    for process in observed["processes"]:
        identity, actual = process["expected"], process["actual"]
        if actual and actual["created"] == identity["created"] and actual["alive"]:
            api = _kernel()
            handle = api.OpenProcess(0x100401, False, identity["pid"])
            assert handle
            try:
                # Pin the process handle and recheck the birth identity before
                # terminating any retained owned watchdog/fixture child.
                clocks = [ctypes.c_uint64() for _ in range(4)]
                assert api.GetProcessTimes(
                    handle, *[ctypes.byref(clock) for clock in clocks]
                )
                assert clocks[0].value == identity["created"]
                assert api.TerminateProcess(handle, 1)
                assert api.WaitForSingleObject(handle, 5000) == 0
            finally:
                assert api.CloseHandle(handle)
    final = _observe(workspace)
    assert all(
        not value["actual"]
        or value["actual"]["created"] != value["expected"]["created"]
        or not value["actual"]["alive"]
        for value in final["processes"]
    )
    return {"restored": True, "before_cleanup": observed, "final": final}


if __name__ == "__main__":
    assert sys.version_info[:3] == (3, 4, 4)
    _WORKSPACE, _OPERATION = sys.argv[1:3]
    assert os.path.basename(_WORKSPACE).startswith("legacy-windows-native-async-")
    _OPERATIONS = {
        "setup": _setup,
        "record": _record_job,
        "record_running": _record_running_job,
        "record_then_timeout": _record_then_timeout,
        "payload": _payload,
        "observe": _observe,
        "cleanup": _cleanup,
        "compare": _compare,
    }
    print(json.dumps(_OPERATIONS[_OPERATION](_WORKSPACE), sort_keys=True))
