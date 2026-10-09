"""Exercise real input binding and fail-closed automatic-poll capture gates."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import json
import runpy
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

from scripts.verify_win_powershell_poll_capture import CASES, verify_capture

_BINDING = """
import json,sys,yaml
from ansible._internal._datatag._tags import TrustedAsTemplate
from ansible.template import Templar
tasks=yaml.safe_load(open(sys.argv[1],encoding='utf-8'))
variables=yaml.safe_load(open(sys.argv[2],encoding='utf-8'))
index,phase=int(sys.argv[3]),sys.argv[4]
data={'powershell_poll_case':variables['powershell_poll_cases'][index],
      'powershell_poll_header':variables['powershell_poll_header'],
      'powershell_poll_workspace':{'path':r'C:\\Temp\\owned-poll'},
      'powershell_poll_index':index,'powershell_poll_phase':phase,
      'playbook_dir':'/owned/tests/integration'}
assert all(task.get('poll')==1 for task in tasks if 'async' in task)
assert not any('async_status' in key for task in tasks for key in task)
expression=tasks[0]['ansible.builtin.set_fact']['powershell_poll_params']
print(json.dumps(Templar(variables=data).template(TrustedAsTemplate().tag(expression))))
"""


@pytest.mark.parametrize("index", range(4))
@pytest.mark.parametrize("phase", ["native", "original"])
def test_actual_core_binds_all_eight_automatic_requests(index: int, phase: str) -> None:
    integration = Path(__file__).parents[1] / "integration"
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            _BINDING,
            str(integration / "tasks/win_powershell_poll_case.yml"),
            str(integration / "vars/win_powershell_poll.yml"),
            str(index),
            phase,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    params = json.loads(result.stdout)
    assert (
        params["parameters"]["MarkerPath"]
        == rf"C:\Temp\owned-poll/owned-jobs/{index}-{phase}.pid"
    )
    assert (
        params["parameters"]["ReleasePath"]
        == rf"C:\Temp\owned-poll/owned-jobs/{index}-{phase}.release"
    )
    if index == 1:
        assert (
            params["path"]
            == "/owned/tests/integration/fixtures/win_powershell_async.ps1"
        )
        assert params["parameters"]["Text"] == "controller parameter λ"
        assert "script" not in params
    else:
        assert params["script"].startswith(
            "[CmdletBinding(SupportsShouldProcess)]\nparam("
        )
        assert "owned async release missing" in params["script"]
    assert ("OutputPath" in params["parameters"]) is (index == 2)


def _identity(pid: int, birth: int) -> dict[str, Any]:
    return {"pid": pid, "created": birth, "alive": True}


def _cache(body: dict[str, Any]) -> dict[str, Any]:
    return {
        "json": body,
        "body_base64": base64.b64encode(json.dumps(body).encode()).decode(),
    }


# This complete synthetic capture keeps its observed values visible together.
# pylint: disable-next=too-many-locals
def _capture() -> dict[str, Any]:
    root, sid = r"C:\Temp\owned-poll", "S-1-5-21-1-500"
    file = {
        "attributes": 32,
        "security": "YQ==",
        "body_base64": "eA==",
        "ctime": 1.0,
        "mtime": 2.0,
        "directory": False,
    }
    machine = {
        "registry": [[], [], [], []],
        "network": [{"address": "owned"}],
        "python_executable": "a" * 64,
        "services": [{"Name": "owned", "StartMode": "Manual", "State": "Stopped"}],
    }
    state = {
        "protected": {"sentinel.bin": file, "remote-script.ps1": file},
        "output": {"output.txt": None},
        "python": "3.4.4",
        "environment": {},
        "utc": "2026-10-04T00:00:00.000000Z",
        "epoch": 100.0,
        "machine": machine,
        "original_machine": machine,
        "cache": {"native": {}, "original": {}},
        "staging": [],
        "engine_scratch": [],
        "processes": [],
        "observed_jobs": {},
    }
    birth = 116444737010000000
    monitor = {
        "identity": _identity(10, birth),
        "sid": sid,
        "process": {"Name": "python.exe", "ProcessId": 10, "ParentProcessId": 1},
    }
    jobs: dict[str, Any] = {}
    records: list[dict[str, Any]] = []
    processes = [{"expected": monitor["identity"], "actual": None}]
    for index, name in enumerate(CASES):
        for phase in ("native", "original"):
            pid = 100 + len(records)
            identifier = f"j1.{pid}"
            startup = {
                "started": True,
                "finished": False,
                "ansible_job_id": identifier,
                "ansible_async_watchdog_pid": pid,
                "results_file": root + f"\\{phase}-cache\\{identifier}",
            }
            result = dict(
                startup,
                finished=True,
                changed=index == 2,
                failed=index == 3,
                result=[
                    {"nested": {"rows": [1, None, "λ"], "yes": True}, "number": 2.5},
                    {"text": "controller parameter λ", "path": "", "root": ""},
                    {"check": True},
                    {},
                ][index],
                output=[
                    [[{"name": "one", "count": 1}, {"name": "two", "count": 2}]],
                    ["file λ"],
                    [],
                    ["before λ"],
                ][index],
                information=[],
                error=(
                    [{"exception": {"message": "async failure λ"}}]
                    if index == 3
                    else []
                ),
            )
            if index == 0:
                result["information"] = [
                    {
                        "message_data": {"label": "information λ"},
                        "tags": ["first", "second"],
                        "source": "Write-Information",
                        "time_generated": "2026-10-04T00:00:00.0000000Z",
                    }
                ]
            chain = [
                {
                    "identity": _identity(pid + 100, birth),
                    "sid": sid,
                    "process": {
                        "Name": "powershell.exe",
                        "ProcessId": pid + 100,
                        "ParentProcessId": pid,
                    },
                },
                {
                    "identity": _identity(pid, birth),
                    "sid": sid,
                    "process": {
                        "Name": "python.exe",
                        "ProcessId": pid,
                        "ParentProcessId": 1,
                    },
                },
            ]
            job = {
                "startup": _cache(startup),
                "completed": _cache(result),
                "phase": phase,
                "name": f"{index}-{phase}",
                "worker": {"identity": _identity(pid, birth), "sid": sid},
                "started_at": 101.0,
                "completed_at": 102.0,
                "pin": {"launch": startup, "chain": chain},
            }
            jobs[identifier] = job
            processes.extend(
                {"expected": item["identity"], "actual": None} for item in chain
            )
            before, after = deepcopy(state), deepcopy(state)
            after["epoch"] = 103.0
            after["observed_jobs"] = deepcopy(jobs)
            request = {
                "script": "literal script",
                "parameters": {
                    "MarkerPath": root + f"/owned-jobs/{index}-{phase}.pid",
                    "ReleasePath": root + f"/owned-jobs/{index}-{phase}.release",
                },
            }
            records.append(
                {
                    "case": {"name": name, "changed": index == 2},
                    "index": index,
                    "phase": phase,
                    "check_mode": index == 2,
                    "validated": True,
                    "request": request,
                    "result": result,
                    "before": {"stdout": json.dumps(before)},
                    "after": {"stdout": json.dumps(after)},
                }
            )
    recovery = deepcopy(state)
    recovery["processes"] = processes
    return {
        "workspace": root,
        "workspace_absent": True,
        "identity": {"account": {"sid": sid}},
        "guard": {
            "stdout": json.dumps(
                {"python": [3, 4, 4], "mac": "BC-24-11-9D-0E-6F", "staging": []}
            )
        },
        "staging_after": {"rc": 0, "stdout": "[]"},
        "finalized": {"rc": 0, "stdout": '{"finalized":true}'},
        "setup": {
            "rc": 0,
            "stdout": json.dumps(
                {
                    "protected": {"machine": machine, "protected": state["protected"]},
                    "monitor": monitor,
                    "monitor_sha256": "a" * 64,
                }
            ),
        },
        "recovery": {
            "rc": 0,
            "stdout": json.dumps(
                {
                    "jobs": jobs,
                    "monitor": monitor,
                    "monitor_ready": {"identity": monitor["identity"], "sid": sid},
                    "recovery": {"restored": True, "state": recovery},
                }
            ),
        },
        "records": records,
    }


def test_complete_capture_passes_without_changing_raw_evidence() -> None:
    capture = _capture()
    before = deepcopy(capture)
    assert verify_capture(capture) == {
        "public_pairs": 4,
        "observed_jobs": 8,
        "bounded_information_clocks": 2,
    }
    assert capture == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("epoch", False),
        ("epoch", float("inf")),
        ("epoch", float("nan")),
        ("epoch", 99.0),
    ],
)
def test_matching_forged_observation_clocks_fail(field: str, value: object) -> None:
    capture = _capture()
    for row in capture["records"][:2]:
        after = json.loads(row["after"]["stdout"])
        after[field] = value
        row["after"]["stdout"] = json.dumps(after)
    with pytest.raises(AssertionError):
        verify_capture(capture)


@pytest.mark.parametrize(
    "fault",
    ["owner", "birth", "completed", "cache", "preview", "extra_record", "closed"],
)
def test_missing_live_cache_identity_or_protection_evidence_is_rejected(
    fault: str,
) -> None:
    capture = _capture()
    closure = json.loads(capture["recovery"]["stdout"])
    job = next(iter(closure["jobs"].values()))
    if fault == "owner":
        job["worker"]["sid"] = "S-1-5-18"
    elif fault == "birth":
        job["worker"]["identity"]["created"] = True
    elif fault == "completed":
        del job["completed"]
    elif fault == "closed":
        closure["recovery"]["state"]["processes"][0]["actual"] = closure["monitor"][
            "identity"
        ]
    elif fault == "extra_record":
        capture["records"].append(deepcopy(capture["records"][-1]))
    else:
        row = capture["records"][4]
        after = json.loads(row["after"]["stdout"])
        if fault == "cache":
            after["cache"]["native"] = {"retained": job["completed"]}
        else:
            after["output"]["output.txt"] = {"body_base64": "eA=="}
        row["after"]["stdout"] = json.dumps(after)
    capture["recovery"]["stdout"] = json.dumps(closure)
    with pytest.raises((AssertionError, KeyError)):
        verify_capture(capture)


def _fixture() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "integration/fixtures/win_powershell_poll.py"
    return runpy.run_path(
        str(path),
        init_globals={
            "POLL_BASE_SOURCE": "_ASYNC={};_WMI={};_RESOURCE={}",
            "RESOURCE_SOURCE": "",
            "ASYNC_SOURCE": "",
            "WMI_SOURCE": "",
            "FILE_SCRIPT": "",
        },
    )


@pytest.mark.parametrize("pid", [True, False, 42.0, 0, -1])
def test_cache_pid_is_validated_before_native_process_access(
    tmp_path: Path, pid: object
) -> None:
    fixture = _fixture()
    globals_ = fixture["_capture"].__globals__
    cache = tmp_path / "native-cache"
    cache.mkdir()
    (cache / "j1.42").touch()
    (tmp_path / "original-cache").mkdir()
    globals_["_BASE"]["_journal"] = Mock(return_value={"active": {"phase": "native"}})
    globals_["_ASYNC"]["_cache"] = Mock(
        return_value={
            "json": {
                "ansible_job_id": "j1.42",
                "started": True,
                "finished": False,
                "ansible_async_watchdog_pid": pid,
                "results_file": str(cache / "j1.42"),
            }
        }
    )
    access = Mock()
    globals_["_ASYNC"]["_process"] = access
    with pytest.raises(AssertionError):
        fixture["_capture"](str(tmp_path), Mock(), {}, [])
    access.assert_not_called()


def test_cleanup_requires_monitor_complete_not_only_process_exit(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    globals_ = fixture["_cleanup"].__globals__
    globals_["_paths"] = Mock(
        return_value={
            "release": str(tmp_path / "release"),
            "complete": str(tmp_path / "missing-complete"),
        }
    )
    globals_["_BASE"]["_cleanup"] = Mock(return_value={"restored": True})
    with pytest.raises(AssertionError, match="original observer error"):
        fixture["_cleanup"](str(tmp_path))
    assert json.loads((tmp_path / "release").read_text()) is True


def test_no_engine_release_before_complete_birth_chain_validation(
    tmp_path: Path,
) -> None:
    fixture = _fixture()
    globals_ = fixture["_pin_engine"].__globals__
    paths = {name: str(tmp_path / name) for name in ("marker", "pin", "release")}
    (tmp_path / "marker").write_text("100")
    globals_["_BASE"]["_journal"] = Mock(return_value={"jobs": {"0-native": paths}})
    globals_["_BASE"]["_process_row"] = Mock(
        side_effect=[
            {
                "identity": _identity(100, 1),
                "process": {"Name": "powershell.exe", "ParentProcessId": 42},
            },
            {
                "identity": _identity(42, 2),
                "process": {"Name": "python.exe", "ParentProcessId": 1},
            },
        ]
    )
    globals_["_owner"] = Mock(return_value="S-1-5-21-1-500")
    job = {
        "name": "0-native",
        "startup": {"json": {"ansible_async_watchdog_pid": 42}},
        "worker": {"identity": _identity(42, 2)},
    }
    with pytest.raises(AssertionError):
        fixture["_pin_engine"](str(tmp_path), Mock(), job)
    assert not (tmp_path / "release").exists() and not (tmp_path / "pin").exists()


def test_temporary_atomic_cache_is_retained_but_not_parsed(tmp_path: Path) -> None:
    fixture = _fixture()
    globals_ = fixture["_capture"].__globals__
    (tmp_path / "native-cache").mkdir()
    (tmp_path / "original-cache").mkdir()
    (tmp_path / "native-cache/j1.42.77.tmp").write_text("unfinished bytes")
    parse = Mock()
    races: list[dict[str, Any]] = []
    globals_["_ASYNC"]["_cache"] = parse
    fixture["_capture"](str(tmp_path), Mock(), {}, races)
    parse.assert_not_called()
    assert len(races) == 1 and races[0]["temporary"] == "j1.42.77.tmp"
    assert races[0]["phase"] == "native" and isinstance(races[0]["observed_at"], float)


def test_unregistered_cache_artifact_is_not_silently_ignored(tmp_path: Path) -> None:
    fixture = _fixture()
    (tmp_path / "native-cache").mkdir()
    (tmp_path / "original-cache").mkdir()
    (tmp_path / "native-cache/not-a-cache.bin").touch()
    with pytest.raises(AssertionError):
        fixture["_capture"](str(tmp_path), Mock(), {}, [])


@pytest.mark.parametrize("name", ["sentinel.bin", "remote-script.ps1"])
@pytest.mark.parametrize("stage", ["final", "observations"])
@pytest.mark.parametrize(
    "field", ["body_base64", "security", "attributes", "mtime", "ctime"]
)
def test_protected_metadata_must_match_the_setup_baseline(
    name: str, stage: str, field: str
) -> None:
    capture = _capture()
    if stage == "final":
        closure = json.loads(capture["recovery"]["stdout"])
        states = [closure["recovery"]["state"]]
    else:
        states = [
            json.loads(row[key]["stdout"])
            for row in capture["records"][:2]
            for key in ("before", "after")
        ]
    for state in states:
        value = state["protected"][name]
        if field in ("security", "body_base64"):
            value[field] = base64.b64encode(b"different protected bytes").decode()
        else:
            value[field] += 1
    if stage == "final":
        capture["recovery"]["stdout"] = json.dumps(closure)
    else:
        for row, pair in zip(capture["records"][:2], (states[:2], states[2:])):
            for key, state in zip(("before", "after"), pair):
                row[key]["stdout"] = json.dumps(state)
    with pytest.raises(AssertionError):
        verify_capture(capture)


@pytest.mark.parametrize("value", [100.0, True, False, 0, -1, "100"])
def test_matching_invalid_watchdog_types_in_all_wrappers_are_rejected(
    value: object,
) -> None:
    capture = _capture()
    closure = json.loads(capture["recovery"]["stdout"])
    for row in capture["records"][:2]:
        job = closure["jobs"][row["result"]["ansible_job_id"]]
        invalid = (
            float(job["worker"]["identity"]["pid"])
            if isinstance(value, float)
            else value
        )
        row["result"]["ansible_async_watchdog_pid"] = invalid
        for name in ("startup", "completed"):
            body = job[name]["json"]
            body["ansible_async_watchdog_pid"] = invalid
            job[name] = _cache(body)
        job["pin"]["launch"]["ansible_async_watchdog_pid"] = invalid
        after = json.loads(row["after"]["stdout"])
        after["observed_jobs"][row["result"]["ansible_job_id"]] = deepcopy(job)
        row["after"]["stdout"] = json.dumps(after)
    capture["recovery"]["stdout"] = json.dumps(closure)
    with pytest.raises(AssertionError):
        verify_capture(capture)


def test_pin_launch_numeric_equality_cannot_hide_a_float_watchdog() -> None:
    capture = _capture()
    closure = json.loads(capture["recovery"]["stdout"])
    row = capture["records"][0]
    job = closure["jobs"][row["result"]["ansible_job_id"]]
    job["pin"]["launch"] = deepcopy(job["pin"]["launch"])
    job["pin"]["launch"]["ansible_async_watchdog_pid"] = float(
        job["worker"]["identity"]["pid"]
    )
    after = json.loads(row["after"]["stdout"])
    after["observed_jobs"][row["result"]["ansible_job_id"]] = deepcopy(job)
    row["after"]["stdout"] = json.dumps(after)
    capture["recovery"]["stdout"] = json.dumps(closure)
    with pytest.raises(AssertionError):
        verify_capture(capture)
