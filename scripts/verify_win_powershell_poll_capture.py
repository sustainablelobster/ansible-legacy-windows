"""Verify four automatic PowerShell pairs and observed owned-cache lifetimes."""

# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import base64
import json
import math
import ntpath
import re
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

# Standalone CLI execution starts in scripts/, not the repository root.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# The existing verifier owns script effects and information-clock projection.
# pylint: disable-next=wrong-import-position
from scripts.verify_win_powershell_capture import _async_chain, compare_record

CASES = (
    "Structured inline output automatically polled",
    "Controller UTF8 file automatically polled",
    "Supported ShouldProcess preview remains nonmutating",
    "Genuine engine failure automatically polled",
)
ALLOCATED = ("ansible_job_id", "ansible_async_watchdog_pid", "results_file")


def _literal(value: Any) -> str:
    return json.dumps(value, sort_keys=True, allow_nan=False)


def _clock(value: Any) -> float:
    assert isinstance(value, (int, float)) and not isinstance(value, bool)
    assert math.isfinite(value)
    return float(value)


def _identity(value: dict[str, Any]) -> tuple[int, int]:
    for name in ("pid", "created"):
        assert isinstance(value[name], int) and not isinstance(value[name], bool)
        assert value[name] > 0
    assert value["alive"] is True
    return value["pid"], value["created"]


def _cache(value: dict[str, Any]) -> dict[str, Any]:
    assert set(value) == {"body_base64", "json"}
    decoded = json.loads(
        base64.b64decode(value["body_base64"], validate=True).decode("utf-8-sig")
    )
    assert isinstance(decoded, dict) and _literal(decoded) == _literal(value["json"])
    return decoded


def _protected(
    state: dict[str, Any], original: dict[str, Any], files: dict[str, Any]
) -> None:
    assert _literal(state["protected"]) == _literal(files)
    assert _literal(state["original_machine"]) == _literal(original)
    assert set(original) == {"registry", "network", "python_executable", "services"}
    assert len(original["registry"]) == 4 and original["network"]
    assert re.fullmatch(r"[0-9a-f]{64}", original["python_executable"])
    assert original["services"]
    current = state["machine"]
    for name in ("registry", "network", "python_executable"):
        assert _literal(current[name]) == _literal(original[name])
    # Keep runtime states in the raw record. The accepted observer compares
    # persistent names/startup modes, not unrelated Windows timer transitions.
    configurations = [
        [{name: row[name] for name in ("Name", "StartMode")} for row in rows]
        for rows in (original["services"], current["services"])
    ]
    assert _literal(configurations[0]) == _literal(configurations[1])
    assert set(state["protected"]) == {"sentinel.bin", "remote-script.ps1"}
    for value in state["protected"].values():
        assert set(value) == {
            "attributes",
            "security",
            "mtime",
            "ctime",
            "directory",
            "body_base64",
        }
        assert value["directory"] is False
        assert isinstance(value["attributes"], int) and not isinstance(
            value["attributes"], bool
        )
        assert value["attributes"] >= 0 and not value["attributes"] & 0x400
        for name in ("security", "body_base64"):
            assert base64.b64decode(value[name], validate=True)
        _clock(value["mtime"])
        _clock(value["ctime"])


def _closed(processes: list[dict[str, Any]]) -> set[tuple[int, int]]:
    identities = set()
    for row in processes:
        identities.add(_identity(row["expected"]))
        actual = row["actual"]
        if actual:
            assert actual["pid"] == row["expected"]["pid"]
            for name in ("pid", "created"):
                assert isinstance(actual[name], int) and not isinstance(
                    actual[name], bool
                )
                assert actual[name] > 0
            assert isinstance(actual["alive"], bool)
        assert (
            not actual
            or actual["created"] != row["expected"]["created"]
            or actual["alive"] is False
        )
    return identities


def _job_window(row: dict[str, Any], job: dict[str, Any]) -> None:
    before, after = (json.loads(row[name]["stdout"]) for name in ("before", "after"))
    start, finish = _clock(before["epoch"]), _clock(after["epoch"])
    assert start <= finish and math.isfinite(finish - start)
    _, birth = _identity(job["worker"]["identity"])
    assert start <= birth / 10_000_000 - 11_644_473_600 <= finish
    assert start <= _clock(job["started_at"]) <= _clock(job["completed_at"]) <= finish


def _public_job(
    row: dict[str, Any], job: dict[str, Any], root: str, sid: str
) -> dict[str, Any]:
    _job_window(row, job)
    startup, completed = _cache(job["startup"]), _cache(job["completed"])
    assert startup["started"] is True and startup["finished"] is False
    assert completed["started"] is True and completed["finished"] is True
    result: dict[str, Any] = deepcopy(row["result"])
    assert result["started"] is True and result["finished"] is True
    identifier = result["ansible_job_id"]
    assert isinstance(identifier, str) and re.fullmatch(r"j[0-9]+\.[0-9]+", identifier)
    assert job["name"] == f'{row["index"]}-{row["phase"]}'
    assert job["phase"] == row["phase"]
    assert job["worker"]["sid"] == sid
    pid, _ = _identity(job["worker"]["identity"])
    for wrapper in (startup, completed, result, job["pin"]["launch"]):
        watchdog = wrapper["ansible_async_watchdog_pid"]
        assert isinstance(watchdog, int) and not isinstance(watchdog, bool)
        assert watchdog > 0
    assert pid == startup["ansible_async_watchdog_pid"]
    assert _literal(job["pin"]["launch"]) == _literal(startup)
    _async_chain(job["pin"], startup)
    for item in job["pin"]["chain"]:
        assert item["sid"] == sid
        _identity(item["identity"])
    for name in ALLOCATED:
        assert (
            _literal(result[name])
            == _literal(startup[name])
            == _literal(completed[name])
        )
    assert result["results_file"] == ntpath.join(
        root, row["phase"] + "-cache", identifier
    )
    for name, value in completed.items():
        if name not in ("invocation", "exception") and not name.startswith("_ansible_"):
            assert _literal(result[name]) == _literal(value), name
    for name in ALLOCATED:
        del result[name]
    return result


def _closure(capture: dict[str, Any]) -> dict[str, Any]:
    assert capture["workspace_absent"] is True
    assert capture["finalized"]["rc"] == 0
    assert json.loads(capture["finalized"]["stdout"]) == {"finalized": True}
    guard = json.loads(capture["guard"]["stdout"])
    assert guard["python"] == [3, 4, 4]
    assert "BC-24-11-9D-0E-6F" in guard["mac"].upper()
    assert capture["staging_after"]["rc"] == 0
    assert _literal(guard["staging"]) == _literal(
        json.loads(capture["staging_after"]["stdout"])
    )
    assert capture["setup"]["rc"] == capture["recovery"]["rc"] == 0
    setup = json.loads(capture["setup"]["stdout"])
    closure: dict[str, Any] = json.loads(capture["recovery"]["stdout"])
    sid = capture["identity"]["account"]["sid"]
    assert isinstance(sid, str) and sid.startswith("S-1-")
    assert _literal(closure["monitor"]) == _literal(setup["monitor"])
    assert closure["monitor"]["sid"] == sid
    assert closure["monitor_ready"] == {
        "identity": setup["monitor"]["identity"],
        "sid": sid,
    }
    assert re.fullmatch(r"[0-9a-f]{64}", setup["monitor_sha256"])
    recovery = closure["recovery"]
    assert recovery["restored"] is True
    state = recovery["state"]
    assert state["cache"] == {"native": {}, "original": {}}
    assert state["staging"] == state["engine_scratch"] == []
    original = setup["protected"]["machine"]
    _protected(state, original, setup["protected"]["protected"])
    assert _identity(setup["monitor"]["identity"]) in _closed(state["processes"])
    return closure


def _phase(
    row: dict[str, Any], index: int, job: dict[str, Any], capture: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    assert row["case"]["name"] == CASES[index] and row["index"] == index
    assert row["validated"] is True and row["check_mode"] is (index == 2)
    assert row["result"]["changed"] is (index == 2)
    assert row["result"].get("failed", False) is (index == 3)
    request: dict[str, Any] = deepcopy(row["request"])
    for name, suffix in (("MarkerPath", ".pid"), ("ReleasePath", ".release")):
        assert request["parameters"][name] == (
            capture["workspace"] + f'/owned-jobs/{index}-{row["phase"]}{suffix}'
        )
        del request["parameters"][name]
    baseline = json.loads(capture["setup"]["stdout"])["protected"]
    for name in ("before", "after"):
        observation = json.loads(row[name]["stdout"])
        _protected(observation, baseline["machine"], baseline["protected"])
        assert observation["output"] == {"output.txt": None}
        assert observation["cache"] == {"native": {}, "original": {}}
        assert observation["staging"] == observation["engine_scratch"] == []
    observed = json.loads(row["after"]["stdout"])["observed_jobs"]
    assert _literal(observed[row["result"]["ansible_job_id"]]) == _literal(job)
    public = _public_job(
        row, job, capture["workspace"], capture["identity"]["account"]["sid"]
    )
    if index == 2:
        assert public["result"] == {"check": True}
    elif index == 0:
        assert _literal(public["result"]) == _literal(
            {"nested": {"rows": [1, None, "λ"], "yes": True}, "number": 2.5}
        )
        assert public["output"] == [
            [{"name": "one", "count": 1}, {"name": "two", "count": 2}]
        ]
        assert len(public["information"]) == 1
        assert public["information"][0]["message_data"] == {"label": "information λ"}
        assert public["information"][0]["tags"] == ["first", "second"]
    elif index == 1:
        assert public["result"] == {
            "text": "controller parameter λ",
            "path": "",
            "root": "",
        }
        assert public["output"] == ["file λ"]
    else:
        assert public["output"] == ["before λ"] and public["result"] == {}
        assert len(public["error"]) == 1
        assert public["error"][0]["exception"]["message"] == "async failure λ"
    return public, request


def _pair(
    pair: list[dict[str, Any]],
    index: int,
    capture: dict[str, Any],
    jobs: dict[str, Any],
) -> int:
    assert [row["phase"] for row in pair] == ["native", "original"]
    projected: dict[str, Any] = {"case": pair[0]["case"]}
    requests = []
    for row in pair:
        public, request = _phase(
            row, index, jobs[row["result"]["ansible_job_id"]], capture
        )
        projected[row["phase"]] = public
        projected[f'before_{row["phase"]}'] = row["before"]
        projected[f'after_{row["phase"]}'] = row["after"]
        requests.append(request)
    assert _literal(requests[0]) == _literal(requests[1])
    return compare_record(projected)


def verify_capture(capture: dict[str, Any]) -> dict[str, int]:
    """Validate typed public parity and literal owned-resource recovery.

    :param capture: Complete retained automatic-poll playbook capture.
    :returns: Compared pairs, observed caches and information-clock counts.
    :raises AssertionError: If a public field, live identity or closure differs.
    """
    closure = _closure(capture)
    jobs = closure["jobs"]
    assert len(jobs) == 8 and len(capture["records"]) == 8
    identifiers = [row["result"]["ansible_job_id"] for row in capture["records"]]
    assert len(set(identifiers)) == 8 and set(identifiers) == set(jobs)
    assert len({_identity(job["worker"]["identity"]) for job in jobs.values()}) == 8
    expected_closed = {_identity(closure["monitor"]["identity"])}
    expected_closed.update(
        _identity(item["identity"])
        for job in jobs.values()
        for item in job["pin"]["chain"]
    )
    assert len(closure["recovery"]["state"]["processes"]) == 1 + sum(
        len(job["pin"]["chain"]) for job in jobs.values()
    )
    assert _closed(closure["recovery"]["state"]["processes"]) == expected_closed
    clocks = sum(
        _pair(capture["records"][index * 2 : index * 2 + 2], index, capture, jobs)
        for index in range(4)
    )
    return {"public_pairs": 4, "observed_jobs": 8, "bounded_information_clocks": clocks}


def main() -> None:
    """Validate a private retained capture without contacting Windows."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    args = parser.parse_args()
    print(
        json.dumps(
            verify_capture(json.loads(args.capture.read_text(encoding="utf-8"))),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
