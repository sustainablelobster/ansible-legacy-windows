"""Check whole DSC automatic-poll results and observed cache/process lifetimes."""

# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import base64
import copy
import json
import math
import ntpath
import re
import sys
from pathlib import Path
from typing import Any, cast

# Direct CLI execution puts scripts/, not the repository, on the import path.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.verify_dsc3_capture import (  # pylint: disable=wrong-import-position
    _literal,
    _public,
    _state,
)

CASES = (
    "inline echo automatically polled",
    "remote echo automatically polled",
    "genuine engine failure automatically polled",
    "local file rejected before transfer and polling",
)


def _clock(value: object) -> float:
    assert isinstance(value, (int, float)) and not isinstance(value, bool)
    assert math.isfinite(value)
    return float(value)


def _closed(row: dict[str, Any]) -> None:
    expected, actual = row["expected"], row["actual"]
    assert isinstance(expected["pid"], int) and not isinstance(expected["pid"], bool)
    assert expected["pid"] > 0
    assert isinstance(expected["created"], int) and not isinstance(
        expected["created"], bool
    )
    assert expected["created"] > 0
    assert expected["alive"] is True
    assert not actual or actual["created"] != expected["created"] or not actual["alive"]


def _cache(value: dict[str, Any]) -> dict[str, Any]:
    decoded = json.loads(
        base64.b64decode(value["body_base64"], validate=True).decode("utf-8-sig")
    )
    assert _literal(decoded) == _literal(value["json"])
    assert isinstance(decoded, dict)
    return cast(dict[str, Any], decoded)


def _worker(
    record: dict[str, Any], job: dict[str, Any], launch: dict[str, Any], sid: str
) -> None:
    assert job["worker"]["sid"] == sid
    worker = job["worker"]["identity"]
    _closed({"expected": worker, "actual": None})
    assert worker["pid"] == launch["ansible_async_watchdog_pid"]
    start, end = _clock(record["before"]["utc"]), _clock(record["after"]["utc"])
    born = worker["created"] / 10000000 - 11644473600
    assert start <= born <= end
    assert start <= _clock(job["started_at"]) <= _clock(job["completed_at"]) <= end


def _public_job(
    record: dict[str, Any], job: dict[str, Any], root: str, sid: str
) -> dict[str, Any]:
    launch, completed = _cache(job["startup"]), _cache(job["completed"])
    result = copy.deepcopy(record["result"])
    identifier = result["ansible_job_id"]
    assert isinstance(identifier, str) and re.fullmatch(r"j[0-9]+\.[0-9]+", identifier)
    assert launch["started"] is True and launch["finished"] is False
    assert result["started"] is True and result["finished"] is True
    assert completed["finished"] is True
    _worker(record, job, launch, sid)
    for name in ("ansible_job_id", "ansible_async_watchdog_pid", "results_file"):
        assert (
            _literal(result[name])
            == _literal(launch[name])
            == _literal(completed[name])
        )
    assert launch["results_file"] == ntpath.join(root, "cache", identifier)
    for name, value in completed.items():
        if name not in ("invocation", "exception") and not name.startswith("_ansible_"):
            assert _literal(result[name]) == _literal(value), name
    for name in ("ansible_job_id", "ansible_async_watchdog_pid", "results_file"):
        del result[name]
    qualified = copy.deepcopy(record)
    qualified["result"] = result
    public, paths = _public(qualified)
    return {"public": public, "clock_paths": paths}


def _protection(observation: dict[str, Any], original: dict[str, Any]) -> None:
    assert set(original) == {"registry", "python_executable", "services", "network"}
    assert len(original["registry"]) == 4 and original["network"]
    assert re.fullmatch(r"[0-9a-f]{64}", original["python_executable"])
    assert original["services"]
    assert _literal(observation["original_protected"]) == _literal(original)
    current = observation["protected"]
    assert set(current) == set(original)
    for name in ("registry", "python_executable", "network"):
        assert _literal(current[name]) == _literal(original[name]), name
    # The maintained protection contract retains runtime states but compares
    # persistent service names/startup modes, not unrelated timer transitions.
    configurations = [
        [{key: value for key, value in row.items() if key != "State"} for row in rows]
        for rows in (original["services"], current["services"])
    ]
    assert _literal(configurations[0]) == _literal(configurations[1])


def _closure(capture: dict[str, Any]) -> dict[str, Any]:
    assert capture["workspace_removed"] is True
    guard = json.loads(capture["guard"]["stdout"])
    assert guard["python"] == [3, 4, 4] and "BC-24-11-3E-87-91" in guard["mac"].upper()
    assert _literal(guard["staging"]) == _literal(
        json.loads(capture["staging_after"]["stdout"])
    )
    recovery = capture["poll_recovery"]
    assert recovery["rc"] == 0
    closure = json.loads(recovery["stdout"])
    original = json.loads(capture["poll_setup"]["stdout"])["protected"]["protected"]
    for observation in (closure["before_cleanup"], closure["recovery"]):
        _protection(observation, original)
    _closed(
        {"expected": closure["monitor_identity"], "actual": closure["monitor_final"]}
    )
    assert _literal(closure["monitor_identity"]) == _literal(
        json.loads(capture["poll_setup"]["stdout"])["monitor"]
    )
    assert closure["recovery"]["restored"] is True
    assert closure["recovery"]["cache_after"] == closure["recovery"]["staging"] == []
    assert closure["recovery"]["engine_processes"] == []
    assert capture["recovery"]["rc"] == 0
    engine = json.loads(capture["recovery"]["stdout"])
    assert engine["restored"] is True and engine["final"]["key_present"] is False
    assert _literal(engine["original_keys"]) == _literal(engine["final_keys"])
    jobs = closure["jobs"]
    assert len(jobs) == len(closure["workers_closed"]) == 6
    for row in closure["workers_closed"]:
        _closed(row)
    assert {_literal(row["expected"]) for row in closure["workers_closed"]} == {
        _literal(job["worker"]["identity"]) for job in jobs.values()
    }
    return cast(dict[str, Any], jobs)


def _record(
    record: dict[str, Any],
    index: int,
    job: dict[str, Any] | None,
    capture: dict[str, Any],
) -> dict[str, Any]:
    assert record["case"] == CASES[index] and record["validated"] is True
    assert record["check_mode"] is False and record["local_rejection"] is (index == 3)
    assert _clock(record["before"]["utc"]) <= _clock(record["after"]["utc"])
    assert _literal(_state(record["before"])) == _literal(_state(record["after"]))
    assert record["observation"]["staging"] == []
    result = record["result"]
    if index == 3:
        assert "ansible_job_id" not in result and "rc" not in result
        public, paths = _public(record)
        assert public["failed"] is True and public["changed"] is False
        assert (
            public["msg"] == "async operations are not supported with local config_file"
        )
        return {"public": public, "clock_paths": paths}
    assert result["changed"] is False
    assert result["rc"] == (2 if index == 2 else 0)
    assert result.get("failed", False) is (index == 2)
    if index == 2:
        assert result["msg"] == "Resource error (ExitCode=2)"
    identifier = result["ansible_job_id"]
    assert identifier in record["observation"]["observed_jobs"]
    assert record["observation"]["jobs"] == []
    assert job is not None
    return _public_job(
        record, job, capture["workspace"], capture["identity"]["account"]["sid"]
    )


def verify_capture(capture: dict[str, Any]) -> dict[str, Any]:
    """Validate four strict pairs without mutating the capture or contacting Windows.

    :param capture: Raw maintained automatic-poll playbook observations.
    :returns: Exact pair, cache and independently observed birth counts.
    :raises AssertionError: If typed public fields, clocks or closure differ.
    """
    jobs, used = _closure(capture), set()
    records = capture["records"]
    assert len(records) == 8
    reports = []
    for index, case in enumerate(CASES):
        pair = records[index * 2 : index * 2 + 2]
        assert [row["phase"] for row in pair] == ["native", "original"]
        projected = []
        for row in pair:
            _protection(
                row["observation"],
                json.loads(capture["poll_setup"]["stdout"])["protected"]["protected"],
            )
            assert row["observation"]["jobs"] == []
            job = None
            if index != 3:
                identifier = row["result"]["ansible_job_id"]
                assert identifier not in used
                used.add(identifier)
                job = jobs[identifier]
            projected.append(_record(row, index, job, capture))
        assert _literal(pair[0]["request"]) == _literal(pair[1]["request"])
        for field in ("before", "after"):
            assert _literal(_state(pair[0][field])) == _literal(_state(pair[1][field]))
        assert _literal(projected[0]) == _literal(projected[1]), case
        reports.append(
            {
                "case": case,
                "clock_paths": projected[0]["clock_paths"],
                "allocated_fields": (
                    []
                    if index == 3
                    else [
                        "ansible_job_id",
                        "ansible_async_watchdog_pid",
                        "results_file",
                    ]
                ),
            }
        )
    assert used == set(jobs)
    return {"verified": True, "public_pairs": 4, "observed_jobs": 6, "cases": reports}


# This standalone verifier keeps its own literal result and cleanup gates.
# pylint: disable=duplicate-code
def main() -> None:
    """Validate one private raw capture without target access.

    :raises AssertionError: If any declared comparison or closure gate fails.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    args = parser.parse_args()
    print(
        json.dumps(
            verify_capture(json.loads(args.capture.read_text(encoding="utf-8"))),
            indent=2,
        )
    )


# pylint: enable=duplicate-code


if __name__ == "__main__":
    main()
