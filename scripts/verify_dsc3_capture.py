"""Compare complete DSC observations with operation-bounded clock evidence."""

# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import base64
import copy
import datetime
import json
import ntpath
import re
from pathlib import Path
from typing import Any, cast


def _duration(value: object) -> float:
    assert isinstance(value, str)
    match = re.fullmatch(r"PT([0-9]+(?:\.[0-9]+)?)S", value)
    assert match is not None, value
    return float(match[1])


def _literal(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def _state(observation: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in observation.items() if key != "utc"}


def _diagnostics(result: dict[str, Any], record: dict[str, Any]) -> list[str]:
    qualified = []
    lines = result.get("stderr", "").splitlines(keepends=True)
    for index, line in enumerate(lines):
        match = re.match(
            r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z) "
            r"(?:ERROR|WARN|INFO|DEBUG|TRACE) ",
            line,
        )
        if match is None:
            continue
        timestamp = datetime.datetime.fromisoformat(match[1]).timestamp()
        assert record["before"]["utc"] <= timestamp <= record["after"]["utc"]
        lines[index] = "<operation-clock>" + line[len(match[1]) :]
        qualified.append(f"stderr line {index} trace timestamp")
    if qualified:
        assert result["stderr_lines"] == result["stderr"].splitlines()
        result["stderr"] = "".join(lines)
        result["stderr_lines"] = result["stderr"].splitlines()
    return qualified


def _async_metadata(
    result: dict[str, Any],
    record: dict[str, Any],
    *,
    completed: bool,
    cache_directory: str | None,
) -> list[str]:
    launch = record["launch"]
    job_id = launch["ansible_job_id"]
    assert isinstance(job_id, str) and re.fullmatch(r"j[0-9]+\.[0-9]+", job_id)
    assert launch["started"] is True and launch["finished"] is False
    assert launch["changed"] is False
    pid = launch["ansible_async_watchdog_pid"]
    assert type(pid) is int and pid > 0  # pylint: disable=unidiomatic-typecheck
    assert cache_directory is not None
    assert launch["results_file"] == ntpath.join(cache_directory, job_id)
    assert result["started"] is True and result["finished"] is completed
    # Exact JSON types matter here: bool must not satisfy an integer PID.
    # pylint: disable=unidiomatic-typecheck
    for field in ("ansible_job_id", "results_file", "ansible_async_watchdog_pid"):
        assert (
            type(result[field]) is type(launch[field])
            and result[field] == launch[field]
        )
        del result[field]
    qualified = [
        "async." + field
        for field in ("ansible_job_id", "results_file", "ansible_async_watchdog_pid")
    ]
    if "attempts" in result:
        assert type(result["attempts"]) is int and 1 <= result["attempts"] <= 30
        del result["attempts"]
        qualified.append("async.attempts")
    # pylint: enable=unidiomatic-typecheck
    return qualified


def _launch_public(record: dict[str, Any], cache_directory: str) -> dict[str, Any]:
    result = cast(dict[str, Any], copy.deepcopy(record["launch"]))
    for field in ("invocation", "exception"):
        result.pop(field, None)
    _async_metadata(result, record, completed=False, cache_directory=cache_directory)
    return result


def _public(
    record: dict[str, Any], cache_directory: str | None = None
) -> tuple[dict[str, Any], list[str]]:
    result = copy.deepcopy(record["result"])
    for field in ("invocation", "exception"):
        result.pop(field, None)
    qualified: list[str] = (
        _async_metadata(result, record, completed=True, cache_directory=cache_directory)
        if "launch" in record
        else []
    )
    qualified.extend(_diagnostics(result, record))
    document = result.get("result")
    if document is None:
        return result, qualified
    metadata = document["metadata"]["Microsoft.DSC"]
    start = datetime.datetime.fromisoformat(metadata["startDatetime"]).timestamp()
    end = datetime.datetime.fromisoformat(metadata["endDatetime"]).timestamp()
    duration = _duration(metadata["duration"])
    assert record["before"]["utc"] <= start <= end <= record["after"]["utc"]
    # datetime truncates the engine's nanoseconds to microseconds, not whole seconds.
    assert abs(end - start - duration) <= 0.000002
    for name in ("startDatetime", "endDatetime", "duration"):
        del metadata[name]
        qualified.append("result.metadata.Microsoft.DSC." + name)
    for index, resource in enumerate(document["results"]):
        resource_metadata = resource["metadata"]["Microsoft.DSC"]
        assert 0 <= _duration(resource_metadata["duration"]) <= duration
        del resource_metadata["duration"]
        qualified.append(f"result.results[{index}].metadata.Microsoft.DSC.duration")
    return result, qualified


def _async_closure(capture: dict[str, Any]) -> None:
    recovery = capture["async_recovery"]
    assert recovery["rc"] == 0
    closure = json.loads(recovery["stdout"])
    assert closure["restored"] is True
    assert closure["cache_after"] == closure["staging"] == []
    assert closure["engine_processes"] == []
    records = capture["records"]
    launches = {
        record["launch"]["ansible_job_id"]: record["launch"]
        for record in records
        if "launch" in record
    }
    assert len(launches) == sum("launch" in record for record in records)
    assert len(closure["jobs"]) == len(launches)
    assert {job["name"] for job in closure["jobs"]} == set(launches)
    for job in closure["jobs"]:
        cached = job["cache"]["json"]
        assert _literal(
            json.loads(
                base64.b64decode(job["cache"]["body_base64"]).decode("utf-8-sig")
            )
        ) == _literal(cached)
        assert cached["finished"] is True
        assert cached["ansible_job_id"] == job["name"]
        assert _literal(cached["ansible_async_watchdog_pid"]) == _literal(
            launches[job["name"]]["ansible_async_watchdog_pid"]
        )
        assert job["process"] is None or not job["process"]["alive"]


def _case_report(case: str, paths: list[str]) -> dict[str, Any]:
    report: dict[str, Any] = {
        "case": case,
        "qualified_clock_paths": [
            path for path in paths if not path.startswith("async.")
        ],
    }
    async_paths = [path for path in paths if path.startswith("async.")]
    if async_paths:
        report["qualified_async_paths"] = async_paths
    return report


def verify_capture(capture: dict[str, Any], *, paired: bool) -> dict[str, Any]:
    """Compare public results with measured clocks and optional async identities.

    :param capture: Raw maintained integration-playbook capture.
    :param paired: Whether every native request must have an original counterpart.
    :returns: Verified cases and exact clock/allocated-async qualification paths.
    :raises AssertionError: If cleanup, clocks, values or JSON types differ.
    """
    assert capture["workspace_removed"] is True
    recovery = capture["recovery"]
    assert recovery["rc"] == 0
    closure = json.loads(recovery["stdout"])
    assert closure["restored"] is True
    assert _literal(closure["original_keys"]) == _literal(closure["final_keys"])
    assert closure["final"]["key_present"] is False
    assert json.loads(capture["staging_before"]["stdout"]) == json.loads(
        capture["staging_after"]["stdout"]
    )
    records = capture["records"]
    assert records
    cache_directory = None
    if "async_recovery" in capture:
        _async_closure(capture)
        cache_directory = ntpath.join(capture["workspace"], "cache")
    reports = []
    previous: dict[str, Any] = {}
    for record in records:
        assert record["validated"] is True
        assert record["before"]["utc"] <= record["after"]["utc"]
        public, paths = _public(record, cache_directory)
        if record["check_mode"] or public.get("failed"):
            assert _literal(_state(record["before"])) == _literal(
                _state(record["after"])
            )
        if record["phase"] == "original":
            assert previous and previous["phase"] == "native"
            assert previous["case"] == record["case"]
            assert _literal(previous["request"]) == _literal(record["request"])
            assert ("launch" in previous) == ("launch" in record)
            if "launch" in record:
                assert cache_directory is not None
                assert _literal(_launch_public(previous, cache_directory)) == _literal(
                    _launch_public(record, cache_directory)
                ), (record["case"], "async launch")
            previous_public, previous_paths = _public(previous, cache_directory)
            assert paths == previous_paths
            assert _literal(previous_public) == _literal(public), record["case"]
            for side in ("before", "after"):
                assert _literal(_state(previous[side])) == _literal(
                    _state(record[side])
                ), (record["case"], side)
            reports.append(_case_report(record["case"], paths))
        else:
            assert record["phase"] == "native"
            if paired and previous:
                assert previous["phase"] == "original"
            if not paired:
                reports.append(_case_report(record["case"], paths))
        previous = record
    if paired:
        assert previous["phase"] == "original"
        assert len(reports) * 2 == len(records)
    return {"verified": True, "paired": paired, "cases": reports}


def main() -> None:
    """Validate one raw capture without contacting a guest.

    :raises AssertionError: If raw recovery or public comparisons fail.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--paired", action="store_true")
    args = parser.parse_args()
    capture = json.loads(args.capture.read_text(encoding="utf-8"))
    print(json.dumps(verify_capture(capture, paired=args.paired), indent=2))


if __name__ == "__main__":
    main()
