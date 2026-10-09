"""Verify complete async WUA public results from retained target observations."""

# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import base64
import json
import ntpath
import re
from copy import deepcopy
from pathlib import Path
from typing import Any


def _same(left: Any, right: Any) -> None:
    assert type(left) is type(right)
    if isinstance(left, dict):
        assert set(left) == set(right)
        for name, value in left.items():
            _same(value, right[name])
    elif isinstance(left, list):
        assert len(left) == len(right)
        for native, source in zip(left, right):
            _same(native, source)
    else:
        assert left == right


# JSON Booleans and floats are not native PIDs, birth times or poll counters.
# pylint: disable=unidiomatic-typecheck
def _public(record: dict[str, Any], phase: str, completed: bool) -> dict[str, Any]:
    launch = record[f"{phase}_launch"]
    identity = json.loads(record[f"{phase}_identity"]["stdout"])
    _same(identity["launch"], launch)
    identifier, pid = launch["ansible_job_id"], launch["ansible_async_watchdog_pid"]
    assert type(identifier) is str and re.fullmatch(r"j[0-9]+\.[0-9]+", identifier)
    assert type(pid) is int and pid > 0
    if identity["worker"] is not None:
        observed = identity["worker"]
        assert observed["pid"] == pid and type(observed["pid"]) is int
        assert type(observed["created"]) is int and observed["created"] > 0
        assert observed["alive"] is True
    result: dict[str, Any] = record[f"{phase}_{'status' if completed else 'launch'}"]
    assert result["ansible_job_id"] == identifier
    assert type(result["ansible_async_watchdog_pid"]) is int
    assert result["ansible_async_watchdog_pid"] == pid
    assert result["started"] is True and result["finished"] is completed
    assert result["results_file"] == launch["results_file"]
    workspace = record.get(f"{phase}_workspace", record.get("workspace"))
    assert type(workspace) is str and workspace
    directory = ntpath.join(workspace, "cache")
    assert ntpath.normcase(ntpath.dirname(result["results_file"])) == ntpath.normcase(
        directory
    )
    assert ntpath.basename(result["results_file"]) == identifier
    output = deepcopy(result)
    output["ansible_job_id"] = "<validated allocated job>"
    output["results_file"] = "<validated owned cache path>"
    output["ansible_async_watchdog_pid"] = "<validated watchdog PID>"
    if "attempts" in output:
        assert type(output["attempts"]) is int and 1 <= output["attempts"] <= 30
        output["attempts"] = "<bounded explicit polling counter>"
    for wrapper in ("invocation", "exception"):
        output.pop(wrapper, None)
    return output


# pylint: enable=unidiomatic-typecheck


def compare_record(record: dict[str, Any]) -> None:
    """Compare a whole public pair and its retained native cache observations.

    :param record: Complete native/released launch, status and target observations.
    :raises AssertionError: A field/type/order differs or ownership is unproven.
    """
    _same(_public(record, "native", False), _public(record, "original", False))
    _same(_public(record, "native", True), _public(record, "original", True))
    for phase in ("native", "original"):
        separate = f"{phase}_observation" in record
        observed = json.loads(
            record[f"{phase}_observation" if separate else "observation"]["stdout"]
        )
        cache = observed["cache_records"]
        expected = (phase,) if separate else ("native", "original")
        assert set(cache) == {
            record[f"{name}_launch"]["ansible_job_id"] for name in expected
        }
        launch = record[f"{phase}_launch"]
        row = cache[launch["ansible_job_id"]]
        body = json.loads(base64.b64decode(row["body_base64"]).decode("utf-8-sig"))
        _same(body, row["json"])
        assert body["finished"] is True
        assert body["ansible_job_id"] == launch["ansible_job_id"]
        assert (
            body["ansible_async_watchdog_pid"] == launch["ansible_async_watchdog_pid"]
        )
        for name, value in body.items():
            if name not in ("invocation", "exception") and not name.startswith(
                "_ansible_"
            ):
                _same(value, record[f"{phase}_status"][name])


def verify_capture(path: Path, last_only: bool = False) -> dict[str, int]:
    """Read complete pairs without changing their raw values or target state.

    :param path: Private capture produced by the async WUA integration playbook.
    :param last_only: Compare only the most recently retained complete pair.
    :returns: Number of validated complete public pairs.
    :raises AssertionError: Any public or ownership observation is invalid.
    """
    records = json.loads(path.read_text(encoding="utf-8"))["results"]
    assert records
    if last_only:
        records = records[-1:]
    for record in records:
        compare_record(record)
    return {"pairs": len(records)}


def compare_phases(
    native_path: Path,
    original_path: Path,
    public_only: bool = False,
    original_closure_path: Path | None = None,
) -> dict[str, int]:
    """Compare independently restored servicing phases without altering either.

    :param native_path: Complete retained native operation and owned observations.
    :param original_path: Identical released request from the restored baseline.
    :param public_only: Explicitly report public parity without claiming cache closure.
    :param original_closure_path: Separate birth-pinned completed-source recovery.
    :returns: Number of validated whole public servicing pairs.
    """
    native = json.loads(native_path.read_text(encoding="utf-8"))
    original = json.loads(original_path.read_text(encoding="utf-8"))
    assert not (public_only and original_closure_path)
    closure = (
        json.loads(original_closure_path.read_text(encoding="utf-8"))
        if original_closure_path
        else None
    )
    if closure is not None:
        _same(closure["original_capture"], original)
        _same(closure["workspace"], original["workspace"])
        assert closure["workspace_absent"] is True
        assert closure["process"]["rc"] == 0
        recovery = json.loads(closure["process"]["stdout"])
        assert recovery["pinned_process_exit_confirmed"] is True
        assert recovery["after"]["holders"] == []
        assert recovery["after"]["processes"] == []
    assert native["phase"] == "native" and original["phase"] == "original"
    _same(native["state"], original["state"])
    _same(native["kb"], original["kb"])
    record = {}
    for name, phase in (("native", native), ("original", original)):
        assert phase["worker_absence"]["rc"] == 0
        if not public_only:
            assert phase["recovery"]["rc"] == 0
            assert json.loads(phase["recovery"]["stdout"])["restored"] is True
            recovered = closure if name == "original" and closure is not None else phase
            assert recovered["workspace_absent"] is True
            _same(
                json.loads(phase["global_before"]["stdout"]),
                json.loads(recovered["global_after"]["stdout"]),
            )
        for field in ("workspace", "launch", "status", "identity", "observation"):
            record[f"{name}_{field}"] = phase[field]
    if public_only:
        _same(_public(record, "native", False), _public(record, "original", False))
        _same(_public(record, "native", True), _public(record, "original", True))
        return {"public_pairs": 1, "owned_cache_pairs": 0}
    compare_record(record)
    return {"pairs": 1}


def main() -> None:
    """Validate retained pairs and report their count."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--last", action="store_true")
    parser.add_argument("--original", type=Path)
    parser.add_argument("--public-only", action="store_true")
    parser.add_argument("--original-closure", type=Path)
    args = parser.parse_args()
    result = (
        compare_phases(
            args.capture, args.original, args.public_only, args.original_closure
        )
        if args.original
        else verify_capture(args.capture, args.last)
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
