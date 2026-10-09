"""Compare public script results while bounding generated information clocks."""

# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import base64
import calendar
import json
import ntpath
import re
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any

_UTC = re.compile(r"(?P<date>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(?P<subsecond>\d+)Z")


# JSON booleans/floats must not satisfy native PID, birth or counter contracts.
# pylint: disable=unidiomatic-typecheck
def _async_chain(pin: dict[str, Any], launch: dict[str, Any]) -> None:
    assert pin["launch"] == launch
    chain = pin["chain"]
    assert chain and chain[0]["process"]["Name"].lower() == "powershell.exe"
    assert chain[-1]["identity"]["pid"] == launch["ansible_async_watchdog_pid"]
    for item in chain:
        identity = item["identity"]
        assert type(identity["created"]) is int and identity["created"] > 0
        assert identity["alive"] is True
        assert identity["pid"] == item["process"]["ProcessId"]
    for child, parent in zip(chain, chain[1:]):
        assert child["process"]["ParentProcessId"] == parent["identity"]["pid"]
        assert child["identity"]["created"] >= parent["identity"]["created"]


def _async_public(
    result: dict[str, Any], record: dict[str, Any], phase: str, completed: bool
) -> dict[str, Any]:
    launch = record[f"launch_{phase}"]
    identifier = launch["ansible_job_id"]
    assert type(identifier) is str and re.fullmatch(r"j[0-9]+\.[0-9]+", identifier)
    assert type(launch["ansible_async_watchdog_pid"]) is int
    assert launch["ansible_async_watchdog_pid"] > 0
    _async_chain(json.loads(record[f"pin_{phase}"]["stdout"]), launch)
    assert (
        type(result["ansible_job_id"]) is str and result["ansible_job_id"] == identifier
    )
    assert type(result["ansible_async_watchdog_pid"]) is int
    assert result["ansible_async_watchdog_pid"] == launch["ansible_async_watchdog_pid"]
    assert type(result["results_file"]) is str
    assert result["results_file"] == launch["results_file"]
    assert result["started"] is True and result["finished"] is completed
    directory = ntpath.join(record["workspace"], phase + "-cache")
    assert ntpath.normcase(ntpath.dirname(result["results_file"])) == ntpath.normcase(
        directory
    )
    assert ntpath.basename(result["results_file"]) == identifier
    output = deepcopy(result)
    output["ansible_job_id"] = "<validated allocated job identifier>"
    output["ansible_async_watchdog_pid"] = "<live birth-journaled watchdog PID>"
    output["results_file"] = "<validated owned job cache path>"
    if "attempts" in output:
        assert type(output["attempts"]) is int and 1 <= output["attempts"] <= 120
        output["attempts"] = "<independently bounded polling counter>"
    for wrapper in ("invocation", "exception"):
        output.pop(wrapper, None)
    return output


# pylint: enable=unidiomatic-typecheck


def _ticks(value: str, precision: int) -> int:
    assert isinstance(value, str)
    match = _UTC.fullmatch(value)
    assert match and len(match["subsecond"]) == precision, value
    date = datetime.strptime(match["date"], "%Y-%m-%dT%H:%M:%S")
    return calendar.timegm(date.timetuple()) * 10_000_000 + int(
        match["subsecond"].ljust(7, "0")
    )


def _public(record: dict[str, Any], phase: str) -> tuple[dict[str, Any], int]:
    result = deepcopy(
        {
            key: value
            for key, value in record[phase].items()
            if key not in {"invocation", "exception"}
        }
    )
    if "information" not in result:
        return result, 0
    information = result["information"]
    assert isinstance(information, list), information
    for item in information:
        assert isinstance(item, dict) and set(item) == {
            "message_data",
            "source",
            "tags",
            "time_generated",
        }, item
        assert isinstance(item["source"], str)
        assert isinstance(item["tags"], list) and all(
            isinstance(tag, str) for tag in item["tags"]
        )
        timestamp = _ticks(item["time_generated"], 7)
        before = json.loads(record[f"before_{phase}"]["stdout"])["utc"]
        after = json.loads(record[f"after_{phase}"]["stdout"])["utc"]
        assert _ticks(before, 6) <= timestamp <= _ticks(after, 6), (
            phase,
            before,
            item,
            after,
        )
        item["time_generated"] = "<independently bounded UTC timestamp>"
    return result, len(information)


def _effects(record: dict[str, Any]) -> None:
    stable_outputs: list[dict[str, Any] | None] = []
    protected = None
    for phase in ("native", "original"):
        before = json.loads(record[f"before_{phase}"]["stdout"])
        after = json.loads(record[f"after_{phase}"]["stdout"])
        assert before["protected"] == after["protected"]
        assert before["environment"] == after["environment"]
        assert before["python"] == after["python"]
        if protected is None:
            protected = before["protected"]
        assert before["protected"] == protected
        assert set(before["output"]) == set(after["output"]) == {"output.txt"}
        if not record["case"].get("changed", False):
            assert before["output"] == after["output"], phase
        output = after["output"]["output.txt"]
        if "output" not in record["case"]:
            assert output is None, phase
            stable_outputs.append(None)
            continue
        assert isinstance(output, dict) and set(output) == {
            "attributes",
            "body_base64",
            "ctime",
            "directory",
            "mtime",
            "security",
        }, output
        assert output["directory"] is False
        expected = base64.b64encode(record["case"]["output"].encode("utf-8"))
        assert output["body_base64"] == expected.decode("ascii"), phase
        # Independent calls create or write this owned file at different times.
        # Retain both clocks; compare them exactly above for unchanged cases.
        stable_outputs.append(
            {
                key: value
                for key, value in output.items()
                if key not in {"ctime", "mtime"}
            }
        )
    assert stable_outputs[0] == stable_outputs[1]


def compare_record(record: dict[str, Any]) -> int:
    """Compare field presence/types/values, bounding only generated clocks.

    :param record: Native/source results and each call's target UTC observations.
    :returns: Number of independently bounded generated information timestamps.
    :raises AssertionError: A public value differs or a timestamp is unbounded.
    """
    _effects(record)
    native, native_clocks = _public(record, "native")
    original, original_clocks = _public(record, "original")
    if "launch_native" in record:
        native = _async_public(native, record, "native", True)
        original = _async_public(original, record, "original", True)
        launch_native = _async_public(record["launch_native"], record, "native", False)
        launch_original = _async_public(
            record["launch_original"], record, "original", False
        )
        assert json.dumps(launch_native, sort_keys=True) == json.dumps(
            launch_original, sort_keys=True
        ), (record["case"]["name"], launch_native, launch_original)
    assert json.dumps(native, sort_keys=True) == json.dumps(original, sort_keys=True), (
        record["case"]["name"],
        native,
        original,
    )
    assert native_clocks == original_clocks
    return native_clocks + original_clocks


def verify_capture(path: Path, last_only: bool = False) -> dict[str, int]:
    """Read and compare retained pairs without modifying their raw evidence.

    :param path: Maintained integration fixture's JSON capture.
    :param last_only: Verify just the newest retained pair before marking valid.
    :returns: Compared-pair and bounded-clock counts.
    :raises AssertionError: A result differs from its source counterpart.
    """
    records = json.loads(path.read_text(encoding="utf-8"))["results"]
    assert records
    if last_only:
        records = records[-1:]
    return {
        "pairs": len(records),
        "bounded_clocks": sum(compare_record(row) for row in records),
    }


def main() -> None:
    """Verify a capture and print comparable-pair and bounded-clock counts."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--last", action="store_true")
    args = parser.parse_args()
    print(json.dumps(verify_capture(args.capture, args.last), sort_keys=True))


if __name__ == "__main__":
    main()
