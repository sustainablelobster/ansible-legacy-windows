"""Validate complete typed Find pairs, bounded Wait elapsed values and recovery."""

# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import json
import math
from pathlib import Path
from typing import Any


def _same(left: Any, right: Any) -> None:
    assert type(left) is type(right), (type(left), type(right))
    if isinstance(left, dict):
        assert left.keys() == right.keys()
        for key, value in left.items():
            _same(value, right[key])
    elif isinstance(left, list):
        assert len(left) == len(right)
        for value, other in zip(left, right):
            _same(value, other)
    else:
        assert left == right, (left, right)


def _public(result: dict[str, Any]) -> dict[str, Any]:
    # Invocation echoes and controller traceback wrappers are diagnostic, not
    # module results. Every other field and the original arrays remain intact.
    return {
        key: value
        for key, value in result.items()
        if key not in ("invocation", "exception")
    }


def _timestamps(files: list[dict[str, Any]]) -> None:
    for row in files:
        for field in ("creationtime", "lastaccesstime", "lastwritetime"):
            value = row[field]
            if row["filename"] == "É.txt":
                _same(value % 1, 0.25)
            else:
                # Integral source timestamps are JSON integers, not floats.
                # pylint: disable-next=unidiomatic-typecheck
                assert type(value) is int


# This standalone verifier keeps its own literal result and cleanup gates.
# pylint: disable=duplicate-code
def verify(capture: dict[str, Any]) -> None:
    """Check a retained public capture without contacting Windows.

    :param capture: Literal complete fixture capture loaded from JSON.
    :raises AssertionError: Public parity, required cases or closure differ.
    """
    assert len(capture["find"]) == 18 and len(capture["wait"]) == 5
    cases: set[tuple[str, bool]] = set()
    for pair in capture["find"]:
        identity = pair["case"]["id"], pair["check"]
        assert identity not in cases
        # A numeric zero is not the captured JSON Boolean check-mode input.
        # pylint: disable-next=unidiomatic-typecheck
        assert type(pair["check"]) is bool
        cases.add(identity)
        native, source = _public(pair["native"]), _public(pair["source"])
        assert not native["failed"] and not source["failed"]
        _same(native, source)
        expected = pair["case"]["names"]
        assert native["matched"] == len(expected)
        # Expected membership is separate from the literal public-array compare.
        assert {row["filename"] for row in native["files"]} == set(expected)
        assert native["examined"] == 10 and native["changed"] is False
        _timestamps(native["files"])
    assert len({identity[0] for identity in cases}) == 9
    wait_cases: set[str] = set()
    for pair in capture["wait"]:
        assert pair["case"]["id"] not in wait_cases
        wait_cases.add(pair["case"]["id"])
        before, after = pair["before"], pair["after"]
        assert before["rc"] == after["rc"] == 0
        bound = float(after["stdout"]) - float(before["stdout"])
        assert math.isfinite(bound) and 0 < bound < 120
        native, source = _public(pair["native"]), _public(pair["source"])
        for result in (native, source):
            assert result["failed"] is False and result["changed"] is False
            # An integer would change the released elapsed field's JSON type.
            # pylint: disable-next=unidiomatic-typecheck
            assert type(result["elapsed"]) is float
            assert math.isfinite(result["elapsed"]) and 0 <= result["elapsed"] <= bound
            assert result["wait_attempts"] == 1
        # Only independently bounded elapsed differs; all keys/types are kept
        # in the raw capture and all remaining public fields compare literally.
        native.pop("elapsed")
        source.pop("elapsed")
        _same(native, source)
    prepared = json.loads(capture["prepare"]["stdout"])
    cleanup = capture["cleanup"]
    assert cleanup["rc"] == 0 and cleanup["failed"] is False
    recovered = json.loads(cleanup["stdout"])
    assert recovered["absent"] is True
    _same(prepared, recovered["before"])
    _same(
        json.loads(capture["staging_before"]["stdout"]),
        json.loads(capture["staging_after"]["stdout"]),
    )


# pylint: enable=duplicate-code


# This standalone verifier keeps its own literal result and cleanup gates.
# pylint: disable=duplicate-code
def main() -> None:
    """Verify one explicit capture with the standalone development interpreter."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    arguments = parser.parse_args()
    verify(json.loads(arguments.capture.read_text(encoding="utf-8")))
    print(
        "PASS:18 complete typed Find pairs,5 bounded Wait pairs and literal owned closure"
    )


# pylint: enable=duplicate-code


if __name__ == "__main__":
    main()
