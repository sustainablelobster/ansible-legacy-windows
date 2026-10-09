"""Verify the bounded ordinary UTF16 public comparisons and literal closure."""

# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import json
import math
import ntpath
import sys
from pathlib import Path
from typing import Any

# Development uses PyYAML without optional stubs; loaded values are checked below.
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[1]

# Direct script execution puts scripts/, not the checkout root, on sys.path.
# The existing typed comparison helpers remain the single local contract.
sys.path.insert(0, str(ROOT))
# The legacy journal has local-wall timestamps and a complete native file schema.
# This import also requires the standalone checkout path initialized above.
# pylint: disable-next=wrong-import-position
from scripts import verify_regex_selection_legacy_capture as legacy
from scripts.verify_regex_selection_capture import (  # pylint: disable=wrong-import-position
    _public,
    _same,
    _timestamps,
)


def _clock_bound(before: dict[str, Any], after: dict[str, Any]) -> float:
    for clock in (before, after):
        _same(clock["rc"], 0)
        assert isinstance(clock["stdout"], str)
        assert math.isfinite(float(clock["stdout"]))
    bound = float(after["stdout"]) - float(before["stdout"])
    assert math.isfinite(bound) and 0 < bound < 120
    return bound


# This standalone verifier keeps its own literal result and cleanup gates.
# pylint: disable=duplicate-code
def _wait_pairs(capture: dict[str, Any], wait_cases: list[dict[str, Any]]) -> None:
    assert len(capture["wait"]) == len(wait_cases) == 2
    for pair, case in zip(capture["wait"], wait_cases):
        _same(pair["case"], case)
        bound = _clock_bound(pair["before"], pair["after"])
        native, source = _public(pair["native"]), _public(pair["source"])
        for result in (native, source):
            assert result["failed"] is False and result["changed"] is False
            elapsed = result.pop("elapsed")
            # The released field is a JSON float even when its value is zero.
            # pylint: disable-next=unidiomatic-typecheck
            assert type(elapsed) is float
            assert math.isfinite(elapsed) and 0 <= elapsed <= bound
            assert result["wait_attempts"] == 1
        _same(native, source)


# pylint: enable=duplicate-code


# This standalone verifier keeps its own literal result and cleanup gates.
# pylint: disable=duplicate-code
def _closure(capture: dict[str, Any]) -> None:
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
def _legacy_find(capture: dict[str, Any], cases: list[dict[str, Any]]) -> None:
    _same(capture["find_cases"], cases)
    expected = [(case, check) for case in cases for check in (False, True)]
    results = capture["find"]["results"]
    assert len(results) == len(expected) == 4
    prepared = json.loads(capture["prepare"]["stdout"])
    for index, (result, (case, check)) in enumerate(zip(results, expected)):
        _same(result["item"], [case, check])
        assert result["ansible_loop_var"] == "item"
        # Reuse the accepted private checks rather than duplicating their schema.
        legacy._successful(result)  # pylint: disable=protected-access
        _same(result["examined"], 10)
        _same(result["matched"], len(case["names"]))
        rows = result["files"]
        assert len(rows) == len(case["names"])
        assert sorted(row["filename"] for row in rows) == sorted(case["names"])
        # This accepted check preserves actual legacy local-wall fractions.
        legacy._timestamps(rows, prepared)  # pylint: disable=protected-access
        for row in rows:
            # The accepted check validates the complete native file schema.
            legacy._file_types(row)  # pylint: disable=protected-access
            name = row["filename"]
            _same(row["path"], ntpath.join(prepared["root"], "files", name))
            _same(row["size"], len(prepared["files"][name]["bytes"]))
            assert row["exists"] is True and row["isreg"] is True
        if check:
            normal = _public(results[index - 1])
            checked = _public(result)
            normal.pop("item")
            checked.pop("item")
            _same(normal, checked)


# pylint: enable=duplicate-code


def _legacy_wait(capture: dict[str, Any], cases: list[dict[str, Any]]) -> None:
    _same(capture["wait_cases"], cases)
    results = capture["wait"]["results"]
    assert len(results) == len(cases) == 2
    bound = _clock_bound(capture["clock_before"], capture["clock_after"])
    for result, case in zip(results, cases):
        _same(result["item"], case)
        assert result["ansible_loop_var"] == "item"
        # The accepted success check is shared with the earlier legacy cohort.
        legacy._successful(result)  # pylint: disable=protected-access
        _same(result["wait_attempts"], 1)
        elapsed = result["elapsed"]
        # Preserve the released float field rather than coercing JSON integers.
        # pylint: disable-next=unidiomatic-typecheck
        assert type(elapsed) is float
        assert math.isfinite(elapsed) and 0 <= elapsed <= bound


def _legacy(capture: dict[str, Any], cases: dict[str, Any]) -> None:
    before, after = capture["before"], capture["after"]
    assert before["rc"] == after["rc"] == capture["prepare"]["rc"] == 0
    identity = json.loads(before["stdout"])
    _same(identity, json.loads(after["stdout"]))
    _same(identity["python"], [3, 4, 4])
    _same(identity["bits"], 32)
    assert capture["expected_windows"] in ([5, 1], [5, 2])
    _same(identity["windows"], capture["expected_windows"])
    assert capture["expected_mac"] in [
        row["MACAddress"] for row in identity["protected"]["network"]
    ]
    prepared = json.loads(capture["prepare"]["stdout"])
    _same(prepared["root"], capture["workspace"]["path"])
    _legacy_find(capture, cases["regex_utf16_find_cases"])
    _legacy_wait(capture, cases["regex_utf16_wait_cases"])
    _closure(capture)


def verify(capture: dict[str, Any]) -> None:
    """Validate four complete Find pairs and two independently timed Wait pairs.

    :param capture: Literal capture from the existing journal-owned fixture.
    :raises AssertionError: Inputs, typed results, memberships or closure differ.
    """
    cases = yaml.safe_load(
        (ROOT / "tests/integration/vars/regex_utf16.yml").read_text(encoding="utf-8")
    )
    if capture.get("mode") == "legacy-native":
        _legacy(capture, cases)
        return
    expected = [
        (case, check)
        for case in cases["regex_utf16_find_cases"]
        for check in (False, True)
    ]
    assert len(capture["find"]) == len(expected) == 4
    # This standalone verifier keeps its own literal result and cleanup gates.
    # pylint: disable=duplicate-code
    for pair, (case, check) in zip(capture["find"], expected):
        _same(pair["case"], case)
        _same(pair["check"], check)
        native, source = _public(pair["native"]), _public(pair["source"])
        _same(native, source)
        assert native["failed"] is False and native["changed"] is False
        assert native["examined"] == 10
        assert native["matched"] == len(native["files"]) == len(case["names"])
        assert sorted(row["filename"] for row in native["files"]) == sorted(
            case["names"]
        )
        _timestamps(native["files"])
    # pylint: enable=duplicate-code
    _wait_pairs(capture, cases["regex_utf16_wait_cases"])
    _closure(capture)


def main() -> None:
    """Validate one retained fixture capture without contacting Windows."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    arguments = parser.parse_args()
    capture = json.loads(arguments.capture.read_text(encoding="utf-8"))
    verify(capture)
    if capture.get("mode") == "legacy-native":
        print("PASS:4 native UTF16 Find requests,2 Wait requests and legacy closure")
    else:
        print(
            "PASS:4 typed ordinary UTF16 Find pairs,2 bounded Wait pairs and literal closure"
        )


if __name__ == "__main__":
    main()
