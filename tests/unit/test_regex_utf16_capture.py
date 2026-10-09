"""Reject false ordinary UTF16 parity and recovery claims without host contact."""

# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

# Development uses PyYAML without optional stubs; the verifier checks its inputs.
import yaml  # type: ignore[import-untyped]

from scripts import verify_regex_utf16_capture as verifier
from tests.unit.test_regex_selection_legacy_capture import _capture as category_capture


def _capture() -> dict[str, Any]:
    cases = yaml.safe_load(
        (verifier.ROOT / "tests/integration/vars/regex_utf16.yml").read_text(
            encoding="utf-8"
        )
    )
    find = []
    for case in cases["regex_utf16_find_cases"]:
        result = {
            "failed": False,
            "changed": False,
            "examined": 10,
            "matched": len(case["names"]),
            "files": [
                {
                    "filename": name,
                    "creationtime": 100.25 if name == "É.txt" else 100,
                    "lastaccesstime": 100.25 if name == "É.txt" else 100,
                    "lastwritetime": 100.25 if name == "É.txt" else 100,
                }
                for name in case["names"]
            ],
        }
        # This workflow keeps an independent fixture and expected-result oracle.
        # pylint: disable=duplicate-code
        for check in (False, True):
            find.append(
                {
                    "case": case,
                    "check": check,
                    "native": copy.deepcopy(result),
                    "source": copy.deepcopy(result),
                }
            )
        # pylint: enable=duplicate-code
    waits = []
    for case in cases["regex_utf16_wait_cases"]:
        result = {"failed": False, "changed": False, "wait_attempts": 1, "elapsed": 0.0}
        waits.append(
            {
                "case": case,
                "before": {"rc": 0, "stdout": "100.0"},
                "after": {"rc": 0, "stdout": "101.0"},
                "native": copy.deepcopy(result),
                "source": copy.deepcopy(result),
            }
        )
    journal = {
        "root": "owned",
        "files": {"data": [1, 2], "attributes": 32, "mtime": 100},
    }
    return {
        "find": find,
        "wait": waits,
        "prepare": {"stdout": json.dumps(journal)},
        "cleanup": {
            "rc": 0,
            "failed": False,
            "stdout": json.dumps({"absent": True, "before": journal}),
        },
        "staging_before": {"stdout": "[]"},
        "staging_after": {"stdout": "[]"},
    }


def test_valid_capture_is_not_mutated() -> None:
    capture = _capture()
    before = copy.deepcopy(capture)
    verifier.verify(capture)
    assert capture == before


def test_standalone_script_works_outside_checkout(tmp_path: Path) -> None:
    capture = tmp_path / "capture.json"
    capture.write_text(json.dumps(_capture()), encoding="utf-8")
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    result = subprocess.run(
        [sys.executable, str(Path(verifier.__file__).resolve()), str(capture)],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    # pylint: enable=duplicate-code
    assert result.stdout.startswith("PASS:4 typed ordinary UTF16 Find pairs")


@pytest.mark.parametrize("field", ["find", "wait"])
def test_incomplete_cohort_fails(field: str) -> None:
    capture = _capture()
    capture[field].pop()
    with pytest.raises(AssertionError):
        verifier.verify(capture)


def test_matching_duplicate_find_files_fail() -> None:
    capture = _capture()
    for side in ("native", "source"):
        files = capture["find"][0][side]["files"]
        files[-1] = copy.deepcopy(files[0])
    with pytest.raises(AssertionError):
        verifier.verify(capture)


@pytest.mark.parametrize("elapsed", [False, 0, 1.001, float("inf"), float("nan")])
def test_wait_elapsed_type_and_independent_bound_fail(elapsed: Any) -> None:
    capture = _capture()
    for side in ("native", "source"):
        capture["wait"][0][side]["elapsed"] = elapsed
    with pytest.raises(AssertionError):
        verifier.verify(capture)


@pytest.mark.parametrize(
    "before,after",
    [(False, True), (100, 101), ("nan", "101"), ("100", "inf"), ("101", "100")],
)
def test_independent_clock_types_values_and_order_fail(before: Any, after: Any) -> None:
    capture = _capture()
    capture["wait"][0]["before"]["stdout"] = before
    capture["wait"][0]["after"]["stdout"] = after
    with pytest.raises(AssertionError):
        verifier.verify(capture)


def test_different_ordered_public_files_fail() -> None:
    capture = _capture()
    capture["find"][0]["source"]["files"].reverse()
    with pytest.raises(AssertionError):
        verifier.verify(capture)


@pytest.mark.parametrize("value", [0, 1, "false"])
def test_check_mode_must_be_literal_boolean(value: Any) -> None:
    capture = _capture()
    capture["find"][0]["check"] = value
    with pytest.raises(AssertionError):
        verifier.verify(capture)


def test_missing_owned_absence_fails() -> None:
    capture = _capture()
    recovered = json.loads(capture["cleanup"]["stdout"])
    recovered["absent"] = False
    capture["cleanup"]["stdout"] = json.dumps(recovered)
    with pytest.raises(AssertionError):
        verifier.verify(capture)


def test_changed_protected_journal_fails() -> None:
    capture = _capture()
    recovered = json.loads(capture["cleanup"]["stdout"])
    recovered["before"]["files"]["attributes"] = 0
    capture["cleanup"]["stdout"] = json.dumps(recovered)
    with pytest.raises(AssertionError):
        verifier.verify(capture)


def test_changed_global_staging_fails() -> None:
    capture = _capture()
    capture["staging_after"]["stdout"] = '["unclosed"]'
    with pytest.raises(AssertionError):
        verifier.verify(capture)


def _legacy_capture() -> dict[str, Any]:
    capture = category_capture([5, 1])
    cases = yaml.safe_load(
        (verifier.ROOT / "tests/integration/vars/regex_utf16.yml").read_text(
            encoding="utf-8"
        )
    )
    files = {
        row["filename"]: row
        for result in capture["find"]["results"]
        for row in result["files"]
    }
    prototype = capture["find"]["results"][0]
    capture["find_cases"] = cases["regex_utf16_find_cases"]
    capture["find"]["results"] = []
    for case in capture["find_cases"]:
        for check in (False, True):
            result = copy.deepcopy(prototype)
            result["item"] = [case, check]
            result["files"] = [copy.deepcopy(files[name]) for name in case["names"]]
            result["matched"] = len(result["files"])
            capture["find"]["results"].append(result)
    capture["wait_cases"] = cases["regex_utf16_wait_cases"]
    capture["wait"]["results"] = capture["wait"]["results"][:2]
    for result, case in zip(capture["wait"]["results"], capture["wait_cases"]):
        result["item"] = case
    return capture


def test_legacy_availability_preserves_literal_fractional_timestamps() -> None:
    capture = _legacy_capture()
    before = copy.deepcopy(capture)
    verifier.verify(capture)
    assert capture == before


@pytest.mark.parametrize(
    "fault", ["identity", "input", "duplicate", "normal-check", "elapsed", "closure"]
)
def test_legacy_false_availability_is_rejected(fault: str) -> None:
    capture = _legacy_capture()
    if fault == "identity":
        capture["expected_windows"] = [5, 2]
    elif fault == "input":
        capture["find"]["results"][0]["item"] = [{}, False]
    elif fault == "duplicate":
        files = capture["find"]["results"][0]["files"]
        files[-1] = copy.deepcopy(files[0])
    elif fault == "normal-check":
        capture["find"]["results"][1]["files"][0]["owner"] = "other"
    elif fault == "elapsed":
        capture["wait"]["results"][0]["elapsed"] = 1000.0
    else:
        capture["staging_after"]["stdout"] = '["unclosed"]'
    with pytest.raises(AssertionError):
        verifier.verify(capture)
