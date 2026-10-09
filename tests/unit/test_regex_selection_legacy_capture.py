"""Find faults in native-only legacy input binding and retained evidence gates."""

# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
import ntpath
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]
from ansible._internal._datatag import _tags  # type: ignore[import-untyped]
from ansible.template import Templar  # type: ignore[import-untyped]

from scripts.verify_regex_selection_legacy_capture import _cases as expected_cases
from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="verifier")
def capture_verifier() -> ModuleType:
    """Load the real development verifier without contacting Windows.

    :returns: The standalone verifier with its accepted sibling comparisons.
    """
    return load_module(
        ROOT / "scripts/verify_regex_selection_legacy_capture.py",
        "legacy_regex_verifier",
    )


def _capture(version: list[int]) -> dict[str, Any]:
    find, wait = expected_cases()
    root = r"C:\owned\legacy-windows-regex-selection-unit"
    names = {name for case in find for name in case["names"]}
    baseline = {
        "root": root,
        "nonce": "literal-nonce",
        "phase": "prepared",
        "files": {
            name: {
                "bytes": [1],
                "attributes": 32,
                "mtime": 1477984205 + (0.25 if name == "É.txt" else 0),
            }
            for name in names
        },
        "texts": {case["file"]: {"bytes": [1]} for case in wait},
        "sentinel": {"bytes": [0, 255]},
    }
    rows = []
    for case in find:
        for check in (False, True):
            files = []
            for name in case["names"]:
                stamp = 1477984205 + (0.25 if name == "É.txt" else 0)
                # This workflow keeps an independent fixture and expected-result oracle.
                # pylint: disable=duplicate-code
                files.append(
                    {
                        "path": ntpath.join(root, "files", name),
                        "filename": name,
                        "attributes": "Archive",
                        "owner": r"LEGACY\Administrator",
                        "exists": True,
                        "isarchive": True,
                        "isdir": False,
                        "ishidden": False,
                        "isreadonly": False,
                        "isreg": True,
                        "islnk": False,
                        "isjunction": False,
                        "isshared": False,
                        "sharename": None,
                        "extension": ".txt",
                        "size": 1,
                        "checksum": None,
                        "nlink": 1,
                        "hlnk_targets": [],
                        "lnk_source": None,
                        "lnk_target": None,
                        "creationtime": stamp,
                        "lastaccesstime": 1791075560.953125,
                        "lastwritetime": stamp,
                    }
                )
                # pylint: enable=duplicate-code
            rows.append(
                {
                    "item": [copy.deepcopy(case), check],
                    "ansible_loop_var": "item",
                    "failed": False,
                    "changed": False,
                    "examined": 10,
                    "matched": len(files),
                    "files": files,
                }
            )
    identity = {
        "python": [3, 4, 4],
        "windows": version,
        "bits": 32,
        "protected": {
            "network": [{"MACAddress": "owned-mac"}],
            "registry": [],
            "python_executable": "literal-hash",
            "services": [],
        },
    }
    return {
        "mode": "legacy-native",
        "expected_windows": version,
        "expected_mac": "owned-mac",
        "find_cases": find,
        "wait_cases": wait,
        "before": {"rc": 0, "stdout": json.dumps(identity)},
        "after": {"rc": 0, "stdout": json.dumps(identity)},
        "workspace": {"path": root},
        "prepare": {"rc": 0, "stdout": json.dumps(baseline)},
        "find": {"results": rows},
        "wait": {
            "results": [
                {
                    "item": case,
                    "ansible_loop_var": "item",
                    "failed": False,
                    "changed": False,
                    "wait_attempts": 1,
                    "elapsed": 0.0,
                }
                for case in wait
            ]
        },
        "clock_before": {"rc": 0, "stdout": "1.0"},
        "clock_after": {"rc": 0, "stdout": "5.0"},
        "cleanup": {
            "rc": 0,
            "failed": False,
            "stdout": json.dumps({"before": baseline, "absent": True}),
        },
        "staging_before": {"stdout": "[]"},
        "staging_after": {"stdout": "[]"},
    }


@pytest.mark.parametrize("version", [[5, 1], [5, 2]])
def test_complete_native_capture_is_checked_without_rewriting(
    verifier: ModuleType, version: list[int]
) -> None:
    capture = _capture(version)
    before = json.dumps(capture)
    verifier.verify(capture)
    assert json.dumps(capture) == before


@pytest.mark.parametrize("access", [1477984205, 1791075560.953125])
def test_legacy_access_timestamps_need_not_retain_the_seed(
    verifier: ModuleType, access: int | float
) -> None:
    capture = _capture([5, 1])
    for result in capture["find"]["results"]:
        for row in result["files"]:
            row["lastaccesstime"] = access
    before = json.dumps(capture)
    verifier.verify(capture)
    assert json.dumps(capture) == before


@pytest.mark.parametrize("access", [1477984205.0, True, float("nan"), "1477984205"])
def test_invalid_access_timestamp_types_are_not_normalized(
    verifier: ModuleType, access: Any
) -> None:
    capture = _capture([5, 1])
    for result in capture["find"]["results"]:
        for row in result["files"]:
            row["lastaccesstime"] = access
    with pytest.raises(AssertionError):
        verifier.verify(capture)


def test_duplicate_file_rows_in_both_halves_are_rejected(
    verifier: ModuleType,
) -> None:
    capture = _capture([5, 1])
    for result in capture["find"]["results"][:2]:
        result["files"].append(copy.deepcopy(result["files"][0]))
    normal = capture["find"]["results"][0]
    checked = capture["find"]["results"][1]
    assert normal["files"] == checked["files"]
    assert {row["filename"] for row in normal["files"]} == set(
        capture["find_cases"][0]["names"]
    )
    with pytest.raises(AssertionError):
        verifier.verify(capture)


@pytest.mark.parametrize(
    "fault",
    [
        "mode",
        "case",
        "case-membership",
        "duplicate",
        "missing-request",
        "failed",
        "changed",
        "normal-check",
        "array-order",
        "wait-input",
        "wait-failure",
    ],
)
def test_faulty_public_inputs_and_results_are_rejected(
    verifier: ModuleType, fault: str
) -> None:
    capture = _capture([5, 1])
    first = capture["find"]["results"][0]
    checked = capture["find"]["results"][1]
    if fault == "mode":
        capture["mode"] = "paired"
    elif fault == "case":
        first["item"][0]["pattern"] = "not the actual category input"
    elif fault == "case-membership":
        capture["find_cases"][0]["names"].append("foreign.txt")
    elif fault == "duplicate":
        capture["find"]["results"][2:4] = copy.deepcopy(capture["find"]["results"][:2])
    elif fault == "missing-request":
        capture["find"]["results"].pop()
    elif fault in ("failed", "changed"):
        first[fault] = True
    elif fault == "normal-check":
        checked["files"][0]["owner"] = "other owner"
    elif fault == "array-order":
        checked["files"].reverse()
    elif fault == "wait-input":
        capture["wait"]["results"][0]["item"] = {}
    else:
        assert fault == "wait-failure"
        capture["wait"]["results"][0]["failed"] = True
    with pytest.raises((AssertionError, KeyError)):
        verifier.verify(capture)


@pytest.mark.parametrize(
    "fault",
    [
        "check-type",
        "count-type",
        "missing-property",
        "file-type",
        "whole-time",
        "fractional-time",
        "elapsed-type",
        "elapsed-nan",
        "clock",
    ],
)
def test_json_types_and_clock_bounds_are_checked(
    verifier: ModuleType, fault: str
) -> None:
    capture = _capture([5, 1])
    first = capture["find"]["results"][0]
    if fault == "check-type":
        first["item"][1] = 0
    elif fault == "count-type":
        first["examined"] = 10.0
    elif fault == "missing-property":
        first["files"][0].pop("owner")
    elif fault == "file-type":
        first["files"][0]["nlink"] = True
    elif fault == "whole-time":
        first["files"][0]["creationtime"] = float(first["files"][0]["creationtime"])
    elif fault == "fractional-time":
        next(row for row in first["files"] if row["filename"] == "É.txt")[
            "creationtime"
        ] = 1477984205
    elif fault == "elapsed-type":
        capture["wait"]["results"][0]["elapsed"] = 0
    elif fault == "elapsed-nan":
        capture["wait"]["results"][0]["elapsed"] = float("nan")
    else:
        assert fault == "clock"
        capture["clock_after"]["stdout"] = "0.0"
    with pytest.raises((AssertionError, KeyError)):
        verifier.verify(capture)


@pytest.mark.parametrize(
    "fault", ["version", "mac", "protected", "sentinel", "cleanup", "staging"]
)
def test_runtime_and_literal_protected_recovery_are_checked(
    verifier: ModuleType, fault: str
) -> None:
    capture = _capture([5, 2])
    if fault in ("version", "mac", "protected"):
        after = json.loads(capture["after"]["stdout"])
        if fault == "version":
            after["windows"] = [10, 0]
        elif fault == "mac":
            after["protected"]["network"][0]["MACAddress"] = "other"
        else:
            after["protected"]["python_executable"] = "changed"
        capture["after"]["stdout"] = json.dumps(after)
    elif fault in ("sentinel", "cleanup"):
        recovery = json.loads(capture["cleanup"]["stdout"])
        if fault == "sentinel":
            recovery["before"]["sentinel"]["bytes"] = [1]
        else:
            recovery["absent"] = False
        capture["cleanup"]["stdout"] = json.dumps(recovery)
    else:
        capture["staging_after"]["stdout"] = '["foreign"]'
    with pytest.raises((AssertionError, KeyError)):
        verifier.verify(capture)


def test_standalone_cli_works_from_outside_checkout(tmp_path: Path) -> None:
    capture = tmp_path / "capture.json"
    capture.write_text(json.dumps(_capture([5, 2])), encoding="utf-8")
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/verify_regex_selection_legacy_capture.py"),
            str(capture),
        ],
        cwd=tmp_path,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "20 typed native Find" in result.stdout


def _render(value: Any, templar: Templar) -> Any:
    if isinstance(value, str):
        return templar.template(_tags.TrustedAsTemplate().tag(value))
    if isinstance(value, list):
        return [_render(item, templar) for item in value]
    if isinstance(value, dict):
        return {key: _render(item, templar) for key, item in value.items()}
    return value


def test_controller_effective_bindings_before_any_guest_execution() -> None:
    play = yaml.safe_load(
        (ROOT / "tests/integration/regex_selection_legacy.yml").read_text()
    )[0]
    assert play["gather_facts"] is False and play["hosts"] == "legacy_windows"
    variables = yaml.safe_load(
        (ROOT / "tests/integration/vars/regex_selection.yml").read_text()
    )
    templar = Templar(variables=variables)
    variables["regex_legacy_caret_case"] = _render(
        play["vars"]["regex_legacy_caret_case"], templar
    )
    templar = Templar(variables=variables)
    cases = _render(play["vars"]["regex_legacy_find_cases"], templar)
    assert cases == expected_cases()[0]
    variables["regex_legacy_find_cases"] = cases
    variables["regex_legacy_workspace"] = {"path": r"C:\owned"}
    block = next(task for task in play["tasks"] if "block" in task)
    find = next(
        task for task in block["block"] if task.get("register") == "regex_legacy_find"
    )
    loop = _render(find["loop"], Templar(variables=variables))
    assert len(loop) == 20
    for case, check in loop:
        current = Templar(
            variables=dict(
                variables, item=[case, check], regex_legacy_find={"registered": True}
            )
        )
        args = _render(find["sustainablelobster.legacy_windows.win_find"], current)
        assert args == {
            "paths": r"C:\owned\files",
            "patterns": [case["pattern"]],
            "use_regex": True,
            "recurse": False,
            "get_checksum": False,
            "case_sensitive": case.get("sensitive", False),
        }
        assert _render(find["check_mode"], current) is check
        assert _render(find["loop"], current) == loop
    wait = next(
        task for task in block["block"] if task.get("register") == "regex_legacy_wait"
    )
    for case in _render(wait["loop"], Templar(variables=variables)):
        args = _render(
            wait["sustainablelobster.legacy_windows.win_wait_for"],
            Templar(variables=dict(variables, item=case)),
        )
        assert args == {
            "path": ntpath.join(r"C:\owned", case["file"]),
            "regex": case["pattern"],
            "state": case["state"],
            "timeout": 3,
        }
    text = (ROOT / "tests/integration/regex_selection_legacy.yml").read_text()
    assert "ansible.windows." not in text and "async:" not in text
    variables["playbook_dir"] = str(ROOT / "tests/integration")
    gate = play["tasks"][-1]["ansible.builtin.command"]["argv"][1]
    assert Path(_render(gate, Templar(variables=variables))).resolve() == (
        ROOT / "scripts/verify_regex_selection_legacy_capture.py"
    )
