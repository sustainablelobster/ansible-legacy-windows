"""Check shorthand fixture binding, the accepted journal and retained gates."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import copy
import importlib.util
import json
import ntpath
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

# Nix provides the maintained Ansible binding and PyYAML without typing stubs.
import yaml  # type: ignore[import-untyped]

from scripts import verify_regex_shorthand_capture as verifier
from tests.unit.test_regex_selection_legacy_capture import _capture as legacy_capture

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(name="fixture")
def shorthand_fixture() -> ModuleType:
    """Load only the target input constants; never execute Windows functions.

    :returns: The isolated target fixture with unexecuted journal procedures.
    """
    spec = importlib.util.spec_from_file_location(
        "tested_shorthand_fixture",
        ROOT / "tests/integration/fixtures/regex_shorthand.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_shorthand_fixture_reuses_the_accepted_journal(
    fixture: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed = []
    monkeypatch.setattr(fixture, "REGEX_FIXTURE_SOURCE", "", raising=False)
    original = "def main():\n    CALLBACK(FILES, TEXT)\n"

    # Execute the fixture's only delegation with an independent callback.
    def execute(source: str, scope: dict[str, object]) -> None:
        assert source == original
        scope["CALLBACK"] = lambda files, text: observed.append((files, text))
        # Exercise the delegation's real namespace behavior using inert source.
        # pylint: disable-next=exec-used
        exec(source, scope)

    monkeypatch.setattr(fixture, "REGEX_FIXTURE_SOURCE", original)
    monkeypatch.setattr(fixture, "exec", execute, raising=False)
    fixture.main()
    assert observed == [(fixture.FILES, fixture.TEXT)]


def test_shorthand_files_are_inert_and_cover_the_selected_differences(
    fixture: ModuleType,
) -> None:
    assert len(fixture.FILES) == len(set(fixture.FILES)) == 12
    assert all(name.endswith(".txt") and "/" not in name for name in fixture.FILES)
    assert {
        "a\u0301.txt",
        "a\u203f.txt",
        "\u08b3.txt",
        "\u0de6.txt",
        "a\u200c.txt",
    } <= set(fixture.FILES)
    assert fixture.TEXT["control.txt"] == "\u001c"


def test_public_wrapper_reuses_only_the_existing_lifecycle() -> None:
    plays = yaml.safe_load(
        (ROOT / "tests/integration/regex_shorthand.yml").read_text(encoding="utf-8")
    )
    assert plays[-1]["ansible.builtin.import_playbook"] == "regex_selection.yml"
    fixture_source = (ROOT / "tests/integration/fixtures/regex_shorthand.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(fixture_source)
    names = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
    assert names == {"main"}
    cases = yaml.safe_load(
        (ROOT / "tests/integration/vars/regex_shorthand.yml").read_text(
            encoding="utf-8"
        )
    )
    assert len(cases["regex_shorthand_find_cases"]) == 8
    assert len(cases["regex_shorthand_wait_cases"]) == 5
    program = cases["regex_shorthand_fixture"]
    assert "b64encode" in program and ".decode('utf-8')" in program


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def _capture(fixture: ModuleType) -> dict[str, Any]:
    cases = yaml.safe_load(
        (ROOT / "tests/integration/vars/regex_shorthand.yml").read_text(
            encoding="utf-8"
        )
    )
    root = r"C:\owned\legacy-windows-regex-selection-unit"
    template = legacy_capture([5, 1])["find"]["results"][0]["files"][0]
    journal = {"root": root, "files": {name: {"bytes": [1]} for name in fixture.FILES}}
    find = []
    for case in cases["regex_shorthand_find_cases"]:
        files = []
        for name in case["names"]:
            entry = copy.deepcopy(template)
            entry.update(path=ntpath.join(root, "files", name), filename=name)
            for field in ("creationtime", "lastaccesstime", "lastwritetime"):
                entry[field] = 100.25 if name == "É.txt" else 100
            files.append(entry)
        result = {
            "files": files,
            "matched": len(files),
            "examined": 12,
            "changed": False,
            "failed": False,
        }
        for check in (False, True):
            find.append(
                {
                    "case": case,
                    "check": check,
                    "native": copy.deepcopy(result),
                    "source": copy.deepcopy(result),
                }
            )
    wait = []
    for case in cases["regex_shorthand_wait_cases"]:
        result = {"failed": False, "changed": False, "wait_attempts": 1, "elapsed": 0.0}
        wait.append(
            {
                "case": case,
                "native": copy.deepcopy(result),
                "source": copy.deepcopy(result),
                "before": {"rc": 0, "stdout": "1.0"},
                "after": {"rc": 0, "stdout": "2.0"},
            }
        )
    return {
        "find": find,
        "wait": wait,
        "workspace": {"path": root},
        "prepare": {"rc": 0, "stdout": json.dumps(journal)},
        "cleanup": {
            "rc": 0,
            "failed": False,
            "stdout": json.dumps({"absent": True, "before": journal}),
        },
        "staging_before": {"stdout": "[]"},
        "staging_after": {"stdout": "[]"},
    }


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def test_capture_verifier_preserves_valid_typed_results(fixture: ModuleType) -> None:
    capture = _capture(fixture)
    before = copy.deepcopy(capture)
    verifier.verify(capture)
    assert capture == before


# pylint: enable=duplicate-code


def test_standalone_capture_command_has_no_pythonpath_requirement(
    fixture: ModuleType, tmp_path: Path
) -> None:
    capture = tmp_path / "capture.json"
    capture.write_text(json.dumps(_capture(fixture)), encoding="utf-8")
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
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
    assert result.stdout.startswith("PASS:16 typed shorthand Find pairs")


@pytest.mark.parametrize(
    "fault", ["duplicate", "owner", "timestamp", "public", "normal-check"]
)
def test_paired_false_find_claims_fail(fixture: ModuleType, fault: str) -> None:
    capture = _capture(fixture)
    for side in ("native", "source"):
        result = capture["find"][0][side]
        if fault == "duplicate":
            result["files"].append(copy.deepcopy(result["files"][0]))
        elif fault == "owner":
            del result["files"][0]["owner"]
        elif fault == "timestamp":
            result["files"][0]["creationtime"] = 100.0
        elif fault == "public":
            result["examined"] = True
        else:
            capture["find"][1][side]["files"].reverse()
    with pytest.raises(AssertionError):
        verifier.verify(capture)


@pytest.mark.parametrize("field", ["find", "wait"])
def test_partial_cohorts_fail(fixture: ModuleType, field: str) -> None:
    capture = _capture(fixture)
    capture[field].pop()
    with pytest.raises(AssertionError):
        verifier.verify(capture)


@pytest.mark.parametrize("elapsed", [True, 0, float("inf"), float("nan"), -0.5, 2.0])
def test_paired_invalid_wait_elapsed_fails(fixture: ModuleType, elapsed: Any) -> None:
    capture = _capture(fixture)
    for side in ("native", "source"):
        capture["wait"][0][side]["elapsed"] = elapsed
    with pytest.raises(AssertionError):
        verifier.verify(capture)


@pytest.mark.parametrize("fault", ["absent", "protected", "staging", "clock"])
def test_owned_recovery_and_independent_clock_gates_fail(
    fixture: ModuleType, fault: str
) -> None:
    capture = _capture(fixture)
    recovered = json.loads(capture["cleanup"]["stdout"])
    if fault == "absent":
        recovered["absent"] = False
    elif fault == "protected":
        recovered["before"]["files"]["a.txt"]["bytes"].append(2)
    elif fault == "staging":
        capture["staging_after"]["stdout"] = '["unexpected"]'
    else:
        capture["wait"][0]["after"]["stdout"] = "nan"
    capture["cleanup"]["stdout"] = json.dumps(recovered)
    with pytest.raises(AssertionError):
        verifier.verify(capture)
