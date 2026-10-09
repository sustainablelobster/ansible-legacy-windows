"""Exercise durable mapped-drive fixture ownership and retryable cleanup."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import json
import os
import subprocess
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


@pytest.fixture(name="fixture")
def fixture_functions(tmp_path: Path) -> Any:
    """Load only fixture operations with independent native substitutes.

    :param tmp_path: Owned temporary recovery directory.
    :returns: Fixture namespace and configurable observations.
    """
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/mapped_drive_fixture.yml").read_text()
    )["mapped_drive_fixture"]
    tree = ast.parse(source, feature_version=(3, 4))
    functions = ast.Module(
        body=[
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name in ("setup", "cleanup")
        ],
        type_ignores=[],
    )
    initial = {
        "logical": ["C", "Z"],
        "remembered": [],
        "connected": [],
        "registry": {"Network": []},
    }
    observe = Mock(return_value=initial)
    namespace = {
        "os": os,
        "json": json,
        "uuid": uuid,
        "JOURNAL": str(tmp_path / "mapped-drive.json"),
        "WORKSPACE": str(tmp_path),
        "observe": observe,
        "share_path": Mock(return_value=None),
        "create_share": Mock(),
        "NETWORK": Mock(),
        "NETAPI": Mock(),
        "checked": lambda _code: None,
    }
    # Run the maintained recovery functions against isolated native substitutes.
    # pylint: disable-next=exec-used
    exec(compile(functions, "fixture.py", "exec"), namespace)
    return SimpleNamespace(namespace=namespace, initial=initial, observe=observe)


def test_share_failure_leaves_verified_original_journal_and_cleanup_retries(
    fixture: Any,
) -> None:
    namespace = fixture.namespace

    def fail_after_backup(state: dict[str, Any]) -> None:
        assert (
            json.loads(Path(namespace["JOURNAL"]).read_text(encoding="utf-8")) == state
        )
        assert state["letter"] == "Y"
        raise OSError("Share service unavailable")

    namespace["create_share"].side_effect = fail_after_backup
    with pytest.raises(OSError, match="Share service unavailable"):
        namespace["setup"]()
    assert namespace["cleanup"]()["restored"] is True
    assert namespace["cleanup"]()["restored"] is True
    assert Path(namespace["JOURNAL"]).exists()
    assert not (Path(namespace["WORKSPACE"]) / "endpoint").exists()


def test_cleanup_never_disconnects_an_unexpected_mapping(fixture: Any) -> None:
    namespace = fixture.namespace
    namespace["create_share"].side_effect = RuntimeError("after journal")
    with pytest.raises(RuntimeError):
        namespace["setup"]()
    current = dict(
        fixture.initial, remembered=[{"drive": "Y:", "path": r"\\unrelated\share"}]
    )
    fixture.observe.return_value = current
    with pytest.raises(AssertionError):
        namespace["cleanup"]()
    namespace["NETWORK"].WNetCancelConnection2W.assert_not_called()
    namespace["NETAPI"].NetShareDel.assert_not_called()
    assert Path(namespace["JOURNAL"]).exists()


def test_second_setup_preserves_the_original_recovery_authority(fixture: Any) -> None:
    namespace = fixture.namespace
    namespace["create_share"].side_effect = RuntimeError("after journal")
    with pytest.raises(RuntimeError):
        namespace["setup"]()
    before = Path(namespace["JOURNAL"]).read_bytes()
    with pytest.raises(AssertionError, match="already exists"):
        namespace["setup"]()
    assert Path(namespace["JOURNAL"]).read_bytes() == before


def test_case_assertion_failure_retains_raw_evidence_without_advancing_state(
    tmp_path: Path,
) -> None:
    tasks = yaml.safe_load(
        (ROOT / "tests/integration/tasks/win_mapped_drive_case.yml").read_text()
    )
    retained_tasks = [
        task
        for task in tasks
        if task["name"]
        in (
            "Retain entire public results and independent mapping observations",
            "Verify public fields and predicted or actual mapping state",
            "Advance the previous state only after successful validation",
        )
    ]
    assert len(retained_tasks) == 3
    baseline = {"remembered": [], "logical": ["C"], "registry": {}}
    after = dict(baseline, logical=["C", "D"])
    play = [
        {
            "name": "Exercise maintained capture and validation on the controller",
            "hosts": "localhost",
            "gather_facts": False,
            "vars": {
                "baseline": baseline,
                "after": after,
                "mapped_drive_initial": {"letter": "M"},
                "mapped_drive_previous": baseline,
                "mapped_drive_result": {
                    "changed": False,
                    "diff": {"before": "", "after": ""},
                },
                "mapped_drive_observation": {"stdout": json.dumps(after)},
                "mapped_drive_case": {
                    "name": "Unexpected native state",
                    "params": {"letter": "M", "state": "absent"},
                    "changed": False,
                    "expected": None,
                },
            },
            "tasks": [
                {
                    "block": retained_tasks,
                    "rescue": [
                        {
                            "name": "Verify failed evidence exists and baseline is not advanced",
                            "ansible.builtin.assert": {
                                "that": [
                                    "mapped_drive_results | length == 1",
                                    "mapped_drive_results[0].snapshot == after",
                                    "mapped_drive_results[0].before == baseline",
                                    "mapped_drive_results[0].result == mapped_drive_result",
                                    "mapped_drive_previous == baseline",
                                ]
                            },
                        }
                    ],
                }
            ],
        }
    ]
    playbook = tmp_path / "capture-failure.yml"
    playbook.write_text(yaml.safe_dump(play, sort_keys=False), encoding="utf-8")
    process = subprocess.run(
        ["ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert process.returncode == 0, process.stdout + process.stderr
    assert "rescued=1" in process.stdout
    assert "Verify failed evidence exists" in process.stdout
