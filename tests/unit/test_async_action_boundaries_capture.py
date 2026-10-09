"""Reject altered public failures, weakened typing and incomplete recovery."""

# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from scripts.verify_async_action_boundaries_capture import verify_capture
from tests.unit.payload_support import ROOT, load_module


def _capture() -> dict[str, Any]:
    empty: dict[str, Any] = {
        "root": None,
        "python": [3, 4, 4],
        "staging": [],
        "root_exists": False,
        "files": {},
        "directories": [],
    }
    protected = {
        **empty,
        "root": "C:\\OwnedBoundary",
        "root_exists": True,
        "files": {
            "sentinel.txt": {
                "data": "cHJvdGVjdGVk",
                "attributes": 32,
                "mtime_ns": 123,
                "size": 9,
            }
        },
    }
    document: dict[str, Any] = {
        name: {"rc": 0, "stdout": json.dumps(value)}
        for name, value in (
            ("before", empty),
            ("protected", protected),
            ("after", protected),
            ("final", empty),
        )
    }
    document["workspace_absent"] = True
    document["workspace"] = {"path": "C:\\OwnedBoundary"}
    final = {**empty, "root": "C:\\OwnedBoundary"}
    document["final"]["stdout"] = json.dumps(final)
    for module in ("win_copy", "win_template"):
        for side, collection in (
            ("native", "sustainablelobster.legacy_windows"),
            ("original", "ansible.windows"),
        ):
            document[side + "_" + module] = {
                "results": [
                    {
                        "failed": True,
                        "changed": False,
                        "boundary_poll": poll,
                        "msg": f"This action ({collection}.{module}) does not support async.",
                    }
                    for poll in (0, 1)
                ]
            }
    return document


def test_complete_public_pairs_and_literal_protected_recovery() -> None:
    document = _capture()
    before = copy.deepcopy(document)
    assert verify_capture(document) == 4
    assert document == before


@pytest.mark.parametrize(
    "field", ["msg", "failed", "changed", "boundary_poll", "ansible_job_id"]
)
def test_changed_public_or_launch_fields_are_not_normalized(field: str) -> None:
    document = _capture()
    result = document["native_win_copy"]["results"][0]
    result[field] = {
        "msg": "other failure",
        "failed": False,
        "changed": True,
        "boundary_poll": False,
        "ansible_job_id": "unexpected",
    }[field]
    with pytest.raises(AssertionError):
        verify_capture(document)


@pytest.mark.parametrize("field", ["data", "attributes", "mtime_ns", "size"])
def test_protected_bytes_and_metadata_must_remain_literal(field: str) -> None:
    document = _capture()
    after = json.loads(document["after"]["stdout"])
    after["files"]["sentinel.txt"][field] = "changed"
    document["after"]["stdout"] = json.dumps(after)
    with pytest.raises(AssertionError):
        verify_capture(document)


@pytest.mark.parametrize("field", ["staging", "root_exists", "files", "directories"])
def test_final_recovery_cannot_hide_extra_resources(field: str) -> None:
    document = _capture()
    final = json.loads(document["final"]["stdout"])
    final[field] = {
        "staging": ["extra"],
        "root_exists": True,
        "files": {"extra": {}},
        "directories": ["extra"],
    }[field]
    document["final"]["stdout"] = json.dumps(final)
    with pytest.raises(AssertionError):
        verify_capture(document)


def test_target_observer_reads_literal_files_without_mutating_them(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    observer = load_module(
        ROOT / "tests/integration/fixtures/async_action_boundary.py",
        "async_action_boundary_observer",
    )
    sentinel = tmp_path / "sentinel.txt"
    data = b"protected\x00\xff"
    sentinel.write_bytes(data)
    before = sentinel.stat()
    monkeypatch.setattr(observer, "_attributes", lambda path: 32)
    captured = observer.snapshot(str(tmp_path))
    assert captured["root"] == str(tmp_path) and captured["root_exists"] is True
    assert captured["files"] == {
        "sentinel.txt": {
            "data": "cHJvdGVjdGVkAP8=",
            "attributes": 32,
            "mtime_ns": before.st_mtime_ns,
            "size": len(data),
        }
    }
    assert sentinel.read_bytes() == data
    assert sentinel.stat().st_mtime_ns == before.st_mtime_ns


def test_wrong_final_workspace_is_not_accepted() -> None:
    document = _capture()
    final = json.loads(document["final"]["stdout"])
    final["root"] = "C:\\OtherWorkspace"
    document["final"]["stdout"] = json.dumps(final)
    with pytest.raises(AssertionError):
        verify_capture(document)
