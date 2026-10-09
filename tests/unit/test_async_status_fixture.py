"""Exercise isolated job fixture ownership and recovery on developer Python."""

# SPDX-License-Identifier: GPL-3.0-or-later
# The actual Windows runtime and filesystem require separate lab evidence.
# pylint: disable=exec-used

import ast
import base64
import ctypes
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

# The pinned development environment supplies PyYAML without typing metadata.
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT

_SOURCE = yaml.safe_load(
    (ROOT / "tests/integration/vars/async_status_fixture.yml").read_text()
)["async_status_program"]


def _run(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    operation: str,
    case: dict[str, Any] | None = None,
) -> dict[str, Any]:
    def _attributes(path: str) -> int:
        if os.path.islink(path):
            return 0x400
        return 0x10 if os.path.isdir(path) else 0x20

    arguments = ["fixture", str(tmp_path), operation]
    if case is not None:
        arguments.append(base64.b64encode(json.dumps(case).encode()).decode())
    ast.parse(_SOURCE, feature_version=(3, 4))
    with monkeypatch.context() as scope:
        scope.setattr(sys, "argv", arguments)
        scope.setattr(sys, "version_info", (3, 4, 4))
        scope.setattr(
            sys, "getwindowsversion", lambda: SimpleNamespace(major=10), raising=False
        )
        scope.setattr(
            ctypes,
            "WinDLL",
            lambda *_args, **_kwargs: SimpleNamespace(GetFileAttributesW=_attributes),
            raising=False,
        )
        exec(compile(_SOURCE, "async_status_fixture.py", "exec"), {})
    captured = capsys.readouterr()
    assert not captured.err
    return json.loads(captured.out)  # type: ignore[no-any-return]


@pytest.mark.parametrize("directory", [False, True])
def test_setup_seed_observe_and_cleanup_restore_empty_workspace(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    directory: bool,
) -> None:
    setup = _run(monkeypatch, capsys, tmp_path, "setup")
    journal = tmp_path / "async-status-recovery.json"
    assert setup["journaled"] and journal.exists()
    case = {"directory": True} if directory else {"contents": "{}"}
    seeded = _run(monkeypatch, capsys, tmp_path, "seed", case)
    observed = _run(monkeypatch, capsys, tmp_path, "observe")

    assert seeded == observed
    assert list(observed["cache"]["children"]) == ["job"]
    restored = _run(monkeypatch, capsys, tmp_path, "cleanup")
    assert restored["restored"]
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("boundary", ["job", "sibling", "workspace", "reparse"])
def test_unowned_or_changed_resources_stop_cleanup_and_keep_journal(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    boundary: str,
) -> None:
    _run(monkeypatch, capsys, tmp_path, "setup")
    journal = tmp_path / "async-status-recovery.json"
    original = journal.read_bytes()
    if boundary == "job":
        (tmp_path / "cache" / "unowned").write_bytes(b"preserve")
    elif boundary == "sibling":
        (tmp_path / "preserved.bin").write_bytes(b"changed")
    elif boundary == "workspace":
        (tmp_path / "unowned").write_bytes(b"preserve")
    else:
        (tmp_path / "cache" / "job").symlink_to(tmp_path / "preserved.bin")

    with pytest.raises(ValueError):
        _run(monkeypatch, capsys, tmp_path, "cleanup")

    assert journal.read_bytes() == original
    assert (tmp_path / "preserved.bin").exists()


def test_case_cannot_seed_an_identifier_outside_its_owned_catalogue(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    _run(monkeypatch, capsys, tmp_path, "setup")

    with pytest.raises(ValueError, match="does not own"):
        _run(
            monkeypatch,
            capsys,
            tmp_path,
            "seed",
            {
                "params": {"jid": "../outside"},
                "contents": "{}",
            },
        )

    assert not (tmp_path.parent / "outside").exists()
    assert (tmp_path / "async-status-recovery.json").exists()


def test_maintained_case_counts_and_public_comparison_gate_are_fixed() -> None:
    cases = yaml.safe_load(
        (ROOT / "tests/integration/vars/async_status.yml").read_text()
    )["async_status_cases"]
    assert len(cases) == 35
    assert len({case["name"] for case in cases}) == 35
    main = (ROOT / "tests/integration/async_status.yml").read_text()
    assert "async_status_expected_count | default(35)" in main
    assert "native | length == expected" in main
    assert "original | length == expected" in main
    assert "map(attribute='result')" in main
    assert "map(attribute='before')" in main
    assert "map(attribute='after')" in main
