"""Require atomic journal recovery in both standalone engine fixtures."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Private journal functions are the recovery boundary being exercised.
# pylint: disable=protected-access

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="fixture", params=["win_dsc", "win_powershell"])
def engine_fixture(request: pytest.FixtureRequest) -> Any:
    """Load each standalone target fixture without invoking Windows APIs.

    :param request: Fixture name selected by the parameterized test.
    :returns: Isolated target fixture module.
    """
    return load_module(
        ROOT / "tests/integration/fixtures" / (request.param + ".py"),
        request.param + "_workspace_fixture",
    )


def test_journal_replace_failure_preserves_original(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fixture._write(str(tmp_path), {"original": True})
    monkeypatch.setattr(fixture.os, "replace", MagicMock(side_effect=OSError("denied")))
    with pytest.raises(OSError, match="denied"):
        fixture._write(str(tmp_path), {"changed": True})
    assert json.loads((tmp_path / "journal.json").read_text()) == {"original": True}
    assert sorted(path.name for path in tmp_path.iterdir()) == ["journal.json"]


def test_unknown_files_are_not_adopted_or_removed(fixture: Any, tmp_path: Path) -> None:
    fixture._write(str(tmp_path), {"workspace": str(tmp_path), "protected": {}})
    (tmp_path / "unknown.txt").write_text("protected", encoding="utf-8")
    with pytest.raises(AssertionError):
        fixture._reset(str(tmp_path))
    assert (tmp_path / "unknown.txt").read_text() == "protected"
