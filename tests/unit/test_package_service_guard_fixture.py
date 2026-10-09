"""Check installer-counter isolation and owned-service cleanup safeguards."""

# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later
# These tests exercise the fixture's private resource-ownership boundaries.
# pylint: disable=protected-access

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="fixture")
def guard_fixture(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load the target fixture without requesting a Windows provider.

    :param monkeypatch: Scoped import substitution.
    :returns: Independently loaded fixture module.
    """
    monkeypatch.setitem(sys.modules, "winreg", SimpleNamespace())
    return load_module(
        ROOT / "tests/integration/fixtures/package_service_guard.py",
        "tested_package_service_guard_fixture",
    )


def test_installer_only_changes_its_owned_counter(
    fixture: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    native = Mock()
    monkeypatch.setattr(fixture, "_sc", native)
    monkeypatch.setattr(
        fixture,
        "sys",
        SimpleNamespace(
            version_info=(3, 4, 4), argv=["fixture.py", str(tmp_path), "install"]
        ),
    )
    for expected in (1, 2):
        fixture.main()
        assert json.loads(capsys.readouterr().out) == {"count": expected}
    assert list(tmp_path.iterdir()) == [tmp_path / "installer-count.txt"]
    native.assert_not_called()


def test_creation_checks_absent_names_before_writing_a_journal(
    fixture: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        fixture, "_configuration", lambda _name: {"ImagePath": "foreign"}
    )
    create = Mock()
    monkeypatch.setattr(fixture, "_require_sc", create)
    with pytest.raises(AssertionError):
        fixture._setup(str(tmp_path))
    assert not list(tmp_path.iterdir())
    create.assert_not_called()


@pytest.mark.parametrize(
    "configuration",
    [
        {"ImagePath": "foreign", "DisplayName": "Display Owned"},
        {"ImagePath": "owned", "DisplayName": "foreign"},
    ],
)
def test_cleanup_refuses_changed_service_ownership(
    fixture: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    configuration: dict[str, str],
) -> None:
    state = {"names": ["Owned"], "image": "owned", "sddl": None}
    monkeypatch.setattr(fixture, "_restore", lambda *_args: None)
    monkeypatch.setattr(fixture, "_configuration", lambda _name: configuration)
    delete = Mock()
    monkeypatch.setattr(fixture, "_require_sc", delete)
    with pytest.raises(AssertionError):
        fixture._cleanup(str(tmp_path), state)
    delete.assert_not_called()


@pytest.mark.parametrize("exit_code", [0, 5])
def test_denial_requires_native_error_even_when_tool_exits_zero(
    fixture: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    exit_code: int,
) -> None:
    state = {"names": ["Owned"], "sddl": None}
    commands = Mock(return_value={"stdout": "D:original"})
    observation = {
        "query": {"Owned": {"rc": exit_code, "stdout": "OpenService FAILED 5"}}
    }
    monkeypatch.setattr(fixture, "_require_sc", commands)
    monkeypatch.setattr(fixture, "_observe", lambda *_args: observation)
    assert fixture._deny(str(tmp_path), state) is observation
    assert json.loads((tmp_path / "service-guard-state.json").read_text()) == {
        "names": ["Owned"],
        "sddl": "D:original",
    }
    assert commands.call_args_list[0].args == ("sdshow", "Owned")
    assert commands.call_args_list[1].args[:2] == ("sdset", "Owned")


def test_denial_rejects_a_successful_status_query(
    fixture: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = {"names": ["Owned"], "sddl": None}
    monkeypatch.setattr(
        fixture, "_require_sc", Mock(return_value={"stdout": "D:original"})
    )
    monkeypatch.setattr(
        fixture,
        "_observe",
        lambda *_args: {"query": {"Owned": {"rc": 0, "stdout": "STOPPED"}}},
    )
    with pytest.raises(AssertionError, match="STOPPED"):
        fixture._deny(str(tmp_path), state)
