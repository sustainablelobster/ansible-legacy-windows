"""Verify durable, scoped user-right fixture recovery without Windows access."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock, call

import pytest

# The pinned development environment supplies PyYAML without optional stubs.
import yaml  # type: ignore[import-untyped]

# Use Ansible's real escaping and Windows-name filter, not bare Jinja semantics.
from ansible.parsing.dataloader import DataLoader  # type: ignore[import-untyped]
from ansible.template import (  # type: ignore[import-untyped]
    Templar,
    trust_as_template,
)

from tests.unit.payload_support import ROOT


@pytest.mark.parametrize("group", ["Guests", "Gäste"])
def test_relative_account_case_renders_one_separator_and_no_builtin_domain(
    group: str,
) -> None:
    cases = yaml.safe_load(
        (ROOT / "tests/integration/vars/user_right.yml").read_text()
    )["user_right_cases"]
    case = next(item for item in cases if "machine-qualified" in item["name"])
    templar = Templar(
        loader=DataLoader(),
        variables={
            "user_right_initial": {"identities": {"S-1-5-32-546": "BUILTIN\\" + group}}
        },
    )
    actual = [
        templar.template(trust_as_template(name)) for name in case["params"]["users"]
    ]
    assert actual == [".\\" + group]
    assert actual[0].count("\\") == 1


@pytest.fixture(name="fixture")
def recovery_fixture(tmp_path: Path) -> Any:
    """Load the maintained recovery functions with isolated LSA operations.

    :param tmp_path: Controller-only recovery directory.
    :returns: Recovery functions, journal path, and current assignment list.
    """
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/user_right_fixture.yml").read_text()
    )["user_right_fixture"]
    definitions: list[ast.stmt] = [
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef)
        and node.name in ("read_journal", "backup", "replace", "setup", "cleanup")
    ]
    state = SimpleNamespace(
        current=["original-1", "original-2"],
        journal=tmp_path / "user-right-recovery.json",
    )

    def _change(_policy: Any, sid: str, remove: bool) -> None:
        assert state.journal.exists()
        if remove:
            state.current.remove(sid)
        else:
            state.current.append(sid)

    state.change = Mock(side_effect=_change)
    scope: dict[str, Any] = {
        "json": json,
        "os": os,
        "WORKSPACE": str(tmp_path),
        "JOURNAL": str(state.journal),
        "RIGHT": "SeCreatePagefilePrivilege",
        "assigned": lambda _policy: list(state.current),
        "observe": lambda _policy: {"sids": list(state.current)},
        "change": state.change,
    }
    # Execute only the maintained recovery functions with isolated native calls.
    # pylint: disable-next=exec-used
    exec(
        compile(
            ast.Module(body=definitions, type_ignores=[]), "user-right-fixture", "exec"
        ),
        scope,
    )
    state.functions = SimpleNamespace(**scope)
    return state


def test_setup_journals_original_before_clearing_and_restores_membership(
    fixture: Any,
) -> None:
    assert fixture.functions.setup(1) == {"sids": []}
    assert json.loads(fixture.journal.read_text())["original"] == [
        "original-1",
        "original-2",
    ]
    fixture.current[:] = ["test-sid"]
    fixture.change.reset_mock()
    assert fixture.functions.cleanup(1) == {
        "restored": True,
        "sids": ["original-1", "original-2"],
    }
    assert fixture.change.mock_calls == [
        call(1, "original-1", False),
        call(1, "original-2", False),
        call(1, "test-sid", True),
    ]
    assert fixture.journal.exists()
    fixture.change.reset_mock()
    assert fixture.functions.cleanup(1)["restored"]
    fixture.change.assert_not_called()


def test_existing_journal_is_never_overwritten(fixture: Any) -> None:
    fixture.functions.backup(1)
    original = fixture.journal.read_bytes()
    with pytest.raises(FileExistsError):
        fixture.functions.setup(1)
    assert fixture.journal.read_bytes() == original
    fixture.change.assert_not_called()


def test_failed_journal_flush_prevents_any_policy_write(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "fsync", Mock(side_effect=OSError("flush failed")))
    with pytest.raises(OSError, match="flush failed"):
        fixture.functions.setup(1)
    fixture.change.assert_not_called()
    assert fixture.current == ["original-1", "original-2"]


def test_partial_setup_failure_retains_original_and_allows_retry(fixture: Any) -> None:
    original_change = fixture.change.side_effect
    calls = 0

    def _fail_once(policy: Any, sid: str, remove: bool) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("denied")
        original_change(policy, sid, remove)

    fixture.change.side_effect = _fail_once
    with pytest.raises(OSError, match="denied"):
        fixture.functions.setup(1)
    assert fixture.current == ["original-2"]
    fixture.change.side_effect = original_change
    assert fixture.functions.cleanup(1)["restored"]
    assert set(fixture.current) == {"original-1", "original-2"}


def test_failed_cleanup_keeps_journal_and_retries_remaining_changes(
    fixture: Any,
) -> None:
    fixture.functions.setup(1)
    fixture.current[:] = ["test-sid"]
    original_change = fixture.change.side_effect
    fixture.change.side_effect = OSError("denied")
    with pytest.raises(OSError, match="denied"):
        fixture.functions.cleanup(1)
    assert fixture.journal.exists()
    fixture.change.side_effect = original_change
    assert fixture.functions.cleanup(1)["restored"]


def test_restoration_verifies_membership_not_just_successful_native_calls(
    fixture: Any,
) -> None:
    fixture.functions.setup(1)
    fixture.change.side_effect = None
    with pytest.raises(AssertionError, match="Assignments differ"):
        fixture.functions.cleanup(1)
    assert fixture.journal.exists()


def test_cleanup_without_journal_does_not_mutate_policy(fixture: Any) -> None:
    assert fixture.functions.cleanup(1) == {"restored": True, "backup": False}
    fixture.change.assert_not_called()


def test_journal_for_other_right_or_workspace_is_rejected(fixture: Any) -> None:
    fixture.functions.backup(1)
    journal = json.loads(fixture.journal.read_text())
    journal["right"] = "SeOtherRight"
    fixture.journal.write_text(json.dumps(journal))
    with pytest.raises(AssertionError):
        fixture.functions.cleanup(1)
    fixture.change.assert_not_called()
