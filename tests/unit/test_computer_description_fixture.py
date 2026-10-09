"""Verify description fixture journaling and recovery without Windows access."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import base64
import copy
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

# The pinned Nix environment supplies PyYAML without its optional typing stubs.
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


@pytest.fixture(name="fixture")
def computer_description_fixture(tmp_path: Path) -> Any:
    """Load journal contracts with native registration and WMI calls replaced.

    :param tmp_path: Disposable controller-only recovery directory.
    :returns: Real journal functions and observable native-operation stand-ins.
    """
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/computer_description_fixture.yml").read_text()
    )["computer_description_fixture"]
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    names = {
        "backup",
        "cleanup",
        "encoded",
        "prepare_owner",
        "read_journal",
        "save_journal",
        "setup",
    }
    definitions: list[ast.stmt] = [
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    initial = {
        "values": {"owner": None, "organization": None, "description": None},
        "registration": {
            "owner": {"exists": False},
            "organization": {"exists": True, "type": 3, "data": "AP8="},
        },
        "security": "unchanged native security descriptor",
        "object_path": "Win32_OperatingSystem=@",
    }
    # pylint: enable=duplicate-code
    api = SimpleNamespace(
        initial=copy.deepcopy(initial),
        current=copy.deepcopy(initial),
        journal=tmp_path / "computer-description-recovery.json",
    )

    def _set_description(object_path: str, value: str | None) -> None:
        assert object_path == initial["object_path"]
        api.current["values"]["description"] = value

    def _restore_value(field: str, saved: dict[str, Any]) -> None:
        api.current["registration"][field] = copy.deepcopy(saved)
        api.current["values"][field] = None
        if saved["exists"] and saved["type"] == 1:
            api.current["values"][field] = base64.b64decode(saved["data"]).decode(
                "utf-16-le"
            )[:-1]

    namespace = {
        "os": os,
        "json": json,
        "base64": base64,
        "JOURNAL": str(api.journal),
        "REGISTRY_PATH": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "VALUE_NAMES": {
            "owner": "RegisteredOwner",
            "organization": "RegisteredOrganization",
        },
        "BASELINE": {
            "owner": "Fixture owner",
            "organization": "Fixture organization",
            "description": "Fixture description",
        },
        "observe": lambda: copy.deepcopy(api.current),
        "registry_snapshot": lambda: (
            copy.deepcopy(api.current["registration"]),
            api.current["security"],
        ),
        "set_description": Mock(side_effect=_set_description),
        "restore_value": Mock(side_effect=_restore_value),
    }
    # Execute only journal contracts; native initialization and main never run.
    # pylint: disable-next=exec-used
    exec(
        compile(
            ast.Module(body=definitions, type_ignores=[]),
            "<computer description fixture>",
            "exec",
        ),
        namespace,
    )
    api.functions = namespace
    return api


def test_backup_journals_raw_types_absence_and_null_before_any_mutation(
    fixture: Any,
) -> None:
    state = fixture.functions["backup"]()
    assert json.loads(fixture.journal.read_text()) == state
    assert state["initial"] == fixture.initial
    assert state["restored"] is False
    assert fixture.current == fixture.initial
    fixture.functions["set_description"].assert_not_called()
    fixture.functions["restore_value"].assert_not_called()


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def test_existing_recovery_journal_cannot_be_replaced(fixture: Any) -> None:
    fixture.journal.write_text("earlier recovery data")
    with pytest.raises(AssertionError, match="already exists"):
        fixture.functions["backup"]()
    assert fixture.journal.read_text() == "earlier recovery data"
    assert fixture.current == fixture.initial


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def test_journal_creation_failure_leaves_system_untouched(fixture: Any) -> None:
    fixture.functions["save_journal"] = Mock(side_effect=OSError("disk full"))
    with pytest.raises(OSError, match="disk full"):
        fixture.functions["backup"]()
    assert fixture.current == fixture.initial
    fixture.functions["set_description"].assert_not_called()
    fixture.functions["restore_value"].assert_not_called()


# pylint: enable=duplicate-code


def test_partial_setup_failure_can_restore_the_original_null_description(
    fixture: Any,
) -> None:
    state = fixture.functions["backup"]()
    restore = fixture.functions["restore_value"]
    fixture.functions["restore_value"] = Mock(side_effect=OSError("registry denied"))
    with pytest.raises(OSError, match="registry denied"):
        fixture.functions["setup"](state)
    assert fixture.current["values"]["description"] == "Fixture description"
    assert json.loads(fixture.journal.read_text())["restored"] is False
    fixture.functions["restore_value"] = restore
    fixture.functions["cleanup"](fixture.functions["read_journal"]())
    assert fixture.current == fixture.initial
    fixture.functions["set_description"].assert_called_with(
        fixture.initial["object_path"], None
    )
    assert json.loads(fixture.journal.read_text())["restored"] is True


def test_cleanup_preserves_backup_after_failure_and_retries_exact_raw_values(
    fixture: Any,
) -> None:
    state = fixture.functions["backup"]()
    fixture.functions["setup"](state)
    restore = fixture.functions["restore_value"]
    fixture.functions["restore_value"] = Mock(side_effect=OSError("registry denied"))
    with pytest.raises(OSError, match="registry denied"):
        fixture.functions["cleanup"](state)
    saved = json.loads(fixture.journal.read_text())
    assert saved["initial"] == fixture.initial
    assert saved["restored"] is False
    fixture.functions["restore_value"] = restore
    fixture.functions["cleanup"](fixture.functions["read_journal"]())
    assert fixture.current == fixture.initial
    assert json.loads(fixture.journal.read_text())["restored"] is True


def test_cleanup_does_not_rewrite_matching_values(fixture: Any) -> None:
    fixture.functions["cleanup"](fixture.functions["backup"]())
    fixture.functions["set_description"].assert_not_called()
    fixture.functions["restore_value"].assert_not_called()


def test_verification_failure_retains_original_journal(fixture: Any) -> None:
    state = fixture.functions["backup"]()
    fixture.current["security"] = "unexpected changed descriptor"
    with pytest.raises(AssertionError, match="Restored registration"):
        fixture.functions["cleanup"](state)
    assert json.loads(fixture.journal.read_text()) == state
    assert state["restored"] is False


def test_journal_for_another_registry_key_is_rejected(fixture: Any) -> None:
    state = fixture.functions["backup"]()
    state["path"] = "another registry key"
    fixture.journal.write_text(json.dumps(state))
    with pytest.raises(AssertionError, match="another key"):
        fixture.functions["read_journal"]()
    assert fixture.current == fixture.initial


def test_missing_owner_preparation_preserves_original_recovery_authority(
    fixture: Any,
) -> None:
    state = fixture.functions["backup"]()
    fixture.functions["setup"](state)
    controlled = copy.deepcopy(fixture.current)
    journal = fixture.journal.read_bytes()
    fixture.functions["prepare_owner"](state, "remove_owner")
    assert fixture.current["registration"]["owner"] == {"exists": False}
    assert fixture.journal.read_bytes() == journal
    fixture.functions["prepare_owner"](state, "restore_owner")
    assert fixture.current == controlled
    assert fixture.journal.read_bytes() == journal
    fixture.functions["cleanup"](state)
    assert fixture.current == fixture.initial


@pytest.mark.parametrize("operation", ["remove_owner", "restore_owner"])
def test_missing_owner_preparation_rejects_values_outside_controlled_state(
    fixture: Any, operation: str
) -> None:
    state = fixture.functions["backup"]()
    fixture.current["registration"]["owner"] = {
        "exists": True,
        "type": 3,
        "data": "AP8=",
    }
    with pytest.raises(AssertionError, match="controlled scenario"):
        fixture.functions["prepare_owner"](state, operation)
    fixture.functions["restore_value"].assert_not_called()
    assert json.loads(fixture.journal.read_text()) == state
