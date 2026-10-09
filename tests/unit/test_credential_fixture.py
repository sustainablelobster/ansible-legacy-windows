"""Verify ownership journaling and partial-failure credential recovery offline."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import base64
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

# PyYAML is supplied by the pinned developer environment without typing stubs.
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


@pytest.fixture(name="fixture")
def credential_fixture(tmp_path: Path) -> Any:
    """Run maintained ownership/recovery functions with only native calls replaced.

    :param tmp_path: Isolated recovery directory.
    :returns: Native substitutes and actual journal functions.
    """
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/credential_fixture.yml").read_text()
    )["credential_fixture"]
    definitions: list[ast.stmt] = [
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef)
        and node.name in {"save", "load", "setup", "cleanup", "verify_unavailable"}
    ]
    state = SimpleNamespace(
        present=set(), key=False, certificate_failure=False, unavailable={}
    )

    def _read(name: str, kind: int) -> Any:
        if kind in state.unavailable:
            error = OSError("Synthetic unsupported credential type")
            # Linux omits winerror; model the Windows exception attribute here.
            error.winerror = state.unavailable[kind]  # type: ignore[attr-defined]
            raise error
        return {"exists": True} if (name, kind) in state.present else None

    def _create(unused_store: int, unused_record: dict[str, Any]) -> None:
        state.key = True
        if state.certificate_failure:
            raise OSError("Synthetic certificate creation failure")

    def _delete(name: str, kind: int, flags: int) -> int:
        assert flags == 0
        state.present.remove((name, kind))
        return 1

    def _acquire(
        unused_pointer: Any,
        unused_name: str,
        unused_provider: str,
        unused_kind: int,
        flags: int,
    ) -> int:
        assert flags == 0x50
        state.key = False
        return 1

    def _require(result: Any) -> None:
        if not result:
            raise OSError("Native cleanup denied")

    namespace: dict[str, Any] = {
        "os": os,
        "base64": base64,
        "json": json,
        "uuid": SimpleNamespace(uuid4=lambda: SimpleNamespace(hex="0123456789abcdef")),
        "WORKSPACE": str(tmp_path),
        "JOURNAL": str(tmp_path / "credential-ownership.json"),
        "TYPES": {
            "generic_password": 1,
            "domain_password": 2,
            "domain_certificate": 3,
            "generic_certificate": 5,
        },
        "read_target": Mock(side_effect=_read),
        "key_exists": Mock(side_effect=lambda unused: state.key),
        "create_owned_certificate": Mock(side_effect=_create),
        "delete_credential": Mock(side_effect=_delete),
        "acquire_provider": Mock(side_effect=_acquire),
        "require": _require,
        "POINTER": lambda: None,
        "ctypes": SimpleNamespace(byref=lambda value: value),
        "PROVIDER": "fixture provider",
    }
    # Exercise maintained functions, not a separate implementation of recovery.
    # pylint: disable-next=exec-used
    exec(
        compile(
            ast.Module(body=definitions, type_ignores=[]),
            "<credential fixture>",
            "exec",
        ),
        namespace,
    )
    state.functions = namespace
    state.journal = Path(namespace["JOURNAL"])
    return state


def test_setup_verifies_all_targets_absent_and_journals_before_certificate_creation(
    fixture: Any,
) -> None:
    record = fixture.functions["setup"](1)
    assert fixture.functions["load"]() == record
    assert fixture.functions["read_target"].call_count == 4
    assert all(
        len(call.args) == 2 for call in fixture.functions["read_target"].call_args_list
    )
    assert record["initial_absence_verified"] is True
    assert "secret" not in fixture.journal.read_text()
    assert len(base64.b64decode(record["proof_key"])) == 32


def test_existing_target_is_neither_disclosed_nor_deleted(fixture: Any) -> None:
    fixture.functions["read_target"].return_value = {"exists": True}
    fixture.functions["read_target"].side_effect = None
    with pytest.raises(AssertionError, match="target already exists"):
        fixture.functions["setup"](1)
    assert not fixture.journal.exists()
    fixture.functions["create_owned_certificate"].assert_not_called()
    fixture.functions["delete_credential"].assert_not_called()


def test_unavailable_legacy_type_is_recorded_without_claiming_absence(
    fixture: Any,
) -> None:
    fixture.unavailable[5] = 87
    record = fixture.functions["setup"](1)
    assert fixture.functions["load"]() == record
    assert record["unavailable"] == {"generic_certificate": 87}
    fixture.present.add((record["target"], 1))
    fixture.functions["cleanup"](1, record)
    assert fixture.present == set() and fixture.key is False
    fixture.functions["delete_credential"].assert_called_once_with(
        record["target"], 1, 0
    )


@pytest.mark.parametrize("kind,code", [(1, 87), (5, 5), (5, 1312)])
def test_unexpected_availability_failure_aborts_before_claiming_ownership(
    fixture: Any, kind: int, code: int
) -> None:
    fixture.unavailable[kind] = code
    with pytest.raises(OSError, match="unsupported credential type"):
        fixture.functions["setup"](1)
    assert not fixture.journal.exists()
    fixture.functions["create_owned_certificate"].assert_not_called()


def test_changed_unavailable_type_is_not_silently_cleaned(fixture: Any) -> None:
    fixture.unavailable[5] = 87
    record = fixture.functions["setup"](1)
    fixture.unavailable.clear()
    with pytest.raises(AssertionError, match="Previously unavailable"):
        fixture.functions["cleanup"](1, record)
    assert fixture.journal.exists() and fixture.key


def test_existing_key_is_not_claimed(fixture: Any) -> None:
    fixture.key = True
    with pytest.raises(AssertionError, match="container already exists"):
        fixture.functions["setup"](1)
    assert not fixture.journal.exists()
    fixture.functions["create_owned_certificate"].assert_not_called()


def test_partial_setup_retains_durable_ownership_for_native_recovery(
    fixture: Any,
) -> None:
    fixture.certificate_failure = True
    with pytest.raises(OSError, match="Synthetic certificate"):
        fixture.functions["setup"](1)
    assert fixture.journal.exists() and fixture.key
    fixture.functions["cleanup"](1, fixture.functions["load"]())
    assert fixture.key is False


def test_cleanup_deletes_only_owned_names_and_verifies_absence(fixture: Any) -> None:
    record = fixture.functions["setup"](1)
    fixture.present.update((record["target"], kind) for kind in (1, 2))
    fixture.present.add(("unrelated-target", 1))
    fixture.functions["cleanup"](1, record)
    assert fixture.present == {("unrelated-target", 1)}
    assert fixture.key is False
    assert [
        call.args for call in fixture.functions["delete_credential"].call_args_list
    ] == [(record["target"], 1, 0), (record["target"], 2, 0)]


def test_cleanup_failure_retains_journal_and_retry_finishes(fixture: Any) -> None:
    record = fixture.functions["setup"](1)
    fixture.present.add((record["target"], 1))
    original = fixture.functions["delete_credential"].side_effect
    fixture.functions["delete_credential"].side_effect = None
    fixture.functions["delete_credential"].return_value = 0
    with pytest.raises(OSError, match="cleanup denied"):
        fixture.functions["cleanup"](1, record)
    assert fixture.journal.exists() and fixture.present and fixture.key
    fixture.functions["delete_credential"].side_effect = original
    fixture.functions["cleanup"](1, fixture.functions["load"]())
    assert not fixture.present and not fixture.key


def test_journal_cannot_claim_another_workspace_or_target_mapping(fixture: Any) -> None:
    record = fixture.functions["setup"](1)
    record["workspace"] += "-different"
    fixture.functions["save"](record)
    with pytest.raises(AssertionError):
        fixture.functions["load"]()


def test_fixture_and_cases_use_python34_native_observation_and_no_enumeration() -> None:
    variables = yaml.safe_load(
        (ROOT / "tests/integration/vars/credential_fixture.yml").read_text()
    )
    source = variables["credential_fixture"]
    ast.parse(source, feature_version=(3, 4))
    assert "CredEnumerate" not in source and "legacy_windows_credential" not in source
    assert "print(json.dumps(state" not in source
    assert "os.fsync" in source and "os.replace" in source
    cases = yaml.safe_load(
        (ROOT / "tests/integration/vars/credential.yml").read_text()
    )["credential_cases"]
    assert len(cases) == 28
    assert {entry["params"]["type"] for entry in cases} == {
        "generic_password",
        "domain_password",
        "domain_certificate",
        "generic_certificate",
    }


def test_public_failure_is_observed_and_privately_saved_before_validation() -> None:
    tasks = yaml.safe_load(
        (ROOT / "tests/integration/tasks/win_credential_case.yml").read_text()
    )[1]
    steps = tasks["block"]
    public = steps[1]
    assert public["rescue"][0]["ansible.builtin.assert"]["that"] == [
        "credential_result is failed"
    ]
    assert steps[2]["register"] == "credential_after"
    assert "ansible.builtin.copy" in steps[3]
    assert steps[3]["ansible.builtin.copy"]["mode"] == "0600"
    assert "ansible.builtin.assert" in steps[4]
    assert "ansible.builtin.copy" in tasks["always"][-1]
