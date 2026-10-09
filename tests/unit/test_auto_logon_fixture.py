"""Test encrypted auto-logon journaling and partial-failure recovery off-target."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import base64
import copy
import ctypes
import hashlib
import hmac
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock, Mock

import pytest

# The development environment supplies PyYAML without optional typing stubs.
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


@pytest.fixture(name="fixture")
def auto_logon_fixture(tmp_path: Path) -> Any:
    """Load journal and recovery functions without executing Windows imports.

    :param tmp_path: Isolated controller-only recovery directory.
    :returns: Real fixture functions with mutable native substitutes.
    """
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/auto_logon_fixture.yml").read_text()
    )["auto_logon_fixture"]
    source = source.replace("{{ auto_logon_account_source | to_json }}", "''").replace(
        "{{ ansible_user | to_json }}", "''"
    )
    names = {"read_journal", "backup", "setup", "cleanup", "observe", "protect"}
    definitions: list[ast.stmt] = [
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    state = SimpleNamespace(
        values={"original": {"kind": 3, "data": "AA=="}},
        password="Original-Private-Password",
        journal=tmp_path / "recovery.dpapi",
    )
    state.original = copy.deepcopy(state.values)
    state.secret_original = state.password

    def _secret(write: bool = False, value: str | None = None) -> str | None:
        if write:
            state.password = value
            return None
        return cast(str | None, state.password)

    def _restore(values: dict[str, Any]) -> None:
        state.values = copy.deepcopy(values)

    namespace: dict[str, Any] = {
        "os": os,
        "json": json,
        "base64": base64,
        "ctypes": ctypes,
        "hmac": hmac,
        "hashlib": hashlib,
        "JOURNAL": str(state.journal),
        "registry": Mock(side_effect=lambda: copy.deepcopy(state.values)),
        "secret": Mock(side_effect=_secret),
        "restore_values": Mock(side_effect=_restore),
        "open_key": MagicMock(),
        "winreg": SimpleNamespace(REG_DWORD=4, SetValueEx=Mock()),
        "NAMES": (
            "AutoAdminLogon",
            "DefaultUserName",
            "DefaultDomainName",
            "AutoLogonCount",
            "DefaultPassword",
        ),
    }
    # Compile maintained contracts, not a second implementation of recovery.
    # pylint: disable-next=exec-used
    exec(
        compile(
            ast.Module(body=definitions, type_ignores=[]),
            "<auto logon fixture>",
            "exec",
        ),
        namespace,
    )
    state.native_protect = namespace["protect"]
    namespace["protect"] = Mock(
        side_effect=lambda data, decrypt=False: (
            base64.b64decode(data[7:])
            if decrypt
            else b"SEALED:" + base64.b64encode(data)
        )
    )
    state.functions = namespace
    return state


def test_backup_encrypts_and_verifies_complete_original_before_any_write(
    fixture: Any,
) -> None:
    state = fixture.functions["backup"]()
    assert state["registry"] == fixture.original
    assert state["secret"] == fixture.secret_original
    assert len(base64.b64decode(state["proof_key"])) == 32
    assert fixture.secret_original.encode() not in fixture.journal.read_bytes()
    assert fixture.functions["read_journal"]() == state
    fixture.functions["winreg"].SetValueEx.assert_not_called()
    fixture.functions["restore_values"].assert_not_called()
    assert not any(
        call.args and call.args[0] is True
        for call in fixture.functions["secret"].call_args_list
    )


def test_existing_journal_is_not_overwritten(fixture: Any) -> None:
    fixture.journal.write_bytes(b"existing recovery")
    with pytest.raises(AssertionError, match="already exists"):
        fixture.functions["setup"]()
    assert fixture.journal.read_bytes() == b"existing recovery"
    fixture.functions["restore_values"].assert_not_called()


@pytest.mark.parametrize("failure", ["protect", "read_journal"])
def test_journal_failure_prevents_registry_or_lsa_mutations(
    fixture: Any, failure: str
) -> None:
    fixture.functions[failure] = Mock(side_effect=OSError("journal failed"))
    with pytest.raises(OSError, match="journal failed"):
        fixture.functions["setup"]()
    fixture.functions["winreg"].SetValueEx.assert_not_called()
    fixture.functions["restore_values"].assert_not_called()
    assert fixture.password == fixture.secret_original


def test_partial_setup_is_recoverable_from_encrypted_journal(fixture: Any) -> None:
    restore = fixture.functions["restore_values"].side_effect
    fixture.functions["restore_values"].side_effect = OSError(
        "partial registry failure"
    )
    with pytest.raises(OSError, match="partial registry failure"):
        fixture.functions["setup"]()
    assert fixture.password is None
    assert fixture.journal.exists()
    fixture.functions["restore_values"].side_effect = restore
    fixture.functions["cleanup"](fixture.functions["read_journal"]())
    assert (
        fixture.password == fixture.secret_original
        and fixture.values == fixture.original
    )


def test_cleanup_failure_retains_journal_and_retry_restores_exact_state(
    fixture: Any,
) -> None:
    state = fixture.functions["backup"]()
    fixture.values, fixture.password = {"modified": 7}, "Changed"
    restore = fixture.functions["restore_values"].side_effect
    fixture.functions["restore_values"].side_effect = OSError("restore denied")
    with pytest.raises(OSError, match="restore denied"):
        fixture.functions["cleanup"](state)
    assert fixture.journal.exists()
    fixture.functions["restore_values"].side_effect = restore
    fixture.functions["cleanup"](state)
    assert (
        fixture.values == fixture.original
        and fixture.password == fixture.secret_original
    )


def test_cleanup_verification_cannot_be_bypassed(fixture: Any) -> None:
    state = fixture.functions["backup"]()
    fixture.functions["restore_values"].side_effect = None
    fixture.values = {"unexpected": 1}
    with pytest.raises(AssertionError, match="Original registry values differ"):
        fixture.functions["cleanup"](state)
    assert fixture.journal.exists()


def test_observer_never_returns_password_or_unkeyed_password_hash(fixture: Any) -> None:
    state = fixture.functions["backup"]()
    fixture.values = {name: None for name in fixture.functions["NAMES"]}
    fixture.functions["TEST_PASSWORDS"] = {"fixture": "Different"}
    result = fixture.functions["observe"](state)
    assert result["secret_present"] and result["secret_matches"] == []
    assert fixture.secret_original not in json.dumps(result)
    expected = hmac.new(
        base64.b64decode(state["proof_key"]),
        json.dumps(fixture.secret_original).encode(),
        hashlib.sha256,
    ).hexdigest()
    assert result["secret_proof"] == expected


def test_fixture_contains_no_reboot_or_password_return_and_is_python34_syntax() -> None:
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/auto_logon_fixture.yml").read_text()
    )["auto_logon_fixture"]
    source = source.replace("{{ auto_logon_account_source | to_json }}", "''").replace(
        "{{ ansible_user | to_json }}", "''"
    )
    ast.parse(source, feature_version=(3, 4))
    play = yaml.safe_load((ROOT / "tests/integration/win_auto_logon.yml").read_text())
    assert "reboot" not in json.dumps(play).replace("without rebooting", "")
    assert "print(json.dumps(state" not in source
