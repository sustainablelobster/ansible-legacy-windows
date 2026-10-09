"""Reject mutated signature inputs and verify owned fixture recovery boundaries."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These concrete private functions are the protected-input fault boundaries.
# pylint: disable=protected-access

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module


@pytest.fixture(name="fixture")
def signature_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load only owned fixture behavior, replacing measured native observations.

    :param tmp_path: Isolated fixture journal.
    :param monkeypatch: Scoped Windows and package-provider substitutions.
    :returns: Concrete fixture, protected record and native observation spies.
    """
    journal = tmp_path / "msp-journal.json"
    journal.write_text("{}", encoding="utf-8")
    record = {
        "signature": {
            "system_cmd": r"C:\Windows\System32\cmd.exe",
            "protected_system_cmd": {"bytes": b"system", "mtime": 1},
            "sources": {"signed cmd.exe": {"bytes": b"owned", "mtime": 2}},
        }
    }
    base = SimpleNamespace(
        JOURNAL=str(journal),
        _read=Mock(return_value=record),
        _file_state=Mock(return_value=record["signature"]["protected_system_cmd"]),
        _snapshot=Mock(return_value={"state": -1, "outputs": {}}),
        _prepare=Mock(return_value={"state": -1, "outputs": {}}),
        _cleanup=Mock(return_value={"restored": True}),
    )
    monkeypatch.syspath_prepend(str(HELPER.parent))
    signature = load_module(
        HELPER.parent / "legacy_windows_package_signature.py", "signature"
    )
    monkeypatch.setitem(sys.modules, "legacy_windows_package_signature", signature)
    monkeypatch.setitem(sys.modules, "package_msp_fixture", base)
    monkeypatch.setattr(sys, "argv", ["fixture", str(tmp_path), "observe"])
    module = load_module(
        ROOT / "tests/integration/fixtures/package_signature_fixture.py", "fixture"
    )
    monkeypatch.setattr(module, "_sources", lambda: record["signature"]["sources"])
    return SimpleNamespace(module=module, base=base, record=record)


def test_signature_observation_retains_every_protected_input_field(
    fixture: Any,
) -> None:
    observed = fixture.module._observe()
    assert observed == {
        "state": -1,
        "outputs": {},
        "signature_sources": fixture.record["signature"]["sources"],
        "protected_system_cmd": fixture.record["signature"]["protected_system_cmd"],
    }


def test_system_command_mutation_blocks_observation_and_recovery(fixture: Any) -> None:
    fixture.base._file_state.return_value = {"bytes": b"modified system", "mtime": 1}
    for operation in (fixture.module._observe, fixture.module._cleanup):
        with pytest.raises(AssertionError):
            operation()
    fixture.base._snapshot.assert_not_called()
    fixture.base._cleanup.assert_not_called()


def test_owned_signature_sample_mutation_blocks_recovery(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        fixture.module,
        "_sources",
        lambda: {"signed cmd.exe": {"bytes": b"modified", "mtime": 2}},
    )
    with pytest.raises(AssertionError):
        fixture.module._cleanup()
    fixture.base._cleanup.assert_not_called()


def test_owned_signature_recovery_requires_original_inputs_before_msi_cleanup(
    fixture: Any,
) -> None:
    assert fixture.module._cleanup() == {
        "restored": True,
        "signature_sources_unchanged": True,
        "system_cmd_unchanged": True,
    }
    fixture.base._cleanup.assert_called_once()


def test_unknown_workspace_file_prevents_complete_recovery_claim(
    fixture: Any, tmp_path: Path
) -> None:
    (tmp_path / "unknown.txt").write_bytes(b"not adopted")
    with pytest.raises(AssertionError):
        fixture.module._cleanup()
    assert (tmp_path / "unknown.txt").read_bytes() == b"not adopted"
