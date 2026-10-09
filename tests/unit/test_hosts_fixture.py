"""Verify hosts backup integrity and recovery without touching Windows hosts."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import base64
import ctypes
import hashlib
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
def hosts_fixture(tmp_path: Path) -> Any:
    """Load the fixture's file-backup contracts with native calls replaced.

    :param tmp_path: Disposable controller-only directory.
    :returns: Real backup/cleanup functions with observable metadata operations.
    """
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/hosts_fixture.yml").read_text()
    )["hosts_fixture"]
    names = {
        "FileTime",
        "backup",
        "cleanup",
        "encoded",
        "read_journal",
        "save_journal",
        "restore_metadata",
    }
    definitions: list[ast.stmt] = [
        node
        for node in ast.parse(source).body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names
    ]
    target = tmp_path / "hosts"
    original = b"original hosts\x00\xff\xfe\r\n"
    target.write_bytes(original)
    metadata = {
        "created": 12345678901234,
        "accessed": 23456789012345,
        "written": 34567890123456,
        "attributes": 32,
        "security": "original SD",
    }
    api = SimpleNamespace(
        target=target,
        original=original,
        original_metadata=dict(metadata),
        metadata=metadata,
        backup=tmp_path / "hosts-original.bin",
        journal=tmp_path / "hosts-recovery.json",
    )

    def _write(data: bytes, attributes: int) -> None:
        target.write_bytes(data)
        api.metadata["attributes"] = attributes

    def _restore(value: dict[str, Any]) -> None:
        api.metadata = dict(value)

    namespace = {
        "os": os,
        "json": json,
        "hashlib": hashlib,
        "base64": base64,
        "ctypes": ctypes,
        "DWORD": ctypes.c_uint32,
        "POINTER": ctypes.c_void_p,
        "HOSTS": str(target),
        "BACKUP": str(api.backup),
        "JOURNAL": str(api.journal),
        "observe": lambda: (target.read_bytes(), dict(api.metadata)),
    }
    # Load only isolated contracts; native imports and main setup never execute.
    # pylint: disable-next=exec-used
    exec(
        compile(
            ast.Module(body=definitions, type_ignores=[]), "<hosts fixture>", "exec"
        ),
        namespace,
    )
    api.restore_native_metadata = namespace["restore_metadata"]
    namespace["write_contents"] = Mock(side_effect=_write)
    namespace["restore_metadata"] = Mock(side_effect=_restore)
    api.functions = namespace
    return api


def test_backup_preserves_bytes_and_verifies_journal_before_host_writes(
    fixture: Any,
) -> None:
    state = fixture.functions["backup"]()
    assert fixture.backup.read_bytes() == fixture.original
    assert fixture.target.read_bytes() == fixture.original
    assert json.loads(fixture.journal.read_text()) == state
    assert state["metadata"] == fixture.original_metadata
    assert state["sha256"] == hashlib.sha256(fixture.original).hexdigest()
    assert not state["restored"]
    fixture.functions["write_contents"].assert_not_called()


def test_existing_backup_cannot_be_replaced(fixture: Any) -> None:
    fixture.backup.write_bytes(b"earlier recovery bytes")
    with pytest.raises(FileExistsError):
        fixture.functions["backup"]()
    assert fixture.backup.read_bytes() == b"earlier recovery bytes"
    assert fixture.target.read_bytes() == fixture.original
    assert not fixture.journal.exists()


def test_failed_journal_creation_leaves_hosts_untouched(fixture: Any) -> None:
    fixture.functions["save_journal"] = Mock(side_effect=OSError("journal disk full"))
    with pytest.raises(OSError, match="journal disk full"):
        fixture.functions["backup"]()
    assert fixture.target.read_bytes() == fixture.original
    fixture.functions["write_contents"].assert_not_called()


@pytest.mark.parametrize("same_length", [False, True])
def test_corrupt_backup_never_overwrites_hosts(fixture: Any, same_length: bool) -> None:
    state = fixture.functions["backup"]()
    fixture.target.write_bytes(b"test hosts")
    damaged = b"x" * len(fixture.original) if same_length else b"short"
    fixture.backup.write_bytes(damaged)
    with pytest.raises(AssertionError, match="Backup (length|digest) changed"):
        fixture.functions["cleanup"](state)
    assert fixture.target.read_bytes() == b"test hosts"
    assert json.loads(fixture.journal.read_text())["restored"] is False
    fixture.functions["write_contents"].assert_not_called()


def test_failed_metadata_restore_keeps_recovery_data_for_retry(fixture: Any) -> None:
    state = fixture.functions["backup"]()
    fixture.target.write_bytes(b"test hosts")
    fixture.metadata["written"] = 99
    restore = fixture.functions["restore_metadata"]
    fixture.functions["restore_metadata"] = Mock(side_effect=OSError("metadata locked"))
    with pytest.raises(OSError, match="metadata locked"):
        fixture.functions["cleanup"](state)
    assert fixture.backup.read_bytes() == fixture.original
    assert json.loads(fixture.journal.read_text())["restored"] is False
    fixture.functions["restore_metadata"] = restore
    fixture.functions["cleanup"](state)
    assert fixture.target.read_bytes() == fixture.original
    assert fixture.metadata == fixture.original_metadata
    assert json.loads(fixture.journal.read_text())["restored"] is True
    assert fixture.backup.exists()


def test_verification_failure_does_not_mark_journal_restored(fixture: Any) -> None:
    state = fixture.functions["backup"]()
    fixture.metadata["accessed"] = 99
    fixture.functions["restore_metadata"] = Mock()
    with pytest.raises(AssertionError, match="Restored metadata differs"):
        fixture.functions["cleanup"](state)
    assert json.loads(fixture.journal.read_text())["restored"] is False
    assert fixture.backup.exists()


def test_journal_for_another_file_is_rejected(fixture: Any) -> None:
    state = fixture.functions["backup"]()
    state["path"] = "another file"
    fixture.journal.write_text(json.dumps(state))
    with pytest.raises(AssertionError, match="another file"):
        fixture.functions["read_journal"]()
    assert fixture.target.read_bytes() == fixture.original


def test_matching_security_is_not_rewritten_when_restoring_times(fixture: Any) -> None:
    native = fixture.functions
    native.update(
        {
            "security_descriptor": Mock(return_value="original SD"),
            "set_security": Mock(),
            "set_attributes": Mock(return_value=True),
            "create_file": Mock(return_value=71),
            "close_handle": Mock(return_value=True),
            "set_times": Mock(return_value=True),
            "require": Mock(),
        }
    )
    fixture.restore_native_metadata(fixture.original_metadata)
    native["set_security"].assert_not_called()
    arguments = native["set_times"].call_args.args
    times = [
        ctypes.cast(value, ctypes.POINTER(native["FileTime"])).contents
        for value in arguments[1:]
    ]
    actual = [value.low | (value.high << 32) for value in times]
    expected = [
        fixture.original_metadata[name] for name in ("created", "accessed", "written")
    ]
    assert actual == expected
    native["close_handle"].assert_called_once_with(71)
