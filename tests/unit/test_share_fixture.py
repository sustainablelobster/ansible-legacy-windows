"""Verify share fixture ownership, durable journaling, and cleanup recovery."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import base64
import ctypes
import json
import os
import re
import struct
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

# Nix supplies PyYAML without its optional typing stubs.
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


@pytest.fixture(name="fixture")
def fixture_functions(tmp_path: Path) -> Any:
    """Load real journal functions without DLL loading or target execution.

    :param tmp_path: Disposable recovery workspace on the controller.
    :returns: Fixture functions and mocked share operations.
    """
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/share_fixture.yml").read_text()
    )["share_fixture"]
    definitions: list[ast.stmt] = [
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef)
        and node.name in ("setup", "cleanup", "read_journal")
    ]
    api = SimpleNamespace(journal=tmp_path / "share-recovery.json", current=None)

    def _observe(_name: str) -> object:
        return api.current

    def _delete(server: None, name: str, reserved: int) -> int:
        assert server is None and reserved == 0
        assert api.journal.exists()
        assert json.loads(api.journal.read_text())["name"] == name
        api.current = None
        return 0

    namespace = {
        "os": os,
        "json": json,
        "re": re,
        "uuid": uuid,
        "sys": SimpleNamespace(getwindowsversion=lambda: (10, 0)),
        "WORKSPACE": str(tmp_path),
        "JOURNAL": str(api.journal),
        "observe": Mock(side_effect=_observe),
        "delete": Mock(side_effect=_delete),
    }
    # Only journal functions execute; the fixture's DLL bindings remain unloaded.
    # pylint: disable-next=exec-used
    exec(
        compile(
            ast.Module(body=definitions, type_ignores=[]), "<share fixture>", "exec"
        ),
        namespace,
    )
    api.functions = namespace
    return api


def test_setup_records_absence_before_creating_owned_directories(fixture: Any) -> None:
    result = fixture.functions["setup"]()
    journal = json.loads(fixture.journal.read_text())
    assert journal["initial"] is None
    assert journal["name"] == result["name"]
    assert Path(journal["path"]).is_dir()
    assert Path(journal["other_path"]).is_dir()
    assert result["supports_encryption"]
    fixture.functions["delete"].assert_not_called()


def test_existing_share_is_not_adopted_or_journaled(fixture: Any) -> None:
    fixture.current = {"existing": "unowned share"}
    with pytest.raises(AssertionError):
        fixture.functions["setup"]()
    assert not fixture.journal.exists()
    fixture.functions["delete"].assert_not_called()


def test_existing_journal_cannot_be_replaced(fixture: Any) -> None:
    fixture.journal.write_text("older recovery authority")
    with pytest.raises(AssertionError):
        fixture.functions["setup"]()
    assert fixture.journal.read_text() == "older recovery authority"
    fixture.functions["delete"].assert_not_called()


def test_failed_journal_write_never_creates_directories_or_shares(fixture: Any) -> None:
    fixture.functions["open"] = Mock(side_effect=OSError("disk full"))
    with pytest.raises(OSError, match="disk full"):
        fixture.functions["setup"]()
    assert not list(fixture.journal.parent.iterdir())
    fixture.functions["delete"].assert_not_called()


def test_cleanup_removes_only_recorded_owned_share_and_keeps_directories(
    fixture: Any,
) -> None:
    result = fixture.functions["setup"]()
    fixture.current = {"name": result["name"], "description": "partially changed"}
    original = fixture.journal.read_bytes()
    assert fixture.functions["cleanup"]() == {
        "restored": True,
        "name": result["name"],
        "initial": None,
        "restored_state": None,
        "directories": [True, True],
    }
    assert fixture.journal.read_bytes() == original
    fixture.functions["delete"].assert_called_once_with(None, result["name"], 0)
    assert fixture.current is None


def test_failed_cleanup_preserves_recovery_authority(fixture: Any) -> None:
    fixture.functions["setup"]()
    fixture.functions["delete"].return_value = 5
    fixture.functions["delete"].side_effect = None
    fixture.functions["ctypes"] = SimpleNamespace(
        WinError=lambda code: OSError(code, "denied")
    )
    original = fixture.journal.read_bytes()
    with pytest.raises(OSError, match="denied"):
        fixture.functions["cleanup"]()
    assert fixture.journal.read_bytes() == original


def test_missing_journal_cleanup_does_not_delete_any_share(fixture: Any) -> None:
    assert fixture.functions["cleanup"]() == {
        "restored": True,
        "initial": None,
        "restored_state": None,
    }
    fixture.functions["delete"].assert_not_called()


@pytest.mark.parametrize(
    "field,value",
    [("name", "unowned"), ("initial", {"existing": "share"}), ("path", "C:\\unowned")],
)
def test_invalid_recovery_authority_cannot_delete_a_share(
    fixture: Any, field: str, value: object
) -> None:
    fixture.functions["setup"]()
    journal = json.loads(fixture.journal.read_text())
    journal[field] = value
    fixture.journal.write_text(json.dumps(journal))
    with pytest.raises(AssertionError):
        fixture.functions["cleanup"]()
    fixture.functions["delete"].assert_not_called()


def test_observer_decodes_access_and_raw_security_from_one_owned_copy() -> None:
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/share_fixture.yml").read_text()
    )["share_fixture"]
    definitions: list[ast.stmt] = [
        node
        for node in ast.parse(source).body
        if (isinstance(node, ast.ClassDef) and node.name in ("ShareInfo", "ShareFlags"))
        or (isinstance(node, ast.FunctionDef) and node.name == "observe")
    ]
    sid = bytes.fromhex("010100000000000100000000")
    ace = struct.pack("<BBHL", 0, 0, 8 + len(sid), 0x1200A9) + sid
    acl = struct.pack("<BBHHH", 2, 0, 8 + len(ace), 1, 0) + ace
    raw = struct.pack("<BBHLLLL", 1, 0, 0x8004, 0, 0, 0, 20) + acl
    foreign = ctypes.create_string_buffer(raw)
    namespace: dict[str, Any] = {
        "ctypes": ctypes,
        "base64": base64,
        "DWORD": ctypes.c_uint32,
        "POINTER": ctypes.c_void_p,
        "WIDE": ctypes.c_wchar_p,
        "sd_length": Mock(return_value=len(raw)),
        "free": Mock(),
    }
    # Execute only the observer's structures and function, never its DLL binding.
    # pylint: disable-next=exec-used
    exec(
        compile(
            ast.Module(body=definitions, type_ignores=[]), "<share observer>", "exec"
        ),
        namespace,
    )
    page = namespace["ShareInfo"](
        "Owned",
        0,
        "",
        0,
        10,
        0,
        "C:\\Owned",
        None,
        0,
        ctypes.cast(foreign, ctypes.c_void_p),
    )
    flags = namespace["ShareFlags"](0)

    def _get(_server: None, _name: str, level: int, output: Any) -> int:
        item = page if level == 502 else flags
        ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.cast(
            ctypes.pointer(item), ctypes.c_void_p
        )
        return 0

    def _access(copied: Any) -> list[dict[str, int]]:
        assert ctypes.addressof(copied) != ctypes.addressof(foreign)
        ctypes.memset(foreign, 0, len(raw))
        return [{"mask": struct.unpack_from("<L", bytes(copied), 32)[0]}]

    namespace.update(get=_get, access=_access)
    result = namespace["observe"]("Owned")
    assert result["access"] == [{"mask": 0x1200A9}]
    assert base64.b64decode(result["security"]) == raw
    assert namespace["free"].call_count == 2
    namespace["sd_length"].assert_called_once()
