"""Exercise audit-policy fixture journaling, refusal, and exact recovery offline."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import hashlib
import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT

# The pinned developer PyYAML dependency provides no type declarations.


@pytest.fixture(name="source")
def fixture_source() -> str:
    """Read the maintained source that executes under Windows Python 3.4.4.

    :returns: Target fixture source.
    """
    document = yaml.safe_load(
        (ROOT / "tests/integration/vars/audit_policy_fixture.yml").read_text(
            encoding="utf-8"
        )
    )
    return str(document["audit_policy_fixture"])


def functions(source: str, directory: Path) -> dict[str, Any]:
    """Load real journal operations with only native policy operations replaced.

    :param source: Maintained fixture text.
    :param directory: Isolated owned backup and journal directory.
    :returns: Loaded journal operations and native substitute boundary.
    """
    tree = ast.parse(source)
    selected = ast.Module(
        body=[
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name in ("save", "load", "setup", "cleanup")
        ],
        type_ignores=[],
    )
    initial = {
        "available": True,
        "policies": [{"category": "system", "subcategory": "file", "flags": 3}],
    }
    controlled = {
        "available": True,
        "policies": [{"category": "system", "subcategory": "file", "flags": 0}],
    }
    namespace: dict[str, Any] = {
        "os": os,
        "json": json,
        "hashlib": hashlib,
        "WORKSPACE": str(directory),
        "JOURNAL": str(directory / "audit-policy-recovery.json"),
        "BACKUP": str(directory / "original-audit-policy.csv"),
        "VERIFIED": str(directory / "restored-audit-policy.csv"),
        "SYSTEM": "system",
        "FILE_SYSTEM": "file",
        "snapshot": Mock(side_effect=[initial, initial, controlled]),
        "restore_system_policy": Mock(),
    }

    def command(arguments: list[str]) -> None:
        if arguments[0] == "/backup":
            Path(arguments[1].removeprefix("/file:")).write_bytes(b"original CSV")
        elif arguments[0] == "/set":
            state = json.loads(Path(namespace["JOURNAL"]).read_text(encoding="utf-8"))
            assert state["initial"] == initial
            assert state["backup_sha256"] == hashlib.sha256(b"original CSV").hexdigest()
        else:
            raise AssertionError("Unexpected auditpol command: " + repr(arguments))

    namespace["command"] = Mock(side_effect=command)
    # Execute only maintained fixture functions with isolated native substitutes.
    # pylint: disable=exec-used
    exec(compile(selected, "audit_policy_fixture", "exec"), namespace)
    # pylint: enable=exec-used
    return namespace


def test_fixture_parses_as_python34_and_checks_owned_workspace(source: str) -> None:
    ast.parse(source, feature_version=(3, 4))
    assert "sys.version_info[:3] == (3, 4, 4)" in source
    assert (
        "legacy-windows-audit-policy-" in source and "tempfile.gettempdir()" in source
    )
    assert "AuditQuerySystemPolicy" in source and "AuditFree" in source
    assert "GetLongPathNameW" in source


def test_journal_and_backup_are_durable_before_first_native_write(
    source: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    namespace = functions(source, tmp_path)
    sync = Mock(wraps=os.fsync)
    monkeypatch.setattr(os, "fsync", sync)
    assert namespace["setup"]()["policies"][0]["flags"] == 0
    assert sync.call_count == 2
    assert [call.args[0][0] for call in namespace["command"].call_args_list] == [
        "/backup",
        "/set",
        "/set",
    ]
    assert Path(namespace["JOURNAL"]).exists()


def test_setup_refuses_to_overwrite_an_existing_recovery_journal(
    source: str, tmp_path: Path
) -> None:
    namespace = functions(source, tmp_path)
    journal = Path(namespace["JOURNAL"])
    journal.write_text("previous recovery data", encoding="utf-8")
    with pytest.raises(AssertionError):
        namespace["setup"]()
    assert journal.read_text(encoding="utf-8") == "previous recovery data"
    namespace["snapshot"].assert_not_called()
    namespace["command"].assert_not_called()


def test_existing_temp_alias_is_expanded_without_accepting_missing_paths(
    source: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ctypes  # pylint: disable=import-outside-toplevel

    selected = ast.Module(
        body=[
            node
            for node in ast.parse(source).body
            if isinstance(node, ast.FunctionDef) and node.name == "_existing_long_path"
        ],
        type_ignores=[],
    )
    long_name = os.path.abspath("existing-long-temp-name")

    def _expand(_path: str, buffer: Any, _size: int) -> int:
        if buffer is None:
            return len(long_name) + 1
        buffer.value = long_name
        return len(long_name)

    native = Mock()
    native.GetLongPathNameW.side_effect = _expand
    monkeypatch.setattr(ctypes, "WinDLL", Mock(return_value=native), raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", Mock(return_value=2), raising=False)
    monkeypatch.setattr(
        ctypes, "WinError", Mock(return_value=OSError("missing")), raising=False
    )
    namespace: dict[str, Any] = {"ctypes": ctypes, "os": os}
    # Exercise the exact maintained path guard with the native lookup isolated.
    # pylint: disable=exec-used
    exec(compile(selected, "audit_policy_temp_guard", "exec"), namespace)
    # pylint: enable=exec-used
    assert namespace["_existing_long_path"]("short-temp-alias") == os.path.normcase(
        long_name
    )
    native.GetLongPathNameW.side_effect = None
    native.GetLongPathNameW.return_value = 0
    with pytest.raises(OSError, match="missing"):
        namespace["_existing_long_path"]("missing-temp-alias")


def test_absent_feature_does_not_create_a_journal_or_invoke_policy_tools(
    source: str, tmp_path: Path
) -> None:
    namespace = functions(source, tmp_path)
    namespace["snapshot"].side_effect = None
    namespace["snapshot"].return_value = {"available": False, "policies": []}
    assert namespace["setup"]() == {"available": False, "policies": []}
    assert not Path(namespace["JOURNAL"]).exists()
    namespace["command"].assert_not_called()


def test_exact_native_and_backup_restoration_precedes_journal_removal(
    source: str, tmp_path: Path
) -> None:
    namespace = functions(source, tmp_path)
    namespace["setup"]()
    initial = json.loads(Path(namespace["JOURNAL"]).read_text(encoding="utf-8"))[
        "initial"
    ]
    namespace["snapshot"].side_effect = None
    namespace["snapshot"].return_value = initial
    result = namespace["cleanup"]()
    assert result == {"restored": True, "initial": initial, "final": initial}
    namespace["restore_system_policy"].assert_called_once_with(initial)
    assert not list(tmp_path.iterdir())


def test_corrupt_backup_is_refused_before_restore_and_retains_recovery_data(
    source: str, tmp_path: Path
) -> None:
    namespace = functions(source, tmp_path)
    namespace["setup"]()
    namespace["command"].reset_mock()
    Path(namespace["BACKUP"]).write_bytes(b"corrupt")
    with pytest.raises(AssertionError):
        namespace["cleanup"]()
    namespace["command"].assert_not_called()
    namespace["restore_system_policy"].assert_not_called()
    assert Path(namespace["JOURNAL"]).exists()
    assert Path(namespace["BACKUP"]).read_bytes() == b"corrupt"


def test_failed_native_restoration_retains_original_backup_and_journal(
    source: str, tmp_path: Path
) -> None:
    namespace = functions(source, tmp_path)
    controlled = namespace["setup"]()
    namespace["snapshot"].side_effect = None
    namespace["snapshot"].return_value = controlled
    with pytest.raises(AssertionError, match="did not restore"):
        namespace["cleanup"]()
    assert Path(namespace["JOURNAL"]).exists()
    assert Path(namespace["BACKUP"]).read_bytes() == b"original CSV"


def test_partial_setup_failure_can_restore_from_the_prewrite_journal(
    source: str, tmp_path: Path
) -> None:
    namespace = functions(source, tmp_path)
    original_command = namespace["command"].side_effect

    def failed_command(arguments: list[str]) -> None:
        original_command(arguments)
        if arguments[0] == "/set":
            raise OSError("setter failed")

    namespace["command"].side_effect = failed_command
    with pytest.raises(OSError, match="setter failed"):
        namespace["setup"]()
    initial = json.loads(Path(namespace["JOURNAL"]).read_text(encoding="utf-8"))[
        "initial"
    ]
    namespace["snapshot"].side_effect = None
    namespace["snapshot"].return_value = initial
    namespace["command"].side_effect = original_command
    assert namespace["cleanup"]()["restored"]
    assert not list(tmp_path.iterdir())


def test_cleanup_retry_replaces_only_its_owned_verification_export(
    source: str, tmp_path: Path
) -> None:
    namespace = functions(source, tmp_path)
    namespace["setup"]()
    initial = json.loads(Path(namespace["JOURNAL"]).read_text(encoding="utf-8"))[
        "initial"
    ]
    namespace["snapshot"].side_effect = None
    namespace["snapshot"].return_value = initial
    Path(namespace["VERIFIED"]).write_bytes(b"previous failed verification")
    assert namespace["cleanup"]()["restored"]
    assert not list(tmp_path.iterdir())


def test_restore_sets_both_flags_for_only_changed_subcategories(source: str) -> None:
    tree = ast.parse(source)
    selected = ast.Module(
        body=[
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "restore_system_policy"
        ],
        type_ignores=[],
    )
    original: list[dict[str, Any]] = [
        {
            "subcategory": "subcategory-" + str(flag),
            "category": "category",
            "flags": flag,
        }
        for flag in (0, 1, 2, 3)
    ]
    current = [{**row, "flags": row["flags"] ^ 3} for row in original]
    original.append({"subcategory": "unchanged", "category": "category", "flags": 3})
    current.append(original[-1].copy())
    namespace: dict[str, Any] = {
        "snapshot": Mock(return_value={"policies": current}),
        "command": Mock(),
    }
    # Execute the maintained restoration entry with only native boundaries mocked.
    # pylint: disable=exec-used
    exec(compile(selected, "audit_policy_restore", "exec"), namespace)
    # pylint: enable=exec-used
    namespace["restore_system_policy"]({"policies": original})
    assert [call.args[0] for call in namespace["command"].call_args_list] == [
        [
            "/set",
            "/subcategory:{subcategory-0}",
            "/success:disable",
            "/failure:disable",
        ],
        ["/set", "/subcategory:{subcategory-1}", "/success:enable", "/failure:disable"],
        ["/set", "/subcategory:{subcategory-2}", "/success:disable", "/failure:enable"],
        ["/set", "/subcategory:{subcategory-3}", "/success:enable", "/failure:enable"],
    ]
    namespace["command"].reset_mock()
    namespace["snapshot"].return_value = {"policies": original}
    namespace["restore_system_policy"]({"policies": original})
    namespace["command"].assert_not_called()
    namespace["snapshot"].return_value = {"policies": current[:-1]}
    with pytest.raises(AssertionError):
        namespace["restore_system_policy"]({"policies": original})
    namespace["command"].assert_not_called()
