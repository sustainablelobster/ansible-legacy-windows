"""Fault-test the maintained public setup matrix and protected cleanup."""

# SPDX-License-Identifier: GPL-3.0-or-later
# pylint: disable=protected-access

import hashlib
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="fixture")
def load_fixture(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Import the maintained fixture without starting its Windows entry point.

    :param monkeypatch: Scoped import/native boundary replacements.
    :returns: The actual fixture with only native observation substituted.
    """
    monkeypatch.setitem(sys.modules, "winreg", ModuleType("winreg"))
    fixture = load_module(ROOT / "tests/integration/fixtures/setup.py", "setup_fixture")
    monkeypatch.setattr(fixture, "_protected_state", lambda: {"original": True})

    def _file(path: str) -> dict[str, object]:
        return {"sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest()}

    monkeypatch.setattr(fixture, "_file", _file)
    return fixture


def _workspace_kernel(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, attributes: int = 0x10
) -> Any:
    kernel = SimpleNamespace(GetFileAttributesW=Mock(return_value=attributes))
    monkeypatch.setattr(
        fixture.ctypes, "WinDLL", lambda *_args, **_kw: kernel, raising=False
    )
    return kernel


def test_workspace_guard_accepts_same_directory_alias_not_literal_spelling(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    temporary = tmp_path / "Long Temporary Directory"
    temporary.mkdir()
    alias = tmp_path / "TEMPDIR~1"
    alias.symlink_to(temporary, target_is_directory=True)
    workspace = temporary / "legacy-windows-setup-parallel-owned"
    workspace.mkdir()
    monkeypatch.setattr(fixture.tempfile, "gettempdir", lambda: str(alias))
    kernel = _workspace_kernel(fixture, monkeypatch)
    assert fixture._root(str(workspace)) == str(workspace)
    kernel.GetFileAttributesW.assert_called_once_with(str(workspace))


@pytest.mark.parametrize("location", ["sibling", "nested"])
def test_workspace_guard_rejects_different_parent_identity(
    fixture: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    location: str,
) -> None:
    temporary = tmp_path / "Temp"
    temporary.mkdir()
    parent = tmp_path / "Other" if location == "sibling" else temporary / "nested"
    parent.mkdir()
    workspace = parent / "legacy-windows-setup-parallel-owned"
    workspace.mkdir()
    monkeypatch.setattr(fixture.tempfile, "gettempdir", lambda: str(temporary))
    kernel = _workspace_kernel(fixture, monkeypatch)
    with pytest.raises(ValueError, match="outside the target temporary directory"):
        fixture._root(str(workspace))
    kernel.GetFileAttributesW.assert_not_called()


@pytest.mark.parametrize("attributes", [0, 0x410])
def test_workspace_guard_still_rejects_files_and_reparse_directories(
    fixture: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    attributes: int,
) -> None:
    workspace = tmp_path / "legacy-windows-setup-parallel-owned"
    workspace.mkdir()
    monkeypatch.setattr(fixture.tempfile, "gettempdir", lambda: str(tmp_path))
    _workspace_kernel(fixture, monkeypatch, attributes)
    with pytest.raises(ValueError, match="ordinary owned directory"):
        fixture._root(str(workspace))


def test_preparation_journals_original_before_first_input_write(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def _fail(_path: str) -> None:
        raise OSError("owned directory creation failed")

    monkeypatch.setattr(fixture.os, "mkdir", _fail)
    with pytest.raises(OSError, match="owned directory creation"):
        fixture._prepare(str(tmp_path))
    journal = json.loads((tmp_path / "setup-journal.json").read_text())
    assert journal == {"workspace": str(tmp_path), "before": {"original": True}}


def test_preparation_preserves_literal_typed_custom_inputs(
    fixture: Any, tmp_path: Path
) -> None:
    fixture._prepare(str(tmp_path))
    inputs = tmp_path / "json-facts"
    assert (inputs / "object.json").read_bytes().startswith(b"\xef\xbb\xbf")
    expected: dict[str, object] = {
        "false": False,
        "zero": 0,
        "null": None,
        "empty": [],
        "single": [{"value": "one"}],
        "array": [1, "two", False, None],
    }
    for name, value in expected.items():
        assert (
            json.loads((inputs / (name + ".json")).read_text(encoding="utf-8-sig"))
            == value
        )
    assert (inputs / "ignored.JSON").is_file()
    assert (inputs / "ignored-directory.json").is_dir()
    assert fixture._cleanup(str(tmp_path))["restored"]


def test_prepared_names_cannot_collide_on_case_insensitive_windows(
    fixture: Any, tmp_path: Path
) -> None:
    fixture._prepare(str(tmp_path))
    for directory in [
        tmp_path,
        *[path for path in tmp_path.iterdir() if path.is_dir()],
    ]:
        names = [path.name for path in directory.iterdir()]
        assert len(names) == len({name.casefold() for name in names})


@pytest.mark.parametrize("created, waited", [(10, 0), (11, 258)])
def test_process_observation_never_manages_a_reused_or_stopped_pid(
    fixture: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    created: int,
    waited: int,
) -> None:
    identity = {"pid": 42, "created": 10}
    (tmp_path / "timeout-identity.json").write_text(json.dumps(identity))

    def _times(_handle: int, pointer: Any, *_arguments: Any) -> int:
        fixture.ctypes.cast(pointer, fixture.ctypes.POINTER(fixture.ctypes.c_uint64))[
            0
        ] = created
        return 1

    kernel = SimpleNamespace(
        OpenProcess=Mock(return_value=77),
        GetProcessTimes=Mock(side_effect=_times),
        WaitForSingleObject=Mock(return_value=waited),
        CloseHandle=Mock(return_value=1),
    )
    monkeypatch.setattr(
        fixture.ctypes, "WinDLL", lambda *_args, **_kw: kernel, raising=False
    )
    assert fixture._timeout_process(str(tmp_path)) == dict(identity, stopped=True)
    kernel.CloseHandle.assert_called_once_with(77)
    if created != identity["created"]:
        kernel.WaitForSingleObject.assert_not_called()


def test_own_live_timeout_process_is_an_actionable_recovery_failure(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    identity = {"pid": 42, "created": 10}
    (tmp_path / "timeout-identity.json").write_text(json.dumps(identity))

    def _times(_handle: int, pointer: Any, *_arguments: Any) -> int:
        fixture.ctypes.cast(pointer, fixture.ctypes.POINTER(fixture.ctypes.c_uint64))[
            0
        ] = identity["created"]
        return 1

    kernel = SimpleNamespace(
        OpenProcess=Mock(return_value=77),
        GetProcessTimes=Mock(side_effect=_times),
        WaitForSingleObject=Mock(return_value=258),
        CloseHandle=Mock(return_value=1),
    )
    monkeypatch.setattr(
        fixture.ctypes, "WinDLL", lambda *_args, **_kw: kernel, raising=False
    )
    with pytest.raises(ValueError, match="literal owned custom-fact process"):
        fixture._timeout_process(str(tmp_path))
    kernel.CloseHandle.assert_called_once_with(77)
    assert json.loads((tmp_path / "timeout-identity.json").read_text()) == identity


@pytest.mark.parametrize("changed", ["configuration", "protected"])
def test_cleanup_rejects_protected_changes_and_preserves_journal(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, changed: str
) -> None:
    fixture._prepare(str(tmp_path))
    original = (tmp_path / "setup-journal.json").read_bytes()
    if changed == "configuration":
        monkeypatch.setattr(fixture, "_protected_state", lambda: {"original": False})
    else:
        (tmp_path / "protected.bin").write_bytes(b"unexpected change")
    with pytest.raises(ValueError, match="protected registry values or sibling"):
        fixture._cleanup(str(tmp_path))
    assert (tmp_path / "setup-journal.json").read_bytes() == original


@pytest.mark.parametrize("relative", ["unexpected.txt", "json-facts/unexpected.txt"])
def test_cleanup_never_accepts_an_unexpected_owned_directory_entry(
    fixture: Any, tmp_path: Path, relative: str
) -> None:
    fixture._prepare(str(tmp_path))
    (tmp_path / relative).write_bytes(b"unrecognized")
    with pytest.raises(ValueError, match="Unexpected"):
        fixture._cleanup(str(tmp_path))
    assert (tmp_path / relative).exists()
    assert (tmp_path / "setup-journal.json").exists()


def test_cleanup_requires_the_literal_journal_workspace(
    fixture: Any, tmp_path: Path
) -> None:
    fixture._prepare(str(tmp_path))
    path = tmp_path / "setup-journal.json"
    document = json.loads(path.read_text())
    document["workspace"] += "-different"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="literal workspace"):
        fixture._cleanup(str(tmp_path))


def test_preparation_never_reuses_existing_data(fixture: Any, tmp_path: Path) -> None:
    existing = tmp_path / "preexisting.txt"
    existing.write_bytes(b"retain")
    with pytest.raises(ValueError, match="new empty workspace"):
        fixture._prepare(str(tmp_path))
    assert existing.read_bytes() == b"retain"
    assert not (tmp_path / "setup-journal.json").exists()


def test_complete_effective_matrix_and_recovery_are_visible() -> None:
    integration = ROOT / "tests/integration"
    variables = yaml.safe_load((integration / "vars/setup.yml").read_text())
    cases = variables["setup_cases"]
    assert len(cases) == 35
    assert len({case["name"] for case in cases}) == 35
    scripts = [case for case in cases if case.get("script")]
    assert len(scripts) == 3
    assert scripts[-1]["params"]["gather_timeout"] == 2
    assert sum(case.get("check", False) for case in cases) == 3
    assert any(case["params"].get("gather_timeout", 1) is None for case in cases)
    assert any(case["params"].get("gather_timeout", 1) == 0 for case in cases)
    assert "rstrip=false" in variables["setup_fixture"]
    minimum = cases[21]["params"]["gather_subset"]
    hardware = cases[22]["params"]["gather_subset"]
    assert all(subset.startswith("!") for subset in minimum + hardware)
    play = yaml.safe_load((integration / "setup.yml").read_text())[0]
    block = next(task for task in play["tasks"] if "block" in task)
    include = next(
        task
        for task in block["block"]
        if task.get("ansible.builtin.include_tasks") == "tasks/setup_case.yml"
    )
    assert include["loop"] == "{{ setup_cases[setup_case_start | default(0) | int :] }}"
    assert [case["name"] for case in cases[29:]] == [
        "JSON custom facts preserve null boolean number object and arrays",
        "Check mode still reads JSON custom facts",
        "Missing custom-fact directory produces the released warning",
        "Explicit script facts retain their PowerShell prerequisite",
        "Check mode still executes explicitly supplied script facts",
        "Local script timeout returns a warning and no late facts",
    ]
    assert include["ansible.builtin.include_tasks"] == "tasks/setup_case.yml"
    assert (
        block["block"][-1]["ansible.builtin.include_tasks"] == "tasks/setup_dynamic.yml"
    )
    assert block["block"][-1]["when"] == "setup_dynamic | default(false) | bool"
    always = block["always"]
    assert any(
        "register" in task and task["register"] == "setup_recovery" for task in always
    )
    assert any("workspace_absent" in str(task) for task in always)
    assert any(
        "setup_staging_before" in str(task) and "setup_staging_after" in str(task)
        for task in always
    )
    tasks = (integration / "tasks/setup_case.yml").read_text()
    assert "rejectattr('key', 'in', ['invocation', 'exception'])" in tasks
    assert "native_comparable | to_json(sort_keys=true)" in tasks
    assert "original_comparable | to_json(sort_keys=true)" in tasks
