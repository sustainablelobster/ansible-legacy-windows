"""Check temporary-object behavior locally without contacting Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Direct helper tests isolate Windows APIs from local filesystem behavior.
# pylint: disable=protected-access

import os
import re
import subprocess
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from tests.unit.payload_support import load_payload, run_payload


@pytest.fixture(name="payload")
def tempfile_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Import the target payload without invoking its JSON entry point.

    :param monkeypatch: Scoped module-path and Windows API substitutes.
    :returns: The loaded module.
    """
    return load_payload("win_tempfile", monkeypatch)


def _response(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, arguments: dict[str, object]
) -> dict[str, object]:
    monkeypatch.setattr(payload, "read_arguments", lambda *_args: arguments)
    monkeypatch.setattr(payload, "_full_path", os.path.abspath)
    result: dict[str, object] = payload._response()
    return result


def _run(
    tmp_path: Path, arguments: object
) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
    return run_payload("win_tempfile", tmp_path, arguments)


@pytest.mark.parametrize("state", ["file", "directory", "DiReCtOrY"])
def test_repeated_creation_is_unique_and_changed(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, state: str
) -> None:
    arguments: dict[str, object] = {"path": str(tmp_path), "state": state}
    first = _response(payload, monkeypatch, arguments)
    second = _response(payload, monkeypatch, arguments)

    assert first["changed"] is second["changed"] is True
    assert first["state"] == second["state"] == state
    assert first["path"] != second["path"]
    for result in (first, second):
        path = Path(str(result["path"]))
        assert path.is_absolute()
        assert path.is_dir() is (state.lower() == "directory")
        assert path.exists()
        assert re.fullmatch(r"ansible\.[a-z0-5]{8}\.[a-z0-5]{3}", path.name)
        if state == "file":
            assert path.read_bytes() == b""


@pytest.mark.parametrize("state", ["file", "directory"])
@pytest.mark.parametrize("parent_kind", ["existing", "missing", "file"])
def test_check_mode_does_not_create_or_inspect_parent_type(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    state: str,
    parent_kind: str,
) -> None:
    parent = tmp_path / "parent"
    if parent_kind == "existing":
        parent.mkdir()
    elif parent_kind == "file":
        parent.write_bytes(b"unchanged")
    before = sorted(tmp_path.rglob("*"))
    result = _response(
        payload,
        monkeypatch,
        {"path": str(parent), "state": state, "_ansible_check_mode": True},
    )

    assert result["changed"] is True
    assert result["state"] == state
    assert Path(str(result["path"])).parent == parent
    assert sorted(tmp_path.rglob("*")) == before
    if parent_kind == "file":
        assert parent.read_bytes() == b"unchanged"


def test_directory_creates_missing_parents(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    parent = tmp_path / "missing" / "nested"
    result = _response(
        payload, monkeypatch, {"path": str(parent), "state": "directory"}
    )

    assert result["changed"] is True
    assert Path(str(result["path"])).is_dir()
    assert parent.is_dir()


@pytest.mark.parametrize("parent_kind", ["missing", "file"])
def test_file_creation_failure_reports_attempted_change(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    parent_kind: str,
) -> None:
    parent = tmp_path / "parent"
    if parent_kind == "file":
        parent.write_bytes(b"unchanged")
    result = _response(payload, monkeypatch, {"path": str(parent)})

    assert result["changed"] is True
    assert result["failed"] is True
    assert result["state"] == "file"
    assert "path" not in result
    assert str(result["msg"]).startswith(
        "No random temporary file worked in 5 attempts. Error: "
    )
    if parent_kind == "missing":
        assert not parent.exists()
    else:
        assert parent.read_bytes() == b"unchanged"


def test_collisions_retry_without_overwriting_existing_file(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    existing = tmp_path / "ansible.collision"
    existing.write_bytes(b"keep")
    names = iter(["collision", "fresh"])
    monkeypatch.setattr(payload, "_random_name", lambda: next(names))
    result = _response(payload, monkeypatch, {"path": str(tmp_path)})

    assert result["changed"] is True
    assert Path(str(result["path"])).name == "ansible.fresh"
    assert existing.read_bytes() == b"keep"


def test_five_collisions_fail_without_replacing_existing_directory(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    existing = tmp_path / "ansible.collision"
    existing.mkdir()
    marker = existing / "keep"
    marker.write_bytes(b"keep")
    attempts = []

    def _collision() -> str:
        attempts.append(True)
        return "collision"

    monkeypatch.setattr(payload, "_random_name", _collision)
    result = _response(
        payload, monkeypatch, {"path": str(tmp_path), "state": "directory"}
    )

    assert result["failed"] is True
    assert result["changed"] is True
    assert len(attempts) == 5
    assert marker.read_bytes() == b"keep"


def test_alias_wins_over_path_and_preserves_unicode_name(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result = _response(
        payload,
        monkeypatch,
        {
            "path": str(tmp_path / "missing"),
            "dest": str(tmp_path),
            "prefix": "Café 雪 [x]-",
            "suffix": ".bin",
        },
    )

    path = Path(str(result["path"]))
    assert path.parent == tmp_path
    assert path.name.startswith("Café 雪 [x]-")
    assert path.name.endswith(".bin")
    assert path.read_bytes() == b""


def test_null_prefix_and_suffix_are_empty(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result = _response(
        payload,
        monkeypatch,
        {"path": str(tmp_path), "prefix": None, "suffix": None},
    )

    assert re.fullmatch(r"[a-z0-5]{8}\.[a-z0-5]{3}", Path(str(result["path"])).name)


def test_environment_expansion_is_case_insensitive_and_percent_only(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("TEMPFILE_PARENT", str(tmp_path))
    monkeypatch.setenv("TEMPFILE_TEXT", "expanded")
    result = _response(
        payload,
        monkeypatch,
        {
            "path": "%tempfile_parent%",
            "prefix": "%tempfile_text%-$TEMPFILE_TEXT-",
            "suffix": "-%TEMPFILE_TEXT%",
        },
    )

    path = Path(str(result["path"]))
    assert path.parent == tmp_path
    assert path.name.startswith("expanded-$TEMPFILE_TEXT-")
    assert path.name.endswith("-expanded")


@pytest.mark.parametrize("arguments", [{}, {"path": None}, {"dest": None}])
def test_default_directory_comes_from_windows(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    arguments: dict[str, object],
) -> None:
    monkeypatch.setattr(payload, "_temporary_directory", lambda: str(tmp_path))
    result = _response(payload, monkeypatch, arguments)

    assert Path(str(result["path"])).parent == tmp_path
    assert Path(str(result["path"])).is_file()


@pytest.mark.parametrize("check_mode", [False, True])
def test_null_state_is_an_attempted_creation_failure(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    check_mode: bool,
) -> None:
    result = _response(
        payload,
        monkeypatch,
        {"path": str(tmp_path), "state": None, "_ansible_check_mode": check_mode},
    )

    assert result["failed"] is True
    assert result["changed"] is True
    assert result["state"] is None
    assert "path" not in result
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("prefix", ["\\rooted-", "/rooted-"])
def test_leading_prefix_separator_stays_under_selected_parent(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, prefix: str
) -> None:
    result = _response(payload, monkeypatch, {"path": str(tmp_path), "prefix": prefix})

    path = Path(str(result["path"]))
    assert path.parent == tmp_path
    assert path.name.startswith("rooted-")
    assert path.is_file()


@pytest.mark.parametrize("check_mode", [False, True])
def test_drive_qualified_prefix_cannot_escape_selected_parent(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    check_mode: bool,
) -> None:
    result = _response(
        payload,
        monkeypatch,
        {
            "path": str(tmp_path),
            "prefix": "C:\\outside-",
            "_ansible_check_mode": check_mode,
        },
    )

    assert result["changed"] is True
    assert result["failed"] is True
    assert result["state"] == "file"
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize(
    "name_parts",
    [
        {"prefix": "bad*"},
        {"prefix": "bad?"},
        {"suffix": '"'},
        {"suffix": "|"},
        {"suffix": ":stream"},
        {"prefix": "bad<"},
        {"suffix": ">"},
        {"prefix": "bad\x00"},
        {"suffix": "\n"},
    ],
)
def test_invalid_name_fails_without_creating_objects(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    check_mode: bool,
    name_parts: dict[str, str],
) -> None:
    arguments: dict[str, object] = {
        "path": str(tmp_path),
        "_ansible_check_mode": check_mode,
        **name_parts,
    }
    result = _response(payload, monkeypatch, arguments)

    assert result == {
        "changed": True,
        "failed": True,
        "state": "file",
        "msg": "No random temporary file worked in 5 attempts. Error: "
        "Invalid Windows characters in the temporary name.",
    }
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("state", ["file", "directory"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_nested_prefix_follows_parent_creation_rules(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    state: str,
    check_mode: bool,
) -> None:
    result = _response(
        payload,
        monkeypatch,
        {
            "path": str(tmp_path),
            "prefix": "nested/prefix-",
            "state": state,
            "_ansible_check_mode": check_mode,
        },
    )

    assert result["changed"] is True
    if not check_mode and state == "file":
        assert result["failed"] is True
        assert not list(tmp_path.iterdir())
    else:
        path = Path(str(result["path"]))
        assert path.parent == tmp_path / "nested"
        assert path.exists() is not check_mode
        if check_mode:
            assert not list(tmp_path.iterdir())


def test_invocation_contains_converted_parameters_before_expansion(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("TEMPFILE_TEXT", "expanded")
    result = _response(
        payload,
        monkeypatch,
        {
            "dest": str(tmp_path),
            "prefix": "%TEMPFILE_TEXT%",
            "suffix": True,
            "_ansible_inject_invocation": True,
        },
    )

    assert result["invocation"] == {
        "module_args": {
            "dest": str(tmp_path),
            "path": str(tmp_path),
            "prefix": "%TEMPFILE_TEXT%",
            "state": "file",
            "suffix": "True",
        }
    }


@pytest.mark.parametrize(
    "arguments",
    [
        {"path": ""},
        {"path": "   "},
        {"dest": ""},
        {"path": "invalid\x00path"},
        {"state": "unknown"},
        {"extra": "private-value"},
    ],
)
@pytest.mark.parametrize("check_mode", [False, True])
def test_validation_failure_is_unchanged(
    tmp_path: Path, arguments: dict[str, object], check_mode: bool
) -> None:
    process, result = _run(tmp_path, {**arguments, "_ansible_check_mode": check_mode})

    assert process.returncode == 1
    assert result["failed"] is True
    assert result["changed"] is False
    assert "state" not in result
    assert "path" not in result
    assert result["msg"]
    assert "private-value" not in process.stdout


def test_windows_temp_path_uses_native_result_and_resizes_buffer(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    capacities = []

    def _get_temp_path(capacity: int, buffer: object) -> int:
        capacities.append(capacity)
        if capacity == 261:
            return 300
        setattr(buffer, "value", "C:\\AccountTemp\\")
        return len("C:\\AccountTemp\\")

    monkeypatch.setattr(
        payload.ctypes,
        "WinDLL",
        lambda *_args, **_kwargs: SimpleNamespace(GetTempPathW=_get_temp_path),
        raising=False,
    )

    assert payload._temporary_directory() == "C:\\AccountTemp\\"
    assert capacities == [261, 301]


def test_windows_temp_path_failure_is_not_replaced_by_a_local_default(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        payload.ctypes,
        "WinDLL",
        lambda *_args, **_kwargs: SimpleNamespace(GetTempPathW=lambda *_call: 0),
        raising=False,
    )
    monkeypatch.setattr(
        payload.ctypes, "WinError", lambda: OSError("native failure"), raising=False
    )

    with pytest.raises(OSError, match="native failure"):
        payload._temporary_directory()


@pytest.mark.parametrize("missing_parts", [[], ["proposed"], ["missing", "proposed"]])
def test_full_path_expands_existing_short_ancestors(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    missing_parts: list[str],
) -> None:
    short_parent = str(tmp_path / "SHORT~1")
    long_parent = str(tmp_path / "Long directory")

    def _get_long_path(path: str, buffer: object, _capacity: int) -> int:
        if path != short_parent:
            return 0
        if buffer is not None:
            setattr(buffer, "value", long_parent)
        return len(long_parent) + (buffer is None)

    monkeypatch.setattr(
        payload.ctypes,
        "WinDLL",
        lambda *_args, **_kwargs: SimpleNamespace(GetLongPathNameW=_get_long_path),
        raising=False,
    )

    assert payload._full_path(
        os.path.join(short_parent, *missing_parts)
    ) == os.path.join(long_parent, *missing_parts)


def test_full_path_remains_absolute_when_no_ancestor_can_be_expanded(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        payload.ctypes,
        "WinDLL",
        lambda *_args, **_kwargs: SimpleNamespace(GetLongPathNameW=lambda *_call: 0),
        raising=False,
    )

    assert payload._full_path("missing/proposed") == os.path.abspath("missing/proposed")
