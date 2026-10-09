"""Check recorded win_file behavior locally with native Windows boundaries replaced."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Direct payload calls isolate filesystem behavior from Ansible's JSON wrapper.
# pylint: disable=protected-access

import datetime
import itertools
import json
import os
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_payload

FILETIME_EPOCH = 504911232000000000
UNIX_EPOCH = 621355968000000000
SECOND = 10000000
CULTURE = json.loads(
    (ROOT / "tests/fixtures/file_datetime.json").read_text(encoding="utf-8")
)["cultures"]["en-US"]


def _local_ticks(value: datetime.datetime) -> int:
    return (
        (value.toordinal() - 1) * 86400
        + value.hour * 3600
        + value.minute * 60
        + value.second
    ) * SECOND + value.microsecond * 10


def _file_info(path: str) -> dict[str, int] | None:
    entry = Path(path)
    try:
        metadata = entry.lstat()
    except (FileNotFoundError, NotADirectoryError):
        return None
    attributes = 0x10 if entry.is_dir() else 0
    if entry.is_symlink():
        attributes |= 0x400
    return {
        "attributes": attributes,
        "access_time": metadata.st_atime_ns // 100 + UNIX_EPOCH - FILETIME_EPOCH,
        "modification_time": metadata.st_mtime_ns // 100 + UNIX_EPOCH - FILETIME_EPOCH,
    }


def _set_file_time(path: str, is_directory: bool, field: str, value: int) -> None:
    assert Path(path).is_dir() is is_directory
    if value < 0:
        raise ValueError("Not a valid Win32 FileTime.")
    metadata = os.stat(path)
    times = [metadata.st_atime_ns, metadata.st_mtime_ns]
    times[0 if field == "access_time" else 1] = (
        value + FILETIME_EPOCH - UNIX_EPOCH
    ) * 100
    os.utime(path, ns=(times[0], times[1]))


def _read_prefix(path: str, count: int) -> bytes:
    with open(path, "rb") as source:
        return source.read(count)


def _remove_directory(path: str) -> None:
    if Path(path).is_symlink():
        os.unlink(path)
    else:
        os.rmdir(path)


@pytest.fixture(name="payload")
def file_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the module using local files and UTC calendar substitutes.

    :param monkeypatch: Scoped native API substitutions.
    :returns: The imported payload; no Windows host is contacted.
    """
    module = load_payload("win_file", monkeypatch)
    monkeypatch.setattr(
        module.filesystem, "create_empty_file", lambda path: Path(path).touch()
    )
    monkeypatch.setattr(module.filesystem, "file_info", _file_info)
    monkeypatch.setattr(module.filesystem, "set_file_time", _set_file_time)
    monkeypatch.setattr(module.filesystem, "read_prefix", _read_prefix)
    monkeypatch.setattr(module.filesystem, "remove_file", os.unlink)
    monkeypatch.setattr(module.filesystem, "remove_directory", _remove_directory)
    monkeypatch.setattr(module.filesystem, "set_attributes", lambda *_args: None)
    monkeypatch.setattr(module.timestamps.calendar, "get_culture", lambda: CULTURE)
    current = itertools.count(_local_ticks(datetime.datetime(2026, 9, 28)), SECOND)
    monkeypatch.setattr(
        module.native_time, "current_local_ticks", lambda: next(current)
    )
    monkeypatch.setattr(
        module.native_time,
        "file_time_to_local_ticks",
        lambda value: value + FILETIME_EPOCH,
    )
    monkeypatch.setattr(
        module.native_time,
        "local_ticks_to_file_time",
        lambda value: value - FILETIME_EPOCH,
    )
    return module


def _manage(
    payload: ModuleType,
    path: Path | str,
    state: str | None = None,
    *,
    check_mode: bool = False,
    **options: object,
) -> dict[str, Any]:
    arguments = {"path": str(path), **options}
    if state is not None:
        arguments["state"] = state
    result: dict[str, Any] = payload._manage(
        payload._parameters(arguments), check_mode=check_mode
    )
    return result


def _execute(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    arguments: dict[str, object],
) -> dict[str, Any]:
    argument_path = tmp_path / "arguments.json"
    argument_path.write_text(json.dumps(arguments), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["win_file.py", str(argument_path)])
    result: dict[str, Any] = payload._execute()
    return result


def test_directory_creates_parents_and_repeats_without_change(
    payload: ModuleType, tmp_path: Path
) -> None:
    target = tmp_path / "Café 雪 [literal]" / "child"

    assert _manage(payload, target, "directory") == {"changed": True}
    assert target.is_dir()
    assert _manage(payload, target, "directory") == {"changed": False}


def test_touch_creates_empty_file_and_repeated_now_changes(
    payload: ModuleType, tmp_path: Path
) -> None:
    target = tmp_path / "Café 雪 [literal].txt"

    assert _manage(payload, target, "touch") == {"changed": True}
    assert target.read_bytes() == b""
    before = target.stat().st_mtime_ns
    assert _manage(payload, target, "touch") == {"changed": True}
    assert target.stat().st_mtime_ns != before


@pytest.mark.parametrize("directory", [False, True])
def test_touch_preserve_is_unchanged_and_keeps_contents(
    payload: ModuleType, tmp_path: Path, directory: bool
) -> None:
    target = tmp_path / "existing"
    if directory:
        target.mkdir()
        (target / "child").write_bytes(b"keep")
    else:
        target.write_bytes(b"keep")
    before = _file_info(str(target))

    assert _manage(
        payload,
        target,
        "ToUcH",
        access_time="PrEsErVe",
        modification_time="PRESERVE",
    ) == {"changed": False}
    assert _file_info(str(target)) == before
    assert (target / "child" if directory else target).read_bytes() == b"keep"


@pytest.mark.parametrize("directory", [False, True])
def test_touch_fixed_timestamps_are_idempotent(
    payload: ModuleType, tmp_path: Path, directory: bool
) -> None:
    target = tmp_path / "existing"
    if directory:
        target.mkdir()
    else:
        target.write_bytes(b"keep")
    for changed in (True, False):
        assert _manage(
            payload,
            target,
            "touch",
            access_time="2020-02-03 04:05:06",
            modification_time="2021-03-04 05:06:07",
        ) == {"changed": changed}
    metadata = target.stat()
    assert metadata.st_atime_ns == 1580702706000000000
    assert metadata.st_mtime_ns == 1614834367000000000


@pytest.mark.parametrize("state", [None, "file", "directory"])
def test_existing_non_touch_states_validate_but_ignore_timestamps(
    payload: ModuleType, tmp_path: Path, state: str | None
) -> None:
    target = tmp_path / "existing"
    if state == "directory":
        target.mkdir()
    else:
        target.write_bytes(b"keep")
    before = _file_info(str(target))

    assert _manage(
        payload,
        target,
        state,
        access_time="2020-02-03 04:05:06",
        modification_time="2021-03-04 05:06:07",
    ) == {"changed": False}
    assert _file_info(str(target)) == before


def test_new_directory_applies_custom_timestamp_formats(
    payload: ModuleType, tmp_path: Path
) -> None:
    target = tmp_path / "new"

    assert _manage(
        payload,
        target,
        "directory",
        access_time="03/02/2020 04:05:06",
        access_time_format="dd/MM/yyyy HH:mm:ss",
        modification_time="04/03/2021 05:06:07",
        modification_time_format="dd/MM/yyyy HH:mm:ss",
    ) == {"changed": True}
    metadata = target.stat()
    assert metadata.st_atime_ns == 1580702706000000000
    assert metadata.st_mtime_ns == 1614834367000000000


@pytest.mark.parametrize("state", [None, "file"])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("trailing_separator", [False, True])
def test_missing_file_is_never_created(
    payload: ModuleType,
    tmp_path: Path,
    state: str | None,
    check_mode: bool,
    trailing_separator: bool,
) -> None:
    target = str(tmp_path / "missing") + (os.sep if trailing_separator else "")

    assert _manage(payload, target, state, check_mode=check_mode) == {
        "changed": False,
        "failed": True,
        "msg": f"path {target} will not be created",
    }
    assert not Path(target).exists()


@pytest.mark.parametrize("state", ["file", "directory"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_wrong_entry_type_fails_without_replacing_it(
    payload: ModuleType, tmp_path: Path, state: str, check_mode: bool
) -> None:
    target = tmp_path / "existing"
    if state == "file":
        target.mkdir()
    else:
        target.write_bytes(b"keep")

    assert _manage(payload, target, state, check_mode=check_mode) == {
        "changed": False,
        "failed": True,
        "msg": f"path {target} is not a {state}",
    }
    assert target.is_dir() is (state == "file")
    if state == "directory":
        assert target.read_bytes() == b"keep"


@pytest.mark.parametrize("state", ["touch", "directory"])
@pytest.mark.parametrize("parent_kind", ["existing", "missing", "file"])
def test_check_mode_predicts_creation_without_mutation_or_parent_rejection(
    payload: ModuleType, tmp_path: Path, state: str, parent_kind: str
) -> None:
    parent = tmp_path / "parent"
    if parent_kind == "existing":
        parent.mkdir()
    elif parent_kind == "file":
        parent.write_bytes(b"keep")
    before = sorted(tmp_path.rglob("*"))

    assert _manage(payload, parent / "child", state, check_mode=True) == {
        "changed": True
    }
    assert sorted(tmp_path.rglob("*")) == before
    if parent_kind == "file":
        assert parent.read_bytes() == b"keep"


@pytest.mark.parametrize("parent_kind", ["missing", "file"])
def test_touch_requires_existing_directory_parent(
    payload: ModuleType, tmp_path: Path, parent_kind: str
) -> None:
    parent = tmp_path / "parent"
    if parent_kind == "file":
        parent.write_bytes(b"keep")

    result = _manage(payload, parent / "child", "touch")

    assert result["changed"] is False
    assert result["failed"] is True
    assert result["msg"]
    assert not (parent / "child").exists()
    if parent_kind == "file":
        assert parent.read_bytes() == b"keep"


@pytest.mark.parametrize("directory", [False, True])
def test_absent_preserves_check_mode_then_removes_and_repeats_unchanged(
    payload: ModuleType, tmp_path: Path, directory: bool
) -> None:
    target = tmp_path / "existing"
    if directory:
        (target / "child").mkdir(parents=True)
        (target / "child" / "keep").write_bytes(b"contents")
    else:
        target.write_bytes(b"contents")
    before = sorted(tmp_path.rglob("*"))

    assert _manage(payload, target, "absent", check_mode=True) == {"changed": True}
    assert sorted(tmp_path.rglob("*")) == before
    assert _manage(payload, target, "absent") == {"changed": True}
    assert not target.exists()
    assert _manage(payload, target, "absent") == {"changed": False}


@pytest.mark.parametrize("directory", [False, True])
def test_touch_link_updates_target_but_repeats_against_link_metadata(
    payload: ModuleType, tmp_path: Path, directory: bool
) -> None:
    target = tmp_path / "target"
    if directory:
        target.mkdir()
    else:
        target.write_bytes(b"keep")
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=directory)
    before = link.lstat().st_mtime_ns

    for _attempt in range(2):
        assert _manage(
            payload,
            link,
            "touch",
            access_time="preserve",
            modification_time="2020-02-03 04:05:06",
        ) == {"changed": True}
        assert target.stat().st_mtime_ns == 1580702706000000000
        assert link.lstat().st_mtime_ns == before


@pytest.mark.parametrize("broken", [False, True])
def test_absent_removes_link_without_visiting_its_target(
    payload: ModuleType, tmp_path: Path, broken: bool
) -> None:
    target = tmp_path / "target"
    if not broken:
        target.mkdir()
        (target / "keep").write_bytes(b"keep")
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)

    assert _manage(payload, link, "absent", check_mode=True) == {"changed": True}
    assert link.is_symlink()
    assert _manage(payload, link, "absent") == {"changed": True}
    assert not link.is_symlink()
    assert _manage(payload, link, "absent") == {"changed": False}
    if not broken:
        assert (target / "keep").read_bytes() == b"keep"
    else:
        assert not target.exists()


def test_partial_removal_failure_names_child_and_can_recover(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "tree"
    target.mkdir()
    first = target / "first"
    locked = target / "locked"
    first.write_bytes(b"first")
    locked.write_bytes(b"locked")
    # Control the local enumeration order so partial progress is reproducible.
    original_listdir = os.listdir
    monkeypatch.setattr(
        payload.filesystem.os, "listdir", lambda path: sorted(original_listdir(path))
    )

    def _delete(path: str) -> None:
        if Path(path) == locked:
            raise PermissionError(13, "owned writer holds file", path)
        os.unlink(path)

    monkeypatch.setattr(payload.filesystem, "remove_file", _delete)
    result = _manage(payload, target, "absent")

    assert result["failed"] is True
    assert result["changed"] is False
    assert str(result["msg"]).startswith(f"Failed to delete {locked}:")
    assert not first.exists()
    assert locked.read_bytes() == b"locked"
    monkeypatch.setattr(payload.filesystem, "remove_file", os.unlink)
    assert _manage(payload, target, "absent") == {"changed": True}
    assert not target.exists()


def test_timestamp_open_failure_is_unchanged_and_can_recover(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "entry"
    target.write_bytes(b"keep")
    before = _file_info(str(target))
    monkeypatch.setattr(
        payload.filesystem,
        "set_file_time",
        Mock(side_effect=PermissionError("owned writer holds file")),
    )

    result = _manage(payload, target, "touch")

    assert result["failed"] is True
    assert result["changed"] is False
    assert str(result["msg"]).startswith(f"Failed to update timestamps on {target}:")
    assert _file_info(str(target)) == before
    assert _manage(payload, target, "touch", check_mode=True) == {"changed": True}
    assert _file_info(str(target)) == before
    monkeypatch.setattr(payload.filesystem, "set_file_time", _set_file_time)
    assert _manage(payload, target, "touch") == {"changed": True}
    assert target.read_bytes() == b"keep"


@pytest.mark.parametrize("created_state", [None, "touch", "directory"])
def test_partial_timestamp_failure_retains_creation_flag_and_can_recover(
    payload: ModuleType, tmp_path: Path, created_state: str | None
) -> None:
    target = tmp_path / "entry"
    if created_state is None:
        target.write_bytes(b"keep")
        os.utime(target, ns=(946684800000000000, 946684800000000000))

    result = _manage(
        payload,
        target,
        created_state or "touch",
        access_time="1500-01-01 00:00:00",
        modification_time="2020-02-03 04:05:06",
    )

    assert result["failed"] is True
    assert result["changed"] is (created_state is not None)
    assert str(result["msg"]).startswith(f"Failed to update timestamps on {target}:")
    assert target.exists()
    assert target.stat().st_mtime_ns == 1580702706000000000
    if created_state is None:
        assert target.stat().st_atime_ns == 946684800000000000
    assert _manage(
        payload,
        target,
        "touch",
        access_time="2020-02-03 04:05:06",
        modification_time="2020-02-03 04:05:06",
    ) == {"changed": True}
    assert _manage(
        payload,
        target,
        "touch",
        access_time="2020-02-03 04:05:06",
        modification_time="2020-02-03 04:05:06",
    ) == {"changed": False}


def test_check_mode_does_not_open_or_validate_native_timestamp_range(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "entry"
    target.write_bytes(b"keep")
    before = _file_info(str(target))
    setter = Mock(side_effect=AssertionError("check mode opened a setter"))
    monkeypatch.setattr(payload.filesystem, "set_file_time", setter)

    assert _manage(
        payload,
        target,
        "touch",
        check_mode=True,
        access_time="1500-01-01 00:00:00",
        modification_time="2020-02-03 04:05:06",
    ) == {"changed": True}
    assert _file_info(str(target)) == before
    setter.assert_not_called()


def test_timestamp_setter_refreshes_metadata_before_comparing_access_time(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "entry"
    target.write_bytes(b"keep")
    desired = 1580702706000000000
    os.utime(target, ns=(desired, 946684800000000000))
    fields = []

    def _set(path: str, directory: bool, field: str, value: int) -> None:
        fields.append(field)
        _set_file_time(path, directory, field, value)
        if field == "modification_time":
            # Opening a native setter can invalidate the cached access time.
            metadata = os.stat(path)
            os.utime(path, ns=(946684800000000000, metadata.st_mtime_ns))

    monkeypatch.setattr(payload.filesystem, "set_file_time", _set)

    assert _manage(
        payload,
        target,
        "touch",
        access_time="2020-02-03 04:05:06",
        modification_time="2020-02-03 04:05:06",
    ) == {"changed": True}
    assert fields == ["modification_time", "access_time"]
    assert target.stat().st_atime_ns == desired


@pytest.mark.parametrize("state", ["file", "directory", "touch", "absent"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_invalid_access_time_fails_before_modification_time_or_state_work(
    payload: ModuleType, tmp_path: Path, state: str, check_mode: bool
) -> None:
    target = tmp_path / "entry"
    target.write_bytes(b"keep")
    before = _file_info(str(target))

    assert _manage(
        payload,
        target,
        state,
        check_mode=check_mode,
        access_time="invalid-access",
        modification_time="invalid-modification",
    ) == {
        "failed": True,
        "changed": False,
        "msg": "Invalid access_time 'invalid-access'",
    }
    assert _file_info(str(target)) == before
    assert target.read_bytes() == b"keep"


@pytest.mark.parametrize("pattern", [None, "", "not a date pattern"])
def test_invalid_modification_format_fails_even_when_state_ignores_timestamps(
    payload: ModuleType, tmp_path: Path, pattern: str | None
) -> None:
    target = tmp_path / "entry"
    target.write_bytes(b"keep")

    assert _manage(
        payload,
        target,
        "file",
        modification_time="2020-02-03 04:05:06",
        modification_time_format=pattern,
    ) == {
        "failed": True,
        "changed": False,
        "msg": "Invalid modification_time '2020-02-03 04:05:06'",
    }


@pytest.mark.parametrize(
    "arguments",
    [
        {"path": "primary", "dest": "secondary", "name": "third"},
        {"dest": "primary", "name": "secondary"},
        {"name": "primary"},
    ],
)
def test_path_alias_precedence(
    payload: ModuleType, arguments: dict[str, object]
) -> None:
    assert payload._parameters(arguments)["path"] == "primary"


@pytest.mark.parametrize("path", [None, ""])
def test_invalid_primary_path_does_not_fall_back_to_alias(
    payload: ModuleType, path: object
) -> None:
    with pytest.raises(ValueError, match="path"):
        payload._parameters({"path": path, "dest": "valid"})


@pytest.mark.parametrize("arguments", [{}, {"state": None}, {"state": False}])
def test_required_path_and_explicit_invalid_state_fail(
    payload: ModuleType, arguments: dict[str, object]
) -> None:
    if "state" in arguments:
        arguments = {"path": "entry", **arguments}
    with pytest.raises(ValueError, match="path|state"):
        payload._parameters(arguments)


def test_execute_accepts_case_insensitive_arguments_and_ignores_unknown_options(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "entry"
    target.write_bytes(b"keep")

    assert _execute(
        payload,
        monkeypatch,
        tmp_path,
        {
            "PATH": str(target),
            "STATE": "FiLe",
            "unused": "private value",
            "_ansible_check_mode": True,
        },
    ) == {"changed": False}


def test_null_touch_timestamps_use_now(payload: ModuleType, tmp_path: Path) -> None:
    target = tmp_path / "entry"
    target.write_bytes(b"keep")
    os.utime(target, ns=(946684800000000000, 946684800000000000))

    assert _manage(
        payload, target, "touch", access_time=None, modification_time=None
    ) == {"changed": True}
    assert target.stat().st_atime_ns > 946684800000000000
    assert target.stat().st_mtime_ns > 946684800000000000


def test_original_basename_resolves_existing_directory_before_creation(
    payload: ModuleType, tmp_path: Path
) -> None:
    assert _manage(
        payload,
        tmp_path,
        "touch",
        _original_basename="Café 雪 [child].txt",
        access_time="preserve",
        modification_time="preserve",
    ) == {"changed": True}
    assert (tmp_path / "Café 雪 [child].txt").read_bytes() == b""


@pytest.mark.parametrize("existing", [False, True])
def test_original_basename_does_not_redirect_a_non_directory(
    payload: ModuleType, tmp_path: Path, existing: bool
) -> None:
    target = tmp_path / "entry"
    if existing:
        target.write_bytes(b"keep")

    assert _manage(
        payload,
        target,
        "touch",
        _original_basename="child",
        access_time="preserve",
        modification_time="preserve",
    ) == {"changed": not existing}
    assert target.read_bytes() == (b"keep" if existing else b"")


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize(
    ("contents", "binary"),
    [
        (b"", False),
        (b"plain text", False),
        (b"\x00", True),
        (b"a" * 8191 + b"\x00", True),
        (b"a" * 8192 + b"\x00", False),
    ],
)
def test_diff_peek_false_and_true_read_only_first_8192_bytes(
    payload: ModuleType,
    tmp_path: Path,
    enabled: bool,
    contents: bytes,
    binary: bool,
) -> None:
    target = tmp_path / "entry"
    target.write_bytes(contents)

    result = _manage(payload, target, "absent", _diff_peek=enabled)

    assert result == {
        "change": False,
        "changed": False,
        "path": str(target),
        "appears_binary": binary,
        "state": "file",
    }
    assert target.read_bytes() == contents


@pytest.mark.parametrize("directory", [False, True])
def test_diff_peek_missing_path_and_directory(
    payload: ModuleType, tmp_path: Path, directory: bool
) -> None:
    target = tmp_path / "entry"
    if directory:
        target.mkdir()

    assert _manage(payload, target, _diff_peek=True) == {
        "change": False,
        "changed": False,
        "path": str(target),
        "appears_binary": False,
        "state": "file" if directory else "absent",
    }


def test_diff_peek_swallows_native_reader_failure(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    target = tmp_path / "entry"
    target.write_bytes(b"\x00")
    monkeypatch.setattr(
        payload.filesystem,
        "read_prefix",
        Mock(side_effect=PermissionError("owned writer holds file")),
    )

    assert _manage(payload, target, _diff_peek=True) == {
        "change": False,
        "changed": False,
        "path": str(target),
        "appears_binary": False,
        "state": "file",
    }


def test_diff_peek_null_disables_peek_but_invalid_time_precedes_peek(
    payload: ModuleType, tmp_path: Path
) -> None:
    target = tmp_path / "entry"
    target.write_bytes(b"\x00")

    assert _manage(payload, target, "file", _diff_peek=None) == {"changed": False}
    assert _manage(payload, target, _diff_peek=False, access_time="invalid") == {
        "failed": True,
        "changed": False,
        "msg": "Invalid access_time 'invalid'",
    }
    assert target.read_bytes() == b"\x00"
