"""Exercise observable line edits and JSON failures without accessing Windows."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# The payload's private argument binder is tested as part of the public request.
# pylint: disable=protected-access

import codecs
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module


@pytest.fixture(name="payload")
def line_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the frontend with its real, target-compatible helper closure.

    :param monkeypatch: Scoped import-path additions.
    :returns: Loaded frontend, without running its JSON entry point.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(
        str(ROOT / "legacy_community_windows/plugins/module_utils")
    )
    return load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_lineinfile.py",
        "tested_community_lineinfile",
    )


def _apply(payload: ModuleType, path: Path, **options: object) -> dict[str, Any]:
    check = options.pop("check", False)
    diff = options.pop("diff", False)
    result: dict[str, Any] = payload.manage(
        payload._parameters({"path": str(path), **options}), check, diff
    )
    return result


def test_create_repeat_replace_remove_and_backup(
    payload: ModuleType, tmp_path: Path
) -> None:
    path = tmp_path / "application.ini"
    result = _apply(payload, path, create=True, line="name=old", diff=True)
    assert result["changed"] is True
    assert result["msg"] == "line added"
    assert result["diff"] == {"before": "", "after": "name=old"}
    assert path.read_bytes() == b"name=old"
    assert _apply(payload, path, line="name=old")["changed"] is False
    result = _apply(payload, path, regex="^name=", line="name=new", backup=True)
    assert result["msg"] == "line replaced"
    assert Path(result["backup_file"]).read_bytes() == b"name=old"
    assert path.read_bytes() == b"name=new"
    result = _apply(payload, path, state="absent", regex="^name=")
    assert result["found"] == 1
    assert result["msg"] == "1 line(s) removed"
    assert path.read_bytes() == b""
    assert _apply(payload, path, state="absent", regex="^name=")["changed"] is False


@pytest.mark.parametrize("ending", [b"", b"\n", b"\r", b"\r\n"])
def test_replacement_preserves_final_newline_presence(
    payload: ModuleType, tmp_path: Path, ending: bytes
) -> None:
    path = tmp_path / "file.txt"
    path.write_bytes(b"setting=first\nsetting=last" + ending)
    result = _apply(payload, path, regex="^setting=", line="setting=new", diff=True)
    expected = b"setting=first\r\nsetting=new" + (b"\r\n" if ending else b"")
    assert path.read_bytes() == expected
    assert result["diff"]["after"] == expected.decode()


@pytest.mark.parametrize(
    "options,expected",
    [
        ({"insertbefore": "BOF"}, b"inserted\r\nalpha\r\nbeta\r\nalpha\r\n"),
        ({"insertafter": "BOF"}, b"inserted\r\nalpha\r\nbeta\r\nalpha\r\n"),
        ({"insertbefore": "^alpha$"}, b"alpha\r\nbeta\r\ninserted\r\nalpha\r\n"),
        ({"insertafter": "^alpha$"}, b"alpha\r\nbeta\r\nalpha\r\ninserted\r\n"),
        ({"insertbefore": "missing"}, b"alpha\r\nbeta\r\nalpha\r\ninserted\r\n"),
        ({"insertafter": "missing"}, b"alpha\r\nbeta\r\nalpha\r\ninserted\r\n"),
    ],
)
def test_inserts_at_last_selector_match_or_requested_boundary(
    payload: ModuleType, tmp_path: Path, options: dict[str, Any], expected: bytes
) -> None:
    path = tmp_path / "file.txt"
    path.write_bytes(b"alpha\nbeta\nalpha\n")
    assert _apply(payload, path, line="inserted", **options)["changed"] is True
    assert path.read_bytes() == expected


def test_literal_matching_is_case_sensitive_and_ignores_unicode_line_separators(
    payload: ModuleType, tmp_path: Path
) -> None:
    path = tmp_path / "file.txt"
    path.write_text("Alpha\u2028Beta\nalpha", encoding="utf-8")
    assert _apply(payload, path, line="Alpha")["changed"] is True
    assert path.read_bytes() == "Alpha\u2028Beta\r\nalpha\r\nAlpha".encode()


@pytest.mark.parametrize("after", ["^gamma$", "BOF", "EOF", "("])
def test_insertbefore_ignores_every_insertafter_selector(
    payload: ModuleType, tmp_path: Path, after: str
) -> None:
    path = tmp_path / "selectors.txt"
    path.write_bytes(b"alpha\nbeta\ngamma")
    result = _apply(
        payload, path, line="inserted", insertbefore="^beta$", insertafter=after
    )
    assert result["changed"] is True
    assert result["warnings"] == [
        "Both insertbefore and insertafter parameters found, ignoring "
        f'"insertafter={after}"'
    ]
    assert path.read_bytes() == b"alpha\r\ninserted\r\nbeta\r\ngamma"


def test_backrefs_expand_every_occurrence_only_in_last_matching_line(
    payload: ModuleType, tmp_path: Path
) -> None:
    path = tmp_path / "file.txt"
    path.write_bytes(b"n=1\nn=2 n=3\n")
    _apply(payload, path, regex=r"n=(\d)", line="number=$1", backrefs=True)
    assert path.read_bytes() == b"n=1\r\nnumber=2 number=3\r\n"


def test_named_references_and_literal_dollars(
    payload: ModuleType, tmp_path: Path
) -> None:
    path = tmp_path / "file.txt"
    path.write_bytes(b"prefix=old")
    _apply(
        payload,
        path,
        regex="(?<setting>prefix)=old",
        line="${setting}=$$value",
        backrefs=True,
    )
    assert path.read_bytes() == b"prefix=$value"


def test_unmatched_backrefs_leave_bytes_and_metadata_unchanged(
    payload: ModuleType, tmp_path: Path
) -> None:
    path = tmp_path / "file.txt"
    original = b"untouched\n"
    path.write_bytes(original)
    before = path.stat().st_mtime_ns
    result = _apply(
        payload, path, regex="missing", line="$1", backrefs=True, backup=True
    )
    assert result["changed"] is False
    assert path.read_bytes() == original
    assert path.stat().st_mtime_ns == before
    assert not list(tmp_path.glob("*.bak"))


def test_absent_removes_all_matches_including_final_empty_line(
    payload: ModuleType, tmp_path: Path
) -> None:
    path = tmp_path / "file.txt"
    path.write_bytes(b"drop\nkeep\ndrop\n")
    result = _apply(payload, path, state="absent", regex="^drop$|^$", diff=True)
    assert result["found"] == 3
    assert path.read_bytes() == b"keep"
    assert result["diff"]["after"] == "keep"


@pytest.mark.parametrize(
    "marker,codec,reported",
    [
        (b"", "utf-8", "utf-8"),
        (codecs.BOM_UTF8, "utf-8", "utf-8"),
        (codecs.BOM_UTF16_LE, "utf-16-le", "utf-16"),
        (codecs.BOM_UTF16_BE, "utf-16-be", "utf-16BE"),
        (codecs.BOM_UTF32_LE, "utf-32-le", "utf-32"),
        (codecs.BOM_UTF32_BE, "utf-32-be", "utf-32BE"),
    ],
)
def test_auto_encoding_preserves_unicode_bom(
    payload: ModuleType, tmp_path: Path, marker: bytes, codec: str, reported: str
) -> None:
    path = tmp_path / "file.txt"
    path.write_bytes(marker + "Café 雪\nold\n".encode(codec))
    result = _apply(payload, path, regex="^old$", line="new", newline="unix")
    assert result["encoding"] == reported
    assert path.read_bytes() == marker + "Café 雪\nnew\n".encode(codec)


@pytest.mark.parametrize(
    "encoding,expected",
    [
        ("utf-8", codecs.BOM_UTF8 + "Café".encode()),
        ("utf-16", codecs.BOM_UTF16_LE + "Café".encode("utf-16-le")),
        # The literal byte oracles encode the accented word below; keep the
        # escape and replacement byte visible rather than reusing its encoder.
        ("windows-1252", b"Caf\xe9"),  # codespell:ignore caf
        ("1252", b"Caf\xe9"),  # codespell:ignore caf
        ("ascii", b"Caf?"),  # codespell:ignore caf
    ],
)
def test_explicit_encoding_on_create(
    payload: ModuleType, tmp_path: Path, encoding: str, expected: bytes
) -> None:
    path = tmp_path / "file.txt"
    _apply(payload, path, create=True, line="Café", encoding=encoding)
    assert path.read_bytes() == expected


def test_check_mode_never_creates_destination_or_backup(
    payload: ModuleType, tmp_path: Path
) -> None:
    path = tmp_path / "missing.txt"
    result = _apply(payload, path, create=True, line="created", backup=True, check=True)
    assert result["changed"] is True
    assert not path.exists()
    path.write_bytes(b"before\n")
    result = _apply(
        payload, path, line="after", regex="^before$", backup=True, check=True
    )
    assert result["changed"] is True
    assert path.read_bytes() == b"before\n"
    assert not list(tmp_path.glob("*.bak"))


def test_validate_failure_preserves_original_and_removes_staging(
    payload: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = sys.modules["legacy_community_windows_lineinfile"]
    path = tmp_path / "file.txt"
    path.write_bytes(b"before")
    staged: list[Path] = []

    def validate(proposed: str, _command: str) -> None:
        staged.append(Path(proposed))
        assert staged[-1].read_bytes() == b"after"
        raise ValueError("controlled validation failure")

    monkeypatch.setattr(helper, "_validate", validate)
    with pytest.raises(ValueError, match="controlled validation failure"):
        _apply(
            payload,
            path,
            regex="before",
            line="after",
            validate="validator %s",
            backup=True,
        )
    assert path.read_bytes() == b"before"
    assert staged and not staged[0].exists()
    assert not list(tmp_path.glob("*.bak"))


def test_validator_receives_literal_command_and_reports_exit_code(
    payload: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = sys.modules["legacy_community_windows_lineinfile"]
    process = MagicMock(returncode=7)
    process.__enter__.return_value = process
    process.communicate.return_value = (b"stdout", b"stderr")
    popen = Mock(return_value=process)
    monkeypatch.setattr(helper.subprocess, "Popen", popen)
    with pytest.raises(ValueError, match="exit 7.*stdout stderr"):
        _apply(
            payload,
            tmp_path / "file.txt",
            create=True,
            line="new",
            validate='"validator.exe" "%s" | literal',
        )
    command = popen.call_args.args[0]
    assert command.startswith('"validator.exe" "')
    assert command.endswith('" | literal')
    assert "shell" not in popen.call_args.kwargs
    process.__exit__.assert_called_once()


@pytest.mark.parametrize(
    "case",
    [
        ({}, "Missing required argument: path"),
        ({"path": "file"}, "line= is required"),
        ({"path": "file", "line": "", "create": True}, "line= is required"),
        ({"path": "file", "line": "text", "backrefs": True}, "regexp= is required"),
        ({"path": "file", "state": "absent"}, "one of line= or regexp="),
        ({"path": "file", "line": "text", "state": "invalid"}, "state must"),
        ({"path": "file", "line": "text", "newline": "invalid"}, "newline must"),
    ],
)
def test_invalid_arguments_return_json_failure(
    payload: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    case: tuple[dict[str, Any], str],
) -> None:
    arguments, expected = case
    request = tmp_path / "arguments.json"
    request.write_text(json.dumps(arguments), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["win_lineinfile.py", str(request)])
    code, result = invoke_payload(payload, capsys)
    assert code == 1
    assert result["failed"] is True
    assert result["changed"] is False
    assert expected in result["msg"]


@pytest.mark.parametrize("alias", ["path", "dest", "destfile", "name"])
def test_path_aliases(payload: ModuleType, alias: str) -> None:
    assert payload._parameters({alias: "C:/file", "line": "value"})["path"] == "C:/file"


@pytest.mark.parametrize(
    "options,message",
    [
        ({"regex": "["}, "regular expression"),
        ({"encoding": "not-a-codec"}, "Unknown text encoding"),
        ({"validate": "no-placeholder"}, "validate must contain %s"),
    ],
)
def test_invalid_edit_does_not_modify_file(
    payload: ModuleType, tmp_path: Path, options: dict[str, Any], message: str
) -> None:
    path = tmp_path / "file.txt"
    path.write_bytes(b"old")
    with pytest.raises(ValueError, match=message):
        _apply(payload, path, line="new", **options)
    assert path.read_bytes() == b"old"


def test_directory_and_missing_file_failures(
    payload: ModuleType, tmp_path: Path
) -> None:
    with pytest.raises(ValueError, match="is a directory"):
        _apply(payload, tmp_path, line="new")
    with pytest.raises(ValueError, match="does not exist"):
        _apply(payload, tmp_path / "missing", line="new")
    with pytest.raises(ValueError, match="does not exist"):
        _apply(payload, tmp_path / "missing", state="absent", line="new", create=True)
