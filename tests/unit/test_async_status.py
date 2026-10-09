"""Exercise job-cache behavior without claiming Windows execution evidence."""

# SPDX-License-Identifier: GPL-3.0-or-later

import codecs
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from tests.unit.payload_support import invoke_payload, load_payload


def _invoke(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    contents: bytes | None,
    **arguments: Any,
) -> tuple[int, dict[str, Any]]:
    payload = load_payload("async_status", monkeypatch)
    monkeypatch.setattr(payload.locale, "getpreferredencoding", lambda _flag: "cp1252")
    monkeypatch.setattr(payload, "_attributes", lambda _path: 0x10)
    arguments = {"jid": "123", "_async_dir": str(tmp_path), **arguments}
    if contents is not None:
        (tmp_path / "123").write_bytes(contents)
    argument_file = tmp_path / "arguments.json"
    argument_file.write_text(json.dumps(arguments), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["async_status.py", str(argument_file)])
    return invoke_payload(payload, capsys)


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize(
    "case",
    [
        ({}, {"finished": 1, "ansible_job_id": "123", "changed": False}),
        ({"started": 1}, {"started": 1, "finished": 0, "changed": False}),
        (
            {"started": 0, "finished": 0},
            {"started": 0, "finished": 0, "changed": False},
        ),
        ({"finished": 0}, {"finished": 1, "ansible_job_id": "123", "changed": False}),
        (
            {"Started": 1, "Finished": 1},
            {"Started": 1, "Finished": 1, "changed": False},
        ),
        ({"Finished": 0}, {"Finished": 1, "ansible_job_id": "123", "changed": False}),
        (
            {"changed": True, "stdout": "done"},
            {"changed": True, "stdout": "done", "finished": 1, "ansible_job_id": "123"},
        ),
        (
            {"started": 1, "ansible_job_id": "stored", "nested": {"field": [1, None]}},
            {
                "started": 1,
                "ansible_job_id": "stored",
                "nested": {"field": [1, None]},
                "finished": 0,
                "changed": False,
            },
        ),
    ],
)
def test_object_records_preserve_all_fields_and_do_not_write(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    case: tuple[dict[str, Any], dict[str, Any]],
    check: bool,
) -> None:
    data, expected = case
    contents = json.dumps(data).encode()
    code, result = _invoke(
        monkeypatch, capsys, tmp_path, contents, _ansible_check_mode=check
    )

    assert code == 0
    assert result == expected
    assert (tmp_path / "123").read_bytes() == contents


@pytest.mark.parametrize("contents", [b"", b" \r\n", b"null", b"[]"])
def test_null_output_preserves_upstream_unhandled_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    contents: bytes,
) -> None:
    code, result = _invoke(monkeypatch, capsys, tmp_path, contents)

    assert code == 1
    assert result == {
        "changed": False,
        "failed": True,
        "exception": "(traceback unavailable)",
        "msg": "Unhandled exception while executing module: "
        "You cannot call a method on a null-valued expression.",
    }
    assert (tmp_path / "123").read_bytes() == contents


@pytest.mark.parametrize("contents", [b"{", b'{"started":1,"Started":2}'])
def test_invalid_json_reports_finished_failure_without_rewriting(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    contents: bytes,
) -> None:
    code, result = _invoke(monkeypatch, capsys, tmp_path, contents)

    assert code == 1
    assert result == {
        "changed": False,
        "failed": True,
        "ansible_job_id": "123",
        "results_file": str(tmp_path / "123"),
        "started": 1,
        "finished": 1,
        "msg": "Could not parse job output: ",
    }
    assert (tmp_path / "123").read_bytes() == contents


@pytest.mark.parametrize("mode", ["status", "cleanup"])
def test_missing_job_is_finished_failure_for_both_modes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    mode: str,
) -> None:
    code, result = _invoke(monkeypatch, capsys, tmp_path, None, mode=mode)

    assert code == 1
    assert result["finished"] == result["started"] == 1
    assert result["msg"] == "could not find job at '" + str(tmp_path) + "'"
    assert not (tmp_path / "123").exists()


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("directory", [False, True])
def test_cleanup_erases_only_the_requested_entry_even_in_check_mode(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    check: bool,
    directory: bool,
) -> None:
    job = tmp_path / "123"
    if directory:
        (job / "nested").mkdir(parents=True)
        (job / "nested" / "child").write_bytes(b"owned")
    else:
        job.write_bytes(b"{}")
    sibling = tmp_path / "preserved"
    sibling.write_bytes(b"unchanged")

    code, result = _invoke(
        monkeypatch, capsys, tmp_path, None, mode="cleanup", _ansible_check_mode=check
    )

    assert code == 0
    assert result == {"changed": False, "ansible_job_id": "123", "erased": str(job)}
    assert not job.exists()
    assert sibling.read_bytes() == b"unchanged"


@pytest.mark.parametrize(
    "encoding", ["utf-8-sig", "utf-16", "utf-32", "utf-16-be", "utf-32-be", "cp1252"]
)
def test_encoding_markers_and_windows_ansi_reader(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    encoding: str,
) -> None:
    text = '{"stdout":"café"}'
    contents = text.encode(encoding)
    if encoding == "utf-16-be":
        contents = codecs.BOM_UTF16_BE + contents
    if encoding == "utf-32-be":
        contents = codecs.BOM_UTF32_BE + contents

    code, result = _invoke(monkeypatch, capsys, tmp_path, contents)

    assert code == 0
    assert result["stdout"] == "café"


def test_unmarked_utf8_is_read_using_ansi_not_silently_corrected(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    code, result = _invoke(
        monkeypatch, capsys, tmp_path, '{"stdout":"\u00e9 \u2603"}'.encode()
    )

    assert code == 0
    assert result["stdout"] == "\u00c3\u00a9 \u00e2\u02dc\u0192"


@pytest.mark.parametrize(
    ("contents", "typename"),
    [
        (b"42", "System.Int32"),
        (b"[1,2]", "System.Int32"),
        (b"true", "System.Boolean"),
        (b'"text"', "System.String"),
    ],
)
def test_non_object_output_has_upstream_type_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    contents: bytes,
    typename: str,
) -> None:
    code, result = _invoke(monkeypatch, capsys, tmp_path, contents)

    assert code == 1
    assert result["exception"] == "(traceback unavailable)"
    assert (
        "[" + typename + "] does not contain a method named 'ContainsKey'."
        in result["msg"]
    )


@pytest.mark.parametrize("contents", [b"[{}]", b'[{"started":1}]'])
def test_object_array_output_has_upstream_array_index_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    contents: bytes,
) -> None:
    code, result = _invoke(monkeypatch, capsys, tmp_path, contents)

    assert code == 1
    assert result == {
        "changed": False,
        "failed": True,
        "exception": "(traceback unavailable)",
        "msg": (
            "Unhandled exception while executing module: "
            'Cannot convert value "finished" to type "System.Int32". Error: '
            '"Input string was not in a correct format."'
        ),
    }
    assert (tmp_path / "123").read_bytes() == contents


def test_directory_read_is_reported_as_running(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    (tmp_path / "123").mkdir()
    code, result = _invoke(monkeypatch, capsys, tmp_path, None)

    assert code == 0
    assert result["started"] == 1 and result["finished"] == 0
    assert (tmp_path / "123").is_dir()


@pytest.mark.parametrize("jid", [None, ""])
def test_explicit_empty_identifier_reads_the_directory_without_trailing_slash(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    jid: str | None,
) -> None:
    code, result = _invoke(monkeypatch, capsys, tmp_path, None, jid=jid)

    assert code == 0
    assert result == {
        "changed": False,
        "ansible_job_id": "",
        "results_file": str(tmp_path),
        "started": 1,
        "finished": 0,
    }
