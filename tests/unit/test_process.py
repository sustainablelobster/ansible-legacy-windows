"""Check shared process behavior locally without contacting Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Pure helpers are tested directly where executing Windows APIs is not possible.
# pylint: disable=protected-access

import codecs
import datetime
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import cast
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="helper")
def process_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the target process helper with the developer interpreter.

    :param monkeypatch: Scoped import path for the adjacent text helper.
    :returns: The loaded Python 3.4-compatible process helper.
    """
    source = ROOT / "legacy_windows/plugins/module_utils/legacy_windows_process.py"
    monkeypatch.syspath_prepend(str(source.parent))
    return load_module(source, "tested_process")


@pytest.fixture(name="text_helper")
def text_decoder() -> ModuleType:
    """Load the shared target text decoder with the developer interpreter.

    :returns: The loaded Python 3.4-compatible text helper.
    """
    source = ROOT / "legacy_windows/plugins/module_utils/legacy_windows_text.py"
    return load_module(source, "tested_text")


@pytest.mark.parametrize("existing_console", [False, True])
@pytest.mark.parametrize("launch_fails", [False, True])
def test_child_inherits_utf8_from_existing_or_allocated_console(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    existing_console: bool,
    launch_fails: bool,
) -> None:
    kernel = Mock()
    kernel.GetConsoleWindow.return_value = int(existing_console)
    kernel.AllocConsole.return_value = True
    monkeypatch.setattr(
        helper.ctypes, "WinDLL", Mock(return_value=kernel), raising=False
    )
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(helper, "resolve_executable", lambda value, _directory: value)
    child = object()

    def _launch(*_args: object, **_kwargs: object) -> object:
        kernel.SetConsoleCP.assert_called_once_with(65001)
        kernel.SetConsoleOutputCP.assert_called_once_with(65001)
        if launch_fails:
            raise OSError("launch failed")
        return child

    monkeypatch.setattr(helper.subprocess, "Popen", _launch)
    if launch_fails:
        with pytest.raises(OSError, match="launch failed"):
            helper._start_process("tool.exe", "tool.exe argument", None)
    else:
        assert helper._start_process("tool.exe", "tool.exe argument", None) is child
    assert kernel.AllocConsole.call_count == int(not existing_console)
    assert kernel.FreeConsole.call_count == int(not existing_console)


def test_guard_below_a_file_is_missing(helper: ModuleType, tmp_path: Path) -> None:
    parent_file = tmp_path / "file"
    parent_file.touch()

    assert not helper._path_exists(str(parent_file / "child"))


def test_access_error_is_not_treated_as_missing(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    def denied(_path: str) -> None:
        raise PermissionError("Access denied")

    monkeypatch.setattr(helper.os, "stat", denied)
    with pytest.raises(PermissionError, match="Access denied"):
        helper._path_exists("private")


def test_path_search_precedes_working_directory(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    search_directory = tmp_path / "search"
    working_directory = tmp_path / "working"
    search_directory.mkdir()
    working_directory.mkdir()
    search_program = search_directory / "tool.exe"
    search_program.touch()
    (working_directory / "tool.exe").touch()
    monkeypatch.setenv("PATH", str(search_directory))

    assert helper.resolve_executable("tool", str(working_directory)) == str(
        search_program
    )
    monkeypatch.setenv("PATH", "")
    assert helper.resolve_executable("tool", str(working_directory)) == str(
        working_directory / "tool.exe"
    )


@pytest.mark.parametrize(
    ("executable", "expected"),
    [("", ".exe"), (".exe", ".exe"), ("probe.", "probe..exe")],
)
def test_windows_extension_detection_preserves_leading_dot(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    executable: str,
    expected: str,
) -> None:
    monkeypatch.setenv("PATH", "")
    assert helper.resolve_executable(executable, None) == expected


@pytest.mark.parametrize(
    ("data", "encoding", "expected"),
    [
        (b"line\r\nend \t", "utf-8", "line\r\nend \t"),
        ("日本".encode("shift_jis"), "shift_jis", "日本"),
        ("über".encode("utf-8"), "ascii", "??ber"),
        (b"\xff", "utf-8", "\ufffd"),
        (codecs.BOM_UTF8 + "☃".encode("utf-8"), "ascii", "☃"),
        (codecs.BOM_UTF16_LE + "☃".encode("utf-16-le"), "ascii", "☃"),
        (codecs.BOM_UTF16_BE + "☃".encode("utf-16-be"), "ascii", "☃"),
        (codecs.BOM_UTF32_LE + "☃".encode("utf-32-le"), "ascii", "☃"),
        (codecs.BOM_UTF32_BE + "☃".encode("utf-32-be"), "ascii", "☃"),
    ],
)
def test_output_decoding_and_bom_precedence(
    text_helper: ModuleType, data: bytes, encoding: str, expected: str
) -> None:
    assert text_helper.decode_bytes(data, encoding) == expected


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"\xc0\xaf", "\ufffd\ufffd"),
        (b"\xe0\x80\x80", "\ufffd\ufffd"),
        (b"\xe0\x9f\xbf", "\ufffd\ufffd"),
        (b"\xed\xa0\x80", "\ufffd\ufffd"),
        (b"\xed\xbf\xbf", "\ufffd\ufffd"),
        (b"\xf0\x80\x80\x80", "\ufffd\ufffd\ufffd"),
        (b"\xf4\x90\x80\x80", "\ufffd\ufffd\ufffd"),
        (b"\xf5\x80\x80\x80", "\ufffd\ufffd\ufffd\ufffd"),
        (b"\xe2\x82", "\ufffd"),
        (b"\xf0\x90\x80", "\ufffd"),
        (b"\xe2\x82a", "\ufffda"),
        (b"\xf0\x90a", "\ufffda"),
        (b"\xf0\x90\x80a", "\ufffda"),
        (b"\xff\xfe", "\ufffd\ufffd"),
    ],
)
def test_utf8_replacement_matches_recorded_reference(
    text_helper: ModuleType, data: bytes, expected: str
) -> None:
    # Prefix prevents FF FE from being interpreted as a stream-opening UTF-16 BOM.
    assert text_helper.decode_bytes(b"prefix|" + data, "utf-8") == "prefix|" + expected


def test_utf8_bom_uses_the_same_replacement_rules(text_helper: ModuleType) -> None:
    assert text_helper.decode_bytes(codecs.BOM_UTF8 + b"\xed\xa0\x80", "ascii") == (
        "\ufffd\ufffd"
    )


@pytest.mark.parametrize("text", ["\u0800", "\ud7ff", "\U00010000", "\U0010ffff"])
def test_utf8_valid_boundaries_are_not_replaced(
    text_helper: ModuleType, text: str
) -> None:
    assert text_helper.decode_bytes(text.encode("utf-8"), "utf-8") == text


def test_shift_jis_windows_extensions_match_recorded_reference(
    helper: ModuleType,
    text_helper: ModuleType,
) -> None:
    encoding = helper._output_encoding("shift_jis")
    assert encoding == "cp932"
    assert text_helper.decode_bytes(b"\x81\x60\xfa\x40", encoding) == "\uff5e\u2170"


def test_windows_1252_undefined_bytes_preserve_control_characters(
    text_helper: ModuleType,
) -> None:
    assert (
        text_helper.decode_bytes(b"A\xe9 \x80 \x81\x8d\x8f\x90\x9d", "cp1252")
        == "A\u00e9 \u20ac \u0081\u008d\u008f\u0090\u009d"
    )


def test_unicode_alias_is_little_endian_without_a_bom(
    helper: ModuleType, text_helper: ModuleType
) -> None:
    encoding = helper._output_encoding("unicode")
    assert encoding == "utf-16-le"
    assert text_helper.decode_bytes(b"A\x00\xea\x96", encoding) == "A\u96ea"


@pytest.mark.parametrize("name", [None, "", "utf-8", "UTF-8"])
def test_utf8_encoding_names(helper: ModuleType, name: str | None) -> None:
    assert helper._output_encoding(name) == "utf-8"


@pytest.mark.parametrize("name", ["utf8", "UTF8", "cp65001", "CP65001"])
def test_unrecognized_windows_utf8_aliases_fail(helper: ModuleType, name: str) -> None:
    with pytest.raises(ValueError, match="Unsupported output_encoding_override"):
        helper._output_encoding(name)


@pytest.mark.parametrize(
    "name",
    [
        "no-such-encoding",
        "base64_codec",
        "zlib",
        "bz2",
        "idna",
        "rot_13",
        "punycode",
        "unicode_escape",
        "raw_unicode_escape",
        "unicode_internal",
    ],
)
def test_unknown_or_nontext_codec_is_actionable(helper: ModuleType, name: str) -> None:
    with pytest.raises(ValueError, match="Unsupported output_encoding_override"):
        helper._output_encoding(name)


@pytest.mark.parametrize(
    "name",
    [
        "idna",
        "base64_codec",
        "zlib",
        "bz2",
        "rot_13",
        "punycode",
        "unicode_escape",
        "raw_unicode_escape",
        "unicode_internal",
    ],
)
def test_unsupported_codec_never_launches_a_child(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    def must_not_launch(*_args: object) -> None:
        pytest.fail("Invalid output encoding launched a child process")

    monkeypatch.setattr(helper, "_start_process", must_not_launch)
    parameters = {"chdir": None, "stdin": None, "output_encoding_override": name}
    result = helper.run_command(None, "program.exe", parameters)

    assert result["failed"] is True
    assert result["changed"] is False
    assert result["rc"] == 2
    assert result["cmd"] == "program.exe"
    assert "Unsupported output_encoding_override" in result["msg"]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (None, None),
        ("", None),
        ("☃\r\n", b"\xe2\x98\x83\r\n"),
        ("\ud800", b"\xef\xbf\xbd"),
        ("\udc00", b"\xef\xbf\xbd"),
        ("\ud800A\udc00", b"\xef\xbf\xbdA\xef\xbf\xbd"),
        ("\ud83e\udd9e", b"\xf0\x9f\xa6\x9e"),
        ("\ud800\ud800\udc00", b"\xef\xbf\xbd\xf0\x90\x80\x80"),
    ],
)
def test_stdin_encodes_with_utf16_surrogate_replacement(
    helper: ModuleType, text: str | None, expected: bytes | None
) -> None:
    assert helper._stdin_bytes(text) == expected


def test_stdin_encoding_failure_cannot_leave_a_child(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    def reject_stdin(_text: str) -> None:
        raise UnicodeError("Cannot encode test input")

    def must_not_launch(*_args: object) -> None:
        pytest.fail("Stdin conversion failure launched a child process")

    monkeypatch.setattr(helper, "_stdin_bytes", reject_stdin)
    monkeypatch.setattr(helper, "_start_process", must_not_launch)
    result = helper.run_command(
        None,
        "program.exe",
        {"chdir": None, "stdin": None, "output_encoding_override": None},
    )

    assert result["failed"] is True
    assert result["changed"] is False
    assert result["rc"] == 2
    assert "Cannot encode test input" in result["msg"]


def _complete_child(
    helper: ModuleType, code: str, stdin: str | None = None
) -> dict[str, object]:
    started = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    with subprocess.Popen(
        [sys.executable, "-c", code],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        return cast(
            dict[str, object],
            helper._complete_process(
                process,
                stdin.encode("utf-8") if stdin is not None else None,
                "utf-8",
                "test child",
                started,
            ),
        )


def test_child_stdin_output_and_timings(helper: ModuleType) -> None:
    result = _complete_child(
        helper,
        "import sys; data = sys.stdin.buffer.read(); "
        "sys.stdout.buffer.write(data); sys.stderr.buffer.write(b'error \\r\\n')",
        "☃\r\nlast line",
    )

    assert result["changed"] is True
    assert result["rc"] == 0
    assert result["cmd"] == "test child"
    assert result["stdout"] == "☃\r\nlast line"
    assert result["stderr"] == "error \r\n"
    assert "failed" not in result
    for name in ("start", "end"):
        assert re.fullmatch(
            r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{6}", str(result[name])
        )
    assert re.fullmatch(r"\d+:\d{2}:\d{2}\.\d{6}", str(result["delta"]))


def test_large_interleaved_output_does_not_deadlock(helper: ModuleType) -> None:
    result = _complete_child(
        helper,
        "import os\nfor unused in range(64):\n"
        "    os.write(1, b'x' * 8192)\n    os.write(2, b'y' * 8192)\n",
    )

    assert result["stdout"] == "x" * (64 * 8192)
    assert result["stderr"] == "y" * (64 * 8192)
    assert result["rc"] == 0


def test_nonzero_exit_keeps_output_and_changed_status(helper: ModuleType) -> None:
    result = _complete_child(
        helper, "import sys; print('before failure'); sys.exit(23)"
    )

    assert result["changed"] is True
    assert result["failed"] is True
    assert result["rc"] == 23
    assert result["stdout"] == "before failure\n"
    assert result["msg"] == "non-zero return code"


def test_launch_failure_uses_windows_error_code(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    def denied(*_args: object) -> None:
        error = OSError("Access denied")
        setattr(error, "winerror", 5)
        raise error

    monkeypatch.setattr(helper, "_start_process", denied)
    result = helper.run_command(
        None,
        "private.exe",
        {"chdir": None, "stdin": None, "output_encoding_override": None},
    )

    assert result == {
        "changed": False,
        "failed": True,
        "cmd": "private.exe",
        "rc": 5,
        "msg": "Failed to run: 'private.exe': Access denied",
    }
