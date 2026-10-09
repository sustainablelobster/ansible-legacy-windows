"""Exercise PowerShell subprocess lifetime and scratch cleanup without Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# The private engine path/cleanup functions are the lifetime boundaries under test.
# pylint: disable=protected-access

import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from tests.unit.payload_support import load_payload


@pytest.fixture(name="engine")
def engine_fixture(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load the helper without starting an installed engine.

    :param monkeypatch: Scoped target imports.
    :returns: Loaded subprocess helper.
    """
    load_payload("win_powershell", monkeypatch)
    return sys.modules["legacy_windows_powershell_engine"]


def _process(output: bytes, error: bytes = b"") -> MagicMock:
    process = MagicMock(returncode=0)
    process.__enter__.return_value = process
    process.communicate.return_value = (output, error)
    return process


def test_request_file_avoids_command_length_and_preserves_host_text(
    engine: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(engine, "_engine_path", lambda _: "powershell.exe")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(engine.tempfile, "mkdtemp", lambda **_: str(scratch))
    cleanup = MagicMock()
    monkeypatch.setattr(engine, "_remove_scratch", cleanup)
    child = _process("host λ\r\n".encode(), b"error\r\n")

    def communicate(encoded: bytes) -> tuple[bytes, bytes]:
        """Record the request and return the simulated engine's host streams.

        :param encoded: Serialized engine request.
        :returns: Simulated direct stdout and stderr.
        """
        request = json.loads(encoded)
        assert request["script"] == "'λ'"
        Path(request["result_path"]).write_text(
            '{"changed":false,"output":[1]}', encoding="utf-8"
        )
        return "host λ\r\n".encode(), b"error\r\n"

    child.communicate.side_effect = communicate
    start = MagicMock(side_effect=[_process(b"5.1.26100.7462\r\n"), child])
    monkeypatch.setattr(engine.subprocess, "Popen", start)
    assert engine.invoke_script({"script": "'λ'", "arguments": ["ignored"]}) == {
        "changed": False,
        "output": [1],
        "host_out": "host λ\r\n",
        "host_err": "error\r\n",
    }
    argv = start.call_args.args[0]
    assert "ignored" not in argv and "-File" in argv
    assert Path(argv[-1]).read_text(encoding="utf-8-sig") == engine._ENGINE_SCRIPT
    assert "-EncodedCommand" not in argv
    assert start.call_args.kwargs["env"]["TEMP"] == str(scratch)
    assert start.call_args.kwargs["env"]["TMP"] == str(scratch)
    cleanup.assert_called_once_with(str(scratch))
    assert child.__exit__.call_count == 1


def test_missing_engine_never_creates_scratch(
    engine: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(engine.os.path, "isfile", lambda _: False)
    start = MagicMock()
    scratch = MagicMock()
    monkeypatch.setattr(engine.subprocess, "Popen", start)
    monkeypatch.setattr(engine.tempfile, "mkdtemp", scratch)
    with pytest.raises(OSError, match="PowerShell 5.1"):
        engine.invoke_script({"script": "1"})
    start.assert_not_called()
    scratch.assert_not_called()


def test_obsolete_engine_is_rejected_before_modern_adapter(
    engine: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(engine, "_engine_path", lambda _: "powershell.exe")
    start = MagicMock(return_value=_process(b"2.0\r\n"))
    monkeypatch.setattr(engine.subprocess, "Popen", start)
    scratch = MagicMock()
    monkeypatch.setattr(engine.tempfile, "mkdtemp", scratch)
    with pytest.raises(ValueError, match="selected engine is 2.0"):
        engine.invoke_script({"script": "1"})
    assert start.call_count == 1
    scratch.assert_not_called()


def test_launch_failure_still_cleans_owned_scratch(
    engine: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(engine, "_engine_path", lambda _: "powershell.exe")
    monkeypatch.setattr(engine.tempfile, "mkdtemp", lambda **_: str(tmp_path))
    cleanup = MagicMock()
    monkeypatch.setattr(engine, "_remove_scratch", cleanup)
    start = MagicMock(side_effect=[_process(b"5.1.0\r\n"), OSError("launch failed")])
    monkeypatch.setattr(engine.subprocess, "Popen", start)
    with pytest.raises(OSError, match="launch failed"):
        engine.invoke_script({"script": "1"})
    cleanup.assert_called_once_with(str(tmp_path))


def test_scratch_cleanup_does_not_traverse_directory_reparse_target(
    engine: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    kernel = MagicMock()
    kernel.GetFileAttributesW.return_value = 0x410
    monkeypatch.setattr(
        engine.ctypes, "WinDLL", MagicMock(return_value=kernel), raising=False
    )
    list_directory = MagicMock()
    remove_directory = MagicMock()
    monkeypatch.setattr(engine.os, "listdir", list_directory)
    monkeypatch.setattr(engine.os, "rmdir", remove_directory)
    engine._remove_scratch("owned-junction")
    list_directory.assert_not_called()
    remove_directory.assert_called_once_with("owned-junction")


def test_owned_readonly_file_is_made_deletable_without_changing_other_attributes(
    engine: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    kernel = MagicMock()
    kernel.GetFileAttributesW.return_value = 0x21
    kernel.SetFileAttributesW.return_value = 1
    monkeypatch.setattr(
        engine.ctypes, "WinDLL", MagicMock(return_value=kernel), raising=False
    )
    remove = MagicMock()
    monkeypatch.setattr(engine.os, "remove", remove)
    engine._remove_scratch("owned-readonly")
    kernel.SetFileAttributesW.assert_called_once_with("owned-readonly", 0x20)
    remove.assert_called_once_with("owned-readonly")
