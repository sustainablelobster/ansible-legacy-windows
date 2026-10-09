"""Exercise the explicit DSC subprocess framing without touching Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import json
import sys
from typing import Any
from unittest.mock import MagicMock

import pytest

from tests.unit.payload_support import load_payload


@pytest.fixture(name="engine")
def engine_fixture(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load the explicit engine boundary without starting PowerShell.

    :param monkeypatch: Scoped helper imports and Windows directory.
    :returns: Imported DSC engine adapter.
    """
    load_payload("win_dsc", monkeypatch)
    module = sys.modules["legacy_windows_dsc_engine"]
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    return module


@pytest.mark.parametrize("sysnative", [True, False])
def test_documented_engine_command_and_utf8_json(
    engine: Any, monkeypatch: pytest.MonkeyPatch, sysnative: bool
) -> None:
    monkeypatch.setattr(
        engine.os.path, "isfile", lambda path: sysnative or "System32" in path
    )
    process = MagicMock()
    process.__enter__.return_value = process
    process.communicate.return_value = (b'{"module_version":null}', b"")
    start = MagicMock(return_value=process)
    monkeypatch.setattr(engine.subprocess, "Popen", start)
    request = {
        "operation": "discover",
        "arguments": {"resource_name": "File", "text": "λ"},
    }
    assert engine.engine_request(request) == {"module_version": None}
    argv = start.call_args.args[0]
    assert ("Sysnative" if sysnative else "System32") in argv[0]
    assert argv[1:5] == ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand"]
    assert base64.b64decode(argv[5]).decode("utf-16-le") == engine.ENGINE_SCRIPT
    assert json.loads(process.communicate.call_args.args[0]) == request


def test_missing_engine_does_not_start_a_child(
    engine: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(engine.os.path, "isfile", lambda _: False)
    start = MagicMock()
    monkeypatch.setattr(engine.subprocess, "Popen", start)
    with pytest.raises(OSError, match="installed Windows PowerShell 5.0"):
        engine.engine_request({"operation": "discover"})
    start.assert_not_called()


@pytest.mark.parametrize("stdout", [b"", b"not-json", b"[]", b"\xff"])
def test_malformed_engine_response_is_actionable(
    engine: Any, monkeypatch: pytest.MonkeyPatch, stdout: bytes
) -> None:
    monkeypatch.setattr(engine.os.path, "isfile", lambda _: True)
    process = MagicMock()
    process.__enter__.return_value = process
    process.communicate.return_value = (stdout, b"engine diagnostic")
    monkeypatch.setattr(engine.subprocess, "Popen", MagicMock(return_value=process))
    with pytest.raises(ValueError, match="JSON"):
        engine.engine_request({"operation": "discover"})
