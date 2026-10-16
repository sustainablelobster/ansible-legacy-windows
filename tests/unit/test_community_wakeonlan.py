"""Observe packet bytes, check mode and failures without Windows or a lab."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import socket
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module


@pytest.fixture(name="payload")
def wake_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the staged payload with the same helper path used on Windows.

    :param monkeypatch: Scoped Python import configuration.
    :returns: Imported Wake-on-LAN payload.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    return load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_wakeonlan.py",
        "tested_community_wakeonlan",
    )


@pytest.mark.parametrize(
    "mac",
    ["00:00:5E:00:53:66", "00-00-5E-00-53-66", "00005e005366"],
)
def test_sends_standard_magic_packet(payload: ModuleType, mac: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(2)
        result = payload._send(  # pylint: disable=protected-access
            {"mac": mac, "broadcast": "127.0.0.1", "port": receiver.getsockname()[1]}
        )
        data, _ = receiver.recvfrom(1024)
    assert result == {"changed": True}
    assert data == b"\xff" * 6 + bytes.fromhex("00005e005366") * 16
    assert len(data) == 102


def test_check_mode_predicts_change_without_opening_socket(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    sender = Mock(side_effect=AssertionError("check mode must not send"))
    monkeypatch.setattr(payload.socket, "socket", sender)
    assert payload._send(  # pylint: disable=protected-access
        {"mac": "00:00:5E:00:53:66", "_ansible_check_mode": True}
    ) == {"changed": True}
    sender.assert_not_called()


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"mac": None},
        {"mac": "short"},
        {"mac": "zz:00:5E:00:53:66"},
        {"mac": "00:00:5E:00:53:66", "broadcast": "not-a-numeric-address"},
        {"mac": "00:00:5E:00:53:66", "port": "not-an-integer"},
        {"mac": "00:00:5E:00:53:66", "port": 2**31},
    ],
)
def test_invalid_arguments_return_actionable_json(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    arguments: dict[str, object],
) -> None:
    path = tmp_path / "args.json"
    path.write_text(json.dumps(arguments), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["win_wakeonlan.py", str(path)])
    code, result = invoke_payload(payload, capsys)
    assert code == 1
    assert result["changed"] is False
    assert result["failed"] is True
    assert result["msg"]


def test_send_failure_is_reported_and_socket_closed(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sender = Mock()
    sender.sendto.side_effect = OSError("controlled UDP failure")
    manager = Mock(
        __enter__=Mock(return_value=sender), __exit__=Mock(return_value=False)
    )
    monkeypatch.setattr(payload.socket, "socket", Mock(return_value=manager))
    path = tmp_path / "args.json"
    path.write_text(json.dumps({"mac": "00:00:5E:00:53:66"}), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["win_wakeonlan.py", str(path)])
    code, result = invoke_payload(payload, capsys)
    assert code == 1
    assert result["failed"] is True
    assert "controlled UDP failure" in result["msg"]
    manager.__exit__.assert_called_once()
