"""Observe message validation and the actual native-utility command boundary."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Direct payload calls isolate validation and process arguments from Windows.
# pylint: disable=protected-access

from types import ModuleType
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module


@pytest.fixture(name="payload")
def message_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the real argument conversions with an independent utility reply.

    :param monkeypatch: Scoped imports and native executable substitutions.
    :returns: Message payload with recorded process execution.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    module = load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_msg.py", "tested_msg"
    )
    monkeypatch.setattr(
        module.shutil, "which", Mock(return_value=r"C:\Windows\msg.exe")
    )
    monkeypatch.setattr(
        module,
        "run_command",
        Mock(
            return_value={
                "rc": 0,
                "stdout": "",
                "stderr": "",
            }
        ),
    )
    return module


def test_default_and_literal_message_arguments(payload: ModuleType) -> None:
    result = payload._send({})
    assert result["changed"] is True and result["rc"] == 0
    assert result["msg"] == "Hello world!"
    assert result["display_seconds"] == 10 and result["wait"] is False
    assert result["runtime_seconds"] >= 0
    assert result["sent_localtime"]
    executable, command, options = payload.run_command.call_args.args
    assert executable == r"C:\Windows\msg.exe"
    assert command.endswith('* /TIME:10 "Hello world!"')
    assert options["stdin"] is None


def test_wait_and_named_destination_preserve_literal_shell_characters(
    payload: ModuleType,
) -> None:
    result = payload._send(
        {
            "msg": "Unicode 雪 & | literal",
            "to": "Console",
            "wait": True,
            "display_seconds": 1,
        }
    )
    assert result["wait"] is True
    assert (
        'Console /TIME:1 /W "Unicode 雪 & | literal"'
        in payload.run_command.call_args.args[1]
    )


def test_preview_does_not_find_or_invoke_executable(payload: ModuleType) -> None:
    result = payload._send({"_ansible_check_mode": True})
    assert result["changed"] is True and result["rc"] == 0
    payload.shutil.which.assert_not_called()
    payload.run_command.assert_not_called()


@pytest.mark.parametrize(
    "changes",
    [
        {"msg": "x" * 256},
        {"msg": "😀" * 128},
        {"display_seconds": "bad"},
        {"display_seconds": 2**31},
        {"msg": None},
        {"to": None},
    ],
)
def test_invalid_request_never_sends(
    payload: ModuleType, changes: dict[str, object]
) -> None:
    with pytest.raises(ValueError):
        payload._send(changes)
    payload.run_command.assert_not_called()


def test_missing_utility_fails_actionably(payload: ModuleType) -> None:
    payload.shutil.which.return_value = None
    with pytest.raises(OSError, match="msg.exe.*not found"):
        payload._send({})
    payload.run_command.assert_not_called()


def test_native_failure_retains_status_and_diagnostics(payload: ModuleType) -> None:
    payload.run_command.return_value = {
        "rc": 1,
        "stdout": "session not found",
        "stderr": "",
    }
    result = payload._send({"to": "absent"})
    assert result["failed"] is True and result["rc"] == 1
    assert result["msg"] == "session not found"
