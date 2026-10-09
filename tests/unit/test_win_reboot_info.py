"""Exercise the reboot-info payload's public JSON contract without Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later

import datetime
import json
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

BOOT = datetime.datetime(2026, 9, 28, 8, 11, 41, 679063)


@pytest.fixture(name="payload")
def reboot_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the payload with observable native-reader substitutes.

    :param monkeypatch: Scoped replacements of native operations.
    :returns: Loaded payload with deterministic reader results.
    """
    module = load_payload("win_reboot_info", monkeypatch)
    monkeypatch.setattr(module.boot, "last_boot_time", Mock(return_value=BOOT))
    monkeypatch.setattr(module.reboot, "recent_reboot", Mock(return_value={}))
    monkeypatch.setattr(module.reboot, "pending_reboot_reasons", Mock(return_value=[]))
    return module


@pytest.fixture(name="invoke")
def reboot_invocation(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> Callable[[object], tuple[int, dict[str, Any]]]:
    """Bind JSON argument-file setup and output capture to this payload.

    :param payload: Module with native readers replaced.
    :param monkeypatch: Scoped argument-file substitution.
    :param tmp_path: Isolated controller test directory.
    :param capsys: Captured JSON output.
    :returns: Callable accepting a module argument document.
    """

    def _invoke(arguments: object) -> tuple[int, dict[str, Any]]:
        argument_file = tmp_path / "arguments.json"
        argument_file.write_text(json.dumps(arguments), encoding="utf-8")
        monkeypatch.setattr(sys, "argv", ["win_reboot_info.py", str(argument_file)])
        return invoke_payload(payload, capsys)

    return _invoke


@pytest.mark.parametrize("check", [False, True])
def test_read_only_results_repeat_and_match_check_mode(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    check: bool,
) -> None:
    expected = {
        "changed": False,
        "last_reboot": {
            "time": "2026-09-28T08:11:41Z",
            "time_epoch": 1790583101.6790628,
            "details": {},
        },
        "reboot_required": False,
        "reboot_required_reasons": [],
    }
    code, result = invoke({"_ansible_check_mode": check})
    assert (code, result) == (0, expected)
    assert invoke({"_ansible_check_mode": check}) == (0, expected)
    assert payload.reboot.recent_reboot.call_args_list == [call(BOOT), call(BOOT)]
    assert isinstance(result["last_reboot"]["time_epoch"], float)


def test_retains_detail_values_and_reason_order(
    payload: ModuleType, invoke: Callable[[object], tuple[int, dict[str, Any]]]
) -> None:
    details = {
        "process": "shutdown.exe",
        "reason": "Reason 雪",
        "reason_code": 2147745794,
        "type": "restart",
        "comment": "",
        "initiated_by": None,
        "event_time": "2026-09-28T08:11:30Z",
    }
    reasons = [
        {"source": "windows_update", "description": "Update reason"},
        {"source": "domain_join", "description": "Domain reason"},
    ]
    payload.reboot.recent_reboot.return_value = details
    payload.reboot.pending_reboot_reasons.return_value = reasons
    code, result = invoke({})
    assert code == 0
    assert result["changed"] is False
    assert result["last_reboot"]["details"] == details
    assert result["reboot_required"] is True
    assert result["reboot_required_reasons"] == reasons


@pytest.mark.parametrize("arguments", [{"unexpected_option": True}, {"NAME": "x"}])
def test_unknown_options_fail_before_native_reads(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    arguments: dict[str, object],
) -> None:
    code, result = invoke(arguments)
    assert code == 1 and result["failed"] is True and result["changed"] is False
    assert result["msg"] == (
        "Unsupported parameters for (sustainablelobster.legacy_windows.win_reboot_info) "
        "module: " + next(iter(arguments)) + ". Supported parameters include: "
    )
    assert "last_reboot" not in result
    payload.boot.last_boot_time.assert_not_called()
    payload.reboot.recent_reboot.assert_not_called()
    payload.reboot.pending_reboot_reasons.assert_not_called()


@pytest.mark.parametrize(
    "error",
    [
        OSError("query failed"),
        ValueError("bad datetime"),
        OverflowError("offset overflow"),
        MemoryError("allocation failed"),
    ],
)
def test_boot_failures_have_the_reference_prefix_and_recover(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    error: Exception,
) -> None:
    payload.boot.last_boot_time.side_effect = error
    code, result = invoke({})
    assert code == 1
    assert result == {
        "changed": False,
        "failed": True,
        "msg": "Failed to get last boot time from CIM: " + str(error),
    }
    payload.reboot.recent_reboot.assert_not_called()
    payload.reboot.pending_reboot_reasons.assert_not_called()
    payload.boot.last_boot_time.side_effect = None
    assert invoke({})[0] == 0


def test_fatal_event_failure_discards_partial_results_and_recovers(
    payload: ModuleType, invoke: Callable[[object], tuple[int, dict[str, Any]]]
) -> None:
    message = 'Cannot find an overload for "Warn" and the argument count: "2".'
    payload.reboot.recent_reboot.side_effect = RuntimeError(message)
    code, result = invoke({})
    assert code == 1 and result["changed"] is False
    assert result["msg"] == "Unhandled exception while executing module: " + message
    assert result["exception"]
    assert "last_reboot" not in result and "reboot_required" not in result
    payload.reboot.pending_reboot_reasons.assert_not_called()
    payload.reboot.recent_reboot.side_effect = None
    assert invoke({})[0] == 0


def test_invocation_contains_no_module_options(
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
) -> None:
    code, result = invoke({"_ANSIBLE_INJECT_INVOCATION": True})
    assert code == 0
    assert result["invocation"] == {"module_args": {}}


@pytest.mark.parametrize("arguments", [[], None, "not a mapping"])
def test_non_mapping_arguments_fail_without_reading_windows(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    arguments: object,
) -> None:
    code, result = invoke(arguments)
    assert (
        code == 1 and result["msg"] == "The argument file must contain a JSON object."
    )
    payload.boot.last_boot_time.assert_not_called()
