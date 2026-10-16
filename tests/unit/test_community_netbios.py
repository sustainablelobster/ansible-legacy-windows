"""Exercise the NetBIOS JSON interface against independent WMI replies."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module

ADAPTER = {
    "Index": 7,
    "MacAddress": "00:11:22:33:44:55",
    "TcpipNetbiosOptions": 0,
    "__PATH": 'Win32_NetworkAdapterConfiguration.Index="7"',
}


@pytest.fixture(name="execute")
def netbios_request(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> tuple[Callable[[dict[str, Any]], tuple[int, dict[str, Any]]], MagicMock]:
    """Run actual JSON binding with only the WMI connection replaced.

    :param monkeypatch: Scoped import and native-boundary substitutions.
    :param tmp_path: Owned module request location.
    :param capsys: JSON output capture.
    :returns: Request callable and independent WMI observation boundary.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    payload = load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_netbios.py",
        "tested_community_netbios",
    )
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.query.return_value = [dict(ADAPTER)]
    connection.call_method.return_value = {"ReturnValue": 0}
    monkeypatch.setattr(payload, "WmiConnection", lambda: connection)
    request = tmp_path / "request.json"

    def run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        """Execute the public request with an independent WMI observation.

        :param arguments: Module arguments serialized into the request file.
        :returns: Payload exit status and decoded JSON response.
        """
        request.write_text(json.dumps(arguments), encoding="utf-8")
        monkeypatch.setattr(sys, "argv", [str(payload.__file__), str(request)])
        return invoke_payload(payload, capsys)

    return run, connection


def test_default_selects_only_ip_enabled_adapters(execute: Any) -> None:
    run, connection = execute
    status, result = run({"state": "enabled"})
    assert status == 0
    assert result == {"changed": True, "reboot_required": False}
    assert "WHERE IPEnabled=TRUE" in connection.query.call_args.args[0]
    connection.call_method.assert_called_once_with(
        ADAPTER["__PATH"],
        "SetTcpipNetbios",
        ("ReturnValue",),
        {"TcpipNetbiosOptions": "1"},
    )
    connection.__exit__.assert_called_once()


def test_matching_setting_is_unchanged(execute: Any) -> None:
    run, connection = execute
    assert run({"state": "default"}) == (
        0,
        {"changed": False, "reboot_required": False},
    )
    connection.call_method.assert_not_called()


def test_check_mode_predicts_without_setter(execute: Any) -> None:
    run, connection = execute
    assert run({"state": "disabled", "_ansible_check_mode": True}) == (
        0,
        {"changed": True, "reboot_required": False},
    )
    connection.call_method.assert_not_called()


def test_exact_names_are_case_insensitive_and_not_wql(execute: Any) -> None:
    run, connection = execute
    connection.query.side_effect = [
        [{"DeviceID": "7", "NetConnectionID": "Office's adapter"}],
        [dict(ADAPTER), dict(ADAPTER, Index=8)],
    ]
    assert run({"state": "disabled", "adapter_names": "OFFICE'S ADAPTER"})[0] == 0
    assert all("Office" not in call.args[0] for call in connection.query.call_args_list)
    connection.call_method.assert_called_once()


@pytest.mark.parametrize(
    "names", [["missing"], ["known", "missing"], ["known", "known"]]
)
def test_all_names_validated_before_any_write(execute: Any, names: list[str]) -> None:
    run, connection = execute
    connection.query.side_effect = [
        [{"DeviceID": "7", "NetConnectionID": "known"}],
        [dict(ADAPTER)],
    ]
    status, result = run({"state": "disabled", "adapter_names": names})
    assert status == 1 and result["changed"] is False
    assert "No configuration changes" in result["msg"]
    connection.call_method.assert_not_called()


@pytest.mark.parametrize("code", [0, 1, 100, 64])
def test_native_status_and_warning_contract(execute: Any, code: int) -> None:
    run, connection = execute
    connection.call_method.return_value = {"ReturnValue": code}
    status, result = run({"state": "disabled"})
    assert status == (1 if code == 64 else 0)
    assert result["reboot_required"] is (code == 1)
    assert result["changed"] is (code != 64)
    if code == 100:
        assert "DHCP not enabled" in result["warnings"][0]


def test_later_failure_preserves_applied_change(execute: Any) -> None:
    run, connection = execute
    connection.query.return_value = [dict(ADAPTER), dict(ADAPTER, Index=8)]
    connection.call_method.side_effect = [
        {"ReturnValue": 1},
        OSError("provider failure"),
    ]
    status, result = run({"state": "disabled"})
    assert status == 1
    assert result["changed"] is True and result["reboot_required"] is True
    assert result["msg"] == "provider failure"
    connection.__exit__.assert_called_once()


@pytest.mark.parametrize(
    "arguments", [{}, {"state": "bad"}, {"state": "disabled", "bad": 1}]
)
def test_invalid_request_never_queries_or_writes(
    execute: Any, arguments: dict[str, Any]
) -> None:
    run, connection = execute
    status, result = run(arguments)
    assert status == 1 and result["changed"] is False
    connection.query.assert_not_called()
    connection.call_method.assert_not_called()
