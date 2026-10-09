"""Exercise DNS zone public binding and complete JSON responses."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Provider substitutes establish controller behavior, not Windows support.

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload


@pytest.fixture(name="runner")
def public_runner(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> Any:
    """Run the public entry point with a recorded provider boundary.

    :param monkeypatch: Scoped provider and argument-file substitutions.
    :param capsys: Captured JSON output.
    :param tmp_path: Isolated argument directory.
    :returns: Request runner and native boundary recorder.
    """
    payload = load_payload("win_dns_zone", monkeypatch)
    manage = Mock(return_value={"changed": False})
    monkeypatch.setattr(payload.dns, "manage", manage)
    path = tmp_path / "arguments.json"

    def _run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        path.write_text(json.dumps(arguments), encoding="utf-8")
        monkeypatch.setattr(sys, "argv", ["win_dns_zone.py", str(path)])
        return invoke_payload(payload, capsys)

    return SimpleNamespace(run=_run, manage=manage)


def test_defaults_and_unchanged_result_remain_sparse(runner: Any) -> None:
    assert runner.run({"name": "Owned.INVALID"}) == (0, {"changed": False})
    runner.manage.assert_called_once_with(
        {
            "name": "Owned.INVALID",
            "type": None,
            "replication": None,
            "dynamic_update": None,
            "state": "present",
            "forwarder_timeout": None,
            "dns_servers": None,
            "directory_partition": None,
        },
        False,
        False,
    )


@pytest.mark.parametrize("name", [None, "", "owned.invalid", 123])
def test_explicit_name_values_reach_source_provider_validation(
    runner: Any, name: Any
) -> None:
    assert runner.run({"name": name})[0] == 0
    assert runner.manage.call_args.args[0]["name"] == (
        str(name) if isinstance(name, int) else name
    )


@pytest.mark.parametrize(
    "servers,expected",
    [
        ("127.0.0.1,127.0.0.2", ["127.0.0.1", "127.0.0.2"]),
        (
            ["127.0.0.2", "127.0.0.1", "127.0.0.2"],
            ["127.0.0.2", "127.0.0.1", "127.0.0.2"],
        ),
        ([], []),
        (None, None),
    ],
)
def test_dns_server_input_preserves_array_order_duplicates_and_null(
    runner: Any, servers: Any, expected: Any
) -> None:
    assert runner.run({"name": "owned.invalid", "dns_servers": servers})[0] == 0
    assert runner.manage.call_args.args[0]["dns_servers"] == expected


def test_null_server_element_fails_before_provider(runner: Any) -> None:
    code, result = runner.run({"name": "owned.invalid", "dns_servers": [None]})
    assert code == 1 and result["msg"] == "dns_servers must not contain null entries."
    runner.manage.assert_not_called()


@pytest.mark.parametrize("timeout", [None, 0, -1, 16, -(2**31), 2**31 - 1, " +3 "])
def test_timeout_binding_keeps_signed_int32_and_defers_provider_range(
    runner: Any, timeout: Any
) -> None:
    assert runner.run({"name": "owned.invalid", "forwarder_timeout": timeout})[0] == 0
    assert runner.manage.call_args.args[0]["forwarder_timeout"] == (
        int(timeout) if timeout is not None else None
    )


@pytest.mark.parametrize(
    "timeout", [True, False, 1.5, "1.0", "", "nan", 2**31, -(2**31) - 1]
)
def test_invalid_timeout_fails_before_provider(runner: Any, timeout: Any) -> None:
    code, result = runner.run({"name": "owned.invalid", "forwarder_timeout": timeout})
    assert code == 1 and result["failed"] and not result["changed"]
    assert "signed 32-bit integer" in result["msg"]
    runner.manage.assert_not_called()


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({}, "missing required arguments: name"),
        ({"name": "owned.invalid", "unsupported": True}, "Unsupported parameters"),
        ({"name": "owned.invalid", "type": "unknown"}, "type must be one of"),
        (
            {"name": "owned.invalid", "replication": "custom"},
            "replication must be one of",
        ),
        ({"name": "owned.invalid", "state": "unknown"}, "state must be one of"),
        (
            {"name": "owned.invalid", "dynamic_update": "unknown"},
            "dynamic_update must be one of",
        ),
        (
            {
                "name": "owned.invalid",
                "directory_partition": "owned.invalid",
                "replication": "forest",
            },
            "mutually exclusive",
        ),
    ],
)
def test_public_validation_precedes_target_provider(
    runner: Any, arguments: dict[str, Any], message: str
) -> None:
    code, result = runner.run(arguments)
    assert code == 1 and result["failed"] and not result["changed"]
    assert message in result["msg"]
    runner.manage.assert_not_called()


def test_choices_nulls_and_check_diff_flags_are_bound(runner: Any) -> None:
    assert (
        runner.run(
            {
                "name": "owned.invalid",
                "type": "FORWARDER",
                "state": None,
                "replication": "NONE",
                "dynamic_update": "SECURE",
                "_ansible_check_mode": "yes",
                "_ansible_diff": True,
            }
        )[0]
        == 0
    )
    arguments, check, diff = runner.manage.call_args.args
    assert arguments["type"] == "forwarder" and arguments["state"] is None
    assert (
        arguments["replication"] == "none" and arguments["dynamic_update"] == "secure"
    )
    assert check and diff


def test_full_provider_failure_and_conditional_fields_are_not_rewritten(
    runner: Any,
) -> None:
    packet = {
        "changed": False,
        "failed": True,
        "msg": "Failed to set properties on the zone owned.invalid: denied",
        "diff": {"before": {"name": "owned.invalid"}},
        "warnings": [
            "The forwarder_timeout param must be an integer value between 0 and 15"
        ],
    }
    runner.manage.return_value = packet
    assert runner.run({"name": "owned.invalid"}) == (1, packet)


def test_missing_provider_error_is_actionable_and_not_successful_noop(
    runner: Any,
) -> None:
    runner.manage.side_effect = OSError(
        "Windows DNS Server zone management provider is unavailable "
        "(ROOT\\Microsoft\\Windows\\Dns)."
    )
    code, result = runner.run({"name": "owned.invalid", "state": "absent"})
    assert code == 1 and result["failed"] and not result["changed"]
    assert "provider is unavailable" in result["msg"]
