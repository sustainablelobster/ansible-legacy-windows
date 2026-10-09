"""Exercise the public capability metadata bindings without a Windows host."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload


@pytest.fixture(name="runner")
def capability_runner(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> Any:
    """Run public JSON requests with a substituted read-only native provider.

    :param monkeypatch: Scoped payload and provider replacements.
    :param capsys: Public output capture.
    :returns: Runner and observable metadata calls.
    """
    module = load_payload("win_capability_info", monkeypatch)
    entries = [{"name": "OpenSSH.Client~~~~0.0.1.0", "state": "Installed"}]
    native = Mock(return_value=entries)
    monkeypatch.setattr(module.capability, "capabilities", native)

    def _run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        monkeypatch.setattr(module, "read_arguments", lambda *_args: arguments)
        return invoke_payload(module, capsys)

    return SimpleNamespace(run=_run, native=native, entries=entries)


@pytest.mark.parametrize("names", [None, []])
@pytest.mark.parametrize("check", [False, True])
def test_null_and_empty_names_read_all_without_changes(
    runner: Any, names: Any, check: bool
) -> None:
    assert runner.run({"name": names, "_ansible_check_mode": check}) == (
        0,
        {"changed": False, "capabilities": runner.entries},
    )
    runner.native.assert_called_once_with(None, None, None)


def test_omitted_names_read_all_metadata(runner: Any) -> None:
    assert runner.run({})[1]["capabilities"] == runner.entries
    runner.native.assert_called_once_with(None, None, None)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("OpenSSH.*,Rsat.*", ["OpenSSH.*", "Rsat.*"]),
        (["OpenSSH.*", "[bad"], ["OpenSSH.*", "[bad"]),
        ([1, False], ["1", "False"]),
    ],
)
def test_name_binding_preserves_order_and_lazy_pattern_validation(
    runner: Any, value: Any, expected: list[str]
) -> None:
    assert runner.run({"name": value})[0] == 0
    runner.native.assert_called_once_with(expected, None, None)


@pytest.mark.parametrize("names", ["", [""]])
def test_one_empty_string_disables_filtering_like_pinned_source(
    runner: Any, names: Any
) -> None:
    assert runner.run({"name": names})[1]["capabilities"] == runner.entries
    runner.native.assert_called_once_with(None, None, None)


def test_two_empty_patterns_remain_a_real_filter(runner: Any) -> None:
    assert runner.run({"name": ["", ""]})[0] == 0
    runner.native.assert_called_once_with(["", ""], None, None)


@pytest.mark.parametrize(
    "level,expected",
    [(0, 0), (2, 2), ("2", 2), (" +1 ", 1), ("2\x00\x00", 2), ("2 \x00", 2)],
)
def test_log_level_uses_signed_integer_string_binding(
    runner: Any, level: Any, expected: int
) -> None:
    assert runner.run({"log_level": level})[0] == 0
    runner.native.assert_called_once_with(None, expected, None)


@pytest.mark.parametrize(
    "value",
    [
        "invalid",
        [],
        {},
        2**31,
        -(2**31) - 1,
        True,
        1.5,
        2.5,
        "1_0",
        "\u00a02\u00a0",
        "\x1c2\x1c",
        "\u20032\u2003",
        "2\x00 ",
        "\x002",
    ],
)
def test_invalid_log_level_fails_before_metadata(runner: Any, value: Any) -> None:
    status, result = runner.run({"log_level": value})
    assert status == 1 and result["failed"] and not result["changed"]
    assert "unable to convert to int" in result["msg"]
    runner.native.assert_not_called()


def test_fractional_integer_error_preserves_measured_upstream_message(
    runner: Any,
) -> None:
    assert runner.run({"log_level": 1.5})[1]["msg"] == (
        "argument for log_level is of type System.Decimal and we were unable "
        "to convert to int: Input string was not in a correct format."
    )


@pytest.mark.parametrize("level", [-1, 3, 4])
def test_unknown_logging_enum_fails_before_any_native_call(
    runner: Any, level: int
) -> None:
    status, result = runner.run({"log_level": level})
    assert status == 1 and not result["changed"]
    assert 'Cannot convert value "' + str(level) + '"' in result["msg"]
    assert '"Errors,Warnings,WarningsInfo"' in result["msg"]
    runner.native.assert_not_called()


def test_reached_wildcard_failure_preserves_measured_upstream_prefix(
    runner: Any,
) -> None:
    runner.native.side_effect = ValueError(
        "The specified wildcard character pattern is not valid: [invalid"
    )
    assert runner.run({"name": ["[invalid"]})[1]["msg"] == (
        "Unhandled exception while executing module: "
        "The specified wildcard character pattern is not valid: [invalid"
    )


@pytest.mark.parametrize("update", [None, False, True, "yes", "no"])
def test_source_and_update_arguments_do_not_turn_metadata_into_installation(
    runner: Any, update: Any
) -> None:
    assert runner.run({"disable_windows_update": update, "source": ["missing-source"]})[
        1
    ] == {"changed": False, "capabilities": runner.entries}
    runner.native.assert_called_once_with(None, None, None)


def test_log_path_expands_environment_without_creating_parent_directory(
    runner: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CAPABILITY_LOG_TEST", "owned")
    assert runner.run({"log_path": "%CAPABILITY_LOG_TEST%/metadata.log"})[0] == 0
    runner.native.assert_called_once_with(None, None, "owned/metadata.log")


def test_native_failure_remains_unchanged_and_retry_can_succeed(runner: Any) -> None:
    runner.native.side_effect = OSError("capability provider is unavailable")
    status, result = runner.run({"name": ["OpenSSH.*"]})
    assert status == 1 and result["failed"] and not result["changed"]
    assert result["msg"] == "capability provider is unavailable"
    runner.native.side_effect = None
    assert runner.run({"name": ["OpenSSH.*"]})[0] == 0


def test_real_json_argument_reader_and_supported_parameter_interface(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    module = load_payload("win_capability_info", monkeypatch)
    metadata = Mock(return_value=[])
    monkeypatch.setattr(module.capability, "capabilities", metadata)
    path = tmp_path / "arguments.json"
    path.write_text(json.dumps({"name": "OpenSSH.*"}), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["win_capability_info.py", str(path)])
    assert invoke_payload(module, capsys) == (0, {"changed": False, "capabilities": []})
    metadata.assert_called_once_with(["OpenSSH.*"], None, None)
    path.write_text(json.dumps({"unsupported_option": True}), encoding="utf-8")
    status, result = invoke_payload(module, capsys)
    assert status == 1 and result["msg"] == (
        "Unsupported parameters for (sustainablelobster.legacy_windows."
        "win_capability_info) module: unsupported_option. Supported parameters "
        "include: disable_windows_update, log_level, log_path, name, source"
    )
