"""Exercise regional setting results and argument ordering without Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, Callable
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

Request = Callable[[dict[str, Any]], tuple[int, dict[str, Any]]]


@pytest.fixture(name="native")
def region_operations() -> Any:
    """Record regional operations independently from the payload.

    :returns: Native-operation mocks and the controlled catalogue.
    """
    calls = Mock()
    calls.cultures.return_value = {"": 127, "en-US": 1033, "en-GB": 2057}
    calls.valid_location.return_value = True
    calls.user_locale.return_value = "en-US"
    calls.change_location.return_value = False
    calls.change_system_locale.return_value = False
    calls.copy_user_settings.return_value = []
    return SimpleNamespace(calls=calls)


@pytest.fixture(name="payload")
def region_payload(monkeypatch: pytest.MonkeyPatch, native: Any) -> ModuleType:
    """Load the actual payload with recorded native boundaries.

    :param monkeypatch: Scoped import and native-operation substitutions.
    :param native: Recorded native operations.
    :returns: Imported regional-setting payload.
    """
    module = load_payload("win_region", monkeypatch)
    for name in (
        "cultures",
        "valid_location",
        "user_locale",
        "change_location",
        "change_format",
        "change_system_locale",
        "copy_user_settings",
    ):
        monkeypatch.setattr(module.region, name, getattr(native.calls, name))
    monkeypatch.setattr(
        module.environment,
        "values_equal",
        lambda left, right: left.lower() == right.lower(),
    )
    return module


@pytest.fixture(name="run_request")
def request_runner(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> Request:
    """Run the JSON entry point with actual argument normalization.

    :param payload: Imported payload with native boundaries substituted.
    :param monkeypatch: Scoped argument-file command line.
    :param tmp_path: Per-test argument directory.
    :param capsys: Captured JSON output.
    :returns: Public request runner.
    """
    path = tmp_path / "arguments.json"
    monkeypatch.setattr(sys, "argv", ["win_region.py", str(path)])

    def _run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        path.write_text(json.dumps(arguments), encoding="utf-8")
        return invoke_payload(payload, capsys)

    return _run


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"copy_settings": True},
        {
            "format": None,
            "location": None,
            "unicode_language": None,
        },
    ],
)
def test_missing_and_null_settings_fail_before_native_reads(
    run_request: Request,
    native: Any,
    arguments: dict[str, Any],
) -> None:
    assert run_request(arguments) == (
        1,
        {
            "changed": False,
            "restart_required": False,
            "failed": True,
            "msg": (
                "An argument for 'format', 'location' or 'unicode_language' "
                "needs to be supplied"
            ),
        },
    )
    assert native.calls.mock_calls == []


def test_location_check_real_and_repeat_use_public_change_result(
    run_request: Request,
    native: Any,
) -> None:
    native.calls.change_location.return_value = True
    expected = {"changed": True, "restart_required": False}
    assert run_request({"location": 12, "_ansible_check_mode": True}) == (0, expected)
    native.calls.change_location.assert_called_once_with("12", True)
    native.calls.change_location.reset_mock()
    assert run_request({"location": "12"}) == (0, expected)
    native.calls.change_location.assert_called_once_with("12", False)
    native.calls.change_location.return_value = False
    assert run_request({"location": "12"}) == (
        0,
        {
            "changed": False,
            "restart_required": False,
        },
    )
    native.calls.change_format.assert_not_called()
    native.calls.change_system_locale.assert_not_called()


def test_format_check_real_repeat_and_case_comparison(
    run_request: Request,
    native: Any,
) -> None:
    expected = {"changed": True, "restart_required": False}
    assert run_request({"format": "en-GB", "_ansible_check_mode": True}) == (
        0,
        expected,
    )
    native.calls.change_format.assert_called_once_with("en-GB", True)
    native.calls.change_format.reset_mock()
    assert run_request({"format": "en-GB", "_ansible_diff": True}) == (0, expected)
    native.calls.change_format.assert_called_once_with("en-GB", False)
    native.calls.change_format.reset_mock()
    native.calls.user_locale.return_value = "en-GB"
    assert run_request({"format": "EN-gb"}) == (
        0,
        {
            "changed": False,
            "restart_required": False,
        },
    )
    native.calls.change_format.assert_not_called()


@pytest.mark.parametrize("check_mode", [False, True])
def test_system_locale_change_returns_restart_flag(
    run_request: Request,
    native: Any,
    check_mode: bool,
) -> None:
    native.calls.change_system_locale.return_value = True
    assert run_request(
        {"unicode_language": "en-GB", "_ansible_check_mode": check_mode}
    ) == (
        0,
        {"changed": True, "restart_required": True},
    )
    native.calls.change_system_locale.assert_called_once_with("en-GB", check_mode)
    native.calls.copy_user_settings.assert_not_called()


@pytest.mark.parametrize("check_mode", [False, True])
def test_copy_runs_only_after_a_change_and_never_in_check_mode(
    run_request: Request,
    native: Any,
    check_mode: bool,
) -> None:
    assert run_request(
        {"format": "en-US", "copy_settings": True, "_ansible_check_mode": check_mode}
    ) == (
        0,
        {"changed": False, "restart_required": False},
    )
    native.calls.copy_user_settings.assert_not_called()
    native.calls.reset_mock()
    assert run_request(
        {"format": "en-GB", "copy_settings": True, "_ansible_check_mode": check_mode}
    ) == (
        0,
        {"changed": True, "restart_required": False},
    )
    if check_mode:
        native.calls.copy_user_settings.assert_not_called()
    else:
        native.calls.copy_user_settings.assert_called_once_with()
        assert native.calls.mock_calls.index(call.change_format("en-GB", False)) < (
            native.calls.mock_calls.index(call.copy_user_settings())
        )


def test_all_validation_finishes_before_any_setting_is_written(
    run_request: Request,
    native: Any,
) -> None:
    assert run_request(
        {"location": "12", "format": "en-GB", "unicode_language": "INVALID"}
    ) == (
        1,
        {
            "changed": False,
            "restart_required": False,
            "failed": True,
            "msg": "The argument unicode_language 'INVALID' does not contain a valid Culture Name",
        },
    )
    native.calls.change_location.assert_not_called()
    native.calls.change_format.assert_not_called()
    native.calls.change_system_locale.assert_not_called()


def test_invalid_geo_id_precedes_invalid_culture_and_all_writes(
    run_request: Request,
    native: Any,
) -> None:
    native.calls.valid_location.return_value = False
    assert run_request({"location": "bad", "format": "INVALID"}) == (
        1,
        {
            "changed": False,
            "restart_required": False,
            "failed": True,
            "msg": "The argument location 'bad' does not contain a valid Geo ID",
        },
    )
    native.calls.change_location.assert_not_called()


def test_all_settings_are_applied_before_profile_copy(
    run_request: Request,
    native: Any,
) -> None:
    native.calls.change_location.return_value = True
    native.calls.change_system_locale.return_value = True
    assert run_request(
        {
            "location": "12",
            "format": "en-GB",
            "unicode_language": "en-GB",
            "copy_settings": True,
        }
    ) == (
        0,
        {"changed": True, "restart_required": True},
    )
    operations = [
        item
        for item in native.calls.mock_calls
        if item[0].startswith("change_") or item[0] == "copy_user_settings"
    ]
    assert operations == [
        call.change_location("12", False),
        call.change_format("en-GB", False),
        call.change_system_locale("en-GB", False),
        call.copy_user_settings(),
    ]


def test_reserved_hive_warning_is_returned_only_when_present(
    run_request: Request,
    native: Any,
) -> None:
    native.calls.copy_user_settings.return_value = ["Existing hive replaced"]
    assert run_request({"format": "en-GB", "copy_settings": True}) == (
        0,
        {
            "changed": True,
            "restart_required": False,
            "warnings": ["Existing hive replaced"],
        },
    )


def test_copy_load_failure_retains_the_original_failed_result_shape(
    run_request: Request,
    native: Any,
    payload: ModuleType,
) -> None:
    error = payload.region.HiveLoadError.__new__(payload.region.HiveLoadError)
    RuntimeError.__init__(error, "Original native load failure")
    native.calls.copy_user_settings.side_effect = error
    assert run_request({"format": "en-GB", "copy_settings": True}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "Original native load failure",
        },
    )
    native.calls.change_format.assert_called_once_with("en-GB", False)


def test_unknown_argument_and_invalid_boolean_fail_before_native_reads(
    run_request: Request,
    native: Any,
) -> None:
    code, result = run_request({"format": "en-US", "unsupported": True})
    assert code == 1
    assert result["msg"].startswith("Unsupported parameters for (")
    assert native.calls.mock_calls == []
    assert run_request({"format": "en-US", "copy_settings": "invalid"}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "Expected a boolean for copy_settings.",
        },
    )
    assert native.calls.mock_calls == []
