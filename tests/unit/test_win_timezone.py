"""Exercise timezone results, predictions, and recovery without Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Frontend calls cover binding and observable native-operation ordering.
# pylint: disable=protected-access

import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Callable
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

CURRENT = "GMT Standard Time"
REQUESTED = "Pacific Standard Time"
RequestRunner = Callable[[object], tuple[int, dict[str, Any]]]


class TimeZoneCommandError(Exception):
    """Supply the helper's command-failure boundary without executing a process.

    :param action: Failed command's diagnostic action.
    :param stdout: Captured standard output.
    :param stderr: Captured standard error.
    :param rc: Command return code.
    """

    def __init__(self, action: str, stdout: str, stderr: str, rc: int) -> None:
        super().__init__(action)
        self.action, self.stdout, self.stderr, self.rc = action, stdout, stderr, rc


@pytest.fixture(name="stored")
def stored_timezone() -> dict[str, str]:
    """Provide a machine timezone setting isolated to each test.

    :returns: The persistent timezone identifier.
    """
    return {"timezone": CURRENT}


@pytest.fixture(name="native")
def timezone_operations(stored: dict[str, str]) -> Mock:
    """Record native boundaries while retaining successful timezone changes.

    :param stored: Persistent machine setting shared with the test.
    :returns: Native-operation recorder for current, listed, and written IDs.
    """
    native = Mock()
    native.get_timezone.side_effect = lambda: stored["timezone"]
    native.available_timezones.return_value = [CURRENT, "", REQUESTED, "", "UTC"]

    def set_timezone(requested: str) -> None:
        stored["timezone"] = next(
            name
            for name in (CURRENT, REQUESTED, "UTC")
            if name.lower() == requested.lower().removesuffix("_dstoff")
        ) + ("_dstoff" if requested.lower().endswith("_dstoff") else "")

    native.set_timezone.side_effect = set_timezone
    return native


@pytest.fixture(name="payload")
def timezone_payload(monkeypatch: pytest.MonkeyPatch, native: Mock) -> ModuleType:
    """Import the frontend with an isolated native timezone helper.

    :param monkeypatch: Scoped helper import substitution.
    :param native: Recorder for persistent timezone reads and writes.
    :returns: Imported timezone payload without host-native operations.
    """
    helper = ModuleType("legacy_windows_timezone")
    for name in ("get_timezone", "available_timezones", "set_timezone"):
        monkeypatch.setattr(helper, name, getattr(native, name), raising=False)
    monkeypatch.setattr(
        helper, "TimeZoneCommandError", TimeZoneCommandError, raising=False
    )
    monkeypatch.setitem(sys.modules, "legacy_windows_timezone", helper)
    module = load_payload("win_timezone", monkeypatch)
    # These public-binding fixtures use ASCII IDs, not native collation tables.
    monkeypatch.setattr(
        module.environment,
        "values_equal",
        lambda left, right: (
            left is right
            if left is None or right is None
            else left.lower() == right.lower()
        ),
    )
    return module


@pytest.fixture(name="run_request")
def request_runner(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> RequestRunner:
    """Run argument files through the module's public JSON entry point.

    :param payload: Loaded module with isolated timezone boundaries.
    :param monkeypatch: Scoped command-line replacement.
    :param tmp_path: Directory for the JSON request file.
    :param capsys: Capture of the module's JSON output.
    :returns: Request runner sharing this test's machine setting.
    """
    argument_file = tmp_path / "arguments.json"
    monkeypatch.setattr(sys, "argv", ["win_timezone.py", str(argument_file)])

    def _run_request(arguments: object) -> tuple[int, dict[str, Any]]:
        argument_file.write_text(json.dumps(arguments), encoding="utf-8")
        return invoke_payload(payload, capsys)

    return _run_request


@pytest.mark.parametrize(
    "flags", [(False, False), (False, True), (True, False), (True, True)]
)
@pytest.mark.parametrize("requested", [CURRENT, CURRENT.lower()])
def test_unchanged_requests_preserve_requested_spelling_and_optional_diff(
    native: Mock,
    stored: dict[str, str],
    run_request: RequestRunner,
    requested: str,
    flags: tuple[bool, bool],
) -> None:
    check, diff = flags
    expected: dict[str, Any] = {
        "changed": False,
        "previous_timezone": CURRENT,
        "timezone": requested,
    }
    if diff:
        expected["diff"] = {"before": CURRENT + "\n", "after": requested + "\n"}
    arguments = {
        "timezone": requested,
        "_ansible_check_mode": check,
        "_ansible_diff": diff,
    }
    assert run_request(arguments) == (0, expected)
    assert run_request(arguments) == (0, expected)
    assert native.mock_calls == [call.get_timezone(), call.get_timezone()]
    assert stored == {"timezone": CURRENT}


@pytest.mark.parametrize("requested", [REQUESTED, REQUESTED.lower()])
def test_check_actual_repeat_preserve_exact_public_results_and_native_order(
    native: Mock,
    stored: dict[str, str],
    run_request: RequestRunner,
    requested: str,
) -> None:
    expected = {
        "changed": True,
        "previous_timezone": CURRENT,
        "timezone": requested,
        "diff": {"before": CURRENT + "\n", "after": requested + "\n"},
    }
    arguments = {"timezone": requested, "_ansible_diff": True}
    assert run_request({**arguments, "_ansible_check_mode": True}) == (0, expected)
    assert stored == {"timezone": CURRENT}
    assert native.mock_calls == [call.get_timezone(), call.available_timezones()]
    native.reset_mock()
    assert run_request(arguments) == (0, expected)
    assert stored == {"timezone": REQUESTED}
    assert native.mock_calls == [
        call.get_timezone(),
        call.available_timezones(),
        call.set_timezone(requested),
    ]
    native.reset_mock()
    expected.update(
        {
            "changed": False,
            "previous_timezone": REQUESTED,
            "diff": {"before": REQUESTED + "\n", "after": requested + "\n"},
        }
    )
    assert run_request(arguments) == (0, expected)
    assert native.mock_calls == [call.get_timezone()]


@pytest.mark.parametrize("suffix", ["_dstoff", "_DSTOFF"])
def test_disable_repeat_and_reenable_daylight_adjustment(
    native: Mock, stored: dict[str, str], run_request: RequestRunner, suffix: str
) -> None:
    stored["timezone"] = REQUESTED
    requested = REQUESTED + suffix
    expected = {
        "changed": True,
        "previous_timezone": REQUESTED,
        "timezone": requested,
    }
    assert run_request({"timezone": requested, "_ansible_check_mode": True}) == (
        0,
        expected,
    )
    assert stored == {"timezone": REQUESTED}
    assert run_request({"timezone": requested}) == (0, expected)
    assert stored == {"timezone": REQUESTED + "_dstoff"}
    assert run_request({"timezone": requested}) == (
        0,
        {
            "changed": False,
            "previous_timezone": REQUESTED + "_dstoff",
            "timezone": requested,
        },
    )
    native.reset_mock()
    assert run_request({"timezone": REQUESTED}) == (
        0,
        {
            "changed": True,
            "previous_timezone": REQUESTED + "_dstoff",
            "timezone": REQUESTED,
        },
    )
    assert stored == {"timezone": REQUESTED}
    assert native.mock_calls[-1] == call.set_timezone(REQUESTED)


@pytest.mark.parametrize(
    "requested",
    [
        "Pacific_dstoff Standard Time",
        "_DSTOFFPacific Standard Time",
        "Pacific Standard Time_dstoff_dstoff",
    ],
)
def test_check_mode_strips_all_occurrences_for_validation_without_a_setter_call(
    native: Mock,
    stored: dict[str, str],
    run_request: RequestRunner,
    requested: str,
) -> None:
    assert run_request({"timezone": requested, "_ansible_check_mode": True}) == (
        0,
        {
            "changed": True,
            "previous_timezone": CURRENT,
            "timezone": requested,
        },
    )
    assert stored == {"timezone": CURRENT}
    assert native.mock_calls == [call.get_timezone(), call.available_timezones()]


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("diff", [False, True])
def test_unsupported_identifier_retains_observation_and_diff_without_a_write(
    native: Mock,
    stored: dict[str, str],
    run_request: RequestRunner,
    check: bool,
    diff: bool,
) -> None:
    expected: dict[str, Any] = {
        "changed": False,
        "previous_timezone": CURRENT,
        "timezone": "Uninstalled timezone",
        "failed": True,
        "msg": "The specified timezone: Uninstalled timezone isn't supported on the machine.",
        "exception": "(traceback unavailable)",
    }
    if diff:
        expected["diff"] = {
            "before": CURRENT + "\n",
            "after": "Uninstalled timezone\n",
        }
    assert run_request(
        {
            "timezone": "Uninstalled timezone",
            "_ansible_check_mode": check,
            "_ansible_diff": diff,
        }
    ) == (1, expected)
    assert stored == {"timezone": CURRENT}
    assert native.mock_calls == [call.get_timezone(), call.available_timezones()]
    assert run_request({"timezone": REQUESTED})[0] == 0


def test_json_entry_matches_case_insensitive_option_names_and_boolean_flags(
    native: Mock, stored: dict[str, str], run_request: RequestRunner
) -> None:
    assert run_request(
        {"TIMEZONE": REQUESTED, "_ANSIBLE_CHECK_MODE": "yes", "_ANSIBLE_DIFF": "on"}
    ) == (
        0,
        {
            "changed": True,
            "previous_timezone": CURRENT,
            "timezone": REQUESTED,
            "diff": {"before": CURRENT + "\n", "after": REQUESTED + "\n"},
        },
    )
    assert stored == {"timezone": CURRENT}
    assert native.set_timezone.call_count == 0


def test_check_mode_retains_display_label_acceptance_from_the_native_catalogue(
    native: Mock, stored: dict[str, str], run_request: RequestRunner
) -> None:
    label = "(UTC-08:00) Pacific Time (US & Canada)"
    native.available_timezones.return_value.append(label)
    assert run_request({"timezone": label, "_ansible_check_mode": True}) == (
        0,
        {"changed": True, "previous_timezone": CURRENT, "timezone": label},
    )
    assert stored == {"timezone": CURRENT}
    assert native.set_timezone.call_count == 0


@pytest.mark.parametrize("requested", [None, "", "_dstoff"])
def test_blank_catalogue_entry_retains_measured_check_mode_null_and_empty_results(
    native: Mock,
    stored: dict[str, str],
    run_request: RequestRunner,
    requested: str | None,
) -> None:
    assert run_request(
        {"timezone": requested, "_ansible_check_mode": True, "_ansible_diff": True}
    ) == (
        0,
        {
            "changed": True,
            "previous_timezone": CURRENT,
            "timezone": requested,
            "diff": {"before": CURRENT + "\n", "after": (requested or "") + "\n"},
        },
    )
    assert stored == {"timezone": CURRENT}
    assert native.mock_calls == [call.get_timezone(), call.available_timezones()]


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({}, "missing required arguments: timezone"),
        (
            {"timezone": REQUESTED, "unexpected": True},
            "Unsupported parameters for (sustainablelobster.legacy_windows.win_timezone) "
            "module: unexpected. Supported parameters include: timezone",
        ),
    ],
)
def test_measured_argument_failures_have_no_timezone_fields_or_native_calls(
    native: Mock,
    run_request: RequestRunner,
    arguments: dict[str, object],
    message: str,
) -> None:
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    assert run_request(arguments) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": message,
            "exception": "(traceback unavailable)",
        },
    )
    # pylint: enable=duplicate-code
    assert native.mock_calls == []


def test_measured_list_binding_appears_in_the_entire_public_failure_result(
    native: Mock, run_request: RequestRunner
) -> None:
    assert run_request(
        {"timezone": [REQUESTED], "_ansible_check_mode": True, "_ansible_diff": True}
    ) == (
        1,
        {
            "changed": False,
            "previous_timezone": CURRENT,
            "timezone": "System.Object[]",
            "diff": {"before": CURRENT + "\n", "after": "System.Object[]\n"},
            "failed": True,
            "msg": "The specified timezone: System.Object[] isn't supported on the machine.",
            "exception": "(traceback unavailable)",
        },
    )
    assert native.mock_calls == [call.get_timezone(), call.available_timezones()]


@pytest.mark.parametrize(
    "requested,rc,stdout",
    [
        (
            None,
            87,
            "TZUTIL: Invalid number of arguments for /s.\n"
            "Use TZUTIL /? for a list of valid options.",
        ),
        (
            "",
            87,
            "TZUTIL: Invalid number of arguments for /s.\n"
            "Use TZUTIL /? for a list of valid options.",
        ),
        *[
            (
                requested,
                516,
                "TZUTIL: Invalid time zone " + requested + ".\n"
                "Use TZUTIL /l for a list of valid time zones.",
            )
            for requested in (
                "_dstoff",
                "_dstoffPacific Standard Time",
                "Pacific Standard Time_dstoff_dstoff",
            )
        ],
    ],
)
def test_measured_utility_failures_retain_all_module_fields_before_recovery(
    native: Mock,
    run_request: RequestRunner,
    requested: str | None,
    rc: int,
    stdout: str,
) -> None:
    native.set_timezone.side_effect = TimeZoneCommandError(
        "setting the specified timezone", stdout, "", rc
    )
    assert run_request({"timezone": requested, "_ansible_diff": True}) == (
        1,
        {
            "changed": False,
            "previous_timezone": CURRENT,
            "timezone": requested,
            "diff": {"before": CURRENT + "\n", "after": (requested or "") + "\n"},
            "failed": True,
            "msg": "An error occurred when setting the specified timezone.",
            "exception": "(traceback unavailable)",
            "stdout": stdout,
            "stderr": "",
            "rc": rc,
        },
    )
    native.set_timezone.assert_called_once_with(requested or "")
    native.set_timezone.side_effect = None
    assert run_request({"timezone": CURRENT}) == (
        0,
        {"changed": False, "previous_timezone": CURRENT, "timezone": CURRENT},
    )


def test_exact_display_label_keeps_its_trailing_space_in_a_utility_failure(
    native: Mock, run_request: RequestRunner
) -> None:
    requested = "(UTC-08:00) Pacific Time (US & Canada) "
    native.available_timezones.return_value.append(requested)
    stdout = (
        "TZUTIL: Invalid time zone (UTC-08:00) Pacific Time (US & Canada) .\n"
        "Use TZUTIL /l for a list of valid time zones."
    )
    native.set_timezone.side_effect = TimeZoneCommandError(
        "setting the specified timezone", stdout, "", 516
    )
    expected: dict[str, Any] = {
        "changed": True,
        "previous_timezone": CURRENT,
        "timezone": requested,
        "diff": {"before": CURRENT + "\n", "after": requested + "\n"},
    }
    assert run_request(
        {"timezone": requested, "_ansible_check_mode": True, "_ansible_diff": True}
    ) == (0, expected)
    native.set_timezone.assert_not_called()
    expected.update(
        {
            "changed": False,
            "failed": True,
            "msg": "An error occurred when setting the specified timezone.",
            "exception": "(traceback unavailable)",
            "stdout": stdout,
            "stderr": "",
            "rc": 516,
        }
    )
    assert run_request({"timezone": requested, "_ansible_diff": True}) == (1, expected)
    native.set_timezone.assert_called_once_with(requested)


def test_no_dst_zone_readback_without_suffix_keeps_repeated_changes_and_prediction(
    native: Mock, stored: dict[str, str], run_request: RequestRunner
) -> None:
    canonical = "India Standard Time"
    requested = canonical + "_dstoff"
    stored["timezone"] = canonical
    native.available_timezones.return_value.append(canonical)

    def _set_no_dst_timezone(_requested: str) -> None:
        stored["timezone"] = canonical

    native.set_timezone.side_effect = _set_no_dst_timezone
    expected = {
        "changed": True,
        "previous_timezone": canonical,
        "timezone": requested,
        "diff": {"before": canonical + "\n", "after": requested + "\n"},
    }
    arguments = {"timezone": requested, "_ansible_diff": True}
    assert run_request(arguments) == (0, expected)
    assert run_request(arguments) == (0, expected)
    assert native.set_timezone.call_args_list == [call(requested), call(requested)]
    upper = requested.upper()
    expected.update(
        {"timezone": upper, "diff": {"before": canonical + "\n", "after": upper + "\n"}}
    )
    assert run_request(
        {"timezone": upper, "_ansible_diff": True, "_ansible_check_mode": True}
    ) == (0, expected)
    assert native.set_timezone.call_count == 2


@pytest.mark.parametrize(
    "operation,action",
    [
        ("get_timezone", "getting the current machine's timezone setting"),
        ("available_timezones", "listing the available timezones"),
        ("set_timezone", "setting the specified timezone"),
    ],
)
def test_command_failure_retains_public_fields_and_exact_output_before_recovery(
    native: Mock,
    stored: dict[str, str],
    run_request: RequestRunner,
    operation: str,
    action: str,
) -> None:
    command = getattr(native, operation)
    successful_operation = command.side_effect
    command.side_effect = TimeZoneCommandError(action, "exact output\n", "error\n", 1)
    expected: dict[str, Any] = {
        "changed": False,
        "previous_timezone": None if operation == "get_timezone" else CURRENT,
        "timezone": REQUESTED,
        "failed": True,
        "msg": "An error occurred when " + action + ".",
        "exception": "(traceback unavailable)",
        "stdout": "exact output\n",
        "stderr": "error\n",
        "rc": 1,
    }
    if operation != "get_timezone":
        expected["diff"] = {"before": CURRENT + "\n", "after": REQUESTED + "\n"}
    assert run_request({"timezone": REQUESTED, "_ansible_diff": True}) == (1, expected)
    assert stored == {"timezone": CURRENT}
    if operation != "set_timezone":
        assert native.set_timezone.call_count == 0
    command.side_effect = successful_operation
    assert run_request({"timezone": REQUESTED}) == (
        0,
        {"changed": True, "previous_timezone": CURRENT, "timezone": REQUESTED},
    )
    assert run_request({"timezone": REQUESTED}) == (
        0,
        {"changed": False, "previous_timezone": REQUESTED, "timezone": REQUESTED},
    )


@pytest.mark.parametrize(
    "supplied,expected",
    [
        (None, None),
        ("", ""),
        ("\u00a0Pacific Standard Time\u2003", "\u00a0Pacific Standard Time\u2003"),
        (True, "True"),
        (False, "False"),
        (42, "42"),
        (-42, "-42"),
        (1.5, "1.5"),
        (["one", "two"], "System.Object[]"),
        ({"name": "value"}, "System.Collections.Hashtable"),
    ],
)
def test_required_string_uses_shared_coercion_without_trimming(
    payload: ModuleType, supplied: object, expected: str | None
) -> None:
    assert payload._parameters({"timezone": supplied}) == expected
