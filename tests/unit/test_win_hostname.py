"""Exercise hostname results, pending renames, and recovery without Windows."""

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

CURRENT = "Existing-Host"
REQUESTED = "New-Host"
RequestRunner = Callable[[object], tuple[int, dict[str, Any]]]


@pytest.fixture(name="stored")
def stored_hostname() -> dict[str, str]:
    """Provide active and pending machine names isolated to each test.

    :returns: The active hostname and initially identical pending name.
    """
    return {"active": CURRENT, "pending": CURRENT}


@pytest.fixture(name="native")
def hostname_operations(stored: dict[str, str]) -> Mock:
    """Record reads and rename requests without activating a pending name.

    :param stored: Persistent active and pending names shared with the test.
    :returns: Recorder for hostname reads and validated rename requests.
    """
    native = Mock()
    native.read_hostname.side_effect = lambda: stored["active"]

    def _rename_hostname(name: str, check_mode: bool = False) -> None:
        if not check_mode:
            stored["pending"] = name

    native.rename_hostname.side_effect = _rename_hostname
    return native


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.fixture(name="payload")
def hostname_payload(monkeypatch: pytest.MonkeyPatch, native: Mock) -> ModuleType:
    """Import the frontend with its native boundaries substituted.

    :param monkeypatch: Scoped imports and native-operation substitutions.
    :param native: Recorder for hostname reads and rename requests.
    :returns: Imported hostname frontend without host-native operations.
    """
    helper = ModuleType("legacy_windows_hostname")
    for name in ("read_hostname", "rename_hostname"):
        monkeypatch.setattr(helper, name, getattr(native, name), raising=False)
    monkeypatch.setitem(sys.modules, "legacy_windows_hostname", helper)
    module = load_payload("win_hostname", monkeypatch)
    # These public-binding fixtures use ASCII names, not native collation tables.
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


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.fixture(name="run_request")
def request_runner(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> RequestRunner:
    """Run argument files through the module's public JSON entry point.

    :param payload: Loaded module with isolated hostname operations.
    :param monkeypatch: Scoped command-line replacement.
    :param tmp_path: Directory for the JSON request file.
    :param capsys: Capture of the module's JSON output.
    :returns: Request runner sharing this test's persistent names.
    """
    argument_file = tmp_path / "arguments.json"
    monkeypatch.setattr(sys, "argv", ["win_hostname.py", str(argument_file)])

    def _run_request(arguments: object) -> tuple[int, dict[str, Any]]:
        argument_file.write_text(json.dumps(arguments), encoding="utf-8")
        return invoke_payload(payload, capsys)

    return _run_request


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.mark.parametrize("requested", [CURRENT, CURRENT.lower(), CURRENT.upper()])
@pytest.mark.parametrize(
    "flags", [(False, False), (False, True), (True, False), (True, True)]
)
def test_unchanged_names_keep_requested_diff_spelling_without_validation_or_rename(
    native: Mock,
    stored: dict[str, str],
    run_request: RequestRunner,
    requested: str,
    flags: tuple[bool, bool],
) -> None:
    check, diff = flags
    expected: dict[str, Any] = {
        "changed": False,
        "old_name": CURRENT,
        "reboot_required": False,
    }
    if diff:
        expected["diff"] = {"before": CURRENT, "after": requested}
    assert run_request(
        {"name": requested, "_ansible_check_mode": check, "_ansible_diff": diff}
    ) == (0, expected)
    assert native.mock_calls == [call.read_hostname()]
    assert stored == {"active": CURRENT, "pending": CURRENT}


# pylint: enable=duplicate-code


def test_check_mode_validates_without_pending_write_then_actual_repeat_reports_change(
    native: Mock, stored: dict[str, str], run_request: RequestRunner
) -> None:
    expected = {
        "changed": True,
        "old_name": CURRENT,
        "reboot_required": True,
        "diff": {"before": CURRENT, "after": REQUESTED},
    }
    arguments = {"name": REQUESTED, "_ansible_diff": True}
    assert run_request({**arguments, "_ansible_check_mode": True}) == (0, expected)
    assert stored == {"active": CURRENT, "pending": CURRENT}
    assert native.mock_calls == [
        call.read_hostname(),
        call.rename_hostname(REQUESTED, check_mode=True),
    ]
    native.reset_mock()
    assert run_request(arguments) == (0, expected)
    assert run_request(arguments) == (0, expected)
    assert stored == {"active": CURRENT, "pending": REQUESTED}
    assert (
        native.mock_calls
        == [
            call.read_hostname(),
            call.rename_hostname(REQUESTED, check_mode=False),
        ]
        * 2
    )
    stored["active"] = stored["pending"]
    native.reset_mock()
    assert run_request(arguments) == (
        0,
        {
            "changed": False,
            "old_name": REQUESTED,
            "reboot_required": False,
            "diff": {"before": REQUESTED, "after": REQUESTED},
        },
    )
    assert native.mock_calls == [call.read_hostname()]


def test_case_insensitive_argument_names_flags_and_ignored_unknown_options(
    native: Mock, stored: dict[str, str], run_request: RequestRunner
) -> None:
    assert run_request(
        {
            "NAME": REQUESTED,
            "ignored": "value",
            "_ANSIBLE_IGNORE_UNKNOWN_OPTS": True,
            "_ANSIBLE_CHECK_MODE": "yes",
            "_ANSIBLE_DIFF": True,
        }
    ) == (
        0,
        {
            "changed": True,
            "old_name": CURRENT,
            "reboot_required": True,
            "diff": {"before": CURRENT, "after": REQUESTED},
        },
    )
    native.rename_hostname.assert_called_once_with(REQUESTED, check_mode=True)
    assert stored["pending"] == CURRENT


@pytest.mark.parametrize(
    "supplied,expected",
    [
        (None, None),
        ("", ""),
        (" Name ", " Name "),
        (True, "True"),
        (False, "False"),
        (42, "42"),
        (-42, "-42"),
        (1.5, "1.5"),
        (["one", "two"], "System.Object[]"),
        ({"name": "value"}, "System.Collections.Hashtable"),
    ],
)
def test_required_string_uses_shared_binding_and_null_presence(
    payload: ModuleType, supplied: object, expected: str | None
) -> None:
    assert payload._parameters({"name": supplied}) == expected


@pytest.mark.parametrize("requested", ["invalid/name", "A" * 64, "Legacy\0Test"])
def test_measured_nonempty_check_requests_do_not_receive_lexical_validation(
    native: Mock,
    stored: dict[str, str],
    run_request: RequestRunner,
    requested: str,
) -> None:
    assert run_request(
        {"name": requested, "_ansible_check_mode": True, "_ansible_diff": True}
    ) == (
        0,
        {
            "changed": True,
            "old_name": CURRENT,
            "reboot_required": True,
            "diff": {"before": CURRENT, "after": requested},
        },
    )
    native.rename_hostname.assert_called_once_with(requested, check_mode=True)
    assert stored == {"active": CURRENT, "pending": CURRENT}


@pytest.mark.parametrize("requested", [None, ""])
@pytest.mark.parametrize(
    "flags", [(False, False), (False, True), (True, False), (True, True)]
)
def test_measured_null_and_empty_failures_retain_initialized_fields_and_null_diff(
    native: Mock,
    run_request: RequestRunner,
    requested: str | None,
    flags: tuple[bool, bool],
) -> None:
    check, diff = flags
    binding_message = (
        "Cannot validate argument on parameter 'NewName'. The argument "
        "is null or empty. Provide an argument that is not null or empty, "
        "and then try the command again."
    )
    native.rename_hostname.side_effect = ValueError(binding_message)
    expected: dict[str, Any] = {
        "changed": False,
        "old_name": CURRENT,
        "reboot_required": False,
        "failed": True,
        "msg": "Failed to rename computer to '': " + binding_message,
        "exception": "(traceback unavailable)",
    }
    if diff:
        expected["diff"] = {"before": CURRENT, "after": requested}
    assert run_request(
        {"name": requested, "_ansible_check_mode": check, "_ansible_diff": diff}
    ) == (1, expected)
    assert native.mock_calls == [
        call.read_hostname(),
        call.rename_hostname(requested, check_mode=check),
    ]


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.mark.parametrize(
    "arguments,message",
    [
        ({}, "missing required arguments: name"),
        (
            {"name": REQUESTED, "unexpected": True},
            "Unsupported parameters for (sustainablelobster.legacy_windows.win_hostname) "
            "module: unexpected. Supported parameters include: name",
        ),
        (
            {"name": REQUESTED, "_ansible_check_mode": "invalid"},
            "Expected a boolean for _ansible_check_mode.",
        ),
        ([], "The argument file must contain a JSON object."),
    ],
)
def test_argument_failure_has_no_hostname_fields_or_native_access(
    native: Mock, run_request: RequestRunner, arguments: object, message: str
) -> None:
    assert run_request(arguments) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": message,
            "exception": "(traceback unavailable)",
        },
    )
    assert native.mock_calls == []


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("error_type", [ValueError, OSError])
def test_rename_failure_preserves_initialized_fields_and_recovery_can_be_retried(
    native: Mock,
    stored: dict[str, str],
    run_request: RequestRunner,
    check: bool,
    error_type: type[Exception],
) -> None:
    successful_rename = native.rename_hostname.side_effect
    native.rename_hostname.side_effect = error_type("The requested name is invalid.")
    assert run_request(
        {"name": REQUESTED, "_ansible_check_mode": check, "_ansible_diff": True}
    ) == (
        1,
        {
            "changed": False,
            "old_name": CURRENT,
            "reboot_required": False,
            "diff": {"before": CURRENT, "after": REQUESTED},
            "failed": True,
            "msg": "Failed to rename computer to 'New-Host': The requested name is invalid.",
            "exception": "(traceback unavailable)",
        },
    )
    assert stored == {"active": CURRENT, "pending": CURRENT}
    native.rename_hostname.assert_called_once_with(REQUESTED, check_mode=check)
    native.rename_hostname.side_effect = successful_rename
    assert run_request({"name": REQUESTED}) == (
        0,
        {"changed": True, "old_name": CURRENT, "reboot_required": True},
    )
    assert stored == {"active": CURRENT, "pending": REQUESTED}


# pylint: enable=duplicate-code


def test_hostname_read_failure_stops_before_rename(
    native: Mock, stored: dict[str, str], run_request: RequestRunner
) -> None:
    native.read_hostname.side_effect = OSError("WMI provider unavailable.")
    assert run_request({"name": REQUESTED, "_ansible_diff": True}) == (
        1,
        {"changed": False, "failed": True, "msg": "WMI provider unavailable."},
    )
    assert native.mock_calls == [call.read_hostname()]
    assert stored == {"active": CURRENT, "pending": CURRENT}
