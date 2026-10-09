"""Exercise public Server Manager binding, source checks and complete results."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Provider substitutes do not establish Windows execution support.

import copy
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload


def _no_change_result() -> dict[str, Any]:
    return {
        "changed": False,
        "exitcode": "NoChangeNeeded",
        "feature_result": [],
        "reboot_required": False,
        "success": True,
        "failed": False,
    }


def _install_result() -> dict[str, Any]:
    # Recorded ansible.windows 3.8.0 Telnet-Client check-mode result.
    return {
        "changed": True,
        "exitcode": "Success",
        "feature_result": [
            {
                "id": 44,
                "display_name": "Telnet Client",
                "message": [],
                "reboot_required": False,
                "skip_reason": "NotSkipped",
                "success": True,
            }
        ],
        "reboot_required": False,
        "success": True,
        "failed": False,
    }


@pytest.fixture(name="runner")
def feature_runner(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> Any:
    """Run the public JSON entry point with an observable provider boundary.

    :param monkeypatch: Scoped argument-path and provider substitutions.
    :param capsys: JSON output capture.
    :param tmp_path: Isolated argument-file directory.
    :returns: Public runner and provider substitute.
    """
    module = load_payload("win_feature", monkeypatch)
    manage = Mock(side_effect=lambda *_args: _no_change_result())
    monkeypatch.setattr(module.features, "manage", manage)
    argument_file = tmp_path / "arguments.json"

    def _run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        argument_file.write_text(json.dumps(arguments), encoding="utf-8")
        monkeypatch.setattr(sys, "argv", ["win_feature.py", str(argument_file)])
        return invoke_payload(module, capsys)

    return SimpleNamespace(run=_run, manage=manage)


def test_defaults_reach_provider_and_return_all_no_change_fields(runner: Any) -> None:
    assert runner.run({"name": "Telnet-Client"}) == (0, _no_change_result())
    runner.manage.assert_called_once_with(
        {
            "names": ["Telnet-Client"],
            "state": "present",
            "include_sub_features": False,
            "include_management_tools": False,
            "source": None,
        },
        False,
    )


@pytest.mark.parametrize(
    "names,expected",
    [
        (
            " TFTP-Client,Telnet-Client,TFTP-Client ",
            ["TFTP-Client", "Telnet-Client", "TFTP-Client"],
        ),
        (["telnet-client", "Telnet-Client"], ["telnet-client", "Telnet-Client"]),
        ("Tel*", ["Tel*"]),
        ("Tel.*", ["Tel.*"]),
    ],
)
def test_names_preserve_order_duplicates_case_and_literal_punctuation(
    runner: Any, names: Any, expected: list[str]
) -> None:
    assert runner.run({"name": names, "state": "PRESENT"})[0] == 0
    options, check = runner.manage.call_args.args
    assert options["names"] == expected
    assert options["state"] == "present"
    assert check is False


@pytest.mark.parametrize("field", ["include_sub_features", "include_management_tools"])
@pytest.mark.parametrize(
    "value,expected", [(None, False), ("no", False), ("yes", True)]
)
def test_nullable_boolean_options_are_bound_before_provider_call(
    runner: Any, field: str, value: Any, expected: bool
) -> None:
    assert runner.run({"name": "Telnet-Client", field: value})[0] == 0
    assert runner.manage.call_args.args[0][field] is expected


def test_case_insensitive_public_keys_and_controller_flag_are_read_from_json(
    runner: Any,
) -> None:
    assert (
        runner.run(
            {
                "NAME": "Telnet-Client",
                "STATE": "ABSENT",
                "INCLUDE_MANAGEMENT_TOOLS": True,
                "_ANSIBLE_CHECK_MODE": True,
            }
        )[0]
        == 0
    )
    options, check = runner.manage.call_args.args
    assert options["state"] == "absent"
    assert options["include_management_tools"] is True
    assert check is True


@pytest.mark.parametrize("check", [False, True])
def test_null_state_reaches_the_provider_for_the_upstream_removal_branch(
    runner: Any, check: bool
) -> None:
    assert runner.run(
        {"name": "Telnet-Client", "state": None, "_ansible_check_mode": check}
    ) == (0, _no_change_result())
    assert runner.manage.call_args.args[0]["state"] is None
    assert runner.manage.call_args.args[1] is check


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("state", ["present", "absent", None])
def test_nonempty_missing_source_precedes_provider_for_every_operation(
    runner: Any, tmp_path: Path, check: bool, state: str | None
) -> None:
    source = str(tmp_path / "missing")
    result = _no_change_result()
    result.update(
        failed=True, msg="Failed to find source path " + source + " for feature install"
    )
    runner.manage.side_effect = OSError("provider unavailable")
    assert runner.run(
        {
            "name": "Telnet-Client",
            "state": state,
            "source": source,
            "_ansible_check_mode": check,
        }
    ) == (1, result)
    runner.manage.assert_not_called()


@pytest.mark.parametrize("directory", [False, True])
def test_existing_literal_source_accepts_file_or_directory(
    runner: Any, tmp_path: Path, directory: bool
) -> None:
    source = tmp_path / "literal [source]"
    if directory:
        source.mkdir()
    else:
        source.write_text("fixture", encoding="utf-8")
    assert runner.run({"name": "Telnet-Client", "source": str(source)})[0] == 0
    assert runner.manage.call_args.args[0]["source"] == str(source)


def test_source_does_not_use_wildcard_expansion(runner: Any, tmp_path: Path) -> None:
    (tmp_path / "source1").mkdir()
    source = str(tmp_path / "source?")
    status, result = runner.run({"name": "Telnet-Client", "source": source})
    assert status == 1
    assert (
        result["msg"] == "Failed to find source path " + source + " for feature install"
    )
    runner.manage.assert_not_called()


@pytest.mark.parametrize("source", [None, ""])
def test_null_and_empty_sources_skip_path_validation_and_reach_provider(
    runner: Any, source: str | None
) -> None:
    runner.manage.side_effect = None
    runner.manage.return_value = _install_result()
    assert runner.run({"name": "Telnet-Client", "source": source}) == (
        0,
        _install_result(),
    )
    assert runner.manage.call_args.args[0]["source"] == source


@pytest.mark.parametrize("state", ["present", "absent"])
def test_check_mode_keeps_complete_prediction_from_provider(
    runner: Any, state: str
) -> None:
    runner.manage.side_effect = None
    runner.manage.return_value = _install_result()
    assert runner.run(
        {"name": "Telnet-Client", "state": state, "_ansible_check_mode": True}
    ) == (0, _install_result())
    assert runner.manage.call_args.args[1] is True


def test_repeated_requests_keep_provider_idempotence_result(runner: Any) -> None:
    runner.manage.side_effect = [_install_result(), _no_change_result()]
    assert runner.run({"name": "Telnet-Client"}) == (0, _install_result())
    assert runner.run({"name": "Telnet-Client"}) == (0, _no_change_result())
    assert runner.manage.call_count == 2


def test_failed_provider_result_preserves_messages_rows_and_reboot(runner: Any) -> None:
    result = _install_result()
    result.update(exitcode="Failed", failed=True, success=False, reboot_required=True)
    result["feature_result"][0].update(
        success=False,
        reboot_required=True,
        message=[{"message_type": "Error", "error_code": 5, "text": "Access denied"}],
    )
    expected = copy.deepcopy(result)
    runner.manage.side_effect = None
    runner.manage.return_value = result
    assert runner.run({"name": "Telnet-Client"}) == (1, expected)


@pytest.mark.parametrize("names", ["Tel*", "Tel.*", "LegacyWindowsUnknownFeature"])
def test_invalid_literal_name_retains_upstream_exception_shape(
    runner: Any, names: str
) -> None:
    diagnostic = (
        "ArgumentNotValid: The role, role service, or feature name is not valid: '"
        + names
        + "'. The name was not found."
    )
    runner.manage.side_effect = ValueError(diagnostic)
    assert runner.run({"name": names, "_ansible_check_mode": True}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "Unhandled exception while executing module: " + diagnostic,
        },
    )
    assert runner.manage.call_args.args[0]["names"] == [names]


@pytest.mark.parametrize(
    "names,diagnostic",
    [
        (
            None,
            "Cannot validate argument on parameter 'Name'. The argument is null "
            "or empty. Provide an argument that is not null or empty, and then try "
            "the command again.",
        ),
        (
            [],
            "Cannot validate argument on parameter 'Name'. The argument is null, "
            "empty, or an element of the argument collection contains a null value. "
            "Supply a collection that does not contain any null values and then try "
            "the command again.",
        ),
    ],
)
def test_null_and_empty_names_preserve_distinct_provider_binding_failures(
    runner: Any, names: Any, diagnostic: str
) -> None:
    runner.manage.side_effect = ValueError(diagnostic)
    assert runner.run({"name": names}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "Unhandled exception while executing module: " + diagnostic,
        },
    )
    assert runner.manage.call_args.args[0]["names"] == names


@pytest.mark.parametrize(
    "state,command",
    [("present", "Install-WindowsFeature"), ("absent", "Uninstall-WindowsFeature")],
)
def test_unavailable_provider_discards_initialized_feature_fields(
    runner: Any, state: str, command: str
) -> None:
    diagnostic = (
        "The term '" + command + "' is not recognized as the name of a cmdlet, "
        "function, script file, or operable program. Check the spelling of the "
        "name, or if a path was included, verify that the path is correct and "
        "try again."
    )
    runner.manage.side_effect = OSError(diagnostic)
    assert runner.run({"name": "Telnet-Client", "state": state}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "Unhandled exception while executing module: " + diagnostic,
        },
    )


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({}, "missing required arguments: name"),
        (
            {"name": "Telnet-Client", "state": "invalid"},
            "value of state must be one of:",
        ),
        (
            {"name": "Telnet-Client", "include_sub_features": "invalid"},
            "Expected a boolean for include_sub_features.",
        ),
        (
            {"name": "Telnet-Client", "include_management_tools": "invalid"},
            "Expected a boolean for include_management_tools.",
        ),
        (
            {"name": "Telnet-Client", "unknown": True},
            "Unsupported parameters for (sustainablelobster.legacy_windows.win_feature)",
        ),
    ],
)
def test_argument_failures_precede_provider_and_initialized_fields(
    runner: Any, arguments: dict[str, Any], message: str
) -> None:
    status, result = runner.run(arguments)
    assert status == 1
    assert result["changed"] is False and result["failed"] is True
    assert message in result["msg"]
    assert set(result) == {"changed", "failed", "msg"}
    runner.manage.assert_not_called()
