"""Exercise hosts requests and JSON failures without accessing Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Frontend calls cover argument binding and the order of file operations.
# pylint: disable=protected-access

import errno
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Callable
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

ADDRESS = "192.0.2.10"
NAME = "application.example.test"
RequestRunner = Callable[[object], tuple[int, dict[str, Any]]]


@pytest.fixture(name="stored")
def stored_lines() -> list[str]:
    """Provide a hosts-file substitute isolated to each test.

    :returns: The persisted file's lines without newline characters.
    """
    return ["# fixture", "127.0.0.1 localhost", "::1 localhost"]


@pytest.fixture(name="native")
def file_operations(stored: list[str]) -> Mock:
    """Record file reads and writes while retaining their effects.

    :param stored: Persisted hosts lines shared with the test.
    :returns: File-operation recorder returning independent read snapshots.
    """
    native = Mock()
    native.read_hosts.side_effect = lambda: list(stored)

    def write_hosts(lines: list[str]) -> None:
        stored[:] = lines

    native.write_hosts.side_effect = write_hosts
    return native


@pytest.fixture(name="payload")
def hosts_payload(monkeypatch: pytest.MonkeyPatch, native: Mock) -> ModuleType:
    """Import the hosts frontend with only its file boundaries substituted.

    :param monkeypatch: Scoped imports and native-operation substitutions.
    :param native: Recorder for persistent file reads and writes.
    :returns: Imported frontend using the actual address and editing helpers.
    """
    module = load_payload("win_hosts", monkeypatch)
    monkeypatch.setattr(module.hosts, "read_hosts", native.read_hosts)
    monkeypatch.setattr(module.hosts, "write_hosts", native.write_hosts)
    # These frontend fixtures use ASCII host names; helper tests cover equality.
    monkeypatch.setattr(
        module.hosts.environment,
        "values_equal",
        lambda left, right, **_options: (
            left is right
            if left is None or right is None
            else left.lower() == right.lower()
        ),
    )
    return module


def _apply(
    payload: ModuleType,
    *,
    check: bool = False,
    diff: bool = False,
    **options: object,
) -> dict[str, Any]:
    result: dict[str, Any] = payload._manage(payload._parameters(options), check, diff)
    return result


@pytest.fixture(name="run_request")
def request_runner(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> RequestRunner:
    """Run argument files through the module's public JSON entry point.

    :param payload: Loaded module with isolated hosts-file operations.
    :param monkeypatch: Scoped command-line replacement.
    :param tmp_path: Directory for the JSON request file.
    :param capsys: Capture of the module's JSON output.
    :returns: Request runner sharing this test's persisted hosts file.
    """
    argument_file = tmp_path / "arguments.json"
    monkeypatch.setattr(sys, "argv", ["win_hosts.py", str(argument_file)])

    def _run_request(arguments: object) -> tuple[int, dict[str, Any]]:
        argument_file.write_text(json.dumps(arguments), encoding="utf-8")
        return invoke_payload(payload, capsys)

    return _run_request


def test_defaults_and_requested_address_spelling(payload: ModuleType) -> None:
    assert payload._parameters({"canonical_name": NAME, "ip_address": "127.1"}) == {
        "state": "present",
        "action": "set",
        "canonical_name": NAME,
        "ip_address": "127.1",
        "aliases": None,
    }


@pytest.mark.parametrize(
    "supplied,expected",
    [
        ("app, alternate", ["app", "alternate"]),
        ("\u00a0app\u2003,\talternate\n", ["app", "alternate"]),
        ("", [""]),
        (None, None),
        ([], []),
        ([" app ", "alternate,other"], [" app ", "alternate,other"]),
        (0, ["0"]),
        (-(2**63), [str(-(2**63))]),
        (2**63 - 1, [str(2**63 - 1)]),
        ([True, 42, 1.5], ["True", "42", "1.5"]),
        ([[], {}], ["System.Object[]", "System.Collections.Hashtable"]),
    ],
)
def test_aliases_follow_shared_list_binding(
    payload: ModuleType, supplied: object, expected: list[str] | None
) -> None:
    parameters = payload._parameters({"state": "absent", "aliases": supplied})
    assert parameters["aliases"] == expected


@pytest.mark.parametrize(
    "supplied,kind",
    [
        (True, "System.Boolean"),
        (False, "System.Boolean"),
        ({}, "System.Collections.Hashtable"),
        (1.5, "System.Decimal"),
        (2**63, "System.Decimal"),
        (-(2**63) - 1, "System.Decimal"),
        (1e30, "System.Double"),
    ],
)
def test_alias_conversion_errors_match_pinned_basic_messages(
    payload: ModuleType, native: Mock, supplied: object, kind: str
) -> None:
    with pytest.raises(ValueError) as error:
        _apply(payload, state="absent", aliases=supplied)
    assert str(error.value) == (
        f"argument for aliases is of type {kind} and we were unable to convert "
        f"to list: {kind} cannot be converted to a list"
    )
    assert native.mock_calls == []


def test_null_alias_element_matches_pinned_basic_failure(
    native: Mock, run_request: RequestRunner
) -> None:
    code, result = run_request({"state": "absent", "aliases": [None]})
    assert code == 1 and result == {
        "failed": True,
        "changed": False,
        "exception": "(traceback unavailable)",
        "msg": (
            'Unhandled exception while executing module: Exception calling "Create" '
            'with "2" argument(s): "Object reference not set to an instance of an object."'
        ),
    }
    assert native.mock_calls == []


@pytest.mark.parametrize("scope", [2**31, 2**32 - 1])
def test_scope_overflow_preserves_the_recorded_exception_fields_without_file_access(
    native: Mock, run_request: RequestRunner, scope: int
) -> None:
    code, result = run_request(
        {"canonical_name": NAME, "ip_address": "fe80::1%" + str(scope)}
    )
    assert code == 1 and result == {
        "changed": False,
        "failed": True,
        "exception": "(traceback unavailable)",
        "msg": (
            'Unhandled exception while executing module: Exception calling "TryParse" '
            'with "2" argument(s): "Specified argument was out of the range of valid '
            'values.\r\nParameter name: scopeid"'
        ),
    }
    assert native.mock_calls == []


@pytest.mark.parametrize(
    "options,missing",
    [
        ({}, "canonical_name, ip_address"),
        ({"canonical_name": NAME}, "ip_address"),
        ({"ip_address": ADDRESS}, "canonical_name"),
    ],
)
def test_present_requires_both_selectors_before_file_access(
    payload: ModuleType, native: Mock, options: dict[str, Any], missing: str
) -> None:
    with pytest.raises(ValueError) as error:
        _apply(payload, **options)
    assert str(error.value) == (
        "state is present but all of the following are missing: " + missing
    )
    assert native.mock_calls == []


@pytest.mark.parametrize("name", ["canonical_name", "ip_address"])
@pytest.mark.parametrize("value", [None, ""])
def test_present_required_arguments_are_checked_by_presence_only(
    payload: ModuleType, name: str, value: str | None
) -> None:
    options = {"canonical_name": NAME, "ip_address": ADDRESS, name: value}
    assert payload._parameters(options)[name] == value


@pytest.mark.parametrize(
    "options,message",
    [
        ({"state": "replace"}, "value of state must be one of: absent, present"),
        ({"action": "replace"}, "value of action must be one of"),
        (
            {"state": "absent", "ip_address": "not-an-address"},
            "win_hosts: Argument ip_address needs to be a valid ip address",
        ),
        ({"state": "absent", "aliases": [None]}, "Object reference not set"),
    ],
)
def test_invalid_parameters_fail_before_file_access(
    payload: ModuleType, native: Mock, options: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        _apply(payload, **options)
    assert native.mock_calls == []


def test_choices_are_case_insensitive_and_null_is_preserved(
    payload: ModuleType,
) -> None:
    assert payload._parameters({"state": "ABSENT", "action": "ADD"}) == {
        "state": "absent",
        "action": "add",
        "aliases": None,
        "canonical_name": None,
        "ip_address": None,
    }
    parameters = payload._parameters({"state": None, "action": None})
    assert parameters["state"] is None and parameters["action"] is None


def test_add_repeat_remove_and_repeat_have_only_necessary_writes(
    payload: ModuleType, native: Mock, stored: list[str]
) -> None:
    original = list(stored)
    options: dict[str, Any] = {"canonical_name": NAME, "ip_address": ADDRESS}
    entry = ADDRESS + " " + NAME + " "
    assert _apply(payload, **options) == {"changed": True}
    assert native.mock_calls == [
        call.read_hosts(),
        call.write_hosts(original + [entry]),
    ]
    assert stored == original + [entry]

    native.reset_mock()
    assert _apply(payload, **options) == {"changed": False}
    assert native.mock_calls == [call.read_hosts()]

    native.reset_mock()
    assert _apply(payload, state="absent", **options) == {"changed": True}
    assert native.mock_calls == [call.read_hosts(), call.write_hosts(original)]
    assert stored == original

    native.reset_mock()
    assert _apply(payload, state="absent", **options) == {"changed": False}
    assert native.mock_calls == [call.read_hosts()]


@pytest.mark.parametrize(
    "case",
    [
        ("set", ["app"], ["app"]),
        ("add", ["app"], ["old", "retained", "app"]),
        ("remove", ["old"], ["retained"]),
    ],
)
def test_alias_actions_persist_the_requested_result_and_repeat_without_writing(
    payload: ModuleType,
    native: Mock,
    stored: list[str],
    case: tuple[str, list[str], list[str]],
) -> None:
    action, aliases, expected = case
    stored[:] = [ADDRESS + " " + NAME + " old retained # keep this comment"]
    options: dict[str, Any] = {
        "canonical_name": NAME,
        "ip_address": ADDRESS,
        "action": action,
        "aliases": aliases,
    }
    assert _apply(payload, **options) == {"changed": True}
    assert stored[0].split("#", 1)[0].split() == [ADDRESS, NAME] + expected
    assert stored[0].endswith("# keep this comment")
    native.write_hosts.assert_called_once_with(stored)
    native.reset_mock()
    assert _apply(payload, **options) == {"changed": False}
    assert native.mock_calls == [call.read_hosts()]


@pytest.mark.parametrize("value", [None, ""])
def test_null_or_empty_present_selectors_append_the_upstream_blank_entry(
    payload: ModuleType, native: Mock, stored: list[str], value: str | None
) -> None:
    original = list(stored)
    assert _apply(payload, canonical_name=value, ip_address=value, diff=True) == {
        "changed": True,
        "diff": {
            "before": "\n".join(original) + "\n",
            "after": "\n".join(original + ["  "]) + "\n",
        },
    }
    assert stored == original + ["  "]
    assert native.mock_calls == [call.read_hosts(), call.write_hosts(stored)]


@pytest.mark.parametrize("state", ["present", "absent"])
def test_check_mode_predicts_diff_without_writing(
    payload: ModuleType, native: Mock, stored: list[str], state: str
) -> None:
    original = list(stored)
    options: dict[str, Any] = {"state": state}
    if state == "present":
        options.update(canonical_name=NAME, ip_address=ADDRESS)
    predicted = _apply(payload, check=True, diff=True, **options)
    assert predicted["changed"] is True
    assert predicted["diff"]["before"] == "\n".join(original) + "\n"
    assert stored == original
    assert native.mock_calls == [call.read_hosts()]
    assert _apply(payload, diff=True, **options) == predicted
    assert predicted["diff"]["after"] == "\n".join(stored) + "\n"


@pytest.mark.parametrize("diff", [False, True])
def test_null_state_reads_without_editing_or_writing(
    payload: ModuleType, native: Mock, stored: list[str], diff: bool
) -> None:
    result = _apply(payload, state=None, diff=diff)
    assert result["changed"] is False and ("diff" in result) is diff
    if diff:
        text = "\n".join(stored) + "\n"
        assert result["diff"] == {"before": text, "after": text}
    assert native.mock_calls == [call.read_hosts()]


def test_empty_file_diff_still_has_final_line_feed(
    payload: ModuleType, native: Mock, stored: list[str]
) -> None:
    stored.clear()
    assert _apply(payload, state="absent", diff=True) == {
        "changed": False,
        "diff": {"before": "\n", "after": "\n"},
    }
    assert native.mock_calls == [call.read_hosts()]


def test_json_flags_names_and_unicode_are_preserved(
    native: Mock, stored: list[str], run_request: RequestRunner
) -> None:
    code, result = run_request(
        {
            "STATE": "PRESENT",
            "CANONICAL_NAME": "café.example.test",
            "IP_ADDRESS": "2001:db8::1",
            "ALIASES": ["雪"],
            "ACTION": "ADD",
            "_ANSIBLE_CHECK_MODE": "yes",
            "_ANSIBLE_DIFF": "yes",
        }
    )
    assert code == 0 and result["changed"] is True
    assert result["diff"]["before"] == "\n".join(stored) + "\n"
    assert result["diff"]["after"].endswith("2001:db8::1 café.example.test 雪\n")
    assert native.mock_calls == [call.read_hosts()]


@pytest.mark.parametrize(
    "case",
    [
        ([], "must contain a JSON object"),
        ({}, "state is present but all of the following are missing"),
        ({"state": "absent", "unknown": True}, "Unsupported parameters"),
        ({"state": "absent", "_ansible_check_mode": "maybe"}, "Expected a boolean"),
        ({"state": "absent", "_ansible_diff": "maybe"}, "Expected a boolean"),
        ({"state": "absent", "ip_address": "invalid"}, "valid ip address"),
    ],
)
def test_json_validation_failures_have_no_file_effects(
    native: Mock, run_request: RequestRunner, case: tuple[object, str]
) -> None:
    arguments, message = case
    code, result = run_request(arguments)
    assert code == 1 and result["failed"] is True and result["changed"] is False
    assert message in result["msg"] and "diff" not in result
    assert native.mock_calls == []


def test_json_can_ignore_unknown_parameters_when_requested(
    native: Mock, run_request: RequestRunner
) -> None:
    code, result = run_request(
        {"state": None, "unknown": True, "_ansible_ignore_unknown_opts": True}
    )
    assert code == 0 and result == {"changed": False}
    assert native.mock_calls == [call.read_hosts()]


@pytest.mark.parametrize("operation", ["read_hosts", "write_hosts"])
def test_file_failure_returns_json_and_a_later_request_recovers(
    native: Mock, stored: list[str], run_request: RequestRunner, operation: str
) -> None:
    original = list(stored)
    boundary = getattr(native, operation)
    successful_operation = boundary.side_effect
    boundary.side_effect = OSError("hosts file operation failed")
    arguments = {"canonical_name": NAME, "ip_address": ADDRESS, "_ansible_diff": True}
    code, result = run_request(arguments)
    assert code == 1 and result == {
        "changed": False,
        "failed": True,
        "msg": "hosts file operation failed",
    }
    assert stored == original
    if operation == "read_hosts":
        native.write_hosts.assert_not_called()

    boundary.side_effect = successful_operation
    native.reset_mock()
    code, result = run_request(arguments)
    assert code == 0 and result["changed"] is True
    assert stored == original + [ADDRESS + " " + NAME + " "]
    native.write_hosts.assert_called_once_with(stored)


def test_readonly_write_failure_preserves_upstream_fields_and_file_contents(
    native: Mock, stored: list[str], run_request: RequestRunner
) -> None:
    original = list(stored)
    filename = r"C:\WINDOWS\System32\drivers\etc\hosts"
    native.write_hosts.side_effect = OSError(
        errno.EACCES, "Permission denied", filename
    )
    code, result = run_request(
        {"canonical_name": NAME, "ip_address": ADDRESS, "_ansible_diff": True}
    )
    assert code == 1 and result == {
        "changed": False,
        "failed": True,
        "msg": (
            "Unhandled exception while executing module: Access to the path "
            f"'{filename}' is denied."
        ),
        "exception": "(traceback unavailable)",
    }
    assert stored == original
    assert native.mock_calls == [
        call.read_hosts(),
        call.write_hosts(original + [ADDRESS + " " + NAME + " "]),
    ]


def test_readonly_file_is_not_written_in_check_mode(
    native: Mock, stored: list[str], run_request: RequestRunner
) -> None:
    original = list(stored)
    filename = r"C:\WINDOWS\System32\drivers\etc\hosts"
    native.write_hosts.side_effect = OSError(
        errno.EACCES, "Permission denied", filename
    )
    code, result = run_request(
        {
            "canonical_name": NAME,
            "ip_address": ADDRESS,
            "_ansible_check_mode": True,
            "_ansible_diff": True,
        }
    )
    assert code == 0 and result == {
        "changed": True,
        "diff": {
            "before": "\n".join(original) + "\n",
            "after": "\n".join(original + [ADDRESS + " " + NAME + " "]) + "\n",
        },
    }
    assert stored == original and native.mock_calls == [call.read_hosts()]


@pytest.mark.parametrize(
    "error",
    [
        OSError(errno.EACCES, "Permission denied"),
        OSError(errno.ENOENT, "Missing file", r"C:\Windows\System32\drivers\etc\hosts"),
    ],
)
def test_unmatched_file_errors_keep_the_shared_failure_result(
    native: Mock, run_request: RequestRunner, error: OSError
) -> None:
    native.read_hosts.side_effect = error
    code, result = run_request({"state": "absent", "_ansible_diff": True})
    assert code == 1 and result == {
        "changed": False,
        "failed": True,
        "msg": str(error),
    }
    native.write_hosts.assert_not_called()


@pytest.mark.parametrize("state", ["present", "absent"])
def test_malformed_host_line_preserves_exception_fields_without_writing(
    native: Mock, stored: list[str], run_request: RequestRunner, state: str
) -> None:
    stored.append("not-an-address malformed.example.test")
    original = list(stored)
    code, result = run_request(
        {
            "state": state,
            "canonical_name": NAME,
            "ip_address": ADDRESS,
            "_ansible_diff": True,
        }
    )
    assert code == 1 and result == {
        "changed": False,
        "failed": True,
        "msg": (
            "Unhandled exception while executing module: The property "
            "'IPAddressToString' cannot be found on this object. Verify that "
            "the property exists."
        ),
        "exception": "(traceback unavailable)",
    }
    assert stored == original and native.mock_calls == [call.read_hosts()]
