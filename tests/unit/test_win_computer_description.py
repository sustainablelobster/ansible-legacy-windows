"""Exercise metadata requests and failure recovery without accessing Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Frontend calls cover binding, comparison, and ordered native operations.
# pylint: disable=protected-access

import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Mapping
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

RequestRunner = Callable[[object], tuple[int, dict[str, Any]]]
FIELDS = ("description", "owner", "organization")
REGISTRATION = {
    "owner": "RegisteredOwner",
    "organization": "RegisteredOrganization",
}


@pytest.fixture(name="stored")
def stored_metadata() -> dict[str, str]:
    """Provide persistent Windows properties isolated to each test.

    :returns: Description and registration values before the request.
    """
    return {
        "description": "Application server",
        "RegisteredOwner": "Operations",
        "RegisteredOrganization": "Example Company",
    }


@pytest.fixture(name="native")
def metadata_operations(stored: dict[str, str]) -> Mock:
    """Record native reads and writes while retaining successful writes.

    :param stored: Persistent properties shared with the test.
    :returns: Recorder for the four native metadata operations.
    """
    native = Mock()
    native.read_description.side_effect = lambda: stored["description"]
    native.read_registration.side_effect = stored.__getitem__

    def write_description(value: str) -> None:
        stored["description"] = value

    native.write_description.side_effect = write_description
    native.write_registration.side_effect = stored.__setitem__
    return native


@pytest.fixture(name="payload")
def metadata_payload(monkeypatch: pytest.MonkeyPatch, native: Mock) -> ModuleType:
    """Import the frontend with its native metadata boundaries substituted.

    :param monkeypatch: Scoped imports and native-operation substitutions.
    :param native: Recorder for persistent metadata reads and writes.
    :returns: Imported metadata frontend.
    """
    module = load_payload("win_computer_description", monkeypatch)
    for name in (
        "read_description",
        "write_description",
        "read_registration",
        "write_registration",
    ):
        monkeypatch.setattr(module.computer, name, getattr(native, name))
    return module


def _apply(
    payload: ModuleType, options: Mapping[str, object], *, check: bool = False
) -> dict[str, Any]:
    result: dict[str, Any] = payload._manage(payload._parameters(options), check)
    return result


@pytest.fixture(name="run_request")
def request_runner(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> RequestRunner:
    """Run argument files through the module's public JSON entry point.

    :param payload: Loaded module with isolated metadata operations.
    :param monkeypatch: Scoped command-line replacement.
    :param tmp_path: Directory for the JSON request file.
    :param capsys: Capture of the module's JSON output.
    :returns: Request runner sharing this test's persistent properties.
    """
    argument_file = tmp_path / "arguments.json"
    monkeypatch.setattr(
        sys, "argv", ["win_computer_description.py", str(argument_file)]
    )

    def _run_request(arguments: object) -> tuple[int, dict[str, Any]]:
        argument_file.write_text(json.dumps(arguments), encoding="utf-8")
        return invoke_payload(payload, capsys)

    return _run_request


@pytest.mark.parametrize("field", FIELDS)
def test_omitted_fields_have_no_value(payload: ModuleType, field: str) -> None:
    assert payload._parameters({field: "Requested"}) == {
        name: "Requested" if name == field else None for name in FIELDS
    }


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize(
    "value,expected",
    [
        (None, None),
        ("", ""),
        ("\u00a0Name\u2003", "\u00a0Name\u2003"),
        (True, "True"),
        (False, "False"),
        (42, "42"),
        (-42, "-42"),
        (1.5, "1.5"),
        (["one", "two"], "System.Object[]"),
        ({"name": "value"}, "System.Collections.Hashtable"),
    ],
)
def test_optional_strings_use_shared_binding(
    payload: ModuleType, field: str, value: object, expected: str | None
) -> None:
    assert payload._parameters({field: value})[field] == expected


@pytest.mark.parametrize("field", FIELDS)
def test_only_the_requested_field_is_read_and_changed(
    payload: ModuleType, native: Mock, stored: dict[str, str], field: str
) -> None:
    before = dict(stored)
    assert _apply(payload, {field: "Requested"}) == {"changed": True}
    property_name = REGISTRATION.get(field, field)
    assert stored == {**before, property_name: "Requested"}
    expected = (
        [call.read_description(), call.write_description("Requested")]
        if field == "description"
        else [
            call.read_registration(property_name),
            call.write_registration(property_name, "Requested"),
        ]
    )
    assert native.mock_calls == expected
    native.reset_mock()
    assert _apply(payload, {field: "Requested"}) == {"changed": False}
    assert native.mock_calls == expected[:1]


@pytest.mark.parametrize("field", FIELDS)
def test_comparisons_are_case_sensitive(
    payload: ModuleType, native: Mock, stored: dict[str, str], field: str
) -> None:
    name = REGISTRATION.get(field, field)
    assert _apply(payload, {field: stored[name].lower()}) == {"changed": True}
    assert len(native.mock_calls) == 2


def test_check_mode_predicts_changes_without_mutating_properties(
    payload: ModuleType, native: Mock, stored: dict[str, str]
) -> None:
    before = dict(stored)
    options = {"owner": "New owner", "organization": "New org", "description": "New"}
    assert _apply(payload, options, check=True) == {"changed": True}
    assert stored == before
    assert native.mock_calls == [
        call.read_description(),
        call.read_registration("RegisteredOwner"),
        call.read_registration("RegisteredOrganization"),
    ]
    native.reset_mock()
    assert _apply(payload, options) == {"changed": True}
    assert native.mock_calls == [
        call.read_description(),
        call.write_description("New"),
        call.read_registration("RegisteredOwner"),
        call.write_registration("RegisteredOwner", "New owner"),
        call.read_registration("RegisteredOrganization"),
        call.write_registration("RegisteredOrganization", "New org"),
    ]
    native.reset_mock()
    assert _apply(payload, options, check=True) == {"changed": False}
    assert _apply(payload, options) == {"changed": False}
    assert native.write_description.call_count == 0
    assert native.write_registration.call_count == 0


def test_empty_strings_clear_all_fields_and_repeat_without_writes(
    payload: ModuleType, native: Mock, stored: dict[str, str]
) -> None:
    options = dict.fromkeys(FIELDS, "")
    assert _apply(payload, options) == {"changed": True}
    assert all(value == "" for value in stored.values())
    native.reset_mock()
    assert _apply(payload, options) == {"changed": False}
    assert native.write_description.call_count == 0
    assert native.write_registration.call_count == 0


@pytest.mark.parametrize("fields", [(field,) for field in FIELDS] + [FIELDS])
def test_explicit_null_satisfies_presence_requirement_without_native_access(
    native: Mock, run_request: RequestRunner, fields: tuple[str, ...]
) -> None:
    assert run_request(dict.fromkeys(fields)) == (0, {"changed": False})
    assert native.mock_calls == []


def test_null_fields_are_skipped_alongside_requested_empty_value(
    native: Mock, stored: dict[str, str], run_request: RequestRunner
) -> None:
    assert run_request({"owner": None, "organization": None, "description": ""}) == (
        0,
        {"changed": True},
    )
    assert native.mock_calls == [call.read_description(), call.write_description("")]
    assert stored["RegisteredOwner"] == "Operations"
    assert stored["RegisteredOrganization"] == "Example Company"


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.mark.parametrize(
    "options,message",
    [
        ({}, "one of the following is required: owner, organization, description"),
        (
            {"unknown": "value"},
            "Unsupported parameters for "
            "(sustainablelobster.legacy_windows.win_computer_description) module: "
            "unknown. Supported parameters include: description, organization, owner",
        ),
        (
            {"owner": "Requested", "_ansible_check_mode": "invalid"},
            "Expected a boolean for _ansible_check_mode.",
        ),
        ([], "The argument file must contain a JSON object."),
    ],
)
def test_argument_failures_include_the_pinned_exception_field_without_native_access(
    native: Mock,
    run_request: RequestRunner,
    options: object,
    message: str,
) -> None:
    assert run_request(options) == (
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
def test_json_entry_matches_case_insensitive_flags_and_has_no_diff(
    native: Mock, stored: dict[str, str], run_request: RequestRunner
) -> None:
    before = dict(stored)
    options = {"DESCRIPTION": "\u00c9quipe \u6f22\u5b57", "_ANSIBLE_DIFF": True}
    assert run_request({**options, "_ANSIBLE_CHECK_MODE": "yes"}) == (
        0,
        {"changed": True},
    )
    assert stored == before
    assert native.mock_calls == [call.read_description()]
    assert run_request(options) == (0, {"changed": True})
    assert stored["description"] == options["DESCRIPTION"]
    assert run_request(options) == (0, {"changed": False})


# pylint: enable=duplicate-code


def test_ignored_unknown_option_does_not_mask_required_field(
    native: Mock, run_request: RequestRunner
) -> None:
    assert run_request(
        {"unknown": "value", "owner": None, "_ansible_ignore_unknown_opts": True}
    ) == (0, {"changed": False})
    assert native.mock_calls == []


@pytest.mark.parametrize("field", ["owner", "organization"])
@pytest.mark.parametrize("check", [False, True])
def test_missing_registration_failure_does_not_create_the_value(
    native: Mock, run_request: RequestRunner, field: str, check: bool
) -> None:
    registration = REGISTRATION[field]
    message = (
        "Unhandled exception while executing module: Property "
        + registration
        + " does not exist at path HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\"
        "Windows NT\\CurrentVersion\\."
    )
    native.read_registration.side_effect = ValueError(message)
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    assert run_request({field: "", "_ansible_check_mode": check}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": message,
            "exception": "(traceback unavailable)",
        },
    )
    # pylint: enable=duplicate-code
    assert native.mock_calls == [call.read_registration(registration)]


@pytest.mark.parametrize("failure", ["read_registration", "write_registration"])
@pytest.mark.parametrize("registration", ["RegisteredOwner", "RegisteredOrganization"])
def test_later_failure_preserves_earlier_writes_and_a_repeat_recovers(
    native: Mock,
    stored: dict[str, str],
    run_request: RequestRunner,
    failure: str,
    registration: str,
) -> None:
    operation = getattr(native, failure)
    successful_operation = operation.side_effect
    message = "Unhandled exception while executing module: Registry access denied."

    def _fail_requested_registration(name: str, *values: str) -> object:
        if name == registration:
            raise ValueError(message)
        return successful_operation(name, *values)

    operation.side_effect = _fail_requested_registration
    options = {"owner": "New owner", "organization": "New org", "description": "New"}
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    assert run_request(options) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": message,
            "exception": "(traceback unavailable)",
        },
    )
    # pylint: enable=duplicate-code
    assert stored == {
        "description": "New",
        "RegisteredOwner": (
            "New owner" if registration == "RegisteredOrganization" else "Operations"
        ),
        "RegisteredOrganization": "Example Company",
    }
    if registration == "RegisteredOwner":
        assert call.read_registration("RegisteredOrganization") not in native.mock_calls
    operation.side_effect = successful_operation
    native.reset_mock()
    assert run_request(options) == (0, {"changed": True})
    expected = [
        call.read_description(),
        call.read_registration("RegisteredOwner"),
    ]
    if registration == "RegisteredOwner":
        expected.append(call.write_registration("RegisteredOwner", "New owner"))
    expected.extend(
        [
            call.read_registration("RegisteredOrganization"),
            call.write_registration("RegisteredOrganization", "New org"),
        ]
    )
    assert native.mock_calls == expected
    assert run_request(options) == (0, {"changed": False})


@pytest.mark.parametrize("operation", ["read_description", "write_description"])
def test_description_failure_stops_before_registration_operations(
    native: Mock, stored: dict[str, str], run_request: RequestRunner, operation: str
) -> None:
    before = dict(stored)
    getattr(native, operation).side_effect = OSError("WMI provider unavailable.")
    assert run_request(dict.fromkeys(FIELDS, "Requested")) == (
        1,
        {"changed": False, "failed": True, "msg": "WMI provider unavailable."},
    )
    assert stored == before
    assert native.read_registration.call_count == 0
    assert native.write_registration.call_count == 0
