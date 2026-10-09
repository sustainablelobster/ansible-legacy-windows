"""Check classic DSC's public result and dynamic argument boundary."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Dynamic schema binding is a private boundary exercised directly here.
# pylint: disable=protected-access

import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload


def _property(name: str, kind: str = "String", **fields: Any) -> dict[str, Any]:
    result = {
        "name": name,
        "type": kind,
        "required": False,
        "reference": None,
        "choices": None,
        "properties": None,
    }
    result.update(fields)
    return result


def _schema() -> dict[str, Any]:
    destination = _property("DestinationPath")
    destination["required"] = True
    return {
        "module_version": None,
        "invocation": {"Name": "File", "ModuleName": "PSDesiredStateConfiguration"},
        "properties": [
            destination,
            _property("Ensure"),
            _property("Force", "Boolean"),
            _property("Attributes", "StringArray"),
            _property("Credential", "Instance", reference="MSFT_Credential"),
        ],
    }


@pytest.fixture(name="dsc")
def dsc_fixture(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load the target helper with scoped imports.

    :param monkeypatch: Scoped helper search path and number symbols.
    :returns: Imported dynamic DSC helper.
    """
    load_payload("win_dsc", monkeypatch)
    return sys.modules["legacy_windows_dsc"]


@pytest.mark.parametrize(
    "desired,check,changed,methods",
    [
        (True, False, False, ["Test"]),
        (True, True, False, ["Test"]),
        (False, True, True, ["Test"]),
        (False, False, True, ["Test", "Set"]),
    ],
)
def test_resource_lifecycle(
    dsc: Any, desired: bool, check: bool, changed: bool, methods: list[str]
) -> None:
    request = MagicMock(
        side_effect=[
            _schema(),
            {"result": [{"InDesiredState": desired}]},
            {"result": [{"RebootRequired": True}]},
        ]
    )
    result = dsc.configure_resource(
        {
            "resource_name": "File",
            "DestinationPath": "owned",
            "_ansible_check_mode": check,
        },
        request,
    )
    assert result == {
        "changed": changed,
        "module_version": None,
        "reboot_required": methods == ["Test", "Set"],
    }
    assert [call.args[0]["method"] for call in request.call_args_list[1:]] == methods


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({}, "missing required arguments: DestinationPath"),
        (
            {"DestinationPath": "owned", "Credential_username": "user"},
            "parameters are required together: Credential_username, Credential_password",
        ),
        (
            {"DestinationPath": "owned", "UnknownFixtureProperty": True},
            "Unsupported parameters for (ansible.windows.win_dsc) module: UnknownFixtureProperty. "
            "Supported parameters include: Attributes, Credential_password, Credential_username, "
            "DestinationPath, Ensure, Force, module_version, resource_name",
        ),
        (
            {"DestinationPath": "owned", "Force": "invalid-fixture-value"},
            "argument for Force is of type System.String and we were unable to convert to bool: "
            "The value 'invalid-fixture-value' is not a valid boolean. Valid booleans include: "
            "y, yes, on, 1, true, t, 1.0, n, no, off, 0, false, f, 0.0",
        ),
    ],
)
def test_dynamic_validation_is_early(
    dsc: Any, arguments: dict[str, Any], message: str
) -> None:
    request = MagicMock(return_value=_schema())
    result = dsc.configure_resource(dict(arguments, resource_name="File"), request)
    assert result == {"changed": False, "failed": True, "msg": message}
    assert request.call_count == 1


def test_discovery_failure_has_no_resource_fields(dsc: Any) -> None:
    request = MagicMock(return_value={"error": "Resource 'missing' not found."})
    assert dsc.configure_resource({"resource_name": "missing"}, request) == {
        "changed": False,
        "failed": True,
        "msg": "Resource 'missing' not found.",
    }


def test_method_failure_retains_version_verbose_warnings_and_secret_redaction(
    dsc: Any,
) -> None:
    request = MagicMock(
        side_effect=[
            _schema(),
            {
                "error": "Failed to invoke DSC Test method: private-secret",
                "warnings": ["private-secret warning"],
                "verbose": ["private-secret trace"],
            },
        ]
    )
    result = dsc.configure_resource(
        {
            "resource_name": "File",
            "DestinationPath": "owned",
            "Credential_username": "user",
            "Credential_password": "private-secret",
            "_ansible_verbosity": 3,
        },
        request,
    )
    redacted = "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
    assert result == {
        "changed": False,
        "module_version": None,
        "reboot_required": False,
        "failed": True,
        "msg": "Failed to invoke DSC Test method: " + redacted,
        "warnings": [redacted + " warning"],
        "verbose_test": [redacted + " trace"],
    }


@pytest.mark.parametrize("attributes", ["Hidden, System", ["Hidden", "System"]])
def test_case_null_and_comma_array_binding(dsc: Any, attributes: Any) -> None:
    request = MagicMock(side_effect=[_schema(), {"result": [{"InDesiredState": True}]}])
    result = dsc.configure_resource(
        {
            "resource_name": "File",
            "destinationpath": "owned",
            "Force": None,
            "Attributes": attributes,
        },
        request,
    )
    assert result["changed"] is False
    assert request.call_args.args[0]["properties"] == {
        "DestinationPath": "owned",
        "Attributes": ["Hidden", "System"],
    }


def test_name_alias_key_and_values_not_value_map(dsc: Any) -> None:
    schema = [_property("Name"), _property("key"), _property("Ensure")]
    assert dsc._properties(
        {"item_name": "alias", "key": "registry", "Ensure": "not-a-choice"}, schema
    ) == {"Name": "alias", "Key": "registry", "Ensure": "not-a-choice"}
    choices = _property("Ensure")
    choices["choices"] = ["Present", "Absent"]
    with pytest.raises(ValueError, match="value of Ensure must be one of"):
        dsc._properties({"Ensure": "invalid"}, [choices])


def test_payload_accepts_dynamic_arguments_without_a_literal_free_form_option(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = load_payload("win_dsc", monkeypatch)
    arguments = {"resource_name": "File", "DestinationPath": "owned"}
    path = tmp_path / "arguments.json"
    path.write_text(json.dumps(arguments), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["win_dsc.py", str(path)])
    configure = MagicMock(return_value={"changed": False})
    monkeypatch.setattr(payload, "configure_resource", configure)
    assert invoke_payload(payload, capsys) == (0, {"changed": False})
    assert configure.call_args.args[0]["DestinationPath"] == "owned"


def test_explicit_version_presence_reaches_discovery_unchanged(dsc: Any) -> None:
    request = MagicMock(return_value={"error": "observed version error"})
    dsc.configure_resource(
        {"resource_name": "File", "module_version": "latest"}, request
    )
    assert request.call_args.args[0]["arguments"]["module_version"] == "latest"


def test_early_validation_redacts_only_schema_declared_credential_passwords(
    dsc: Any,
) -> None:
    schema = _schema()
    schema["properties"].append(_property("Ordinary_password"))
    request = MagicMock(return_value=schema)
    result = dsc.configure_resource(
        {
            "resource_name": "File",
            "DestinationPath": "owned",
            "Force": "private-secret",
            "Credential_username": "user",
            "Credential_password": "private-secret",
        },
        request,
    )
    assert "private-secret" not in result["msg"]
    result = dsc.configure_resource(
        {
            "resource_name": "File",
            "DestinationPath": "owned",
            "Force": "ordinary-text",
            "Ordinary_password": "ordinary-text",
        },
        request,
    )
    assert "ordinary-text" in result["msg"]


def test_embedded_credential_redaction_follows_the_discovered_schema(dsc: Any) -> None:
    entry = _property(
        "Embedded",
        "Instance",
        reference="Example_Embedded",
        properties=[_property("Account", "Instance", reference="MSFT_Credential")],
    )
    assert dsc._credential_passwords(
        {"embedded": {"ACCOUNT_PASSWORD": "secret"}}, [entry]
    ) == ["secret"]


@pytest.mark.parametrize(
    "value,kind,detail",
    [
        (True, "Boolean", "Input string was not in a correct format."),
        (False, "Boolean", "Input string was not in a correct format."),
        (2.5, "Decimal", "Input string was not in a correct format."),
        (2.0, "Decimal", "Input string was not in a correct format."),
        ("1.0", "String", "Input string was not in a correct format."),
        ("١٢", "String", "Input string was not in a correct format."),
        ("12\u00a0", "String", "Input string was not in a correct format."),
        ("12\x00 ", "String", "Input string was not in a correct format."),
        ([], "Object[]", "Input string was not in a correct format."),
        (
            {},
            "Collections.Generic.Dictionary`2[System.String,System.Object]",
            "Input string was not in a correct format.",
        ),
        (2147483648, "Int64", "Value was either too large or too small for an Int32."),
        (-2147483649, "Int64", "Value was either too large or too small for an Int32."),
        (2**63, "Decimal", "Value was either too large or too small for an Int32."),
        (
            79228162514264337593543950335,
            "Decimal",
            "Value was either too large or too small for an Int32.",
        ),
        (
            79228162514264337593543950336,
            "Double",
            "Input string was not in a correct format.",
        ),
    ],
)
def test_sint32_schema_rejects_invalid_values_before_resource_invocation(
    dsc: Any, value: object, kind: str, detail: str
) -> None:
    schema = dict(_schema(), properties=[_property("Count", "SInt32")])
    request = MagicMock(return_value=schema)
    result = dsc.configure_resource(
        {"resource_name": "Example", "Count": value}, request
    )
    assert result == {
        "changed": False,
        "failed": True,
        "msg": f"argument for Count is of type System.{kind} and we were "
        f"unable to convert to int: {detail}",
    }
    assert request.call_count == 1


@pytest.mark.parametrize(
    "value,expected",
    [
        (0, 0),
        (-2147483648, -2147483648),
        (2147483647, 2147483647),
        (" +12 ", 12),
        ("\t-12\r\n\x00", -12),
        ("12\x00\x00", 12),
    ],
)
def test_sint32_schema_preserves_signed_ascii_integer_binding(
    dsc: Any, value: object, expected: int
) -> None:
    schema = dict(_schema(), properties=[_property("Count", "SInt32")])
    request = MagicMock(side_effect=[schema, {"result": [{"InDesiredState": True}]}])
    assert (
        dsc.configure_resource({"resource_name": "Example", "Count": value}, request)[
            "changed"
        ]
        is False
    )
    assert request.call_args.args[0]["properties"] == {"Count": expected}


@pytest.mark.parametrize(
    "kind,value", [("String", "pReSeNt"), ("StringArray", ["present", "ABSENT"])]
)
def test_values_schema_choices_accept_case_without_rewriting_values(
    dsc: Any, kind: str, value: object
) -> None:
    entry = _property("Ensure", kind, choices=["Present", "Absent"])
    schema = dict(_schema(), properties=[entry])
    request = MagicMock(side_effect=[schema, {"result": [{"InDesiredState": True}]}])
    assert (
        dsc.configure_resource({"resource_name": "Example", "Ensure": value}, request)[
            "changed"
        ]
        is False
    )
    assert request.call_args.args[0]["properties"] == {"Ensure": value}


@pytest.mark.parametrize(
    "kind,value,message",
    [
        (
            "String",
            "invalid",
            "value of Ensure must be one of: Present, Absent. Got no match for: invalid",
        ),
        (
            "StringArray",
            ["invalid", "INVALID", "other"],
            "value of Ensure must be one or more of: Present, Absent. "
            "Got no match for: invalid, other",
        ),
    ],
)
def test_values_schema_failure_preserves_source_distinct_order_and_message(
    dsc: Any, kind: str, value: object, message: str
) -> None:
    schema = dict(
        _schema(), properties=[_property("Ensure", kind, choices=["Present", "Absent"])]
    )
    request = MagicMock(return_value=schema)
    assert dsc.configure_resource(
        {"resource_name": "Example", "Ensure": value}, request
    ) == {
        "changed": False,
        "failed": True,
        "msg": message,
    }
    assert request.call_count == 1


def test_unicode_choices_use_native_ordinal_comparison_with_full_utf16_lengths(
    dsc: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    compare = MagicMock(return_value=2)
    library = MagicMock(CompareStringOrdinal=compare)
    monkeypatch.setattr(
        dsc.ctypes, "WinDLL", MagicMock(return_value=library), raising=False
    )
    assert dsc._ordinal_equal("𐐀\x00Å", "𐐨\x00å")
    compare.assert_called_once_with("𐐀\x00Å", 4, "𐐨\x00å", 4, True)
    compare.return_value = 1
    assert not dsc._ordinal_equal("ß", "SS")
    compare.return_value = 2
    assert dsc._ordinal_equal("\ud800", "\ud800")
    compare.assert_called_with("\ud800", 1, "\ud800", 1, True)


def test_unicode_comparison_native_failure_is_not_silently_accepted(
    dsc: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    compare = MagicMock(return_value=0)
    monkeypatch.setattr(
        dsc.ctypes,
        "WinDLL",
        MagicMock(return_value=MagicMock(CompareStringOrdinal=compare)),
        raising=False,
    )
    monkeypatch.setattr(dsc.ctypes, "get_last_error", lambda: 87, raising=False)
    monkeypatch.setattr(
        dsc.ctypes,
        "WinError",
        lambda code: OSError(code, "invalid comparison"),
        raising=False,
    )
    with pytest.raises(OSError, match="invalid comparison"):
        dsc._ordinal_equal("Å", "å")
