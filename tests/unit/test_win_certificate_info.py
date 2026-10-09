"""Exercise the certificate payload's JSON interface without Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

CERTIFICATE = {
    "archived": False,
    "dns_names": ["Fixture 雪", "example.test"],
    "extensions": [{"critical": False, "field": None, "value": "05 00"}],
    "friendly_name": "Fixture alias",
    "has_private_key": True,
    "intended_purposes": ["Server Authentication", None],
    "is_ca": False,
    "issued_by": "Fixture issuer",
    "issued_to": "Fixture 雪",
    "issuer": "CN=Fixture issuer",
    "key_usages": ["DigitalSignature", "KeyEncipherment"],
    "path_length_constraint": 0,
    "public_key": "ZmFrZSBwdWJsaWMga2V5",
    "raw": "ZmFrZSBjZXJ0aWZpY2F0ZQ==",
    "serial_number": "01FF",
    "signature_algorithm": "sha256RSA",
    "ski": "1234",
    "subject": "CN=Fixture 雪",
    "thumbprint": "0123456789ABCDEF0123456789ABCDEF01234567",
    "valid_from": 1704067200.0,
    "valid_from_iso8601": "2024-01-01T00:00:00Z",
    "valid_to": 1893456000.0,
    "valid_to_iso8601": "2030-01-01T00:00:00Z",
    "version": 3,
}


@pytest.fixture(name="payload")
def certificate_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the payload with an isolated native-reader substitute.

    :param monkeypatch: Scoped helper import substitution.
    :returns: Payload with deterministic certificate records.
    """
    backend = ModuleType("legacy_windows_certificate")
    monkeypatch.setattr(
        backend,
        "read_certificates",
        Mock(return_value=[copy.deepcopy(CERTIFICATE)]),
        raising=False,
    )
    monkeypatch.setitem(sys.modules, "legacy_windows_certificate", backend)
    return load_payload("win_certificate_info", monkeypatch)


@pytest.fixture(name="invoke")
def certificate_invocation(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> Callable[[object], tuple[int, dict[str, Any]]]:
    """Invoke the payload through its argument file and JSON output.

    :param payload: Payload with a substituted native-reader boundary.
    :param monkeypatch: Scoped command arguments.
    :param tmp_path: Isolated argument-file directory.
    :param capsys: Captured module output.
    :returns: Callable accepting a JSON-serializable argument document.
    """

    def _invoke(arguments: object) -> tuple[int, dict[str, Any]]:
        argument_file = tmp_path / "arguments.json"
        argument_file.write_text(json.dumps(arguments), encoding="utf-8")
        monkeypatch.setattr(
            sys, "argv", ["win_certificate_info.py", str(argument_file)]
        )
        return invoke_payload(payload, capsys)

    return _invoke


@pytest.mark.parametrize("check", [False, True])
def test_default_read_preserves_all_certificate_fields_and_repeats_in_check_mode(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    check: bool,
) -> None:
    arguments = {"_ansible_check_mode": check, "_ansible_diff": True}
    expected = {"changed": False, "exists": True, "certificates": [CERTIFICATE]}
    assert invoke(arguments) == (0, expected)
    assert invoke(arguments) == (0, expected)
    assert payload.certificate.read_certificates.call_args_list == [
        call("My", "LocalMachine", None),
        call("My", "LocalMachine", None),
    ]


def test_empty_selection_returns_false_and_empty_list(
    payload: ModuleType, invoke: Callable[[object], tuple[int, dict[str, Any]]]
) -> None:
    payload.certificate.read_certificates.return_value = []
    assert invoke({"thumbprint": "not found"}) == (
        0,
        {"changed": False, "exists": False, "certificates": []},
    )
    payload.certificate.read_certificates.assert_called_once_with(
        "My", "LocalMachine", "not found"
    )


@pytest.mark.parametrize("location", ["CurrentUser", "currentuser", "LOCALMACHINE"])
def test_selected_store_and_literal_thumbprint_reach_native_reader(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    location: str,
) -> None:
    code, result = invoke(
        {
            "STORE_NAME": "Fixture 雪",
            "STORE_LOCATION": location,
            "THUMBPRINT": " ab cd ",
            "_ANSIBLE_INJECT_INVOCATION": True,
        }
    )
    assert code == 0
    payload.certificate.read_certificates.assert_called_once_with(
        "Fixture 雪", location, " ab cd "
    )
    assert result["invocation"] == {
        "module_args": {
            "store_name": "Fixture 雪",
            "store_location": location,
            "thumbprint": " ab cd ",
        }
    }


@pytest.mark.parametrize(
    ("value", "converted"),
    [
        (None, None),
        ("", ""),
        (0, "0"),
        (-1, "-1"),
        (1.5, "1.5"),
        (True, "True"),
        (False, "False"),
        ([], "System.Object[]"),
        ({"name": "value"}, "System.Collections.Hashtable"),
    ],
)
def test_store_name_and_thumbprint_use_shared_upstream_string_conversion(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    value: object,
    converted: str | None,
) -> None:
    code, result = invoke({"store_name": value, "thumbprint": value})
    assert code == 0 and result["exists"] is True
    payload.certificate.read_certificates.assert_called_once_with(
        converted, "LocalMachine", converted
    )


@pytest.mark.parametrize(
    ("value", "text"),
    [
        ("", ""),
        (" User ", " User "),
        ("Local_Machine", "Local_Machine"),
        (True, "True"),
        (1, "1"),
        ([], "System.Object[]"),
        ({}, "System.Collections.Hashtable"),
    ],
)
def test_invalid_location_fails_before_native_reads(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    value: object,
    text: str,
) -> None:
    assert invoke({"store_location": value}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": (
                "value of store_location must be one of: CurrentUser, LocalMachine. "
                "Got no match for: " + text
            ),
        },
    )
    payload.certificate.read_certificates.assert_not_called()


def test_null_location_returns_upstream_conversion_failure_before_native_reads(
    payload: ModuleType, invoke: Callable[[object], tuple[int, dict[str, Any]]]
) -> None:
    code, result = invoke({"store_location": None})
    assert code == 1 and result["changed"] is False and result["failed"] is True
    assert result["msg"] == (
        'Unhandled exception while executing module: Cannot convert value "" '
        'to type "System.Security.Cryptography.X509Certificates.StoreLocation". '
        'Error: "The identifier name  cannot be processed because it is either '
        "too similar or identical to the following enumerator names: "
        'CurrentUser, LocalMachine. Use a more specific identifier name."'
    )
    assert "RuntimeError:" in result["exception"]
    assert "certificates" not in result and "exists" not in result
    payload.certificate.read_certificates.assert_not_called()


def test_conditional_extension_fields_remain_absent_and_order_is_retained(
    payload: ModuleType, invoke: Callable[[object], tuple[int, dict[str, Any]]]
) -> None:
    records = [
        {"thumbprint": "A", "extensions": [], "raw": "first"},
        {"thumbprint": "B", "extensions": [], "raw": "second"},
    ]
    payload.certificate.read_certificates.return_value = records
    assert invoke({}) == (
        0,
        {"changed": False, "exists": True, "certificates": records},
    )


@pytest.mark.parametrize(
    "error", [OSError("certificate store read denied"), ValueError("bad certificate")]
)
def test_native_failure_returns_json_without_partial_certificates_and_recovers(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    error: Exception,
) -> None:
    payload.certificate.read_certificates.side_effect = error
    assert invoke({}) == (
        1,
        {"changed": False, "failed": True, "msg": str(error)},
    )
    payload.certificate.read_certificates.side_effect = None
    assert invoke({}) == (
        0,
        {"changed": False, "exists": True, "certificates": [CERTIFICATE]},
    )


def test_unexpected_failure_uses_shared_json_error_contract(
    payload: ModuleType, invoke: Callable[[object], tuple[int, dict[str, Any]]]
) -> None:
    payload.certificate.read_certificates.side_effect = RuntimeError(
        "unexpected failure"
    )
    code, result = invoke({})
    assert code == 1 and result["changed"] is False and result["failed"] is True
    assert (
        result["msg"]
        == "Unhandled exception while executing module: unexpected failure"
    )
    assert "RuntimeError: unexpected failure" in result["exception"]
    assert "certificates" not in result and "exists" not in result


def test_unknown_options_fail_before_native_reads(
    payload: ModuleType, invoke: Callable[[object], tuple[int, dict[str, Any]]]
) -> None:
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    assert invoke({"name": "unused"}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": (
                "Unsupported parameters for "
                "(sustainablelobster.legacy_windows.win_certificate_info) module: name. "
                "Supported parameters include: store_location, store_name, thumbprint"
            ),
        },
    )
    # pylint: enable=duplicate-code
    payload.certificate.read_certificates.assert_not_called()


def test_ignore_unknown_flag_and_requested_invocation_use_public_arguments_only(
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
) -> None:
    code, result = invoke(
        {
            "unused": True,
            "_ansible_ignore_unknown_opts": True,
            "_ansible_inject_invocation": "yes",
        }
    )
    assert code == 0 and result["invocation"] == {
        "module_args": {
            "store_location": "LocalMachine",
            "store_name": "My",
            "thumbprint": None,
        }
    }


@pytest.mark.parametrize("arguments", [[], None, "not a mapping"])
def test_non_mapping_arguments_fail_before_native_reads(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    arguments: object,
) -> None:
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    assert invoke(arguments) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "The argument file must contain a JSON object.",
        },
    )
    # pylint: enable=duplicate-code
    payload.certificate.read_certificates.assert_not_called()
