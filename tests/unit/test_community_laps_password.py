"""Verify lookup configuration, directory results and credential protection."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
from types import ModuleType
from typing import Any, cast
from unittest.mock import Mock

import pytest

# Ansible's controller interfaces do not distribute typing metadata.
from ansible.errors import AnsibleLookupError  # type: ignore[import-untyped]
from ansible.plugins.loader import lookup_loader  # type: ignore[import-untyped]


@pytest.fixture(name="directory")
def directory_fixture(monkeypatch: pytest.MonkeyPatch) -> tuple[Any, ModuleType, Mock]:
    """Expose the real lookup loader with an independent directory boundary.

    :param monkeypatch: Scoped LDAP connection and capability substitutions.
    :returns: Actual lookup plugin, its module and independent LDAP connection.
    """
    plugin = lookup_loader.get(
        "sustainablelobster.legacy_community_windows.laps_password"
    )
    assert plugin is not None
    module = sys.modules[type(plugin).__module__]
    connection = Mock()
    connection.read_rootdse_s.return_value = {
        "defaultNamingContext": [b"DC=example,DC=test"]
    }
    connection.search_s.return_value = [
        (
            "CN=OLD-PC,DC=example,DC=test",
            {
                "distinguishedName": [b"CN=OLD-PC,DC=example,DC=test"],
                "ms-Mcs-AdmPwd": ["secret-café".encode()],
            },
        ),
        (None, ["ldap://referral.example.test"]),
    ]
    monkeypatch.setattr(module, "HAS_LDAP", True)
    monkeypatch.setattr(module.ldap, "SASL_AVAIL", True)
    monkeypatch.setattr(module.ldap, "TLS_AVAIL", True)
    monkeypatch.setattr(module.ldap, "initialize", Mock(return_value=connection))
    monkeypatch.setattr(module.ldap, "set_option", Mock())
    return plugin, module, connection


def lookup(directory: tuple[Any, ModuleType, Mock], **options: Any) -> list[str]:
    """Invoke the actual public lookup with encrypted simple-bind defaults.

    :param directory: Actual plugin, its module and independent LDAP connection.
    :param options: Public lookup options overriding fixture defaults.
    :returns: Passwords in requested term order.
    """
    arguments = {
        "domain": "dc.example.test",
        "auth": "simple",
        "scheme": "ldaps",
        "username": "Operator@example.test",
        "password": "bind-secret",
        **options,
    }
    return cast(list[str], directory[0].run(["OLD-PC"], **arguments))


def test_lookup_returns_password_and_ignores_referrals(
    directory: tuple[Any, ModuleType, Mock],
) -> None:
    assert lookup(directory) == ["secret-café"]
    directory[1].ldap.initialize.assert_called_once_with(
        "ldaps://dc.example.test:636", bytes_mode=False
    )
    directory[2].bind_s.assert_called_once_with("Operator@example.test", "bind-secret")
    directory[2].search_s.assert_called_once_with(
        "DC=example,DC=test",
        directory[1].ldap.SCOPE_SUBTREE,
        "(&(objectClass=computer)(CN=OLD-PC))",
        attrlist=["distinguishedName", "ms-Mcs-AdmPwd"],
    )
    directory[2].unbind_s.assert_called_once_with()


def test_explicit_uri_and_search_base_override_discovery(
    directory: tuple[Any, ModuleType, Mock],
) -> None:
    assert lookup(
        directory,
        domain="ldaps://specific.example.test:1636",
        port=1389,
        scheme="ldap",
        search_base="OU=Computers,DC=example,DC=test",
    ) == ["secret-café"]
    directory[1].ldap.initialize.assert_called_once_with(
        "ldaps://specific.example.test:1636", bytes_mode=False
    )
    directory[2].read_rootdse_s.assert_not_called()
    assert directory[2].search_s.call_args.args[0] == "OU=Computers,DC=example,DC=test"


def test_multiple_terms_preserve_order(directory: tuple[Any, ModuleType, Mock]) -> None:
    connection = directory[2]
    connection.search_s.side_effect = [
        [("CN=First", {"distinguishedName": [b"CN=First"], "ms-Mcs-AdmPwd": [b"one"]})],
        [
            (
                "CN=Second",
                {"distinguishedName": [b"CN=Second"], "ms-Mcs-AdmPwd": [b"two"]},
            )
        ],
    ]
    assert directory[0].run(
        ["First", "Second"], domain="dc.example.test", auth="gssapi"
    ) == ["one", "two"]
    connection.sasl_gssapi_bind_s.assert_called_once_with()
    connection.bind_s.assert_not_called()
    connection.unbind_s.assert_called_once_with()


@pytest.mark.parametrize(
    "rows,message",
    [
        ([], "Failed to find the server"),
        (
            [("CN=OLD-PC", {"distinguishedName": [b"CN=OLD-PC"]})],
            "did not have the LAPS attribute",
        ),
        (
            [
                ("CN=One", {"distinguishedName": [b"CN=One"]}),
                ("CN=Two", {"distinguishedName": [b"CN=Two"]}),
            ],
            "Found too many results",
        ),
    ],
)
def test_missing_ambiguous_or_unreadable_password_fails_and_closes(
    directory: tuple[Any, ModuleType, Mock],
    rows: list[Any],
    message: str,
) -> None:
    directory[2].search_s.return_value = rows
    with pytest.raises(AnsibleLookupError, match=message):
        lookup(directory)
    directory[2].unbind_s.assert_called_once_with()


def test_plaintext_is_rejected_before_connecting(
    directory: tuple[Any, ModuleType, Mock],
) -> None:
    with pytest.raises(
        AnsibleLookupError, match="plaintext traffic exposing credentials"
    ):
        lookup(directory, scheme="ldap")
    directory[1].ldap.initialize.assert_not_called()


def test_plaintext_requires_explicit_opt_in(
    directory: tuple[Any, ModuleType, Mock],
) -> None:
    assert lookup(directory, scheme="ldap", allow_plaintext=True) == ["secret-café"]
    directory[1].ldap.initialize.assert_called_once_with(
        "ldap://dc.example.test:389", bytes_mode=False
    )


def test_start_tls_precedes_bind(directory: tuple[Any, ModuleType, Mock]) -> None:
    assert lookup(directory, scheme="ldap", start_tls=True) == ["secret-café"]
    calls = [call[0] for call in directory[2].mock_calls]
    assert calls.index("start_tls_s") < calls.index("bind_s") < calls.index("search_s")


@pytest.mark.parametrize("validation", ["never", "allow", "try", "demand"])
def test_certificate_validation_modes(
    directory: tuple[Any, ModuleType, Mock],
    validation: str,
) -> None:
    assert lookup(directory, validate_certs=validation) == ["secret-café"]
    ldap = directory[1].ldap
    ldap.set_option.assert_any_call(
        ldap.OPT_X_TLS_REQUIRE_CERT, getattr(ldap, "OPT_X_TLS_" + validation.upper())
    )


def test_certificate_alias_expands_and_validates_local_path(
    directory: tuple[Any, ModuleType, Mock],
    tmp_path: Any,
) -> None:
    certificate = tmp_path / "ca.pem"
    certificate.write_text("test CA", encoding="utf-8")
    assert lookup(directory, cacert_file=str(certificate)) == ["secret-café"]
    ldap = directory[1].ldap
    ldap.set_option.assert_any_call(ldap.OPT_X_TLS_CACERTFILE, str(certificate))


def test_missing_certificate_does_not_connect(
    directory: tuple[Any, ModuleType, Mock],
    tmp_path: Any,
) -> None:
    with pytest.raises(AnsibleLookupError, match="does not exist"):
        lookup(directory, ca_cert=str(tmp_path / "missing.pem"))
    directory[1].ldap.initialize.assert_not_called()


@pytest.mark.parametrize(
    "options,message",
    [
        (
            {"auth": "simple", "password": ""},
            "username and password values are required",
        ),
        ({"auth": "gssapi"}, "Explicit credentials are not supported"),
    ],
)
def test_invalid_authentication_has_no_network_side_effect(
    directory: tuple[Any, ModuleType, Mock],
    options: dict[str, Any],
    message: str,
) -> None:
    with pytest.raises(AnsibleLookupError, match=message):
        lookup(directory, **options)
    directory[1].ldap.initialize.assert_not_called()


@pytest.mark.parametrize(
    "capability,options,message",
    [
        ("TLS_AVAIL", {}, "Cannot use TLS"),
        (
            "SASL_AVAIL",
            {"auth": "gssapi", "username": None, "password": None},
            "SASL is not configured",
        ),
    ],
)
def test_missing_ldap_capabilities_report_actionable_failures(
    directory: tuple[Any, ModuleType, Mock],
    monkeypatch: pytest.MonkeyPatch,
    capability: str,
    options: dict[str, Any],
    message: str,
) -> None:
    monkeypatch.setattr(directory[1].ldap, capability, False)
    with pytest.raises(AnsibleLookupError, match=message):
        lookup(directory, **options)
    directory[1].ldap.initialize.assert_not_called()


def test_missing_optional_controller_dependency(
    directory: tuple[Any, ModuleType, Mock],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(directory[1], "HAS_LDAP", False)
    monkeypatch.setattr(directory[1], "_ldap_import_error", "independent import error")
    with pytest.raises(AnsibleLookupError, match="python-ldap"):
        lookup(directory)
    directory[1].ldap.initialize.assert_not_called()


def test_common_name_is_a_literal_not_an_injected_filter(
    directory: tuple[Any, ModuleType, Mock],
) -> None:
    directory[0].run(["OLD*(PC)\\name"], domain="dc.example.test", auth="gssapi")
    assert directory[2].search_s.call_args.args[2] == (
        r"(&(objectClass=computer)(CN=OLD\2a\28PC\29\5cname))"
    )


@pytest.mark.parametrize("operation", ["start_tls_s", "bind_s", "search_s"])
def test_directory_failure_always_closes_the_connection(
    directory: tuple[Any, ModuleType, Mock],
    operation: str,
) -> None:
    getattr(directory[2], operation).side_effect = directory[1].ldap.LDAPError(
        "fixture failure"
    )
    with pytest.raises((AnsibleLookupError, directory[1].ldap.LDAPError)):
        lookup(directory, scheme="ldap", start_tls=True)
    directory[2].unbind_s.assert_called_once_with()
