"""Exercise the controller-only LDAP diagnostic without DNS or directory calls."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import importlib
import importlib.metadata
from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock, Mock

# The diagnostic intentionally exposes these internal probes only as action data.
# Isolating them makes optional-library failures testable without network access.
# pylint: disable=protected-access
# The test bootstrap exposes both source collections before importing plugins.
import ansible_collections.sustainablelobster.legacy_ad.plugins.action.debug_ldap_client as debug
import pytest
from ansible.plugins.action import ActionBase  # type: ignore[import-untyped]


def test_diagnostic_reports_missing_optional_libraries_without_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(debug, "HAS_KRB5", False)
    monkeypatch.setattr(debug, "HAS_DNSRESOLVER", False)
    monkeypatch.setattr(ActionBase, "run", Mock(return_value={}))
    plugin = object.__new__(debug.ActionModule)
    result = plugin.run(task_vars={})
    assert result["kerberos"] == {}
    assert result["dns"] == {}
    assert set(result["packages"]) == {
        "dnspython",
        "dpapi_ng",
        "krb5",
        "pyspnego",
        "sansldap",
    }
    assert all(isinstance(value, str) for value in result["packages"].values())
    assert not result.get("failed", False)
    assert not result.get("changed", False)
    assert plugin._supports_check_mode
    assert plugin._supports_async


def test_diagnostic_includes_installed_package_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    imported = Mock()
    version = Mock(return_value="2.0.0")
    monkeypatch.setattr(importlib, "import_module", imported)
    monkeypatch.setattr(importlib.metadata, "version", version)
    plugin = object.__new__(debug.ActionModule)
    assert plugin._import_lib("spnego", "pyspnego") == "2.0.0"
    imported.assert_called_once_with("spnego")
    version.assert_called_once_with("pyspnego")


def test_diagnostic_reports_import_error_in_the_package_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        importlib,
        "import_module",
        Mock(side_effect=ImportError("test package unavailable")),
    )
    plugin = object.__new__(debug.ActionModule)
    value = plugin._import_lib("missing-package")
    assert "ImportError: test package unavailable" in value


def test_diagnostic_preserves_kerberos_cache_and_credential_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = object()
    cache = MagicMock()
    cast(Mock, cache.__str__).return_value = "FILE:/fixture/ccache"
    cache.principal = "reader@EXAMPLE.TEST"
    cache.__iter__.return_value = iter(
        [SimpleNamespace(client="reader@EXAMPLE.TEST", server="ldap/dc@EXAMPLE.TEST")]
    )
    fake_krb5 = SimpleNamespace(
        init_context=Mock(return_value=context),
        get_default_realm=Mock(return_value=b"EXAMPLE.TEST"),
        cc_default=Mock(return_value=cache),
    )
    monkeypatch.setattr(debug, "HAS_KRB5", True)
    monkeypatch.setattr(debug, "krb5", fake_krb5, raising=False)
    plugin = object.__new__(debug.ActionModule)
    result = plugin._get_kerberos_info()
    assert result["default_realm"] == "EXAMPLE.TEST"
    assert result["default_cc"]["principal"] == "reader@EXAMPLE.TEST"
    assert result["default_cc"]["creds"] == [
        {"client": "reader@EXAMPLE.TEST", "server": "ldap/dc@EXAMPLE.TEST"}
    ]
    assert result["exception"] is None


def test_diagnostic_kerberos_error_is_data_not_action_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_krb5 = SimpleNamespace(
        init_context=Mock(side_effect=RuntimeError("fixture context failure"))
    )
    monkeypatch.setattr(debug, "HAS_KRB5", True)
    monkeypatch.setattr(debug, "krb5", fake_krb5, raising=False)
    plugin = object.__new__(debug.ActionModule)
    assert "fixture context failure" in plugin._get_kerberos_info()["exception"]


def test_diagnostic_selects_lowest_priority_then_highest_weight_dns_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = [
        SimpleNamespace(target="low.example.test.", port=389, weight=20, priority=1),
        SimpleNamespace(target="dc.example.test.", port=389, weight=10, priority=0),
        SimpleNamespace(target="dc2.example.test.", port=1389, weight=5, priority=0),
    ]
    resolve = Mock(return_value=records)
    monkeypatch.setattr(debug, "HAS_DNSRESOLVER", True)
    monkeypatch.setattr(
        debug,
        "dns",
        SimpleNamespace(resolver=SimpleNamespace(resolve=resolve)),
        raising=False,
    )
    plugin = object.__new__(debug.ActionModule)
    result = plugin._get_server_lookup_info("EXAMPLE.TEST")
    assert result["default_server"] == "dc.example.test"
    assert result["default_port"] == 389
    assert len(result["records"]) == 3
    assert result["exception"] is None
    resolve.assert_called_once_with("_ldap._tcp.dc._msdcs.EXAMPLE.TEST", "SRV")
