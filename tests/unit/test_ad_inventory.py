"""Exercise LDAP inventory's public host data and connection arguments locally."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import socket
import ssl
import threading
from contextlib import nullcontext
from pathlib import Path
from queue import Queue
from typing import Any, cast
from unittest.mock import Mock

import pytest
import sansldap

# Ansible does not distribute typing metadata for its controller interfaces.
from ansible.errors import AnsibleError  # type: ignore[import-untyped]
from ansible.inventory.data import InventoryData  # type: ignore[import-untyped]
from ansible.parsing.dataloader import DataLoader  # type: ignore[import-untyped]
from ansible.plugins.loader import inventory_loader  # type: ignore[import-untyped]
from ansible.template import trust_as_template  # type: ignore[import-untyped]

# The test bootstrap exposes both source collections before importing plugins.
from ansible_collections.sustainablelobster.legacy_ad.plugins.inventory import (
    ldap,
)
from ansible_collections.sustainablelobster.legacy_ad.plugins.plugin_utils import (
    _ldap as controller_ldap,
)
from ansible_collections.sustainablelobster.legacy_ad.plugins.plugin_utils._ldap import (
    _authentication,
)
from ansible_collections.sustainablelobster.legacy_ad.plugins.plugin_utils._ldap.client import (
    SyncLDAPClient,
)
from ansible_collections.sustainablelobster.legacy_ad.plugins.plugin_utils._ldap.schema import (
    LDAPSchema,
)


@pytest.fixture(name="inventory_case")
def inventory_case_fixture(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Prepare a real Ansible inventory with an isolated directory search.

    :param monkeypatch: Scoped plugin connection replacements.
    :returns: Options, LDAP search, connection, and inventory fixtures.
    """
    options: dict[str, Any] = {
        "compose": {},
        "groups": {},
        "keyed_groups": [],
        "strict": True,
        "attributes": {},
        "filter": None,
        "filter_without_computer": False,
        "search_base": None,
        "search_scope": "subtree",
        "use_extra_vars": False,
        "leading_separator": True,
        "trailing_separator": True,
        "server": "directory.example.test",
        "username": "EXAMPLE\\reader",
        "password": "fixture-not-a-secret",
        "auth_protocol": "ntlm",
        "encrypt": True,
    }
    client = Mock()
    client.search.return_value = {
        "CN=CLIENT1,OU=Clients,DC=example,DC=test": {
            "name": [b"CLIENT1"],
            "dNSHostName": [b"client1.example.test"],
        },
        "CN=CLIENT2,OU=Clients,DC=example,DC=test": {
            "name": [b"CLIENT2"],
        },
    }
    connect = Mock(return_value=nullcontext(client))
    monkeypatch.setattr(ldap, "create_ldap_connection", connect)
    schema = LDAPSchema({})
    monkeypatch.setattr(LDAPSchema, "load_schema", Mock(return_value=schema))
    plugin = ldap.InventoryModule()
    monkeypatch.setattr(plugin, "set_options", Mock())
    monkeypatch.setattr(plugin, "_read_config_data", Mock())
    monkeypatch.setattr(plugin, "get_option", options.__getitem__)
    monkeypatch.setattr(plugin, "get_options", options.copy)
    return {
        "options": options,
        "client": client,
        "connect": connect,
        "plugin": plugin,
        "inventory": InventoryData(),
        "loader": DataLoader(),
    }


def _parse(case: dict[str, Any]) -> Any:
    case["plugin"].parse(
        case["inventory"],
        case["loader"],
        "/fixture.sustainablelobster.legacy_ad.ldap.yml",
        cache=False,
    )
    return case["inventory"]


@pytest.mark.parametrize(
    "suffix",
    [
        "sustainablelobster.legacy_ad.ldap.yml",
        "sustainablelobster.legacy_ad.ldap.yaml",
        "microsoft.ad.ldap.yml",
        "microsoft.ad.ldap.yaml",
    ],
)
def test_inventory_accepts_legacy_and_new_filename_suffixes(
    tmp_path: Path, suffix: str
) -> None:
    source = tmp_path / f"directory.{suffix}"
    source.write_text("plugin: sustainablelobster.legacy_ad.ldap\n", encoding="utf-8")
    assert ldap.InventoryModule().verify_file(str(source))


@pytest.mark.parametrize("suffix", ["ldap.yml", "legacy_ad.yml", "inventory.txt"])
def test_inventory_rejects_unrecognized_filename_suffixes(
    tmp_path: Path, suffix: str
) -> None:
    source = tmp_path / suffix
    source.write_text("plugin: sustainablelobster.legacy_ad.ldap\n", encoding="utf-8")
    assert not ldap.InventoryModule().verify_file(str(source))


def test_inventory_preserves_upstream_hostname_and_host_variables(
    inventory_case: dict[str, Any],
) -> None:
    inventory = _parse(inventory_case)
    assert set(inventory.hosts) == {"CLIENT1", "CLIENT2"}
    first = inventory.hosts["CLIENT1"].vars
    assert first["ansible_host"] == "client1.example.test"
    assert first["microsoft_ad_distinguished_name"] == (
        "CN=CLIENT1,OU=Clients,DC=example,DC=test"
    )
    assert "ansible_host" not in inventory.hosts["CLIENT2"].vars
    assert "raw" not in first
    assert "this" not in first
    assert str(inventory_case["client"].search.call_args.kwargs["filter"]) == (
        "(objectCategory=computer)"
    )
    assert inventory_case["connect"].call_args.kwargs["encrypt"] is True
    assert inventory_case["connect"].call_args.kwargs["auth_protocol"] == "ntlm"


@pytest.mark.parametrize("scope", ["base", "one_level", "subtree"])
@pytest.mark.parametrize("only_custom", [True, False])
def test_inventory_preserves_filters_search_base_and_scope(
    inventory_case: dict[str, Any], scope: str, only_custom: bool
) -> None:
    inventory_case["options"].update(
        {
            "filter": "(name=CLIENT*)",
            "filter_without_computer": only_custom,
            "search_base": "OU=Clients,DC=example,DC=test",
            "search_scope": scope,
        }
    )
    _parse(inventory_case)
    search = inventory_case["client"].search.call_args.kwargs
    assert search["search_base"] == "OU=Clients,DC=example,DC=test"
    assert (
        search["search_scope"]
        == {
            "base": sansldap.SearchScope.BASE,
            "one_level": sansldap.SearchScope.ONE_LEVEL,
            "subtree": sansldap.SearchScope.SUBTREE,
        }[scope]
    )
    expected = "(name=CLIENT*)"
    if not only_custom:
        expected = f"(&(objectCategory=computer){expected})"
    assert str(search["filter"]) == expected


def test_inventory_composes_attributes_hostname_and_groups(
    inventory_case: dict[str, Any],
) -> None:
    inventory_case["options"].update(
        {
            "attributes": {
                "name": {"directory_name": "this | first"},
                "location": {"site": "this | first"},
                "comment": {"comment_bytes": "raw | first"},
            },
            "compose": {"inventory_hostname": "directory_name | lower"},
            "groups": {"clients": trust_as_template("site == 'London'")},
            "keyed_groups": [{"key": trust_as_template("site"), "prefix": "site"}],
        }
    )
    entries = inventory_case["client"].search.return_value
    for entry in entries.values():
        entry["location"] = [b"London"]
        entry["comment"] = [b"native LDAP"]
    inventory = _parse(inventory_case)
    assert set(inventory.hosts) == {"client1", "client2"}
    assert inventory.hosts["client1"].vars["directory_name"] == "CLIENT1"
    assert inventory.hosts["client1"].vars["comment_bytes"] == "bmF0aXZlIExEQVA="
    assert set(inventory.groups["clients"].hosts) == set(inventory.hosts.values())
    assert set(inventory.groups["site_London"].hosts) == set(inventory.hosts.values())


@pytest.mark.parametrize("strict", [True, False])
def test_inventory_honors_strict_attribute_template_failures(
    inventory_case: dict[str, Any], strict: bool
) -> None:
    inventory_case["options"]["strict"] = strict
    inventory_case["options"]["attributes"] = {
        "comment": {"invalid": "not_defined.property"}
    }
    if strict:
        with pytest.raises(
            AnsibleError, match="Could not set invalid for host CLIENT1"
        ):
            _parse(inventory_case)
    else:
        inventory = _parse(inventory_case)
        assert "invalid" not in inventory.hosts["CLIENT1"].vars


def test_missing_controller_dependencies_fail_before_connecting(
    inventory_case: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ldap, "HAS_LDAP", False)
    monkeypatch.setattr(ldap, "_ldap_import_error", ImportError("missing sansldap"))
    with pytest.raises(AnsibleError, match="sansldap and pyspnego"):
        _parse(inventory_case)
    inventory_case["connect"].assert_not_called()


def test_inventory_loads_real_config_through_the_collection_loader(
    inventory_case: dict[str, Any], tmp_path: Path
) -> None:
    source = tmp_path / "hosts.microsoft.ad.ldap.yml"
    source.write_text(
        "plugin: sustainablelobster.legacy_ad.ldap\n"
        "server: directory.example.test\n"
        "auth_protocol: ntlm\n"
        "username: EXAMPLE\\reader\n"
        "password: fixture-not-a-secret\n"
        "attributes:\n"
        "  name:\n"
        "    directory_name: this | first\n"
        "compose:\n"
        "  inventory_hostname: directory_name | lower\n"
        "groups:\n"
        "  clients: directory_name.startswith('CLIENT')\n",
        encoding="utf-8",
    )
    plugin = cast(
        ldap.InventoryModule | None,
        inventory_loader.get("sustainablelobster.legacy_ad.ldap"),
    )
    assert plugin is not None
    # Pylint conflates Ansible's generic loader with unrelated action plugins;
    # this call exercises the real inventory loader and its concrete public API.
    # pylint: disable-next=no-member
    plugin.parse(
        inventory_case["inventory"], inventory_case["loader"], str(source), cache=False
    )
    inventory = inventory_case["inventory"]
    assert set(inventory.hosts) == {"client1", "client2"}
    assert len(inventory.groups["clients"].hosts) == 2
    assert inventory_case["connect"].call_args.kwargs["server"] == (
        "directory.example.test"
    )


@pytest.mark.parametrize("fragment", [b"", b"\0", b"\0\0", b"\0\0\0"])
def test_encrypted_ldap_retains_a_split_length_header(fragment: bytes) -> None:
    context = Mock()
    encryptor = _authentication.SpnegoEncryptor(context)
    assert encryptor.unwrap(fragment) == (b"", 0)
    context.unwrap.assert_not_called()


def test_encrypted_ldap_retains_incomplete_payload_then_decodes_one_frame() -> None:
    context = Mock()
    context.unwrap.return_value.data = b"decoded LDAP entry"
    encryptor = _authentication.SpnegoEncryptor(context)
    frame = b"\0\0\0\5token"
    assert encryptor.unwrap(frame[:-1]) == (b"", 0)
    assert encryptor.unwrap(frame + b"next-frame") == (b"decoded LDAP entry", 9)
    context.unwrap.assert_called_once_with(b"token")


def test_starttls_disconnect_fails_without_retrying_an_empty_socket() -> None:
    sock = Mock()
    sock.recv.return_value = b""
    with pytest.raises(ConnectionError, match="closed during StartTLS"):
        SyncLDAPClient.start_tls(sansldap.LDAPClient(), sock)
    sock.recv.assert_called_once_with(4096)


@pytest.mark.parametrize(
    "options,error",
    [
        ({"auth_protocol": "simple"}, "simple auth with encryption"),
        ({"auth_protocol": "certificate"}, "TLS must be used"),
    ],
)
def test_controller_rejects_unsafe_authentication_before_connecting(
    monkeypatch: pytest.MonkeyPatch, options: dict[str, Any], error: str
) -> None:
    connect = Mock()
    monkeypatch.setattr(socket, "create_connection", connect)
    with pytest.raises(ValueError, match=error):
        controller_ldap.create_ldap_connection(server="dc.example.test", **options)
    connect.assert_not_called()


def test_ldaps_handshake_failure_releases_the_original_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sock = Mock()
    context = Mock()
    context.wrap_socket.side_effect = ssl.SSLError("fixture handshake failure")
    monkeypatch.setattr(socket, "create_connection", Mock(return_value=sock))
    monkeypatch.setattr(ssl, "create_default_context", Mock(return_value=context))
    with pytest.raises(ssl.SSLError, match="fixture handshake failure"):
        controller_ldap.create_ldap_connection(
            server="dc.example.test", auth_protocol="simple", tls_mode="ldaps"
        )
    sock.close.assert_called_once()


def test_ldap_peer_closure_before_bind_is_reported_instead_of_hanging() -> None:
    sock, peer = socket.socketpair()
    client = SyncLDAPClient("fixture", sansldap.LDAPClient(), sock)
    failures: Queue[Exception] = Queue()
    try:
        peer.shutdown(socket.SHUT_WR)
        # Synchronize the peer closure before exercising the public bind operation.
        client._reader_task.join(timeout=1)  # pylint: disable=protected-access

        def _bind() -> None:
            try:
                client.bind("reader", sansldap.SimpleCredential("fixture"))
            # The public operation must report any reader failure to its caller.
            except Exception as exc:  # pylint: disable=broad-exception-caught
                failures.put(exc)

        worker = threading.Thread(target=_bind, daemon=True)
        worker.start()
        worker.join(timeout=1)
        assert not worker.is_alive(), "LDAP bind hung after the reader had stopped"
        error = failures.get_nowait()
        assert isinstance(error, RuntimeError)
        assert "connection has been shutdown" in str(error)
    finally:
        client.close()
        peer.close()


@pytest.mark.parametrize(
    "attributes,expected",
    [
        ({"bad": ["value"]}, "expecting a dictionary"),
        ({"bad": {"value": 123}}, "expecting a string"),
    ],
)
def test_inventory_rejects_invalid_attribute_templates_before_search(
    inventory_case: dict[str, Any], attributes: dict[str, Any], expected: str
) -> None:
    inventory_case["options"]["attributes"] = attributes
    with pytest.raises(AnsibleError, match=expected):
        _parse(inventory_case)
    inventory_case["connect"].assert_not_called()
