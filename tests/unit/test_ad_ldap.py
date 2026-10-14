"""Exercise native LDAP paging, cleanup, security and value conversion offline."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Tests inspect native bindings and parser internals without contacting a host.
# pylint: disable=protected-access

import ctypes
import importlib
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT


@pytest.fixture(name="ldap")
def ldap_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Import target-only helpers using their staged adjacent-import layout.

    :param monkeypatch: Scoped adjacent-helper import paths.
    :returns: The native LDAP helper.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    monkeypatch.syspath_prepend(str(HELPER.parent))
    return importlib.import_module("legacy_ad_ldap")


@pytest.mark.parametrize(
    ("value", "expected"),
    [("a*(b)\\\0", r"a\2a\28b\29\5c\00"), (b"\x00\xff", r"\00\ff"), ("é", "é")],
)
def test_filter_values_are_escaped(
    ldap: ModuleType, value: str | bytes, expected: str
) -> None:
    assert ldap.escape_filter(value) == expected


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("*", "(objectClass=*)"),
        (
            "ObjectClass -eq 'user' -and name -like 'A*'",
            "(&(objectClass=user)(name=A*))",
        ),
        (
            "name -eq 'a' -or name -eq 'b' -and -not name -eq 'c'",
            "(|(name=a)(&(name=b)(!(name=c))))",
        ),
        (
            "(name -eq 'a' -or name -eq 'b') -and name -ne 'c'",
            "(&(|(name=a)(name=b))(!(name=c)))",
        ),
        ("Name -eq 'a*(b)'", r"(name=a\2a\28b\29)"),
        ("Name -notlike '*foo*'", "(!(name=*foo*))"),
        ("isDeleted -eq $true", "(isDeleted=TRUE)"),
        (
            "whenCreated -gt '20200201000000.0Z'",
            "(&(whenCreated=*)(!(whenCreated<=20200201000000.0Z)))",
        ),
        ("logonCount -lt 4", "(&(logonCount=*)(!(logonCount>=4)))"),
        ("logonCount -le 4", "(logonCount<=4)"),
        ("logonCount -ge 4", "(logonCount>=4)"),
        ("name -approx 'joe'", "(name~=joe)"),
        (
            "groupType -band 0x80000000",
            "(groupType:1.2.840.113556.1.4.803:=2147483648)",
        ),
        ("groupType -bor 6", "(groupType:1.2.840.113556.1.4.804:=6)"),
        (
            "memberOf -recursivematch 'CN=Group,DC=test'",
            "(memberOf:1.2.840.113556.1.4.1941:=CN=Group,DC=test)",
        ),
        ("name -eq 'O''Brien'", "(name=O'Brien)"),
        ('name -eq "a`"b"', '(name=a"b)'),
        (r"name -eq 'a\5cb\00'", r"(name=a\5cb\00)"),
    ],
)
def test_expression_filter_translation(
    ldap: ModuleType, expression: str, expected: str
) -> None:
    assert ldap is not None
    parser = importlib.import_module("legacy_ad_filter")
    assert parser.expression_to_ldap(expression) == expected


@pytest.mark.parametrize(
    "expression",
    [
        "",
        "name -eq $secret",
        "name -eq $(Remove-Item foo)",
        "name -eq 'unterminated",
        "name -eq 'a'; cmd",
        "name;cmd -eq 'a'",
        "(name -eq 'a'",
        "name -invalid 'a'",
        "name -eq 'a')",
        "name -eq",
    ],
)
def test_invalid_filters_never_evaluate_input(
    ldap: ModuleType, expression: str
) -> None:
    assert ldap is not None
    parser = importlib.import_module("legacy_ad_filter")
    with pytest.raises(ValueError):
        parser.expression_to_ldap(expression)


def test_explicit_credentials_use_unicode_counts_and_split_domain(
    ldap: ModuleType,
) -> None:
    identity, buffers = ldap._credential("DOMAIN\\user😀", "secret😀")
    assert identity.user == "user😀"
    assert identity.domain == "DOMAIN"
    assert identity.password == "secret😀"
    assert (
        identity.user_length,
        identity.domain_length,
        identity.password_length,
        identity.flags,
    ) == (6, 6, 8, 2)
    assert len(buffers) == 3


def test_winldap_uses_the_cdecl_abi(
    ldap: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = Mock()
    loader = Mock(return_value=library)
    monkeypatch.setattr(ldap, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(ldap.ctypes, "CDLL", loader)
    assert ldap._library() is library
    loader.assert_called_once_with("wldap32", use_last_error=True)
    assert library.ldap_initW.restype is ctypes.c_void_p
    assert library.ldap_bind_sW.argtypes[3] is ctypes.c_uint32


def _connection(ldap: ModuleType, library: SimpleNamespace) -> Any:
    connection = ldap.LDAPConnection.__new__(ldap.LDAPConnection)
    connection.library = library
    connection.handle = 1
    connection._root = {"supportedcontrol": [ldap.SHOW_DELETED.encode()]}
    return connection


def test_authentication_requires_signing_encryption_and_negotiate(
    ldap: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = SimpleNamespace(
        ldap_initW=Mock(return_value=1),
        ldap_set_optionW=Mock(return_value=0),
        ldap_connect=Mock(return_value=0),
        ldap_bind_sW=Mock(return_value=0),
        ldap_unbind=Mock(return_value=0),
    )
    monkeypatch.setattr(ldap, "_library", lambda: library)
    connection = ldap.LDAPConnection("dc.test", "DOMAIN\\user", "secret")
    assert library.ldap_initW.call_args.args == ("dc.test", 389)
    options = library.ldap_set_optionW.call_args_list
    assert [call.args[1] for call in options] == [0x11, 0x95, 0x96]
    assert options[1].args[2].value == options[2].args[2].value == 1
    assert library.ldap_bind_sW.call_args.args[1] is None
    assert library.ldap_bind_sW.call_args.args[3] == 0x486
    connection.close()
    connection.close()
    library.ldap_unbind.assert_called_once_with(1)


def test_security_option_failure_closes_connection_without_binding(
    ldap: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = SimpleNamespace(
        ldap_initW=Mock(return_value=1),
        ldap_set_optionW=Mock(side_effect=[0, 53]),
        ldap_err2stringW=Mock(return_value="Unsupported security"),
        ldap_bind_sW=Mock(),
        ldap_unbind=Mock(return_value=0),
    )
    monkeypatch.setattr(ldap, "_library", lambda: library)
    with pytest.raises(ldap.LDAPError, match="signing and encryption"):
        ldap.LDAPConnection("dc.test")
    library.ldap_bind_sW.assert_not_called()
    library.ldap_unbind.assert_called_once_with(1)


def test_paging_reads_last_page_and_frees_every_native_result(
    ldap: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    states = iter([(0, 20), (0, 21), (94, 22)])

    def _next_page(
        _handle: int, _page: int, _timeout: Any, _size: int, _count: Any, result: Any
    ) -> int:
        status, pointer = next(states)
        ctypes.cast(result, ctypes.POINTER(ctypes.c_void_p))[0] = pointer
        return status

    library = SimpleNamespace(
        ldap_search_init_pageW=Mock(return_value=10),
        ldap_get_next_page_s=Mock(side_effect=_next_page),
        ldap_msgfree=Mock(),
        ldap_search_abandon_page=Mock(),
    )
    connection = _connection(ldap, library)
    monkeypatch.setattr(
        connection,
        "_entries",
        lambda result: [{"dn": str(result.value), "attributes": {}}],
    )
    rows = connection.search("DC=test", ldap.SCOPE_SUBTREE, "(objectClass=*)", ["name"])
    assert [row["dn"] for row in rows] == ["20", "21", "22"]
    assert [call.args[0].value for call in library.ldap_msgfree.call_args_list] == [
        20,
        21,
        22,
    ]
    library.ldap_search_abandon_page.assert_called_once_with(1, 10)


def test_failed_page_never_returns_partial_success(
    ldap: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = SimpleNamespace(
        ldap_search_init_pageW=Mock(return_value=10),
        ldap_get_next_page_s=Mock(side_effect=[0, 4]),
        ldap_err2stringW=Mock(return_value="Size limit exceeded"),
        ldap_msgfree=Mock(),
        ldap_search_abandon_page=Mock(),
    )
    connection = _connection(ldap, library)
    monkeypatch.setattr(connection, "_entries", Mock())
    with pytest.raises(ldap.LDAPError, match="Size limit"):
        connection.search("DC=test", ldap.SCOPE_SUBTREE, "(objectClass=*)", ["name"])
    library.ldap_search_abandon_page.assert_called_once_with(1, 10)


def test_deleted_control_is_checked_before_search(ldap: ModuleType) -> None:
    library = SimpleNamespace(ldap_search_init_pageW=Mock())
    connection = _connection(ldap, library)
    connection._root = {}
    with pytest.raises(ValueError, match="deleted objects"):
        connection.search(
            "DC=test",
            ldap.SCOPE_SUBTREE,
            "(objectClass=*)",
            ["name"],
            include_deleted=True,
        )
    library.ldap_search_init_pageW.assert_not_called()


def test_ranged_attributes_are_completed_in_order(
    ldap: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = _connection(ldap, SimpleNamespace())
    search = Mock(
        side_effect=[{"dn": "CN=x,DC=test", "attributes": {"member;range=2-*": [b"c"]}}]
    )
    monkeypatch.setattr(connection, "search", lambda *_args, **_kwargs: [search()])
    row = {"dn": "CN=x,DC=test", "attributes": {"member;range=0-1": [b"a", b"b"]}}
    connection._complete_ranges(row, False, False)
    assert row["attributes"] == {"member": [b"a", b"b", b"c"]}


@pytest.mark.parametrize(
    ("syntax", "single", "values", "expected"),
    [
        ("2.5.5.8", True, [b"TRUE"], True),
        ("2.5.5.9", True, [b"-2147483646"], -2147483646),
        ("2.5.5.16", True, [b"9223372036854775807"], 9223372036854775807),
        ("2.5.5.10", False, [b"\x00\xff", b"\x01\x02"], ["AP8=", "AQI="]),
        ("2.5.5.12", True, ["Français".encode()], "Français"),
        (
            "2.5.5.11",
            True,
            [b"20250201123456.1234567Z"],
            "2025-02-01T12:34:56.1234567Z",
        ),
        ("2.5.5.11", True, [b"20250201123456+0130"], "2025-02-01T11:04:56.0000000Z"),
        ("2.5.5.11", True, [b"990201123456Z"], "1999-02-01T12:34:56.0000000Z"),
        ("2.5.5.12", True, [], None),
        ("2.5.5.12", False, [], []),
    ],
)
def test_schema_converts_values_and_cardinality(
    ldap: ModuleType, syntax: str, single: bool, values: list[bytes], expected: Any
) -> None:
    assert ldap is not None
    helper = importlib.import_module("legacy_ad_schema")
    schema = helper.DirectorySchema.__new__(helper.DirectorySchema)
    schema.attributes = {"test": {"syntax": syntax, "single": single, "name": "test"}}
    assert schema.cast("test", values) == expected


def test_binary_sid_preserves_authority_and_subauthorities(ldap: ModuleType) -> None:
    assert ldap is not None
    helper = importlib.import_module("legacy_ad_schema")
    assert (
        helper.sid_text(bytes.fromhex("01020000000000052000000020020000"))
        == "S-1-5-32-544"
    )
    with pytest.raises(ValueError, match="binary SID"):
        helper.sid_text(b"short")


def test_native_modifications_preserve_binary_length_and_null_deletes(
    ldap: ModuleType,
) -> None:
    changes, owners = ldap._modifications(
        [(2, "audio", [b"a\0b"]), (1, "description", [])]
    )
    assert owners
    first = changes[0].contents
    assert first.name == "audio"
    assert first.operation == 0x82
    binary = first.values[0].contents
    assert binary.length == 3
    assert ctypes.string_at(binary.value, binary.length) == b"a\0b"
    second = changes[1].contents
    assert second.operation == 0x81
    assert not second.values
    assert not changes[2]


def test_native_create_modify_rename_delete_bindings(ldap: ModuleType) -> None:
    library = SimpleNamespace(
        ldap_add_ext_sW=Mock(return_value=0),
        ldap_modify_ext_sW=Mock(return_value=0),
        ldap_rename_ext_sW=Mock(return_value=0),
        ldap_delete_ext_sW=Mock(return_value=0),
    )
    connection = _connection(ldap, library)
    dn = "OU=Test,DC=example,DC=test"
    connection.add(dn, {"ou": [b"Test"], "objectClass": [b"organizationalUnit"]})
    assert library.ldap_add_ext_sW.call_args.args[:2] == (1, dn)
    connection.modify(dn, [(2, "nTSecurityDescriptor", [b"descriptor"])])
    controls = library.ldap_modify_ext_sW.call_args.args[3]
    assert controls[0].contents.oid == ldap.SD_FLAGS
    assert (
        ctypes.string_at(
            controls[0].contents.value.value, controls[0].contents.value.length
        )
        == b"\x30\x03\x02\x01\x07"
    )
    connection.rename(dn, "OU=Renamed", "DC=example,DC=test")
    assert library.ldap_rename_ext_sW.call_args.args == (
        1,
        dn,
        "OU=Renamed",
        "DC=example,DC=test",
        1,
        None,
        None,
    )
    connection.delete(dn)
    library.ldap_delete_ext_sW.assert_called_once_with(1, dn, None, None)


@pytest.mark.parametrize(
    ("sddl", "expected"),
    [
        ("D:(D;;SDDT;;;WD)", True),
        ("D:(D;;0x10040;;;S-1-1-0)", True),
        ("D:(D;ID;SDDT;;;WD)", False),
        ("D:(A;;SDDT;;;WD)", False),
        ("D:(D;;SD;;;WD)", False),
    ],
)
def test_protection_reads_explicit_everyone_delete_deny(
    ldap: ModuleType, sddl: str, expected: bool
) -> None:
    assert ldap is not None
    helper = importlib.import_module("legacy_ad_schema")
    assert helper.protected_from_deletion(sddl) is expected
