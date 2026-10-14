"""Test the public object_info payload contract with independent directory data."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import binascii
import copy
import importlib
import json
import sys
import uuid
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module

DN = "CN=Ansible User,CN=Users,DC=example,DC=test"
GUID = "c8c6569e-4688-4f3c-8462-afc4ff60817b"
_ATTRIBUTES = {
    "distinguishedName": ("2.5.5.1", True),
    "name": ("2.5.5.12", True),
    "objectClass": ("2.5.5.2", False),
    "objectGUID": ("2.5.5.10", True),
    "memberOf": ("2.5.5.1", False),
    "department": ("2.5.5.12", True),
    "audio": ("2.5.5.10", False),
    "logonCount": ("2.5.5.9", True),
    "modifyTimestamp": ("2.5.5.11", True),
    "nTSecurityDescriptor": ("2.5.5.15", True),
    "objectSid": ("2.5.5.17", True),
    "sAMAccountType": ("2.5.5.9", True),
    "userAccountControl": ("2.5.5.9", True),
    "groupType": ("2.5.5.9", True),
    "msDS-SupportedEncryptionTypes": ("2.5.5.9", True),
    "company": ("2.5.5.12", True),
    "description": ("2.5.5.12", False),
    "canonicalName": ("2.5.5.12", True),
    "whenCreated": ("2.5.5.11", True),
}


class Directory:
    """Keep observable searches separate from payload result conversion."""

    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.closed = False
        self.constructed_attributes = {"canonicalName"}
        self.entries: list[dict[str, Any]] = [
            {
                "dn": DN,
                "attributes": {
                    "distinguishedName": [DN.encode()],
                    "name": [b"Ansible User"],
                    "objectClass": [
                        b"top",
                        b"person",
                        b"organizationalPerson",
                        b"user",
                    ],
                    "objectGUID": [uuid.UUID(GUID).bytes_le],
                    "memberOf": [b"CN=Group,DC=example,DC=test"],
                    "audio": [b"\x01\x02", b"\x00\xff"],
                    "logonCount": [b"0"],
                    "modifyTimestamp": [b"20250101123456.0Z"],
                    "company": [b"Contoso"],
                    "sAMAccountType": [b"805306368"],
                    "userAccountControl": [b"66050"],
                    "groupType": [b"-2147483646"],
                    "msDS-SupportedEncryptionTypes": [b"31"],
                },
            }
        ]

    def __enter__(self) -> "Directory":
        return self

    def __exit__(self, *_args: Any) -> None:
        self.closed = True

    def naming_context(self, name: str = "defaultNamingContext") -> str:
        """Return the fixture's independently defined search root.

        :param name: Requested naming-context property.
        :returns: The domain or schema search base.
        """
        return (
            "CN=Schema,CN=Configuration,DC=example,DC=test"
            if name == "schemaNamingContext"
            else "DC=example,DC=test"
        )

    def search(
        self,
        base: str,
        scope: int,
        ldap_filter: str,
        attributes: list[str],
        **flags: Any
    ) -> list[dict[str, Any]]:
        """Apply requested property selection to the independent fixture.

        :param base: Query search base.
        :param scope: Base, one-level or subtree scope.
        :param ldap_filter: LDAP query to record for assertions.
        :param attributes: Protocol attributes to return.
        :param flags: Independent server-control flags.
        :returns: Copied directory entries with requested protocol values.
        """
        self.calls.append((base, scope, ldap_filter, attributes, flags))
        if ldap_filter == "(objectClass=attributeSchema)":
            return [
                {
                    "dn": "CN=" + name,
                    "attributes": {
                        "lDAPDisplayName": [name.encode()],
                        "attributeSyntax": [syntax.encode()],
                        "isSingleValued": [b"TRUE" if single else b"FALSE"],
                    },
                }
                for name, (syntax, single) in _ATTRIBUTES.items()
            ]
        rows = copy.deepcopy(self.entries)
        if scope == 0:
            if base.startswith("<GUID="):
                target = binascii.unhexlify(base[6:-1])
                rows = [
                    row for row in rows if row["attributes"]["objectGUID"][0] == target
                ]
            else:
                rows = [row for row in rows if row["dn"] == base]
        elif base == self.naming_context():
            # Naming contexts are separate LDAP partitions, not one DN subtree.
            rows = [
                row for row in rows if ",cn=configuration," not in row["dn"].lower()
            ]
        for row in rows:
            if "*" not in attributes:
                wanted = {name.lower() for name in attributes}
                row["attributes"] = {
                    name: values
                    for name, values in row["attributes"].items()
                    if name.lower() in wanted
                }
            else:
                wanted = {name.lower() for name in attributes}
                row["attributes"] = {
                    name: values
                    for name, values in row["attributes"].items()
                    if name not in self.constructed_attributes or name.lower() in wanted
                }
        return rows


@pytest.fixture(name="directory")
def directory_state() -> Directory:
    """Return an independent directory fixture with raw protocol values.

    :returns: The directory fixture.
    """
    return Directory()


@pytest.fixture(name="payload")
def info_payload(monkeypatch: pytest.MonkeyPatch, directory: Directory) -> ModuleType:
    """Load staged target helpers and substitute only the LDAP connection.

    :param monkeypatch: Scoped import paths and LDAP connection substitute.
    :param directory: Independent directory fixture.
    :returns: The imported object_info target payload.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    monkeypatch.syspath_prepend(str(HELPER.parent))
    module = load_module(
        ROOT / "legacy_ad/plugins/modules/object_info.py", "tested_ad_object_info"
    )
    monkeypatch.setattr(module.ldap, "LDAPConnection", Mock(return_value=directory))
    return module


def _run(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    arguments: dict[str, Any],
) -> tuple[int, dict[str, Any]]:
    source = tmp_path / "arguments.json"
    source.write_text(json.dumps(arguments), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["object_info.py", str(source)])
    return invoke_payload(payload, capsys)


def test_default_properties_and_check_mode(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    arguments = {"identity": DN, "_ansible_check_mode": True}
    status, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0
    assert result == {
        "changed": False,
        "objects": [
            {
                "DistinguishedName": DN,
                "Name": "Ansible User",
                "ObjectClass": "user",
                "ObjectGUID": GUID,
            }
        ],
    }
    assert directory.closed
    assert directory.calls[0][:3] == (DN, 0, "(objectClass=*)")


def test_guid_identity_finds_objects_in_the_configuration_partition(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dn = "CN=Link,CN=IP,CN=Sites,CN=Configuration,DC=example,DC=test"
    entry = directory.entries[0]
    entry["dn"] = dn
    entry["attributes"].update(
        distinguishedName=[dn.encode()],
        name=[b"Link"],
        objectClass=[b"top", b"siteLink"],
    )
    status, result = _run(payload, monkeypatch, tmp_path, capsys, {"identity": GUID})
    assert status == 0
    assert result["objects"] == [
        {
            "DistinguishedName": dn,
            "Name": "Link",
            "ObjectClass": "siteLink",
            "ObjectGUID": GUID,
        }
    ]


def test_typed_properties_and_flags(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    properties = [
        "memberOf",
        "audio",
        "department",
        "logonCount",
        "modifyTimestamp",
        "sAMAccountType",
        "userAccountControl",
        "groupType",
        "msDS-SupportedEncryptionTypes",
    ]
    arguments = {"identity": GUID, "properties": properties}
    status, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0
    values = result["objects"][0]
    assert values["memberOf"] == ["CN=Group,DC=example,DC=test"]
    assert values["audio"] == ["AQI=", "AP8="]
    assert values["department"] is None
    assert values["logonCount"] == 0
    assert values["modifyTimestamp"] == "2025-01-01T12:34:56.0000000Z"
    assert values["sAMAccountType_AnsibleFlags"] == ["SAM_USER_OBJECT"]
    assert values["userAccountControl_AnsibleFlags"] == [
        "ADS_UF_ACCOUNTDISABLE",
        "ADS_UF_NORMAL_ACCOUNT",
        "ADS_UF_DONT_EXPIRE_PASSWD",
    ]
    assert values["groupType_AnsibleFlags"] == [
        "GROUP_TYPE_ACCOUNT_GROUP",
        "GROUP_TYPE_SECURITY_ENABLED",
    ]
    assert values["msDS-SupportedEncryptionTypes_AnsibleFlags"] == [
        "DES_CBC_CRC",
        "DES_CBC_MD5",
        "RC4_HMAC",
        "AES128_CTS_HMAC_SHA1_96",
        "AES256_CTS_HMAC_SHA1_96",
    ]


def test_invalid_property_warns_and_omits_each_object(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory.entries *= 2
    arguments = {"filter": "*", "properties": ["NotAProperty"]}
    status, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0
    assert result["objects"] == []
    assert len(result["warnings"]) == 2
    assert all("NotAProperty" in text and DN in text for text in result["warnings"])


def test_filter_scope_base_credentials_and_deleted_control(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    arguments = {
        "filter": "ObjectClass -eq 'user'",
        "search_scope": "one_level",
        "search_base": "",
        "domain_server": "dc.example.test",
        "domain_username": "DOMAIN\\user",
        "domain_password": "secret",
        "include_deleted": True,
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0
    assert not result["changed"]
    assert directory.calls[0] == (
        "",
        1,
        "(objectClass=user)",
        ["objectGUID", "distinguishedName"],
        {"include_deleted": True},
    )
    payload.ldap.LDAPConnection.assert_called_once_with(
        "dc.example.test", "DOMAIN\\user", "secret"
    )
    assert "secret" not in json.dumps(result)


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"filter": "*", "identity": DN},
        {"identity": DN, "search_scope": "base"},
        {"identity": DN, "search_base": ""},
        {"filter": "*", "domain_username": "user"},
        {"filter": "*", "domain_password": "secret"},
        {"filter": "*", "search_scope": "wrong"},
        {"ldap_filter": ""},
        {"filter": "*", "unknown": 1},
    ],
)
def test_validation_always_returns_objects_without_connecting(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    arguments: dict[str, Any],
) -> None:
    status, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 1
    assert result["objects"] == []
    assert result["changed"] is False
    payload.ldap.LDAPConnection.assert_not_called()


def test_missing_identity_is_successful_empty_result(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        directory,
        "search",
        Mock(side_effect=payload.ldap.LDAPError(32, "No such object")),
    )
    status, result = _run(payload, monkeypatch, tmp_path, capsys, {"identity": DN})
    assert status == 0
    assert result == {"changed": False, "objects": []}


def test_authentication_failure_preserves_objects(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload.ldap.LDAPConnection.side_effect = payload.ldap.LDAPError(
        49, "Invalid credentials"
    )
    status, result = _run(payload, monkeypatch, tmp_path, capsys, {"filter": "*"})
    assert status == 1
    assert result["objects"] == []
    assert "Invalid credentials" in result["msg"]


def test_wildcard_reads_each_objects_populated_properties(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory.entries.append(copy.deepcopy(directory.entries[0]))
    directory.entries[1]["dn"] = "CN=Second User,CN=Users,DC=example,DC=test"
    directory.entries[1]["attributes"]["objectGUID"] = [
        uuid.UUID("11111111-2222-3333-4444-555555555555").bytes_le
    ]
    directory.entries[1]["attributes"].pop("company")
    directory.entries[1]["attributes"]["department"] = [b"Engineering"]
    arguments = {"ldap_filter": "(objectClass=user)", "properties": ["*"]}
    status, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0
    assert result["objects"][0]["company"] == "Contoso"
    assert "department" not in result["objects"][0]
    assert result["objects"][1]["department"] == "Engineering"
    assert "company" not in result["objects"][1]


def test_sid_and_descriptor_output_use_native_converter(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    helper = importlib.import_module("legacy_ad_schema")
    directory.entries[0]["attributes"]["objectSid"] = [
        bytes.fromhex("01020000000000052000000020020000")
    ]
    directory.entries[0]["attributes"]["nTSecurityDescriptor"] = [b"native descriptor"]
    monkeypatch.setattr(
        helper.accounts, "sid_to_name", lambda _sid: "BUILTIN\\Administrators"
    )
    monkeypatch.setattr(
        helper, "security_descriptor_text", lambda _value: "O:BAG:BAD:(D;;SDDT;;;WD)"
    )
    arguments = {
        "identity": DN,
        "properties": [
            "objectSID",
            "nTSecurityDescriptor",
            "ProtectedFromAccidentalDeletion",
        ],
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0
    values = result["objects"][0]
    assert values["objectSID"] == {
        "Sid": "S-1-5-32-544",
        "Name": "BUILTIN\\Administrators",
    }
    assert values["nTSecurityDescriptor"] == "O:BAG:BAD:(D;;SDDT;;;WD)"
    assert values["ProtectedFromAccidentalDeletion"] is True
    assert directory.calls[-1][-1]["security_descriptor"] is True


def test_wildcard_explicitly_requests_constructed_extended_properties(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory.entries[0]["attributes"]["canonicalName"] = [
        b"example.test/Users/Ansible User"
    ]
    directory.entries[0]["attributes"]["whenCreated"] = [b"20250101123456.0Z"]
    arguments = {"identity": DN, "properties": ["*"]}
    status, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0
    assert "canonicalName" in directory.calls[-1][3]
    assert "whenCreated" in directory.calls[-1][3]
    assert result["objects"][0]["CanonicalName"] == "example.test/Users/Ansible User"
    assert result["objects"][0]["Created"] == "2025-01-01T12:34:56.0000000Z"


def test_explicit_properties_do_not_expand_into_unrequested_aliases(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory.entries[0]["attributes"]["canonicalName"] = [
        b"example.test/Users/Ansible User"
    ]
    arguments = {"identity": DN, "properties": ["company"]}
    status, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0
    assert "canonicalName" not in directory.calls[-1][3]
    assert "CanonicalName" not in result["objects"][0]


def test_description_alias_projects_scalar_from_multivalued_schema(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    arguments = {"identity": DN, "properties": ["Description"]}
    for values, expected in (
        ([], None),
        ([b"Initial description"], "Initial description"),
        ([b"First description", b"Second description"], "First description"),
    ):
        directory.entries[0]["attributes"]["description"] = values
        status, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
        assert status == 0
        assert result["objects"][0]["Description"] == expected
        assert directory.entries[0]["attributes"]["description"] == values
