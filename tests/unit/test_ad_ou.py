"""Exercise OU and generic-object public lifecycle behavior without Windows."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# The fixture independently models objects, protection and LDAP write requests.
# Schema fixtures and direct payload calls intentionally remain independent of
# the read-only object_info oracle rather than sharing expected result machinery.
# pylint: disable=protected-access,duplicate-code

import binascii
import copy
import importlib
import json
import sys
import uuid
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module

BASE = "DC=example,DC=test"
_SCHEMA = {
    "objectGUID": ("2.5.5.10", True),
    "objectClass": ("2.5.5.2", False),
    "name": ("2.5.5.12", True),
    "nTSecurityDescriptor": ("2.5.5.15", True),
    "description": ("2.5.5.12", False),
    "displayName": ("2.5.5.12", True),
    "l": ("2.5.5.12", True),
    "c": ("2.5.5.12", True),
    "managedBy": ("2.5.5.1", True),
    "postalCode": ("2.5.5.12", True),
    "st": ("2.5.5.12", True),
    "street": ("2.5.5.12", True),
    "comment": ("2.5.5.12", True),
    # This synthetic schema attribute exercises arbitrary multivalue strings.
    "testMultiString": ("2.5.5.12", False),
    "logonCount": ("2.5.5.9", True),
    "audio": ("2.5.5.10", False),
    "accountExpires": ("2.5.5.16", True),
    "wWWHomePage": ("2.5.5.12", True),
}


class Directory:
    """Model independently observable native LDAP object operations."""

    def __init__(self) -> None:
        self.objects: dict[str, dict[str, list[bytes]]] = {}
        self.writes: list[tuple[Any, ...]] = []
        self.fail_action: str | None = None
        self.closed = False
        self.sequence = 0

    def close(self) -> None:
        """Record closure of the owned authenticated connection."""
        self.closed = True

    def naming_context(self, name: str = "defaultNamingContext") -> str:
        """Return the fixture's schema or default domain naming context.

        :param name: Requested naming context.
        :returns: The independent fixture base.
        """
        return (
            "CN=Schema,CN=Configuration," + BASE
            if name == "schemaNamingContext"
            else BASE
        )

    def search(
        self,
        base: str,
        scope: int,
        ldap_filter: str,
        attributes: list[str],
        **_flags: Any
    ) -> list[dict[str, Any]]:
        """Read copied protocol values from independent fixture state.

        :param base: Query base DN or extended GUID DN.
        :param scope: Native LDAP search scope.
        :param ldap_filter: LDAP query string.
        :param attributes: Requested protocol attribute names.
        :param _flags: Server-control flags; the independent fixture records state only.
        :returns: Matching entries with selected attribute values.
        """
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
                for name, (syntax, single) in _SCHEMA.items()
            ]
        rows = []
        for dn, values in self.objects.items():
            if base.startswith("<GUID="):
                matches = values["objectGUID"] == [binascii.unhexlify(base[6:-1])]
            elif scope == 0:
                matches = dn.lower() == base.lower()
            elif ldap_filter.startswith("(|(sAMAccountName="):
                requested = ldap_filter.split("=", 1)[1].split(")", 1)[0].encode()
                matches = values.get("sAMAccountName") == [requested] or values.get(
                    "userPrincipalName"
                ) == [requested]
            else:
                matches = dn.lower() == base.lower() or dn.lower().endswith(
                    "," + base.lower()
                )
            if matches:
                wanted = {name.lower() for name in attributes}
                rows.append(
                    {
                        "dn": dn,
                        "attributes": copy.deepcopy(
                            {
                                key: value
                                for key, value in values.items()
                                if key.lower() in wanted
                            }
                        ),
                    }
                )
        return rows

    def _failure(self, action: str) -> None:
        if self.fail_action == action:
            self.fail_action = None
            raise OSError(5, "Requested write denied")

    def add(self, dn: str, values: dict[str, list[bytes]]) -> None:
        """Create an independent fixture object with a generated GUID.

        :param dn: Desired distinguished name.
        :param values: Requested encoded attributes.
        :raises OSError: If the injected creation failure is active.
        """
        self._failure("add")
        self.sequence += 1
        self.writes.append(("add", dn, copy.deepcopy(values)))
        created = copy.deepcopy(values)
        created["objectGUID"] = [uuid.UUID(int=self.sequence).bytes_le]
        created["objectClass"] = [b"top"] + created["objectClass"]
        created["name"] = created.get("ou", created.get("cn", []))
        created.setdefault("nTSecurityDescriptor", [b"O:DAG:DAD:AI(A;;GA;;;DA)"])
        self.objects[dn] = created

    def modify(self, dn: str, changes: list[tuple[int, str, list[bytes]]]) -> None:
        """Apply the requested encoded changes to fixture state.

        :param dn: Existing distinguished name.
        :param changes: Native add/delete/replace tuples.
        :raises OSError: If the injected modification failure is active.
        """
        self._failure("modify")
        self.writes.append(("modify", dn, copy.deepcopy(changes)))
        for operation, name, values in changes:
            prior = next(
                (key for key in self.objects[dn] if key.lower() == name.lower()), name
            )
            if operation == 1:
                self.objects[dn].pop(prior, None)
            else:
                self.objects[dn][prior] = list(values)

    def rename(self, dn: str, rdn: str, parent: str) -> None:
        """Rename the fixture object while retaining its immutable GUID.

        :param dn: Existing distinguished name.
        :param rdn: Desired relative distinguished name.
        :param parent: Desired parent DN.
        :raises OSError: If the injected rename failure is active.
        """
        self._failure("rename")
        values = self.objects.pop(dn)
        values["name"] = [rdn.split("=", 1)[1].encode()]
        destination = rdn + "," + parent
        self.writes.append(("rename", dn, rdn, parent))
        self.objects[destination] = values

    def delete(self, dn: str) -> None:
        """Remove a childless fixture entry without deleting other objects.

        :param dn: Distinguished name to remove.
        :raises OSError: If deletion fails or the object still has children.
        """
        self._failure("delete")
        if any(name.endswith("," + dn) for name in self.objects):
            raise OSError(66, "Object has children")
        self.writes.append(("delete", dn))
        del self.objects[dn]


@pytest.fixture(name="directory")
def directory_state() -> Directory:
    """Provide fresh independent directory object state.

    :returns: The native operation fixture.
    """
    return Directory()


@pytest.fixture(name="payload")
def ou_payload(monkeypatch: pytest.MonkeyPatch, directory: Directory) -> ModuleType:
    """Import adjacent target helpers and substitute native boundaries only.

    :param monkeypatch: Scoped import and native API substitutions.
    :param directory: Independent fixture holding observable directory state.
    :returns: The OU target payload.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    monkeypatch.syspath_prepend(str(HELPER.parent))
    helper = importlib.import_module("legacy_ad_object")
    monkeypatch.setattr(helper, "LDAPConnection", Mock(return_value=directory))
    monkeypatch.setattr(
        helper, "security_descriptor_text", lambda value: value.decode()
    )
    monkeypatch.setattr(
        helper, "security_descriptor_bytes", lambda value: value.encode()
    )
    schema = importlib.import_module("legacy_ad_schema")
    monkeypatch.setattr(
        schema, "security_descriptor_text", lambda value: value.decode()
    )
    monkeypatch.setattr(
        schema, "security_descriptor_bytes", lambda value: value.encode()
    )
    return load_module(ROOT / "legacy_ad/plugins/modules/ou.py", "tested_ad_ou")


def _run(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    values: dict[str, Any],
) -> tuple[int, dict[str, Any]]:
    arguments = tmp_path / "arguments.json"
    arguments.write_text(json.dumps(values), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["ou.py", str(arguments)])
    return invoke_payload(payload, capsys)


def test_preview_create_repeat_and_default_protection(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    status, preview = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"name": "Deployment", "_ansible_check_mode": True, "_ansible_diff": True},
    )
    assert status == 0
    assert preview["changed"]
    assert preview["object_guid"] == "00000000-0000-0000-0000-000000000000"
    assert preview["distinguished_name"] == "OU=Deployment," + BASE
    assert preview["diff"]["before"] is None
    assert preview["diff"]["after"]["protect_from_deletion"]
    assert directory.objects == {}
    status, created = _run(
        payload, monkeypatch, tmp_path, capsys, {"name": "Deployment"}
    )
    assert status == 0 and created["changed"]
    assert created["object_guid"] != preview["object_guid"]
    descriptor = directory.objects[created["distinguished_name"]][
        "nTSecurityDescriptor"
    ][0]
    assert b"(D;;SDDT;;;WD)" in descriptor
    writes = len(directory.writes)
    status, repeated = _run(
        payload, monkeypatch, tmp_path, capsys, {"name": "Deployment"}
    )
    assert status == 0 and not repeated["changed"]
    assert repeated["object_guid"] == created["object_guid"]
    assert len(directory.writes) == writes
    assert directory.closed


def test_properties_clear_and_custom_attribute_lists(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    arguments = {
        "name": "Deployment",
        "description": "Deployment OU",
        "display_name": "Deploy",
        "city": "Berlin",
        "country": "DE",
        "postal_code": "10115",
        "state_province": "Berlin",
        "street": "Street 1",
        "attributes": {"set": {"testMultiString": ["alpha", "beta"]}},
    }
    status, created = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0 and created["changed"]
    values = directory.objects[created["distinguished_name"]]
    assert values["description"] == [b"Deployment OU"]
    assert values["l"] == [b"Berlin"]
    assert values["street"] == [b"Street 1"]
    status, repeated = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {**arguments, "attributes": {"set": {"testMultiString": ["beta", "alpha"]}}},
    )
    assert status == 0 and not repeated["changed"]
    status, updated = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {
            "identity": created["object_guid"],
            "description": "",
            "attributes": {
                "add": {"testMultiString": ["gamma"]},
                "remove": {"testMultiString": ["alpha"]},
            },
            "_ansible_diff": True,
        },
    )
    assert status == 0 and updated["changed"]
    assert "description" not in values
    assert values["testMultiString"] == [b"beta", b"gamma"]
    assert updated["diff"]["before"]["description"] == "Deployment OU"
    assert updated["diff"]["after"]["description"] is None
    assert updated["diff"]["after"]["attributes"]["testMultiString"] == [
        "beta",
        "gamma",
    ]


def test_single_valued_comment_rejects_multiple_values_without_mutation(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    status, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"name": "Deployment", "attributes": {"set": {"comment": ["a", "b"]}}},
    )
    assert status == 1
    assert result["failed"] and not result["changed"]
    assert "comment permits only one value" in result["msg"]
    assert directory.writes == []


def test_custom_attributes_compare_strings_case_sensitively(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"name": "Deployment", "attributes": {"set": {"comment": ["VALUE"]}}},
    )
    status, changed = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"name": "Deployment", "attributes": {"set": {"comment": ["value"]}}},
    )
    assert status == 0 and changed["changed"]
    assert directory.objects["OU=Deployment," + BASE]["comment"] == [b"value"]


def test_case_only_mapped_string_changes_are_applied_and_idempotent(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    initial = {
        "name": "Deployment",
        "description": "INITIAL",
        "display_name": "DISPLAY",
        "city": "BERLIN",
    }
    status, created = _run(payload, monkeypatch, tmp_path, capsys, initial)
    assert status == 0 and created["changed"]
    desired = {
        "identity": created["object_guid"],
        "description": "initial",
        "display_name": "display",
        "city": "Berlin",
        "_ansible_diff": True,
    }
    status, updated = _run(payload, monkeypatch, tmp_path, capsys, desired)
    assert status == 0 and updated["changed"]
    values = directory.objects[created["distinguished_name"]]
    assert values["description"] == [b"initial"]
    assert values["displayName"] == [b"display"]
    assert values["l"] == [b"Berlin"]
    assert updated["diff"]["before"]["description"] == "INITIAL"
    assert updated["diff"]["after"]["description"] == "initial"
    writes = len(directory.writes)
    status, repeated = _run(payload, monkeypatch, tmp_path, capsys, desired)
    assert status == 0 and not repeated["changed"]
    assert len(directory.writes) == writes


def test_managed_by_dn_comparison_remains_case_insensitive(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    manager_dn = "CN=Manager,CN=Users," + BASE
    directory.objects[manager_dn] = {
        "objectGUID": [uuid.UUID(int=500).bytes_le],
        "name": [b"Manager"],
        "sAMAccountName": [b"manager"],
    }
    status, created = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"name": "Deployment", "managed_by": "manager"},
    )
    assert status == 0 and created["changed"]
    directory.objects[created["distinguished_name"]]["managedBy"] = [
        manager_dn.upper().encode()
    ]
    writes = len(directory.writes)
    status, repeated = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"identity": created["object_guid"], "managed_by": "manager"},
    )
    assert status == 0 and not repeated["changed"]
    assert len(directory.writes) == writes


def test_clearing_an_unset_mapped_property_does_not_write(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    status, created = _run(
        payload, monkeypatch, tmp_path, capsys, {"name": "Deployment"}
    )
    assert status == 0
    writes = len(directory.writes)
    status, repeated = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"identity": created["object_guid"], "description": "   ", "display_name": ""},
    )
    assert status == 0 and not repeated["changed"]
    assert len(directory.writes) == writes


def test_preview_existing_changes_does_not_write(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, created = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"name": "Deployment", "description": "before"},
    )
    before = copy.deepcopy(directory.objects)
    writes = len(directory.writes)
    status, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {
            "identity": created["object_guid"],
            "name": "Renamed",
            "description": "after",
            "protect_from_deletion": False,
            "_ansible_check_mode": True,
        },
    )
    assert status == 0 and result["changed"]
    assert result["distinguished_name"] == "OU=Renamed," + BASE
    assert directory.objects == before
    assert len(directory.writes) == writes


def test_rename_move_and_default_path_sentinel(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, created = _run(payload, monkeypatch, tmp_path, capsys, {"name": "Deployment"})
    destination = "OU=Parent," + BASE
    status, moved = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"identity": created["object_guid"], "name": "Renamed", "path": destination},
    )
    assert status == 0 and moved["changed"]
    assert moved["distinguished_name"] == "OU=Renamed," + destination
    assert moved["object_guid"] == created["object_guid"]
    assert (
        b"(D;;SDDT;;;WD)"
        in directory.objects[moved["distinguished_name"]]["nTSecurityDescriptor"][0]
    )
    status, returned = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"identity": moved["object_guid"], "path": "microsoft.ad.default_path"},
    )
    assert status == 0 and returned["changed"]
    assert returned["distinguished_name"] == "OU=Renamed," + BASE


def test_move_failure_restores_existing_protection(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, created = _run(payload, monkeypatch, tmp_path, capsys, {"name": "Deployment"})
    directory.fail_action = "rename"
    status, failed = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"identity": created["object_guid"], "path": "OU=Other," + BASE},
    )
    assert status == 1 and failed["failed"]
    assert "Requested write denied" in failed["msg"]
    assert created["distinguished_name"] in directory.objects
    assert (
        b"(D;;SDDT;;;WD)"
        in directory.objects[created["distinguished_name"]]["nTSecurityDescriptor"][0]
    )


def test_remove_tree_preview_delete_and_repeat(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, parent = _run(payload, monkeypatch, tmp_path, capsys, {"name": "Parent"})
    _, child = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"name": "Child", "path": parent["distinguished_name"]},
    )
    before = copy.deepcopy(directory.objects)
    status, preview = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {
            "identity": parent["object_guid"],
            "state": "absent",
            "_ansible_check_mode": True,
        },
    )
    assert status == 0 and preview["changed"]
    assert directory.objects == before
    status, deleted = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"identity": parent["object_guid"], "state": "absent"},
    )
    assert status == 0 and deleted["changed"]
    assert deleted["object_guid"] == parent["object_guid"]
    assert directory.objects == {}
    assert [call[1] for call in directory.writes if call[0] == "delete"] == [
        child["distinguished_name"],
        parent["distinguished_name"],
    ]
    status, repeated = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"identity": parent["object_guid"], "state": "absent"},
    )
    assert status == 0 and not repeated["changed"]
    assert repeated["object_guid"] is None


def test_failed_delete_restores_protection_of_surviving_object(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _, created = _run(payload, monkeypatch, tmp_path, capsys, {"name": "Deployment"})
    directory.fail_action = "delete"
    status, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"identity": created["object_guid"], "state": "absent"},
    )
    assert status == 1 and result["failed"]
    assert (
        b"(D;;SDDT;;;WD)"
        in directory.objects[created["distinguished_name"]]["nTSecurityDescriptor"][0]
    )


def test_failed_creation_does_not_report_a_completed_mutation(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory.fail_action = "add"
    status, result = _run(
        payload, monkeypatch, tmp_path, capsys, {"name": "Deployment"}
    )
    assert status == 1 and result["failed"]
    assert not result["changed"]
    assert directory.objects == {}


def test_ou_absence_does_not_remove_another_object_class(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    user_dn = "CN=Existing User,CN=Users," + BASE
    directory.objects[user_dn] = {
        "objectGUID": [uuid.UUID(int=500).bytes_le],
        "name": [b"Existing User"],
        "objectClass": [b"top", b"person", b"user"],
    }
    before = copy.deepcopy(directory.objects)
    status, result = _run(
        payload, monkeypatch, tmp_path, capsys, {"identity": user_dn, "state": "absent"}
    )
    assert status == 0
    assert not result["changed"]
    assert result["object_guid"] is None
    assert directory.objects == before
    assert directory.writes == []


def test_generic_absence_remains_unrestricted_when_type_is_supplied(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert payload is not None
    generic = load_module(
        ROOT / "legacy_ad/plugins/modules/object.py", "tested_ad_object"
    )
    user_dn = "CN=Existing User,CN=Users," + BASE
    directory.objects[user_dn] = {
        "objectGUID": [uuid.UUID(int=500).bytes_le],
        "name": [b"Existing User"],
        "objectClass": [b"top", b"person", b"user"],
        "nTSecurityDescriptor": [b"O:DAG:DAD:AI(A;;GA;;;DA)"],
    }
    status, result = _run(
        generic,
        monkeypatch,
        tmp_path,
        capsys,
        {"identity": user_dn, "type": "organizationalUnit", "state": "absent"},
    )
    assert status == 0
    assert result["changed"]
    assert directory.objects == {}


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"name": "OU", "state": "bad"},
        {"name": "OU", "domain_username": "user"},
        {"name": "OU", "attributes": {"unsupported": {}}},
        {"name": "OU", "domain_credentials": [{"username": "user"}]},
        {
            "name": "OU",
            "domain_username": "user",
            "domain_password": "secret",
            "domain_credentials": [{"username": "user", "password": "secret"}],
        },
    ],
)
def test_invalid_public_arguments_fail_without_connecting(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    arguments: dict[str, Any],
) -> None:
    status, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 1 and result["failed"]
    helper = importlib.import_module("legacy_ad_object")
    helper.LDAPConnection.assert_not_called()


def test_default_credentials_and_dn_lookup(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    account_dn = "CN=Manager,CN=Users," + BASE
    directory.objects[account_dn] = {
        "objectGUID": [uuid.UUID(int=500).bytes_le],
        "name": [b"Manager"],
        "sAMAccountName": [b"manager"],
    }
    status, created = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {
            "name": "Deployment",
            "managed_by": "manager",
            "domain_credentials": [{"username": "DOMAIN\\user", "password": "secret"}],
        },
    )
    assert status == 0
    assert directory.objects[created["distinguished_name"]]["managedBy"] == [
        account_dn.encode()
    ]
    helper = importlib.import_module("legacy_ad_object")
    helper.LDAPConnection.assert_called_once_with(None, "DOMAIN\\user", "secret")
    assert "secret" not in json.dumps(created)


@pytest.mark.parametrize("mode", ["process", "explicit", "unnamed"])
@pytest.mark.parametrize("named", [False, True])
def test_foreign_server_uses_only_explicit_or_matching_named_credentials(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    named: bool,
) -> None:
    del payload
    helper = importlib.import_module("legacy_ad_object")
    default = {"name": None, "username": "default-user", "password": "default-pass"}
    override = {
        "name": "FOREIGN.EXAMPLE.TEST",
        "username": "named-user",
        "password": "named-pass",
    }
    connection = Mock()
    native = Mock(return_value=connection)
    monkeypatch.setattr(helper, "LDAPConnection", native)
    arguments = {
        "domain_server": "home.example.test",
        "domain_username": "explicit-user" if mode == "explicit" else None,
        "domain_password": "explicit-pass" if mode == "explicit" else None,
        "domain_credentials": ([default] if mode == "unnamed" else [])
        + ([override] if named else []),
    }
    with helper.DirectorySession(arguments) as session:
        session.connection()
        session.connection("foreign.example.test")
        session.connection("FOREIGN.EXAMPLE.TEST")
    home = (
        ("explicit-user", "explicit-pass")
        if mode == "explicit"
        else ("default-user", "default-pass") if mode == "unnamed" else (None, None)
    )
    foreign = (
        ("named-user", "named-pass")
        if named
        else ("explicit-user", "explicit-pass") if mode == "explicit" else (None, None)
    )
    assert native.call_args_list == [
        call("home.example.test", *home),
        call("foreign.example.test", *foreign),
    ]
    assert connection.close.call_count == 2


@pytest.mark.parametrize(
    "case",
    [
        ("Comma,Name", r"Comma\,Name"),
        (" leading", r"\ leading"),
        ("trailing ", "trailing\\ "),
        ("a+b", r"a\+b"),
        ("a\\b", r"a\\b"),
        ("#name", r"\#name"),
    ],
)
def test_literal_names_are_escaped_in_new_dn(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    case: tuple[str, str],
) -> None:
    name, expected = case
    status, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"name": name, "_ansible_check_mode": True},
    )
    assert status == 0
    assert result["distinguished_name"] == "OU=" + expected + "," + BASE


def test_generic_object_creation_and_type_changes(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert payload is not None
    generic = load_module(
        ROOT / "legacy_ad/plugins/modules/object.py", "tested_ad_object"
    )
    status, created = _run(
        generic, monkeypatch, tmp_path, capsys, {"name": "Contact", "type": "contact"}
    )
    assert status == 0 and created["changed"]
    assert created["distinguished_name"] == "CN=Contact," + BASE
    assert (
        b"(D;;SDDT;;;WD)"
        not in directory.objects[created["distinguished_name"]]["nTSecurityDescriptor"][
            0
        ]
    )
    status, repeated = _run(
        generic, monkeypatch, tmp_path, capsys, {"name": "Contact", "type": "contact"}
    )
    assert status == 0 and not repeated["changed"]
    writes = len(directory.writes)
    status, changed_type = _run(
        generic,
        monkeypatch,
        tmp_path,
        capsys,
        {"identity": created["object_guid"], "type": "container"},
    )
    assert status == 1 and changed_type["failed"]
    assert len(directory.writes) == writes


def test_custom_attribute_types_and_filetime(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    status, created = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {
            "name": "Typed",
            "attributes": {
                "set": {
                    "audio": [{"type": "bytes", "value": "AP8="}],
                    "accountExpires": {
                        "type": "date_time",
                        "value": "1601-01-01T01:30:00.0000001+01:30",
                    },
                    "logonCount": {"type": "int", "value": "3"},
                }
            },
        },
    )
    assert status == 0
    values = directory.objects[created["distinguished_name"]]
    assert values["audio"] == [b"\x00\xff"]
    assert values["accountExpires"] == [b"1"]
    assert values["logonCount"] == [b"3"]
