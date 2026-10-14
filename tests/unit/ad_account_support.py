"""Model native AD account operations independently of payload planning."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import importlib
import json
import struct
import sys
import uuid
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module

# Explicit re-export makes the shared fixture constant visible to strict typing.
from tests.unit.test_ad_ou import BASE as BASE  # pylint: disable=useless-import-alias
from tests.unit.test_ad_ou import Directory as ObjectDirectory

USERS = "CN=Users," + BASE
COMPUTERS = "CN=Computers," + BASE


def sid_bytes(value: str) -> bytes:
    """Encode fixture SIDs without invoking a Windows account API.

    :param value: SID string.
    :returns: Binary fixture SID.
    """
    fields = value.split("-")
    numbers = [int(field) for field in fields[3:]]
    return (
        bytes([1, len(numbers)])
        + int(fields[2]).to_bytes(6, "big")
        + b"".join(struct.pack("<I", number) for number in numbers)
    )


class Directory(ObjectDirectory):
    """Expose independent native account state and LDAP modification semantics."""

    def __init__(self) -> None:
        super().__init__()
        self.passwords: dict[str, str] = {}
        self.fail_attribute: str | None = None
        self.missing_schema: set[str] = set()
        self.seed(
            BASE,
            "domainDNS",
            "domain",
            extra={
                "wellKnownObjects": [
                    ("B:32:A9D1CA15768811D1ADED00C04FD8D5CD:" + USERS).encode(),
                    ("B:32:AA312825768811D1ADED00C04FD8D5CD:" + COMPUTERS).encode(),
                ]
            },
        )
        self.seed(
            "CN=Domain Users," + USERS,
            "group",
            "Domain Users",
            513,
            {"groupType": [b"-2147483646"]},
        )
        self.seed(
            "CN=Domain Computers," + USERS,
            "group",
            "Domain Computers",
            515,
            {"groupType": [b"-2147483646"]},
        )

    # LDAP fixture identities have separate DN, class, SAM, SID and attributes.
    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def seed(
        self,
        dn: str,
        kind: str,
        sam: str,
        rid: int | None = None,
        extra: dict[str, list[bytes]] | None = None,
    ) -> dict[str, list[bytes]]:
        """Create an observed fixture account without recording a module write.

        :param dn: Fixture distinguished name.
        :param kind: Structural LDAP object class.
        :param sam: Fixture SAM account name.
        :param rid: Last SID component.
        :param extra: Additional encoded attributes.
        :returns: Fixture values kept in directory state.
        """
        self.sequence += 1
        values = {
            "objectGUID": [uuid.UUID(int=self.sequence).bytes_le],
            "objectSid": [
                sid_bytes(
                    "S-1-5-21-1-2-3-"
                    + str(rid if rid is not None else 1000 + self.sequence)
                )
            ],
            "objectClass": [b"top", kind.encode()],
            "name": [dn.split("=", 1)[1].split(",", 1)[0].encode()],
            "sAMAccountName": [sam.encode()],
            "nTSecurityDescriptor": [b"O:DAG:DAD:AI(A;;GA;;;DA)"],
        }
        if kind in ("user", "computer"):
            values.update(
                {
                    "userAccountControl": [b"512" if kind == "user" else b"4096"],
                    "pwdLastSet": [b"1234"],
                    "primaryGroupID": [b"513" if kind == "user" else b"515"],
                }
            )
            self.passwords[dn] = "ExistingPassword1!"
        values.update(extra or {})
        self.objects[dn] = values
        return values

    # pylint: enable=too-many-arguments,too-many-positional-arguments

    # Schema records, account records and generated back-links are intentionally
    # evaluated together by this independent protocol-state fixture.
    def search(  # pylint: disable=too-many-locals
        self,
        base: str,
        scope: int,
        ldap_filter: str,
        attributes: list[str],
        **flags: Any
    ) -> list[dict[str, Any]]:
        """Return copied schema/account values and independently maintained links.

        :param base: Query DN or extended GUID base.
        :param scope: Native LDAP search scope.
        :param ldap_filter: Requested LDAP filter.
        :param attributes: Requested attributes.
        :param flags: Native server-control flags.
        :returns: Copied LDAP entries.
        """
        if ldap_filter == "(objectClass=attributeSchema)":
            rows = super().search(base, scope, ldap_filter, attributes, **flags)
            existing = {
                row["attributes"]["lDAPDisplayName"][0].decode().lower() for row in rows
            }
            extras = {
                "objectSid": ("2.5.5.17", True),
                "sAMAccountName": ("2.5.5.12", True),
                "userAccountControl": ("2.5.5.9", True),
                "groupType": ("2.5.5.9", True),
                "member": ("2.5.5.1", False),
                "memberOf": ("2.5.5.1", False),
                "servicePrincipalName": ("2.5.5.12", False),
                "msDS-SupportedEncryptionTypes": ("2.5.5.9", True),
                "msDS-AllowedToActOnBehalfOfOtherIdentity": ("2.5.5.15", True),
                "company": ("2.5.5.12", True),
                "mail": ("2.5.5.12", True),
                "givenName": ("2.5.5.12", True),
                "streetAddress": ("2.5.5.12", True),
                "sn": ("2.5.5.12", True),
                "userPrincipalName": ("2.5.5.12", True),
                "dNSHostName": ("2.5.5.12", True),
                "location": ("2.5.5.12", True),
            }
            for name, (syntax, single) in extras.items():
                if name.lower() not in existing:
                    # Independent fixtures spell out the LDAP schema wire record;
                    # sharing payload schema construction would weaken the oracle.
                    # pylint: disable=duplicate-code
                    rows.append(
                        {
                            "dn": "CN=" + name,
                            "attributes": {
                                "lDAPDisplayName": [name.encode()],
                                "attributeSyntax": [syntax.encode()],
                                "isSingleValued": [b"TRUE" if single else b"FALSE"],
                            },
                        }
                    )
                    # pylint: enable=duplicate-code
            return [
                row
                for row in rows
                if row["attributes"]["lDAPDisplayName"][0].decode().lower()
                not in self.missing_schema
            ]
        if ldap_filter.startswith("(objectSid="):
            encoded = ldap_filter.split("=", 1)[1][:-1]
            wanted = bytes(int(piece, 16) for piece in encoded.split("\\")[1:])
            rows = [
                {"dn": dn, "attributes": copy.deepcopy(values)}
                for dn, values in self.objects.items()
                if values.get("objectSid") == [wanted]
            ]
        elif ldap_filter.startswith("(|(sAMAccountName="):
            requested = ldap_filter.split("=", 1)[1].split(")", 1)[0].lower().encode()
            rows = [
                {"dn": dn, "attributes": copy.deepcopy(values)}
                for dn, values in self.objects.items()
                if any(
                    value.lower() == requested
                    for key in ("sAMAccountName", "userPrincipalName")
                    for value in values.get(key, [])
                )
            ]
        else:
            rows = super().search(base, scope, ldap_filter, attributes, **flags)
        for row in rows:
            if "memberof" in [name.lower() for name in attributes]:
                row["attributes"]["memberOf"] = [
                    dn.encode()
                    for dn, values in self.objects.items()
                    if row["dn"].encode() in values.get("member", [])
                ]
            wanted_names = {name.lower() for name in attributes}
            row["attributes"] = {
                key: value
                for key, value in row["attributes"].items()
                if key.lower() in wanted_names
            }
        return rows

    def add(self, dn: str, values: dict[str, list[bytes]]) -> None:
        """Create an account with server-owned immutable identity attributes.

        :param dn: Distinguished name.
        :param values: Initial attributes.
        """
        super().add(dn, values)
        self.objects[dn]["objectSid"] = [
            sid_bytes("S-1-5-21-1-2-3-" + str(1000 + self.sequence))
        ]
        kind = values["objectClass"][-1]
        if kind in (b"user", b"computer"):
            self.objects[dn]["pwdLastSet"] = [b"0"]
            self.objects[dn]["primaryGroupID"] = [b"513" if kind == b"user" else b"515"]

    def modify(self, dn: str, changes: list[tuple[int, str, list[bytes]]]) -> None:
        """Apply add/delete/replace, password reset, or an injected native failure.

        :param dn: Distinguished name.
        :param changes: Native LDAP modification list.
        :raises OSError: If the requested failure or security rule applies.
        """
        self._failure("modify")
        for _operation, name, _values in changes:
            if name.lower() == self.fail_attribute:
                raise OSError(50, "Insufficient access rights")
        self.writes.append(("modify", dn, copy.deepcopy(changes)))
        for operation, name, values in changes:
            if name.lower() == "unicodepwd":
                self.passwords[dn] = values[0].decode("utf-16-le")[1:-1]
                self.objects[dn]["pwdLastSet"] = [b"12345"]
                computed = int(
                    self.objects[dn].get("msDS-User-Account-Control-Computed", [b"0"])[
                        0
                    ]
                )
                self.objects[dn]["msDS-User-Account-Control-Computed"] = [
                    str(computed & ~0x800000).encode()
                ]
                continue
            if name.lower() in ("pwdlastset", "lockouttime"):
                computed = int(
                    self.objects[dn].get("msDS-User-Account-Control-Computed", [b"0"])[
                        0
                    ]
                )
                if name.lower() == "lockouttime" and values == [b"0"]:
                    computed &= ~16
                elif name.lower() == "pwdlastset":
                    computed = (
                        computed | 0x800000
                        if values == [b"0"]
                        else computed & ~0x800000
                    )
                self.objects[dn]["msDS-User-Account-Control-Computed"] = [
                    str(computed).encode()
                ]
            previous = next(
                (key for key in self.objects[dn] if key.lower() == name.lower()), name
            )
            old = self.objects[dn].get(previous, [])
            if operation == 0:
                self.objects[dn][previous] = old + [
                    value for value in values if value not in old
                ]
            elif operation == 1:
                updated = (
                    [value for value in old if value not in values] if values else []
                )
                if updated:
                    self.objects[dn][previous] = updated
                else:
                    self.objects[dn].pop(previous, None)
            else:
                self.objects[dn][previous] = list(values)

    def rename(self, dn: str, rdn: str, parent: str) -> None:
        """Follow an account rename in its secret and linked membership state.

        :param dn: Existing DN.
        :param rdn: Desired RDN.
        :param parent: Desired parent.
        """
        super().rename(dn, rdn, parent)
        destination = rdn + "," + parent
        if dn in self.passwords:
            self.passwords[destination] = self.passwords.pop(dn)
        for values in self.objects.values():
            if "member" in values:
                values["member"] = [
                    destination.encode() if value == dn.encode() else value
                    for value in values["member"]
                ]


def load_account_payload(
    name: str, monkeypatch: pytest.MonkeyPatch, directory: Directory
) -> ModuleType:
    """Load a real account payload while replacing only Windows API boundaries.

    :param name: user, group or computer payload basename.
    :param monkeypatch: Scoped native-boundary and import-path substitutions.
    :param directory: Independent LDAP state.
    :returns: Loaded account JSON payload.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    monkeypatch.syspath_prepend(str(HELPER.parent))
    # Policy and account fixtures replace the same native boundaries. Keeping
    # this setup explicit makes each fixture's dependency closure visible.
    # pylint: disable=duplicate-code
    helper = importlib.import_module("legacy_ad_object")
    monkeypatch.setattr(helper, "LDAPConnection", Mock(return_value=directory))
    monkeypatch.setattr(helper.accounts, "sid_bytes", sid_bytes)
    for module_name in (
        "legacy_ad_object",
        "legacy_ad_schema",
        "legacy_ad_account",
        "legacy_ad_" + name,
    ):
        module = importlib.import_module(module_name)
        if hasattr(module, "security_descriptor_text"):
            monkeypatch.setattr(
                module, "security_descriptor_text", lambda value: value.decode()
            )
            monkeypatch.setattr(
                module, "security_descriptor_bytes", lambda value: value.encode()
            )
    # pylint: enable=duplicate-code
    return load_module(
        ROOT / "legacy_ad/plugins/modules" / (name + ".py"), "tested_ad_" + name
    )


def invoke_account(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    values: dict[str, Any],
) -> tuple[int, dict[str, Any]]:
    """Exercise a real account module's argument-file and JSON process contract.

    :param payload: Loaded account module.
    :param monkeypatch: Scoped argv substitution.
    :param tmp_path: Owned pytest argument directory.
    :param capsys: JSON output capture.
    :param values: Requested public module arguments.
    :returns: Process status and decoded module result.
    """
    arguments = tmp_path / "arguments.json"
    arguments.write_text(json.dumps(values), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [payload.__name__, str(arguments)])
    return invoke_payload(payload, capsys)
