"""Independent directory state for native policy payload behavior tests."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import importlib
import re
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.ad_account_support import BASE
from tests.unit.ad_account_support import Directory as AccountDirectory
from tests.unit.ad_account_support import sid_bytes
from tests.unit.payload_support import HELPER, ROOT, load_module

PSO_PATH = "CN=Password Settings Container,CN=System," + BASE
PSO_DN = "CN=Policy," + PSO_PATH
GPO_PATH = "CN=Policies,CN=System," + BASE
TARGET = "OU=Applications," + BASE
GUIDS = (
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
    "33333333-3333-4333-8333-333333333333",
)


class Directory(AccountDirectory):
    """Model policy attributes, ordered links and individual LDAP operations."""

    def __init__(self) -> None:
        super().__init__()
        self.functional_level = 4
        self.fail_subject_operation: int | None = None
        self.seed(
            TARGET, "organizationalUnit", "applications", extra={"gPOptions": [b"1"]}
        )
        for number, guid in enumerate(GUIDS):
            self.seed(
                "CN={" + guid + "}," + GPO_PATH,
                "groupPolicyContainer",
                "unused",
                extra={
                    "cn": [("{" + guid + "}").encode()],
                    "displayName": [("Policy " + str(number + 1)).encode()],
                },
            )

    def __enter__(self) -> "Directory":
        return self

    def __exit__(self, _kind: Any, _value: Any, _traceback: Any) -> None:
        self.close()

    def search(
        self,
        base: str,
        scope: int,
        ldap_filter: str,
        attributes: list[str],
        **flags: Any,
    ) -> list[dict[str, Any]]:
        """Return independent policy schema, rootDSE and directory observations.

        :param base: Search base DN.
        :param scope: LDAP search scope.
        :param ldap_filter: Requested filter.
        :param attributes: Requested protocol names.
        :param flags: Optional server-control flags.
        :returns: Copied matching protocol entries.
        """
        if base == "" and attributes == ["domainFunctionality"]:
            return [
                {
                    "dn": "",
                    "attributes": {
                        "domainFunctionality": [str(self.functional_level).encode()]
                    },
                }
            ]
        rows = super().search(base, scope, ldap_filter, attributes, **flags)
        if ldap_filter == "(objectClass=attributeSchema)":
            properties = {
                "msDS-PasswordSettingsPrecedence": "2.5.5.9",
                "msDS-MinimumPasswordLength": "2.5.5.9",
                "msDS-PasswordComplexityEnabled": "2.5.5.8",
                "msDS-LockoutThreshold": "2.5.5.9",
                "msDS-PasswordReversibleEncryptionEnabled": "2.5.5.8",
                "msDS-PasswordHistoryLength": "2.5.5.9",
                "msDS-MinimumPasswordAge": "2.5.5.16",
                "msDS-MaximumPasswordAge": "2.5.5.16",
                "msDS-LockoutObservationWindow": "2.5.5.16",
                "msDS-LockoutDuration": "2.5.5.16",
                "msDS-PSOAppliesTo": "2.5.5.1",
            }
            for name, syntax in properties.items():
                if name.lower() not in self.missing_schema:
                    rows.append(
                        {
                            "dn": "CN=" + name,
                            "attributes": {
                                "lDAPDisplayName": [name.encode()],
                                "attributeSyntax": [syntax.encode()],
                                "isSingleValued": [
                                    b"FALSE" if name == "msDS-PSOAppliesTo" else b"TRUE"
                                ],
                            },
                        }
                    )
        if "(objectClass=groupPolicyContainer)" in ldap_filter:
            rows = [
                row
                for row in rows
                if self.objects[row["dn"]]["objectClass"][-1] == b"groupPolicyContainer"
            ]
            if "(displayName=" in ldap_filter:
                encoded = ldap_filter.split("(displayName=", 1)[1][:-2]
                wanted = (
                    re.sub(
                        r"\\([0-9a-fA-F]{2})",
                        lambda match: chr(int(match.group(1), 16)),
                        encoded,
                    )
                    .lower()
                    .encode()
                )
                rows = [
                    row
                    for row in rows
                    if any(
                        value.lower() == wanted
                        for value in self.objects[row["dn"]].get("displayName", [])
                    )
                ]
        return rows

    def modify(self, dn: str, changes: list[tuple[int, str, list[bytes]]]) -> None:
        """Apply one native modification or an isolated subject-operation failure.

        :param dn: Distinguished name.
        :param changes: Ordered add/delete/replace operations.
        :raises OSError: The armed subject operation is rejected.
        """
        if any(
            operation == self.fail_subject_operation
            and name.lower() == "msds-psoappliesto"
            for operation, name, _values in changes
        ):
            raise OSError(50, "Subject operation denied")
        super().modify(dn, changes)


def payload(
    name: str, monkeypatch: pytest.MonkeyPatch, directory: Directory
) -> ModuleType:
    """Load a real PSO/GPO payload, substituting only the native connection.

    :param name: Policy payload basename.
    :param monkeypatch: Scoped native-boundary substitutions.
    :param directory: Independent directory state.
    :returns: Loaded JSON payload.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    monkeypatch.syspath_prepend(str(HELPER.parent))
    if name == "pso":
        helper = importlib.import_module("legacy_ad_object")
        monkeypatch.setattr(helper, "LDAPConnection", Mock(return_value=directory))
        monkeypatch.setattr(helper.accounts, "sid_bytes", sid_bytes)
        for module_name in (
            "legacy_ad_object",
            "legacy_ad_schema",
            "legacy_ad_account",
        ):
            module = importlib.import_module(module_name)
            monkeypatch.setattr(
                module, "security_descriptor_text", lambda value: value.decode()
            )
            monkeypatch.setattr(
                module, "security_descriptor_bytes", lambda value: value.encode()
            )
        return load_module(ROOT / "legacy_ad/plugins/modules/pso.py", "tested_ad_pso")
    helper = importlib.import_module("legacy_ad_policy_gpo")
    monkeypatch.setattr(helper, "LDAPConnection", Mock(return_value=directory))
    monkeypatch.setattr(helper, "_pdc", Mock(return_value="dc.example.test"))
    return load_module(ROOT / "legacy_ad/plugins/modules/gpo.py", "tested_ad_gpo")


def state(directory: Directory) -> dict[str, dict[str, list[bytes]]]:
    """Copy observable directory state before a check-mode request.

    :param directory: Fixture directory.
    :returns: Independent copied state.
    """
    return copy.deepcopy(directory.objects)
