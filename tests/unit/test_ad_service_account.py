"""Exercise the public gMSA payload against independent native LDAP state."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import copy
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from tests.unit.ad_account_support import (
    BASE,
    USERS,
)
from tests.unit.ad_account_support import Directory as AccountDirectory
from tests.unit.ad_account_support import (
    invoke_account,
    load_account_payload,
)

CONTAINER = "CN=Managed Service Accounts," + BASE
ACCOUNT = "CN=Service," + CONTAINER
ALLOWED = "CN=Allowed," + USERS
DENIED = "CN=Other," + USERS
ALLOWED_SID = "S-1-5-21-1-2-3-1101"
OTHER_SID = "S-1-5-21-1-2-3-1102"


class Directory(AccountDirectory):
    """Expose gMSA schema and a separately advertised default container."""

    def __init__(self) -> None:
        super().__init__()
        self.objects[BASE]["otherWellKnownObjects"] = [
            ("B:32:1EB93889E40C45DF9F0C64D23BBB6237:" + CONTAINER).encode()
        ]
        self.seed(CONTAINER, "container", "Managed Service Accounts")
        self.seed(ALLOWED, "user", "Allowed", 1101)
        self.seed(DENIED, "user", "Other", 1102)
        self.read_attributes: list[list[str]] = []

    def search(
        self,
        base: str,
        scope: int,
        ldap_filter: str,
        attributes: list[str],
        **flags: Any
    ) -> list[dict[str, Any]]:
        """Provide copied native schema values independent of payload defaults.

        :param base: Native search base.
        :param scope: Native search scope.
        :param ldap_filter: Requested LDAP filter.
        :param attributes: Requested attributes.
        :param flags: Native LDAP controls.
        :returns: Copied native directory rows.
        """
        self.read_attributes.append(list(attributes))
        rows = super().search(base, scope, ldap_filter, attributes, **flags)
        if ldap_filter == "(objectClass=attributeSchema)":
            for name, syntax in (
                ("msDS-ManagedPasswordInterval", "2.5.5.9"),
                ("msDS-GroupMSAMembership", "2.5.5.15"),
            ):
                if name.lower() not in self.missing_schema:
                    # Independent LDAP wire rows must not reuse payload metadata.
                    # pylint: disable=duplicate-code
                    rows.append(
                        {
                            "dn": "CN=" + name,
                            "attributes": {
                                "lDAPDisplayName": [name.encode()],
                                "attributeSyntax": [syntax.encode()],
                                "isSingleValued": [b"TRUE"],
                            },
                        }
                    )
                    # pylint: enable=duplicate-code
        return rows

    def modify(self, dn: str, changes: list[tuple[int, str, list[bytes]]]) -> None:
        """Apply native writes with the observed WinLDAP empty-replace boundary.

        :param dn: Target distinguished name.
        :param changes: Requested native LDAP modifications.
        :raises OSError: If WinLDAP would reject an empty replacement.
        """
        if any(operation == 2 and not values for operation, _name, values in changes):
            raise OSError(89, "WinLDAP rejects an empty replacement.")
        super().modify(dn, changes)


@pytest.fixture(name="directory")
def directory_fixture() -> Directory:
    """Provide an independently modeled gMSA directory.

    :returns: Independent LDAP fixture.
    """
    return Directory()


@pytest.fixture(name="payload")
def payload_fixture(
    monkeypatch: pytest.MonkeyPatch, directory: Directory
) -> ModuleType:
    """Replace only native boundaries of the real public payload.

    :param monkeypatch: Scoped native substitutions.
    :param directory: Independent LDAP fixture.
    :returns: Actual JSON payload module.
    """
    return load_account_payload("service_account", monkeypatch, directory)


def execute(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """Exercise the public JSON argument/result boundary.

    :param payload: Actual service-account payload.
    :param monkeypatch: Scoped argv substitution.
    :param tmp_path: Owned argument directory.
    :param capsys: JSON process-output capture.
    :param arguments: Public module arguments.
    :returns: Decoded observable result.
    """
    code, result = invoke_account(payload, monkeypatch, tmp_path, capsys, arguments)
    assert code == (1 if result.get("failed") else 0)
    return result


def test_creation_uses_other_well_known_container_and_directory_owned_password(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    options = {
        "name": "Service",
        "dns_hostname": "service.example.test",
        "_ansible_diff": True,
    }
    result = execute(payload, monkeypatch, tmp_path, capsys, options)
    assert result["changed"] and not result.get("failed"), result
    assert result["distinguished_name"] == ACCOUNT
    assert result["sid"].startswith("S-1-5-21-")
    assert result["object_guid"] != "00000000-0000-0000-0000-000000000000"
    assert (
        directory.objects[ACCOUNT]["objectClass"][-1]
        == b"msDS-GroupManagedServiceAccount"
    )
    assert directory.objects[ACCOUNT]["sAMAccountName"] == [b"Service$"]
    assert directory.objects[ACCOUNT]["userAccountControl"] == [b"4096"]
    assert directory.objects[ACCOUNT]["msDS-ManagedPasswordInterval"] == [b"30"]
    assert ACCOUNT not in directory.passwords
    assert all(
        "msds-managedpassword" not in map(str.lower, names)
        for names in directory.read_attributes
    )
    assert result["diff"]["before"] is None
    assert result["diff"]["after"]["enabled"] is True
    assert result["diff"]["after"]["attributes"] == {}
    directory.writes.clear()
    repeated = execute(payload, monkeypatch, tmp_path, capsys, options)
    assert not repeated["changed"] and not repeated.get("failed"), repeated
    assert directory.writes == []


# Keep the independently executed account JSON/check-mode contract explicit.
# pylint: disable=duplicate-code
def test_creation_prediction_has_upstream_identifiers_and_no_native_writes(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = execute(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {
            "name": "Service",
            "dns_hostname": "service.example.test",
            "allowed_to_retrieve_password": {"set": ["Allowed"]},
            "_ansible_check_mode": True,
            "_ansible_diff": True,
        },
    )
    # pylint: enable=duplicate-code
    assert result["changed"] and not result.get("failed"), result
    assert result["distinguished_name"] == ACCOUNT
    assert result["object_guid"] == "00000000-0000-0000-0000-000000000000"
    assert result["sid"] == "S-1-5-0000"
    assert ACCOUNT not in directory.objects and directory.writes == []
    assert result["diff"]["after"]["allowed_to_retrieve_password"] == [ALLOWED]


@pytest.mark.parametrize(
    "options,message",
    [
        (
            {"name": "Service"},
            "dns_hostname is required when creating a new service account.",
        ),
        (
            {
                "name": "Service",
                "dns_hostname": "service.example.test",
                "outbound_auth_only": True,
            },
            "dns_hostname can not be set when outbound_auth_only=true.",
        ),
        (
            {
                "name": "Service",
                "dns_hostname": "service.example.test",
                "kerberos_encryption_types": {"set": ["unknown"]},
            },
            "must contain aes128, aes256, des or rc4",
        ),
        (
            {
                "name": "Service",
                "dns_hostname": "service.example.test",
                "outbound_auth_only": [],
            },
            "Expected a boolean for outbound_auth_only.",
        ),
        (
            {
                "name": "Service",
                "dns_hostname": "service.example.test",
                "do_not_append_dollar_to_sam": "",
            },
            "Expected a boolean for do_not_append_dollar_to_sam.",
        ),
    ],
)
# Pytest injects native state, the JSON process boundary and each case separately.
def test_invalid_inputs_fail_without_mutation(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    options: dict[str, Any],
    message: str,
) -> None:
    result = execute(payload, monkeypatch, tmp_path, capsys, options)
    assert result["failed"] and not result["changed"]
    assert message in result["msg"] and directory.writes == []


@pytest.mark.parametrize(
    "attribute", ["msds-managedpasswordinterval", "msds-groupmsamembership"]
)
# The schema capability case is separate from the native and process fixtures.
def test_missing_directory_capability_fails_before_creation(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    attribute: str,
) -> None:
    directory.missing_schema.add(attribute)
    result = execute(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"name": "Service", "dns_hostname": "service.example.test"},
    )
    assert result["failed"] and not result["changed"]
    assert attribute in result["msg"].lower() and directory.writes == []


def test_outbound_creation_and_repetition_do_not_write_temporary_dns_or_password(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    options = {"name": "Service", "outbound_auth_only": True, "_ansible_diff": True}
    result = execute(payload, monkeypatch, tmp_path, capsys, options)
    assert result["changed"] and not result.get("failed"), result
    assert not directory.objects[ACCOUNT].get("dNSHostName")
    assert "dns_hostname" not in result["diff"]["after"]
    directory.writes.clear()
    repeated = execute(payload, monkeypatch, tmp_path, capsys, options)
    assert not repeated["changed"] and directory.writes == []


def test_changed_retrieval_list_replaces_custom_descriptor_and_empty_list_clears(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory.seed(
        ACCOUNT,
        "msDS-GroupManagedServiceAccount",
        "Service$",
        extra={
            "userAccountControl": [b"4096"],
            "msDS-ManagedPasswordInterval": [b"30"],
            "msDS-GroupMSAMembership": [
                ("O:BAG:BAD:(D;;RP;;;WD)(A;;RP;;;" + ALLOWED_SID + ")").encode()
            ],
        },
    )
    options = {
        "identity": "Service",
        "allowed_to_retrieve_password": {"remove": ["Allowed"], "add": ["Other"]},
        "_ansible_diff": True,
    }
    original = copy.deepcopy(directory.objects[ACCOUNT])
    predicted = execute(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        dict(options, _ansible_check_mode=True),
    )
    assert predicted["changed"] and not predicted.get("failed"), predicted
    assert directory.objects[ACCOUNT] == original and directory.writes == []
    assert predicted["diff"]["before"]["allowed_to_retrieve_password"] == [ALLOWED]
    assert predicted["diff"]["after"]["allowed_to_retrieve_password"] == [DENIED]
    result = execute(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        options,
    )
    assert result["changed"] and not result.get("failed"), result
    descriptor = directory.objects[ACCOUNT]["msDS-GroupMSAMembership"][0].decode()
    assert descriptor == "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + OTHER_SID + ")"
    cleared = execute(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {
            "identity": result["object_guid"],
            "allowed_to_retrieve_password": {"set": []},
        },
    )
    assert cleared["changed"] and not cleared.get("failed"), cleared
    assert not directory.objects[ACCOUNT].get("msDS-GroupMSAMembership")
    directory.writes.clear()
    repeated = execute(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {
            "identity": result["object_guid"],
            "allowed_to_retrieve_password": {"set": []},
        },
    )
    assert not repeated["changed"] and directory.writes == []


def test_disabled_flags_spn_encryption_and_delegation_are_idempotent(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    options = {
        "name": "Service",
        "dns_hostname": "service.example.test",
        "enabled": False,
        "trusted_for_delegation": True,
        "sam_account_name": "Plain",
        "do_not_append_dollar_to_sam": True,
        "upn": "plain@example.test",
        "spns": {"set": ["HOST/service.example.test"]},
        "kerberos_encryption_types": {"set": ["aes128", "aes256"]},
        "principals_allowed_to_delegate": {"set": ["Allowed"]},
        "allowed_to_retrieve_password": {"set": ["Other"]},
    }
    result = execute(payload, monkeypatch, tmp_path, capsys, options)
    assert result["changed"] and not result.get("failed"), result
    values = directory.objects[ACCOUNT]
    assert values["userAccountControl"] == [b"528386"]
    assert values["sAMAccountName"] == [b"Plain"]
    assert values["msDS-SupportedEncryptionTypes"] == [b"24"]
    assert values["servicePrincipalName"] == [b"HOST/service.example.test"]
    assert ALLOWED_SID.encode() in values["msDS-AllowedToActOnBehalfOfOtherIdentity"][0]
    assert OTHER_SID.encode() in values["msDS-GroupMSAMembership"][0]
    assert values["msDS-GroupMSAMembership"] == [
        ("O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + OTHER_SID + ")").encode()
    ]
    directory.writes.clear()
    repeated = execute(payload, monkeypatch, tmp_path, capsys, options)
    assert not repeated["changed"] and not repeated.get("failed"), repeated
    assert directory.writes == []


def test_deletion_preview_real_removal_and_repeated_absence_retain_identifiers(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory.seed(
        ACCOUNT,
        "msDS-GroupManagedServiceAccount",
        "Service$",
        extra={"userAccountControl": [b"4096"]},
    )
    original = copy.deepcopy(directory.objects[ACCOUNT])
    prediction = execute(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"identity": "Service", "state": "absent", "_ansible_check_mode": True},
    )
    assert prediction["changed"] and not prediction.get("failed"), prediction
    assert directory.objects[ACCOUNT] == original and directory.writes == []
    removed = execute(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"identity": "Service$", "state": "absent"},
    )
    assert removed["changed"] and not removed.get("failed"), removed
    assert (
        removed["object_guid"] == prediction["object_guid"]
        and removed["sid"] == prediction["sid"]
    )
    assert ACCOUNT not in directory.objects
    repeated = execute(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"identity": "Service", "state": "absent"},
    )
    assert not repeated["changed"] and not repeated.get("failed"), repeated


def test_native_failure_keeps_created_identity_and_partial_change(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory.fail_attribute = "msds-groupmsamembership"
    result = execute(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {
            "name": "Service",
            "dns_hostname": "service.example.test",
            "allowed_to_retrieve_password": {"set": ["Allowed"]},
        },
    )
    assert result["failed"] and result["changed"]
    assert result["distinguished_name"] == ACCOUNT
    assert result["sid"].startswith("S-1-5-21-") and ACCOUNT in directory.objects


@pytest.mark.parametrize("deny_ace", ["", "(D;;RP;;;" + ALLOWED_SID + ")"])
# The custom ACL case is separate from the native and JSON boundary fixtures.
def test_same_principal_write_only_ace_is_projected_and_retained_unchanged(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    deny_ace: str,
) -> None:
    original = "O:BAG:BAD:" + deny_ace + "(A;;WP;;;" + ALLOWED_SID + ")"
    directory.seed(
        ACCOUNT,
        "msDS-GroupManagedServiceAccount",
        "Service$",
        extra={
            "userAccountControl": [b"4096"],
            "msDS-GroupMSAMembership": [original.encode()],
        },
    )
    options = {
        "identity": "Service",
        "allowed_to_retrieve_password": {"set": ["Allowed"]},
        "_ansible_diff": True,
    }
    predicted = execute(
        payload, monkeypatch, tmp_path, capsys, dict(options, _ansible_check_mode=True)
    )
    assert not predicted["changed"] and not predicted.get("failed"), predicted
    assert directory.objects[ACCOUNT]["msDS-GroupMSAMembership"] == [original.encode()]
    assert predicted["diff"]["before"]["allowed_to_retrieve_password"] == [ALLOWED]
    assert predicted["diff"]["after"]["allowed_to_retrieve_password"] == [ALLOWED]
    repeated = execute(payload, monkeypatch, tmp_path, capsys, options)
    assert not repeated["changed"] and directory.writes == []
    assert directory.objects[ACCOUNT]["msDS-GroupMSAMembership"] == [original.encode()]


@pytest.mark.parametrize("rights", ["GR", "GA", "0x10", "RPWP"])
# Each rights case is independent of the native directory and JSON fixtures.
def test_existing_allow_principal_projection_is_idempotent(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    rights: str,
) -> None:
    directory.seed(
        ACCOUNT,
        "msDS-GroupManagedServiceAccount",
        "Service$",
        extra={
            "userAccountControl": [b"4096"],
            "msDS-GroupMSAMembership": [
                ("O:BAG:BAD:(A;;" + rights + ";;;" + ALLOWED_SID + ")").encode()
            ],
        },
    )
    result = execute(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {
            "identity": "Service",
            "allowed_to_retrieve_password": {"set": ["Allowed"]},
            "_ansible_diff": True,
        },
    )
    assert not result["changed"] and not result.get("failed"), result
    assert directory.writes == []
    assert result["diff"]["after"]["allowed_to_retrieve_password"] == [ALLOWED]
