"""Exercise computer module behavior against independently modeled AD state."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import importlib
import json
import string
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest
from ansible_collections.sustainablelobster.legacy_ad.plugins.action.computer import (
    ActionModule,
)

from tests.unit.ad_account_support import (
    COMPUTERS,
    Directory,
    load_account_payload,
)
from tests.unit.test_ad_ou import BASE
from tests.unit.test_python_action import _action


@pytest.fixture(name="directory")
def directory_fixture() -> Directory:
    """Provide directory state independently of the account implementation.

    :returns: The native LDAP account-state fixture.
    """
    return Directory()


@pytest.fixture(name="payload")
def payload_fixture(
    monkeypatch: pytest.MonkeyPatch, directory: Directory
) -> ModuleType:
    """Load the real computer payload with only native boundaries replaced.

    :param monkeypatch: Scoped import-path and native-boundary replacements.
    :param directory: Independent LDAP state.
    :returns: The computer module JSON payload.
    """
    return load_account_payload("computer", monkeypatch, directory)


def execute(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """Call the public JSON payload with a real serialized argument file.

    :param payload: Loaded computer payload.
    :param monkeypatch: Scoped command-line replacement.
    :param tmp_path: Owned argument-file directory.
    :param arguments: Module arguments including standard Ansible flags.
    :returns: The payload's observable Ansible result.
    """
    argument_file = tmp_path / "computer-arguments.json"
    argument_file.write_text(json.dumps(arguments), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["computer.py", str(argument_file)])
    result: dict[str, Any] = payload.execute()
    return result


def test_computer_action_stages_the_complete_owned_helper_closure_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, shell, events = _action(ActionModule, monkeypatch)
    action.run()
    transferred = [Path(str(event[1])) for event in events if event[0] == "transfer"]
    assert all(source.is_file() for source in transferred)
    assert [source.name for source in transferred] == [
        "legacy_windows_module.py",
        "legacy_windows_account.py",
        "legacy_ad_ldap.py",
        "legacy_ad_filter.py",
        "legacy_ad_schema.py",
        "legacy_ad_object.py",
        "legacy_ad_account.py",
        "legacy_ad_result.py",
        "legacy_ad_computer.py",
    ]
    assert shell.tmpdir is None
    assert len([event for event in events if event[0] == "cleanup"]) == 1


def test_create_sets_a_secret_before_enabling_and_is_idempotent(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    result = execute(
        payload, monkeypatch, tmp_path, {"name": "Machine", "_ansible_diff": True}
    )
    dn = "CN=Machine," + COMPUTERS
    assert result["changed"] and not result.get("failed")
    assert result["distinguished_name"] == dn
    assert result["sid"].startswith("S-1-5-21-")
    assert result["object_guid"] != "00000000-0000-0000-0000-000000000000"
    assert directory.objects[dn]["sAMAccountName"] == [b"Machine$"]
    assert directory.objects[dn]["userAccountControl"] == [b"4096"]
    creation = next(write for write in directory.writes if write[0] == "add")
    assert creation[2]["userAccountControl"] == [b"4098"]
    modifications = [
        write[2][0][1] for write in directory.writes if write[0] == "modify"
    ]
    assert modifications == ["unicodePwd", "userAccountControl"]
    password = directory.passwords[dn]
    assert len(password) == 240
    assert all(
        any(character in group for character in password)
        for group in (
            string.ascii_lowercase,
            string.ascii_uppercase,
            string.digits,
            string.punctuation,
        )
    )
    assert password not in json.dumps(result)
    assert result["diff"]["before"] is None
    assert result["diff"]["after"]["enabled"] is True
    assert "userAccountControl" not in result["diff"]["after"]["attributes"]
    directory.writes.clear()
    repeated = execute(payload, monkeypatch, tmp_path, {"name": "Machine"})
    assert repeated["changed"] is False
    assert directory.passwords[dn] == password
    assert directory.writes == []


def test_new_disabled_computer_still_gets_a_password(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    result = execute(
        payload, monkeypatch, tmp_path, {"name": "Machine", "enabled": False}
    )
    dn = result["distinguished_name"]
    assert result["changed"] and not result.get("failed")
    assert len(directory.passwords[dn]) == 240
    assert directory.objects[dn]["userAccountControl"] == [b"4098"]


def test_check_mode_creation_predicts_without_generating_a_secret(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    native = importlib.import_module("legacy_ad_computer")
    secret = Mock(side_effect=AssertionError("check mode must not allocate a secret"))
    monkeypatch.setattr(native, "random_computer_password", secret)
    result = execute(
        payload,
        monkeypatch,
        tmp_path,
        {"name": "Machine", "_ansible_check_mode": True, "_ansible_diff": True},
    )
    assert result["changed"] and not result.get("failed")
    assert result["object_guid"] == "00000000-0000-0000-0000-000000000000"
    assert result["sid"] == "S-1-5-0000"
    assert result["distinguished_name"] == "CN=Machine," + COMPUTERS
    assert directory.writes == []
    assert "CN=Machine," + COMPUTERS not in directory.objects
    secret.assert_not_called()


def test_password_failure_leaves_disabled_account_and_actual_identifiers(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory.fail_attribute = "unicodepwd"
    result = execute(payload, monkeypatch, tmp_path, {"name": "Machine"})
    assert result["failed"] and result["changed"]
    assert result["sid"].startswith("S-1-5-21-")
    assert directory.objects[result["distinguished_name"]]["userAccountControl"] == [
        b"4098"
    ]
    assert result["distinguished_name"] not in directory.passwords
    assert "Insufficient access" in result["msg"]


@pytest.mark.parametrize(
    "sam,do_not_append,expected",
    [
        ("Alias", False, b"Alias$"),
        ("Alias$", False, b"Alias$"),
        ("Alias", True, b"Alias"),
        (None, True, b"Machine$"),
        ("", False, b"Machine$"),
        ("", True, b"Machine$"),
    ],
)
# The three parameterized SAM inputs and four fixture inputs remain explicit.
def test_sam_suffix_rules(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    sam: str | None,
    do_not_append: bool,
    expected: bytes,
) -> None:
    result = execute(
        payload,
        monkeypatch,
        tmp_path,
        {
            "name": "Machine",
            "sam_account_name": sam,
            "do_not_append_dollar_to_sam": do_not_append,
        },
    )
    assert not result.get("failed")
    assert directory.objects[result["distinguished_name"]]["sAMAccountName"] == [
        expected
    ]


def test_bare_sam_prefers_exact_identity_before_dollar_fallback(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    exact = "CN=Exact," + COMPUTERS
    suffix = "CN=Suffix," + COMPUTERS
    directory.seed(exact, "computer", "Machine")
    directory.seed(suffix, "computer", "Machine$")
    result = execute(
        payload,
        monkeypatch,
        tmp_path,
        {"identity": "Machine", "display_name": "Updated"},
    )
    assert result["distinguished_name"] == exact
    assert directory.objects[exact]["displayName"] == [b"Updated"]
    assert "displayName" not in directory.objects[suffix]


def test_bare_sam_uses_dollar_fallback_only_after_exact_miss(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    dn = "CN=Machine," + COMPUTERS
    directory.seed(dn, "computer", "Machine$")
    result = execute(
        payload,
        monkeypatch,
        tmp_path,
        {"identity": "Machine", "display_name": "Updated"},
    )
    assert result["distinguished_name"] == dn
    assert directory.objects[dn]["displayName"] == [b"Updated"]


@pytest.mark.parametrize(
    "identity",
    [
        "00000000-0000-0000-0000-000000000001",
        "CN=Missing," + COMPUTERS,
        "S-1-5-21-1-2-3-9999",
    ],
)
def test_typed_missing_identities_do_not_use_sam_fallback(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    identity: str,
) -> None:
    account = importlib.import_module("legacy_ad_account")
    lookup = Mock(wraps=account.find_object)
    monkeypatch.setattr(account, "find_object", lookup)
    result = execute(
        payload, monkeypatch, tmp_path, {"identity": identity, "state": "absent"}
    )
    assert not result.get("failed") and result["changed"] is False
    assert lookup.call_count == 1
    assert directory.writes == []


def test_flags_preserve_unrelated_bits_and_do_not_reset_existing_password(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    dn = "CN=Machine," + COMPUTERS
    values = directory.seed(
        dn,
        "computer",
        "Machine$",
        extra={"userAccountControl": [str(4098 | 65536 | 524288).encode()]},
    )
    result = execute(
        payload,
        monkeypatch,
        tmp_path,
        {
            "identity": "Machine$",
            "enabled": True,
            "trusted_for_delegation": False,
            "_ansible_diff": True,
        },
    )
    assert result["changed"] and not result.get("failed")
    assert values["userAccountControl"] == [str(4096 | 65536).encode()]
    assert directory.passwords[dn] == "ExistingPassword1!"
    assert result["diff"]["before"]["enabled"] is False
    assert result["diff"]["after"]["enabled"] is True
    assert result["diff"]["before"]["trusted_for_delegation"] is True
    assert result["diff"]["after"]["trusted_for_delegation"] is False


@pytest.mark.parametrize("value", [69632, [69632], {"type": "int", "value": 69632}])
def test_creation_preserves_requested_raw_flags_until_secure_enable(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    value: Any,
) -> None:
    result = execute(
        payload,
        monkeypatch,
        tmp_path,
        {
            "name": "Machine",
            "attributes": {"set": {"useraccountcontrol": value}},
            "_ansible_diff": True,
        },
    )
    assert not result.get("failed")
    creation = next(write for write in directory.writes if write[0] == "add")
    assert creation[2]["useraccountcontrol"] == [b"69634"]
    assert directory.objects[result["distinguished_name"]]["useraccountcontrol"] == [
        b"69632"
    ]
    assert result["diff"]["after"]["attributes"]["useraccountcontrol"] == 69632


def test_named_disable_overrides_a_raw_update_without_losing_other_bits(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    dn = "CN=Machine," + COMPUTERS
    values = directory.seed(
        dn, "computer", "Machine$", extra={"userAccountControl": [b"69634"]}
    )
    result = execute(
        payload,
        monkeypatch,
        tmp_path,
        {
            "identity": "Machine$",
            "enabled": False,
            "attributes": {"set": {"userAccountControl": 69632}},
        },
    )
    assert result["changed"] and not result.get("failed")
    assert values["userAccountControl"] == [b"69634"]


def test_default_computers_path_respects_directory_redirection(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    redirected = "OU=Managed Computers," + BASE
    directory.objects[BASE]["wellKnownObjects"][1] = (
        "B:32:AA312825768811D1ADED00C04FD8D5CD:" + redirected
    ).encode()
    result = execute(payload, monkeypatch, tmp_path, {"name": "Machine"})
    assert not result.get("failed")
    assert result["distinguished_name"] == "CN=Machine," + redirected


def test_managed_by_and_case_sensitive_string_properties_repeat_and_clear(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    principal = "CN=Principal,CN=Users," + BASE
    directory.seed(principal, "user", "Principal")
    result = execute(
        payload,
        monkeypatch,
        tmp_path,
        {
            "name": "Machine",
            "managed_by": {"name": "Principal"},
            "dns_hostname": "Machine.example.test",
            "location": "Rack",
            "upn": "machine@example.test",
        },
    )
    assert not result.get("failed")
    dn = result["distinguished_name"]
    assert directory.objects[dn]["managedBy"] == [principal.encode()]
    repeated = execute(
        payload,
        monkeypatch,
        tmp_path,
        {"identity": "Machine$", "location": "rack", "upn": "MACHINE@EXAMPLE.TEST"},
    )
    assert repeated["changed"] is True
    assert directory.objects[dn]["location"] == [b"rack"]
    assert directory.objects[dn]["userPrincipalName"] == [b"MACHINE@EXAMPLE.TEST"]
    repeated = execute(
        payload,
        monkeypatch,
        tmp_path,
        {"identity": "Machine$", "location": "rack", "upn": "MACHINE@EXAMPLE.TEST"},
    )
    assert repeated["changed"] is False
    cleared = execute(
        payload,
        monkeypatch,
        tmp_path,
        {"identity": "Machine$", "managed_by": "", "location": "", "upn": ""},
    )
    assert cleared["changed"] and not cleared.get("failed")
    assert all(
        name not in directory.objects[dn]
        for name in ("managedBy", "location", "userPrincipalName")
    )


@pytest.mark.parametrize("state", ["present", "absent"])
def test_noncomputer_identity_never_mutates_the_resolved_account(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    state: str,
) -> None:
    dn = "CN=Principal,CN=Users," + BASE
    values = directory.seed(dn, "user", "Principal")
    result = execute(
        payload, monkeypatch, tmp_path, {"identity": "Principal", "state": state}
    )
    assert not result.get("failed") and dn in directory.objects
    assert values["sAMAccountName"] == [b"Principal"]
    assert all(write[1] != dn for write in directory.writes)
    assert result["changed"] == (state == "present")
    if state == "present":
        assert result["distinguished_name"] == "CN=Principal," + COMPUTERS
    else:
        assert directory.writes == [] and result["sid"] is None


def test_post_creation_attribute_failure_retains_completed_changes_and_identifiers(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory.fail_attribute = "serviceprincipalname"
    result = execute(
        payload,
        monkeypatch,
        tmp_path,
        {"name": "Machine", "spn": {"set": ["HOST/Machine"]}},
    )
    assert result["failed"] and result["changed"]
    assert result["sid"].startswith("S-1-5-21-")
    assert directory.objects[result["distinguished_name"]]["userAccountControl"] == [
        b"4096"
    ]
    assert len(directory.passwords[result["distinguished_name"]]) == 240


def test_spn_creation_union_and_existing_set_precedence(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    result = execute(
        payload,
        monkeypatch,
        tmp_path,
        {
            "name": "Machine",
            "spns": {
                "add": ["HOST/Machine"],
                "set": ["HTTP/Machine"],
                "remove": ["HOST/Machine"],
            },
        },
    )
    dn = result["distinguished_name"]
    assert set(directory.objects[dn]["servicePrincipalName"]) == {
        b"HOST/Machine",
        b"HTTP/Machine",
    }
    updated = execute(
        payload,
        monkeypatch,
        tmp_path,
        {
            "identity": "Machine$",
            "spn": {
                "add": ["HOST/Unused"],
                "set": ["HTTP/Machine"],
                "remove": ["HTTP/Machine"],
            },
        },
    )
    assert updated["changed"] and not updated.get("failed")
    assert directory.objects[dn]["servicePrincipalName"] == [b"HTTP/Machine"]
    repeated = execute(
        payload,
        monkeypatch,
        tmp_path,
        {"identity": "Machine$", "spn": {"set": ["http/machine"]}},
    )
    assert repeated["changed"] is False


@pytest.mark.parametrize("encryption_type", ["des", "DES"])
def test_des_creation_uses_the_vendor_enum_and_repeats_without_writes(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    encryption_type: str,
) -> None:
    arguments = {
        "name": "Machine",
        "kerberos_encryption_types": {"set": [encryption_type]},
        "_ansible_diff": True,
    }
    result = execute(payload, monkeypatch, tmp_path, arguments)
    dn = result["distinguished_name"]
    assert result["changed"] and not result.get("failed")
    assert directory.objects[dn]["msDS-SupportedEncryptionTypes"] == [b"3"]
    assert result["diff"]["after"]["kerberos_encryption_types"] == [encryption_type]
    password = directory.passwords[dn]
    directory.writes.clear()
    repeated = execute(payload, monkeypatch, tmp_path, arguments)
    assert repeated["changed"] is False
    assert repeated["diff"]["before"]["kerberos_encryption_types"] == ["DES"]
    assert directory.passwords[dn] == password
    assert directory.writes == []


@pytest.mark.parametrize("existing", [False, True])
def test_des_check_mode_predicts_without_creating_or_updating(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    existing: bool,
) -> None:
    dn = "CN=Machine," + COMPUTERS
    if existing:
        directory.seed(
            dn,
            "computer",
            "Machine$",
            extra={"msDS-SupportedEncryptionTypes": [b"4"]},
        )
    result = execute(
        payload,
        monkeypatch,
        tmp_path,
        {
            "name": "Machine",
            "kerberos_encryption_types": {"add": ["des"]},
            "_ansible_check_mode": True,
            "_ansible_diff": True,
        },
    )
    assert result["changed"] and not result.get("failed")
    assert result["diff"]["after"]["kerberos_encryption_types"] == (
        ["RC4", "des"] if existing else ["des"]
    )
    if existing:
        assert directory.objects[dn]["msDS-SupportedEncryptionTypes"] == [b"4"]
    else:
        assert dn not in directory.objects
    assert directory.writes == []


def test_des_add_remove_and_clear_preserve_other_encryption_types(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    dn = "CN=Machine," + COMPUTERS
    directory.seed(
        dn,
        "computer",
        "Machine$",
        extra={"msDS-SupportedEncryptionTypes": [b"20"]},
    )
    for request, expected in (
        ({"add": ["des"]}, b"23"),
        ({"remove": ["DES"]}, b"20"),
        ({"set": ["des"]}, b"3"),
        ({"set": []}, b"0"),
    ):
        arguments: dict[str, Any] = {
            "identity": "Machine$",
            "kerberos_encryption_types": request,
        }
        result = execute(payload, monkeypatch, tmp_path, arguments)
        assert result["changed"] and not result.get("failed")
        assert directory.objects[dn]["msDS-SupportedEncryptionTypes"] == [expected]
        directory.writes.clear()
        repeated = execute(payload, monkeypatch, tmp_path, arguments)
        assert repeated["changed"] is False and directory.writes == []


@pytest.mark.parametrize(
    "option,attribute,value",
    [
        (
            "kerberos_encryption_types",
            "msds-supportedencryptiontypes",
            {"set": ["aes256"]},
        ),
        ("delegates", "msds-allowedtoactonbehalfofotheridentity", {"set": []}),
    ],
)
# Each case supplies an option, its missing LDAP attribute and the request value.
def test_missing_schema_is_rejected_before_creation(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    option: str,
    attribute: str,
    value: dict[str, Any],
) -> None:
    directory.missing_schema.add(attribute)
    result = execute(payload, monkeypatch, tmp_path, {"name": "Machine", option: value})
    assert result["failed"] and result["changed"] is False
    assert attribute.lower() in result["msg"].lower()
    assert directory.writes == []


def test_kerberos_list_updates_and_clear(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    result = execute(
        payload,
        monkeypatch,
        tmp_path,
        {"name": "Machine", "kerberos_encryption_types": {"set": ["aes128", "aes256"]}},
    )
    dn = result["distinguished_name"]
    assert directory.objects[dn]["msDS-SupportedEncryptionTypes"] == [b"24"]
    result = execute(
        payload,
        monkeypatch,
        tmp_path,
        {
            "identity": "Machine$",
            "kerberos_encryption_types": {"remove": ["aes128"], "add": ["rc4"]},
        },
    )
    assert result["changed"] and directory.objects[dn][
        "msDS-SupportedEncryptionTypes"
    ] == [b"20"]
    repeated = execute(
        payload,
        monkeypatch,
        tmp_path,
        {
            "identity": "Machine$",
            "kerberos_encryption_types": {"remove": ["aes128"], "add": ["rc4"]},
        },
    )
    assert repeated["changed"] is False
    cleared = execute(
        payload,
        monkeypatch,
        tmp_path,
        {"identity": "Machine$", "kerberos_encryption_types": {"set": []}},
    )
    assert cleared["changed"] and directory.objects[dn][
        "msDS-SupportedEncryptionTypes"
    ] == [b"0"]


def test_delegate_lookup_failures_and_blank_entries(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    failed = execute(
        payload,
        monkeypatch,
        tmp_path,
        {"name": "Machine", "delegates": {"set": ["CN=Missing," + BASE]}},
    )
    assert failed["failed"] and not failed["changed"] and directory.writes == []
    principal = "CN=Principal,CN=Users," + BASE
    directory.seed(principal, "user", "Principal", 1100)
    result = execute(
        payload,
        monkeypatch,
        tmp_path,
        {
            "name": "Machine",
            "principals_allowed_to_delegate": {
                "lookup_failure_action": "warn",
                "set": ["", {"name": " "}, "CN=Missing," + BASE, "Principal"],
            },
        },
    )
    assert not result.get("failed") and len(result["warnings"]) == 1
    descriptor = directory.objects[result["distinguished_name"]][
        "msDS-AllowedToActOnBehalfOfOtherIdentity"
    ][0]
    assert b"S-1-5-21-1-2-3-1100" in descriptor


def test_absent_keeps_sid_and_has_idempotent_repeat(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    dn = "CN=Machine," + COMPUTERS
    directory.seed(dn, "computer", "Machine$")
    preview = execute(
        payload,
        monkeypatch,
        tmp_path,
        {"identity": "Machine", "state": "absent", "_ansible_check_mode": True},
    )
    assert preview["changed"] and dn in directory.objects
    removed = execute(
        payload,
        monkeypatch,
        tmp_path,
        {"identity": "Machine", "state": "absent", "_ansible_diff": True},
    )
    assert removed["changed"] and removed["sid"] == preview["sid"]
    assert removed["diff"]["after"] is None and dn not in directory.objects
    repeated = execute(
        payload, monkeypatch, tmp_path, {"identity": "Machine", "state": "absent"}
    )
    assert repeated["changed"] is False


def test_check_mode_rename_retains_identifiers_and_directory_state(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    dn = "CN=Machine," + COMPUTERS
    values = directory.seed(dn, "computer", "Machine$", 1000)
    result = execute(
        payload,
        monkeypatch,
        tmp_path,
        {"identity": "Machine$", "name": "Renamed", "_ansible_check_mode": True},
    )
    assert result["changed"] and not result.get("failed")
    assert result["distinguished_name"] == "CN=Renamed," + COMPUTERS
    assert dn in directory.objects and directory.writes == []
    assert result["sid"] == "S-1-5-21-1-2-3-1000"
    assert values["sAMAccountName"] == [b"Machine$"]


@pytest.mark.parametrize(
    "arguments",
    [
        {"enabled": "invalid"},
        {"do_not_append_dollar_to_sam": []},
        {"do_not_append_dollar_to_sam": {}},
        {"do_not_append_dollar_to_sam": ""},
        {"spn": {"bad": []}},
        {"kerberos_encryption_types": {"set": ["unknown"]}},
        {"delegates": {"set": [{"server": "example.test"}]}},
    ],
)
def test_invalid_options_fail_without_mutation(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    arguments: dict[str, Any],
) -> None:
    result = execute(
        payload, monkeypatch, tmp_path, dict({"name": "Machine"}, **arguments)
    )
    assert result["failed"] and not result["changed"]
    assert directory.writes == []


@pytest.mark.parametrize("check", [False, True])
def test_spn_alias_wins_on_existing_account_and_preserves_check_mode(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    check: bool,
) -> None:
    dn = "CN=Alias," + COMPUTERS
    values = directory.seed(
        dn,
        "computer",
        "Alias$",
        1100,
        {"servicePrincipalName": [b"HOST/old"]},
    )
    arguments = {
        "identity": "Alias$",
        "spn": {"set": ["HOST/ignored"]},
        "spns": {"set": ["HOST/alias"]},
        "_ansible_check_mode": check,
    }
    result = execute(payload, monkeypatch, tmp_path, arguments)
    assert result["changed"] and not result.get("failed")
    assert values["servicePrincipalName"] == [b"HOST/old" if check else b"HOST/alias"]
    if check:
        assert directory.writes == []
    else:
        directory.writes.clear()
        result = execute(payload, monkeypatch, tmp_path, arguments)
        assert not result["changed"] and not result.get("failed")
        assert directory.writes == []
