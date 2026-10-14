"""Exercise native AD user behavior through its public argument/JSON contract."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Pytest fixtures and explicit input/output case fields remain named separately.
# pylint: disable=too-many-arguments,too-many-positional-arguments

import copy
import ctypes
import importlib
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.ad_account_support import USERS, Directory
from tests.unit.ad_account_support import invoke_account as _run
from tests.unit.ad_account_support import load_account_payload
from tests.unit.payload_support import HELPER, ROOT


@pytest.fixture(name="directory")
def directory_state() -> Directory:
    """Provide independent user/password/group state.

    :returns: Mutable native LDAP fixture.
    """
    return Directory()


@pytest.fixture(name="payload")
def user_payload(monkeypatch: pytest.MonkeyPatch, directory: Directory) -> ModuleType:
    """Load the user payload and substitute its native credential probe.

    :param monkeypatch: Scoped native boundary substitutions.
    :param directory: Independent LDAP state.
    :returns: Loaded account JSON payload.
    """
    payload = load_account_payload("user", monkeypatch, directory)
    native = importlib.import_module("legacy_ad_user")
    monkeypatch.setattr(
        native,
        "password_matches",
        lambda username, password: password in directory.passwords.values(),
    )
    return payload


def test_create_passwordless_user_disabled_and_repeat_idempotent(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = {
        "name": "Alice",
        "firstname": "Alice",
        "surname": "Example",
        "email": "alice@example.test",
        "_ansible_diff": True,
    }
    status, first = _run(payload, monkeypatch, tmp_path, capsys, args)
    assert status == 0 and first["changed"]
    dn = "CN=Alice," + USERS
    assert directory.objects[dn]["userAccountControl"] == [b"514"]
    assert directory.objects[dn]["sAMAccountName"] == [b"Alice"]
    assert dn not in directory.passwords
    assert first["diff"]["after"]["enabled"] is False
    directory.writes.clear()
    status, repeat = _run(payload, monkeypatch, tmp_path, capsys, args)
    assert status == 0 and not repeat["changed"]
    assert repeat["sid"] == first["sid"]
    assert directory.writes == []


def test_password_creation_sets_secret_before_enabling_and_masks_diff(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    password = "TestPassword2!"
    module_args: dict[str, Any] = {
        "name": "Alice",
        "password": password,
        "_ansible_diff": True,
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0 and result["changed"]
    dn = result["distinguished_name"]
    assert directory.passwords[dn] == password
    assert directory.objects[dn]["userAccountControl"] == [b"512"]
    changes = [
        change[1]
        for write in directory.writes
        if write[0] == "modify"
        for change in write[2]
    ]
    assert changes.index("unicodePwd") < changes.index("userAccountControl")
    assert password not in json.dumps(result)
    assert result["diff"]["after"]["password"] == "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"


def test_password_reset_failure_leaves_disabled_account_and_observed_sid(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory.fail_attribute = "unicodepwd"
    module_args: dict[str, Any] = {
        "name": "Partial",
        "password": "TestPassword2!",
        "_ansible_diff": True,
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 1 and result["changed"]
    assert directory.objects[result["distinguished_name"]]["userAccountControl"] == [
        b"514"
    ]
    assert result["sid"] is not None
    assert "TestPassword2!" not in json.dumps(result)
    assert directory.closed


@pytest.mark.parametrize(
    "policy,password,changed",
    [
        ("always", "ExistingPassword1!", True),
        ("on_create", "DifferentPassword2!", False),
        ("when_changed", "ExistingPassword1!", False),
        ("when_changed", "DifferentPassword2!", True),
    ],
)
def test_existing_password_update_policies(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    policy: str,
    password: str,
    changed: bool,
) -> None:
    dn = "CN=Alice," + USERS
    directory.seed(dn, "user", "alice", 1100)
    module_args: dict[str, Any] = {
        "identity": "alice",
        "password": password,
        "update_password": policy,
        "_ansible_diff": True,
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0 and result["changed"] is changed
    assert password not in json.dumps(result)
    assert directory.passwords[dn] == (password if changed else "ExistingPassword1!")


def test_check_mode_password_change_and_flags_are_nonmutating(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dn = "CN=Alice," + USERS
    directory.seed(dn, "user", "alice", 1100)
    module_args: dict[str, Any] = {
        "identity": "alice",
        "password": "DifferentPassword2!",
        "enabled": False,
        "password_expired": True,
        "_ansible_check_mode": True,
        "_ansible_diff": True,
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0 and result["changed"]
    assert directory.passwords[dn] == "ExistingPassword1!"
    assert directory.objects[dn]["userAccountControl"] == [b"512"]
    assert directory.writes == []
    assert "DifferentPassword2!" not in json.dumps(result)


def test_check_mode_creation_returns_markers_without_a_password_write(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module_args: dict[str, Any] = {
        "name": "Preview",
        "password": "PreviewPassword2!",
        "_ansible_check_mode": True,
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0 and result["changed"]
    assert result["sid"] == "S-1-5-0000"
    assert result["object_guid"] == "00000000-0000-0000-0000-000000000000"
    assert directory.writes == []


def test_named_account_flags_preserve_unrelated_uac_bits(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dn = "CN=Alice," + USERS
    directory.seed(dn, "user", "alice", 1100, {"userAccountControl": [b"262656"]})
    module_args: dict[str, Any] = {
        "identity": "alice",
        "enabled": False,
        "password_never_expires": True,
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0 and result["changed"]
    assert int(directory.objects[dn]["userAccountControl"][0]) == 262656 | 2 | 65536


def test_creation_preserves_raw_uac_bits_and_enables_after_password(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module_args: dict[str, Any] = {
        "name": "CustomFlags",
        "password": "TestPassword2!",
        "attributes": {"set": {"userAccountControl": 262656}},
        "_ansible_diff": True,
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0
    assert (
        int(directory.objects[result["distinguished_name"]]["userAccountControl"][0])
        == 262656
    )
    assert "userAccountControl" in result["diff"]["after"]["attributes"]


def test_password_expiry_reset_order_and_repeat(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dn = "CN=Alice," + USERS
    directory.seed(dn, "user", "alice", 1100)
    args = {
        "identity": "alice",
        "password": "DifferentPassword2!",
        "password_expired": True,
        "update_password": "on_create",
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, args)
    assert status == 0 and result["changed"]
    assert directory.objects[dn]["pwdLastSet"] == [b"0"]
    directory.writes.clear()
    status, repeat = _run(payload, monkeypatch, tmp_path, capsys, args)
    assert status == 0 and not repeat["changed"]
    assert directory.writes == []


def test_unlock_clears_only_computed_locked_account(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dn = "CN=Alice," + USERS
    directory.seed(
        dn,
        "user",
        "alice",
        1100,
        {"lockoutTime": [b"1234"], "msDS-User-Account-Control-Computed": [b"16"]},
    )
    module_args: dict[str, Any] = {"identity": "alice", "account_locked": False}
    status, result = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0 and result["changed"]
    assert directory.objects[dn]["lockoutTime"] == [b"0"]


def test_user_groups_add_remove_and_repeat_reconcile_group_owned_links(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dn = "CN=Alice," + USERS
    directory.seed(dn, "user", "alice", 1100)
    old, new = "CN=Old," + USERS, "CN=New," + USERS
    directory.seed(
        old,
        "group",
        "old",
        1200,
        {"groupType": [b"-2147483646"], "member": [dn.encode()]},
    )
    directory.seed(new, "group", "new", 1201, {"groupType": [b"-2147483646"]})
    args = {
        "identity": "alice",
        "groups": {"add": ["new"], "remove": ["old"]},
        "_ansible_diff": True,
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, args)
    assert status == 0 and result["changed"]
    assert directory.objects[new]["member"] == [dn.encode()]
    assert not directory.objects[old].get("member")
    assert result["diff"]["after"]["groups"] == sorted(
        [new, "CN=Domain Users," + USERS]
    )
    directory.writes.clear()
    status, repeat = _run(payload, monkeypatch, tmp_path, capsys, args)
    assert status == 0 and not repeat["changed"]
    assert directory.writes == []


@pytest.mark.parametrize("empty_set,warning", [(False, True), (True, False)])
def test_primary_group_removal_retains_upstream_attempted_change_signal(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    empty_set: bool,
    warning: bool,
) -> None:
    directory.seed("CN=Alice," + USERS, "user", "alice", 1100)
    request = {"set": []} if empty_set else {"remove": ["Domain Users"]}
    module_args: dict[str, Any] = {"identity": "alice", "groups": request}
    status, result = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0 and result["changed"]
    assert bool(result.get("warnings")) is warning
    assert directory.writes == []


@pytest.mark.parametrize(
    "policy,expected_status,warning",
    [("fail", 1, False), ("ignore", 0, False), ("warn", 0, True)],
)
def test_group_write_failure_policy_preserves_native_failure_outcome(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    policy: str,
    expected_status: int,
    warning: bool,
) -> None:
    directory.seed("CN=Alice," + USERS, "user", "alice", 1100)
    directory.seed(
        "CN=New," + USERS, "group", "new", 1200, {"groupType": [b"-2147483646"]}
    )
    directory.fail_attribute = "member"
    module_args: dict[str, Any] = {
        "identity": "alice",
        "groups": {"add": ["new"], "permissions_failure_action": policy},
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == expected_status
    assert bool(result.get("warnings")) is warning
    assert result["changed"] is (expected_status == 0)


def test_spn_set_has_precedence_and_case_insensitive_repeat(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dn = "CN=Alice," + USERS
    directory.seed(dn, "user", "alice", 1100, {"servicePrincipalName": [b"HTTP/old"]})
    module_args: dict[str, Any] = {
        "identity": "alice",
        "spn": {
            "set": ["HTTP/new"],
            "add": ["HTTP/ignored"],
            "remove": ["HTTP/new"],
        },
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0 and result["changed"]
    assert directory.objects[dn]["servicePrincipalName"] == [b"HTTP/new"]
    directory.writes.clear()
    module_args = {"identity": "alice", "spns": {"set": ["http/NEW"]}}
    status, repeat = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0 and not repeat["changed"]
    assert directory.writes == []


def test_password_change_denies_preserve_unrelated_dacl_and_are_idempotent(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dn = "CN=Alice," + USERS
    directory.seed(dn, "user", "alice", 1100)
    args = {"identity": "alice", "user_cannot_change_password": True}
    status, result = _run(payload, monkeypatch, tmp_path, capsys, args)
    assert status == 0 and result["changed"]
    descriptor = directory.objects[dn]["nTSecurityDescriptor"][0].decode()
    assert "(A;;GA;;;DA)" in descriptor
    assert descriptor.count("ab721a53-1e2f-11d0-9819-00aa0040529b") == 2
    directory.writes.clear()
    status, repeat = _run(payload, monkeypatch, tmp_path, capsys, args)
    assert status == 0 and not repeat["changed"]
    assert directory.writes == []
    module_args: dict[str, Any] = {
        "identity": "alice",
        "user_cannot_change_password": False,
    }
    status, cleared = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0 and cleared["changed"]
    assert directory.objects[dn]["nTSecurityDescriptor"] == [
        b"O:DAG:DAD:AI(A;;GA;;;DA)"
    ]


def test_delegation_schema_failure_precedes_account_creation(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory.missing_schema.add("msds-allowedtoactonbehalfofotheridentity")
    module_args: dict[str, Any] = {"name": "Unsupported", "delegates": {"set": []}}
    status, result = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 1 and "schema does not support" in result["msg"]
    assert directory.writes == []


@pytest.mark.parametrize(
    "values",
    [
        {"account_locked": True},
        {"password_expired": True, "password_never_expires": True},
        {"update_password": "unknown"},
        {"spn": {"unexpected": []}},
    ],
)
def test_invalid_account_options_fail_without_native_mutation(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    values: dict[str, object],
) -> None:
    module_args: dict[str, Any] = {"name": "Invalid", **values}
    status, result = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 1 and result["failed"]
    assert directory.writes == []


@pytest.mark.parametrize("canonical", ["canonical", {"invalid": "type"}])
def test_supplied_alias_overrides_canonical_before_validation_and_repeats(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    canonical: Any,
) -> None:
    arguments = {
        "name": "Alias",
        "surname": canonical,
        "lastname": "AliasSurname",
        "spn": {"set": ["HTTP/ignored"]},
        "spns": {"set": ["HTTP/alias"]},
        "delegates": {"set": ["missing"]},
        "principals_allowed_to_delegate": {"set": []},
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0 and result["changed"]
    values = directory.objects[result["distinguished_name"]]
    assert values["sn"] == [b"AliasSurname"]
    assert values["servicePrincipalName"] == [b"HTTP/alias"]
    directory.writes.clear()
    status, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0 and not result["changed"]
    assert directory.writes == []


def test_explicit_null_alias_overrides_supplied_canonical(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    arguments = {"name": "Alias", "surname": "ignored", "lastname": None}
    status, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0 and result["changed"]
    assert "sn" not in directory.objects[result["distinguished_name"]]


def test_nested_group_failure_alias_overrides_canonical(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory.seed("CN=Alias," + USERS, "user", "alias", 1100)
    arguments = {
        "identity": "alias",
        "groups": {
            "add": ["missing"],
            "lookup_failure_action": "fail",
            "missing_behaviour": "IGNORE",
        },
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0 and not result["changed"]
    assert directory.writes == []


def test_mixed_case_lifecycle_and_password_choices(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    arguments = {
        "name": "CaseChoice",
        "state": "PRESENT",
        "update_password": "ON_CREATE",
    }
    status, created = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0 and created["changed"]
    status, repeat = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0 and not repeat["changed"]
    status, removed = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"identity": created["distinguished_name"], "state": "ABSENT"},
    )
    assert status == 0 and removed["changed"]
    assert created["distinguished_name"] not in directory.objects


@pytest.mark.parametrize("option", ["state", "update_password"])
def test_explicit_empty_choice_is_not_treated_as_omission(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    option: str,
) -> None:
    original = copy.deepcopy(directory.objects)
    status, result = _run(
        payload, monkeypatch, tmp_path, capsys, {"name": "InvalidChoice", option: ""}
    )
    assert status == 1 and not result["changed"]
    assert option in result["msg"]
    assert directory.objects == original and directory.writes == []


def test_absent_wrong_structural_class_does_not_delete_group(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dn = "CN=NotAUser," + USERS
    directory.seed(dn, "group", "not_a_user", 1200, {"groupType": [b"-2147483646"]})
    module_args: dict[str, Any] = {"identity": "not_a_user", "state": "absent"}
    status, result = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0 and not result["changed"]
    assert result["sid"] is None
    assert dn in directory.objects and directory.writes == []


def test_policy_expired_password_can_be_cleared_without_resetting_the_secret(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dn = "CN=Alice," + USERS
    directory.seed(
        dn, "user", "alice", 1100, {"msDS-User-Account-Control-Computed": [b"8388608"]}
    )
    module_args: dict[str, Any] = {"identity": "alice", "password_expired": False}
    status, result = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0 and result["changed"]
    assert directory.objects[dn]["pwdLastSet"] == [b"-1"]
    assert directory.passwords[dn] == "ExistingPassword1!"
    directory.writes.clear()
    status, repeated = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0 and not repeated["changed"]
    assert directory.writes == []


@pytest.mark.parametrize(
    "code,success,expected",
    [
        (0, True, True),
        (1327, False, True),
        (1328, False, True),
        (1329, False, True),
        (1385, False, True),
        (1326, False, False),
        (1330, False, False),
        (1793, False, False),
        (1907, False, False),
        (1331, False, False),
    ],
)
def test_password_probe_uses_native_upstream_error_classes(
    monkeypatch: pytest.MonkeyPatch,
    code: int,
    success: bool,
    expected: bool,
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    monkeypatch.syspath_prepend(str(HELPER.parent))
    native = importlib.import_module("legacy_ad_user")

    def _logon(*arguments: Any) -> int:
        if success:
            ctypes.cast(arguments[5], ctypes.POINTER(ctypes.c_void_p))[0] = 99
        return int(success)

    security = SimpleNamespace(LogonUserW=Mock(side_effect=_logon))
    kernel = SimpleNamespace(CloseHandle=Mock(return_value=1))
    monkeypatch.setattr(
        ctypes,
        "WinDLL",
        lambda name, **_flags: security if name == "advapi32" else kernel,
        raising=False,
    )
    monkeypatch.setattr(ctypes, "get_last_error", lambda: code, raising=False)
    assert native.password_matches("DOMAIN\\alice", "Secret1!") is expected
    assert security.LogonUserW.call_args.args[:5] == (
        "alice",
        "DOMAIN",
        "Secret1!",
        3,
        0,
    )
    assert kernel.CloseHandle.call_count == int(success)
    if success:
        assert kernel.CloseHandle.call_args.args[0].value == 99


def test_password_probe_does_not_hide_unknown_native_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    monkeypatch.syspath_prepend(str(HELPER.parent))
    native = importlib.import_module("legacy_ad_user")
    security = SimpleNamespace(LogonUserW=Mock(return_value=0))
    kernel = SimpleNamespace(CloseHandle=Mock(return_value=1))
    monkeypatch.setattr(
        ctypes,
        "WinDLL",
        lambda name, **_flags: security if name == "advapi32" else kernel,
        raising=False,
    )
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5, raising=False)
    monkeypatch.setattr(
        ctypes, "WinError", lambda code: OSError(code, "Native failure"), raising=False
    )
    with pytest.raises(OSError) as failure:
        native.password_matches("alice@example.test", "Secret1!")
    assert failure.value.errno == 5
    assert security.LogonUserW.call_args.args[:2] == ("alice@example.test", None)
    kernel.CloseHandle.assert_not_called()


@pytest.mark.parametrize("password", ["", "   "])
def test_blank_creation_password_is_omitted_like_upstream(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    password: str,
) -> None:
    module_args = {"name": "BlankPassword", "password": password, "_ansible_diff": True}
    status, result = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0 and result["changed"]
    assert result["distinguished_name"] not in directory.passwords
    assert directory.objects[result["distinguished_name"]]["userAccountControl"] == [
        b"514"
    ]
    assert "password" not in result["diff"]["after"]


def test_no_log_passwords_hide_matching_diff_values_and_invocation(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = "UserSecret1!"
    module_args = {
        "name": "SecretFixture",
        "password": secret,
        "description": secret,
        "domain_username": "admin",
        "domain_password": "DomainSecret2!",
        "company": "DomainSecret2!",
        "domain_credentials": [
            {"name": "foreign", "username": "admin", "password": "ForeignSecret3!"}
        ],
        "firstname": "ForeignSecret3!",
        "_ansible_diff": True,
        "_ansible_inject_invocation": True,
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0 and result["changed"]
    for password in (secret, "DomainSecret2!", "ForeignSecret3!"):
        assert password not in json.dumps(result)
    assert directory.passwords[result["distinguished_name"]] == secret
    assert (
        result["invocation"]["module_args"]["password"]
        == "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
    )
    assert (
        result["diff"]["after"]["description"] == "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
    )


def test_validation_failure_and_secret_parameter_names_are_sanitized(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module_args = {
        "name": "Invalid",
        "password": "SecretParameter1!",
        "SecretParameter1!": True,
        "old_password": "OldSecret2!",
        "_ansible_inject_invocation": True,
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 1
    assert "SecretParameter1!" not in json.dumps(result)
    assert "OldSecret2!" not in json.dumps(result)
    assert directory.writes == []


def test_unexpected_failure_tracebacks_do_not_leak_passwords(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = "SecretTrace1!"

    def _fail(_arguments: object, _result: object) -> None:
        raise RuntimeError(secret)

    monkeypatch.setattr(payload, "manage_user", _fail)
    status, result = _run(
        payload, monkeypatch, tmp_path, capsys, {"name": "Invalid", "password": secret}
    )
    assert status == 1
    assert secret not in json.dumps(result)
    assert "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER" in result["exception"]
    assert directory.writes == []
