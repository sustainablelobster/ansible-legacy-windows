"""Exercise the group payload's public behavior against independent LDAP state."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Pytest fixtures and explicit input/output case fields remain named separately.
# pylint: disable=too-many-arguments,too-many-positional-arguments

from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from tests.unit.ad_account_support import BASE, USERS, Directory
from tests.unit.ad_account_support import invoke_account as _run
from tests.unit.ad_account_support import load_account_payload


@pytest.fixture(name="directory")
def directory_state() -> Directory:
    """Provide independent account state for each public behavior case.

    :returns: Mutable LDAP fixture.
    """
    return Directory()


@pytest.fixture(name="payload")
def group_payload(monkeypatch: pytest.MonkeyPatch, directory: Directory) -> ModuleType:
    """Load the real group payload with only native boundaries substituted.

    :param monkeypatch: Scoped fixture substitutions.
    :param directory: Independent LDAP state.
    :returns: Loaded JSON payload.
    """
    return load_account_payload("group", monkeypatch, directory)


def test_preview_creation_is_nonmutating_and_returns_markers(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module_args: dict[str, Any] = {
        "name": "Deployment",
        "scope": "global",
        "_ansible_check_mode": True,
        "_ansible_diff": True,
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0 and result["changed"]
    assert result["distinguished_name"] == "CN=Deployment," + USERS
    assert result["object_guid"] == "00000000-0000-0000-0000-000000000000"
    assert result["sid"] == "S-1-5-0000"
    assert result["diff"]["before"] is None
    assert result["diff"]["after"]["scope"] == "global"
    assert directory.writes == []
    assert directory.closed


def test_creation_and_repeat_keep_security_global_defaults(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = {
        "name": "Deployment",
        "scope": "global",
        "description": "Deployment accounts",
        "_ansible_diff": True,
    }
    status, first = _run(payload, monkeypatch, tmp_path, capsys, args)
    assert status == 0 and first["changed"]
    dn = first["distinguished_name"]
    assert directory.objects[dn]["groupType"] == [b"-2147483646"]
    assert directory.objects[dn]["sAMAccountName"] == [b"Deployment"]
    assert first["sid"] != "S-1-5-0000"
    directory.writes.clear()
    status, repeat = _run(payload, monkeypatch, tmp_path, capsys, args)
    assert status == 0 and not repeat["changed"]
    assert repeat["object_guid"] == first["object_guid"]
    assert directory.writes == []


@pytest.mark.parametrize(
    "scope,category,expected",
    [
        ("global", "security", -2147483646),
        ("domainlocal", "security", -2147483644),
        ("universal", "distribution", 8),
    ],
)
def test_group_type_native_bits(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    scope: str,
    category: str,
    expected: int,
) -> None:
    module_args: dict[str, Any] = {
        "name": "Kinds",
        "scope": scope,
        "category": category,
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0
    assert directory.objects[result["distinguished_name"]]["groupType"] == [
        str(expected).encode()
    ]


def test_scope_is_only_required_for_actual_creation(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module_args: dict[str, Any] = {"name": "Missing"}
    status, failure = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 1 and "scope must be set" in failure["msg"]
    assert directory.writes == []
    directory.seed(
        "CN=Existing," + USERS,
        "group",
        "existing",
        extra={"groupType": [b"-2147483646"]},
    )
    module_args = {"identity": "existing"}
    status, result = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0 and not result["changed"]


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("attribute_name", ["groupType", "GROUPTYPE"])
def test_raw_group_type_is_not_overwritten_when_named_options_are_omitted(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    check: bool,
    attribute_name: str,
) -> None:
    dn = "CN=RawType," + USERS
    directory.seed(dn, "group", "RawType", extra={"groupType": [b"-2147483646"]})
    arguments: dict[str, Any] = {
        "identity": "RawType",
        "attributes": {"set": {attribute_name: {"type": "int", "value": 8}}},
        "_ansible_check_mode": check,
        "_ansible_diff": True,
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0 and result["changed"]
    assert result["diff"]["after"]["attributes"][attribute_name] == [8]
    if check:
        assert directory.objects[dn]["groupType"] == [b"-2147483646"]
        assert not directory.writes
    else:
        assert directory.objects[dn]["groupType"] == [b"8"]
        directory.writes.clear()
        status, repeated = _run(payload, monkeypatch, tmp_path, capsys, arguments)
        assert status == 0 and not repeated["changed"]
        assert not directory.writes


def test_named_group_type_normalizes_the_raw_attribute_spelling(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dn = "CN=MixedType," + USERS
    directory.seed(dn, "group", "MixedType", extra={"groupType": [b"-2147483646"]})
    arguments = {
        "identity": "MixedType",
        "category": "distribution",
        "attributes": {"set": {"GROUPTYPE": {"type": "int", "value": 2}}},
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0 and result["changed"]
    assert directory.objects[dn]["groupType"] == [b"2"]
    group_type_changes = [
        change
        for write in directory.writes
        if write[0] == "modify"
        for change in write[2]
        if change[1].lower() == "grouptype"
    ]
    assert group_type_changes == [(2, "groupType", [b"2"])]


def test_member_replacement_uses_link_deltas_not_replace(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    alice, bob = "CN=Alice," + USERS, "CN=Bob," + USERS
    directory.seed(alice, "user", "alice", 1100)
    directory.seed(bob, "user", "bob", 1101)
    dn = "CN=BuiltinTest," + USERS
    directory.seed(
        dn,
        "group",
        "BuiltinTest",
        1200,
        {"groupType": [b"-2147483643"], "member": [alice.encode()]},
    )
    module_args: dict[str, Any] = {
        "identity": "BuiltinTest",
        "members": {"set": ["bob"]},
        "_ansible_diff": True,
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0 and result["changed"]
    assert directory.objects[dn]["member"] == [bob.encode()]
    member_changes = [
        change
        for write in directory.writes
        if write[0] == "modify"
        for change in write[2]
        if change[1] == "member"
    ]
    assert member_changes == [
        (1, "member", [alice.encode()]),
        (0, "member", [bob.encode()]),
    ]
    assert result["diff"]["before"]["members"] == [alice]
    assert result["diff"]["after"]["members"] == [bob]
    directory.writes.clear()
    module_args = {"identity": "BuiltinTest", "members": {"set": ["BOB"]}}
    status, repeat = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0 and not repeat["changed"]
    assert directory.writes == []


@pytest.mark.parametrize(
    "policy,status,warnings",
    [("fail", 1, False), ("ignore", 0, False), ("warn", 0, True)],
)
def test_missing_member_lookup_policy(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    policy: str,
    status: int,
    warnings: bool,
) -> None:
    module_args: dict[str, Any] = {
        "name": "Lookup",
        "scope": "global",
        "members": {"add": ["missing"], "lookup_failure_action": policy},
    }
    outcome, result = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert outcome == status
    assert bool(result.get("warnings")) == warnings
    if status == 1:
        assert directory.writes == []


def test_move_rename_keeps_sid_and_guid(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module_args: dict[str, Any] = {"name": "Before", "scope": "global"}
    status, first = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0
    module_args = {
        "identity": first["object_guid"],
        "name": "After",
        "path": "OU=Managed," + BASE,
    }
    status, moved = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0 and moved["changed"]
    assert moved["distinguished_name"] == "CN=After,OU=Managed," + BASE
    assert moved["object_guid"] == first["object_guid"]
    assert moved["sid"] == first["sid"]
    assert moved["distinguished_name"] in directory.objects


def test_absent_is_idempotent_and_retains_removed_identifiers(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module_args: dict[str, Any] = {"name": "Disposable", "scope": "global"}
    status, first = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0
    module_args = {"identity": first["sid"], "state": "absent", "_ansible_diff": True}
    status, removed = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0 and removed["changed"]
    assert removed["sid"] == first["sid"]
    assert removed["object_guid"] == first["object_guid"]
    assert removed["diff"]["after"] is None
    assert first["distinguished_name"] not in directory.objects
    module_args = {"identity": first["sid"], "state": "absent"}
    status, repeat = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 0 and not repeat["changed"]
    assert repeat["sid"] is None


def test_link_failure_retains_successful_creation_and_sid(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory.seed("CN=Alice," + USERS, "user", "alice", 1100)
    directory.fail_attribute = "member"
    module_args: dict[str, Any] = {
        "name": "Partial",
        "scope": "global",
        "members": {"add": ["alice"]},
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, module_args)
    assert status == 1 and result["changed"]
    assert result["distinguished_name"] in directory.objects
    assert result["sid"] is not None
    assert directory.closed
