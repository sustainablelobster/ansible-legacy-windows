"""Exercise PSO lifecycle and exact-subject management through public JSON."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Pytest native-boundary fixtures and JSON argument/result fields stay explicit.
# pylint: disable=too-many-arguments,too-many-positional-arguments
# Repeated JSON invocations are independent behavior cases, not duplicated logic.
# pylint: disable=duplicate-code

import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from tests.unit.ad_account_support import USERS
from tests.unit.ad_account_support import invoke_account as _run
from tests.unit.test_ad_policy_support import PSO_DN, PSO_PATH, Directory
from tests.unit.test_ad_policy_support import payload as load_payload
from tests.unit.test_ad_policy_support import state


@pytest.fixture(name="directory")
def _directory() -> Directory:
    return Directory()


@pytest.fixture(name="payload")
def _payload(monkeypatch: pytest.MonkeyPatch, directory: Directory) -> ModuleType:
    return load_payload("pso", monkeypatch, directory)


def test_creation_defaults_match_reference_not_current_domain_policy(
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
        {"name": "Policy", "precedence": 100, "_ansible_diff": True},
    )
    assert status == 0 and result["changed"] and result["distinguished_name"] == PSO_DN
    stored = directory.objects[PSO_DN]
    expected = {
        "msDS-PasswordSettingsPrecedence": [b"100"],
        "msDS-PasswordReversibleEncryptionEnabled": [b"TRUE"],
        "msDS-PasswordHistoryLength": [b"24"],
        "msDS-PasswordComplexityEnabled": [b"TRUE"],
        "msDS-MinimumPasswordLength": [b"7"],
        "msDS-MinimumPasswordAge": [b"-864000000000"],
        "msDS-MaximumPasswordAge": [b"-36288000000000"],
        "msDS-LockoutThreshold": [b"0"],
        "msDS-LockoutObservationWindow": [b"-18000000000"],
        "msDS-LockoutDuration": [b"-18000000000"],
    }
    assert {name: stored[name] for name in expected} == expected
    assert result["diff"] == {
        "before": None,
        "after": {
            "name": "Policy",
            "path": PSO_PATH,
            "attributes": {},
            "precedence": 100,
        },
    }
    directory.writes.clear()
    status, repeat = _run(
        payload, monkeypatch, tmp_path, capsys, {"name": "Policy", "precedence": 100}
    )
    assert status == 0 and not repeat["changed"] and not directory.writes


def test_creation_preview_reports_zero_guid_and_never_writes(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    before = state(directory)
    status, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"name": "Policy", "precedence": 100, "_ansible_check_mode": True},
    )
    assert status == 0 and result["changed"]
    assert result["object_guid"] == "00000000-0000-0000-0000-000000000000"
    assert state(directory) == before and not directory.writes


def test_named_settings_update_keep_unrequested_defaults_and_boolean_diff_types(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _run(payload, monkeypatch, tmp_path, capsys, {"name": "Policy", "precedence": 100})
    directory.writes.clear()
    request = {
        "name": "Policy",
        "min_password_length": 20,
        "complexity_enabled": False,
        "lockout_threshold": 5,
        "_ansible_diff": True,
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, request)
    assert status == 0 and result["changed"]
    assert result["diff"]["before"]["complexity_enabled"] is True
    assert result["diff"]["after"]["complexity_enabled"] is False
    assert result["diff"]["before"]["min_password_length"] == 7
    assert result["diff"]["after"]["min_password_length"] == 20
    assert directory.objects[PSO_DN]["msDS-PasswordReversibleEncryptionEnabled"] == [
        b"TRUE"
    ]
    assert directory.objects[PSO_DN]["msDS-PasswordSettingsPrecedence"] == [b"100"]
    directory.writes.clear()
    assert _run(payload, monkeypatch, tmp_path, capsys, request)[1]["changed"] is False
    assert not directory.writes


def test_custom_reversible_encryption_override_is_preserved_on_creation(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = {
        "name": "Policy",
        "precedence": 100,
        "attributes": {"set": {"msDS-PasswordReversibleEncryptionEnabled": False}},
        "_ansible_diff": True,
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, request)
    assert status == 0
    assert directory.objects[PSO_DN]["msDS-PasswordReversibleEncryptionEnabled"] == [
        b"FALSE"
    ]
    assert result["diff"]["after"]["attributes"] == {
        "msDS-PasswordReversibleEncryptionEnabled": [False]
    }


def test_subjects_are_resolved_replaced_and_omission_does_not_clear_assignments(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    alice, bob = "CN=Alice," + USERS, "CN=Bob," + USERS
    directory.seed(alice, "user", "alice")
    directory.seed(bob, "group", "bob", extra={"groupType": [b"-2147483646"]})
    status, first = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"name": "Policy", "precedence": 100, "subjects": ["alice"]},
    )
    assert status == 0 and first["changed"]
    assert directory.objects[PSO_DN]["msDS-PSOAppliesTo"] == [alice.encode()]
    directory.writes.clear()
    request = {"name": "Policy", "subjects": ["bob"], "_ansible_diff": True}
    status, result = _run(payload, monkeypatch, tmp_path, capsys, request)
    assert status == 0 and result["changed"]
    subject_writes = [write[2] for write in directory.writes if write[0] == "modify"]
    assert subject_writes == [
        [(0, "msDS-PSOAppliesTo", [bob.encode()])],
        [(1, "msDS-PSOAppliesTo", [alice.encode()])],
    ]
    assert result["diff"]["before"]["subjects"] == ["Alice"]
    assert result["diff"]["after"]["subjects"] == ["bob"]
    directory.writes.clear()
    assert not _run(payload, monkeypatch, tmp_path, capsys, request)[1]["changed"]
    assert not _run(payload, monkeypatch, tmp_path, capsys, {"name": "Policy"})[1][
        "changed"
    ]
    assert directory.objects[PSO_DN]["msDS-PSOAppliesTo"] == [bob.encode()]


def test_subject_clear_check_mode_and_actual_removal_keep_policy_object(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    alice = "CN=Alice," + USERS
    directory.seed(alice, "user", "alice")
    _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"name": "Policy", "precedence": 100, "subjects": ["alice"]},
    )
    before = state(directory)
    directory.writes.clear()
    status, preview = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"name": "Policy", "subjects": [], "_ansible_check_mode": True},
    )
    assert (
        status == 0
        and preview["changed"]
        and state(directory) == before
        and not directory.writes
    )
    status, result = _run(
        payload, monkeypatch, tmp_path, capsys, {"name": "Policy", "subjects": []}
    )
    assert status == 0 and result["changed"] and PSO_DN in directory.objects
    assert "msDS-PSOAppliesTo" not in directory.objects[PSO_DN]


@pytest.mark.parametrize(
    "kind,group_type",
    [
        ("group", b"-2147483644"),
        ("group", b"-2147483640"),
        ("organizationalUnit", None),
    ],
)
def test_invalid_subject_types_fail_before_policy_creation(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    kind: str,
    group_type: bytes | None,
) -> None:
    directory.seed(
        "CN=Subject," + USERS,
        kind,
        "subject",
        extra={"groupType": [group_type]} if group_type else {},
    )
    status, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"name": "Policy", "precedence": 100, "subjects": ["subject"]},
    )
    assert (
        status == 1
        and not result["changed"]
        and ("must be global" in result["msg"] or "must be a global" in result["msg"])
    )
    assert PSO_DN not in directory.objects and not directory.writes


def test_subject_remove_failure_keeps_successful_additions_and_reports_change(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    alice, bob = "CN=Alice," + USERS, "CN=Bob," + USERS
    directory.seed(alice, "user", "alice")
    directory.seed(bob, "user", "bob")
    _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"name": "Policy", "precedence": 100, "subjects": ["alice"]},
    )
    directory.writes.clear()
    directory.fail_subject_operation = 1
    status, result = _run(
        payload, monkeypatch, tmp_path, capsys, {"name": "Policy", "subjects": ["bob"]}
    )
    assert status == 1 and result["changed"] and result["object_guid"]
    assert directory.objects[PSO_DN]["msDS-PSOAppliesTo"] == [
        alice.encode(),
        bob.encode(),
    ]
    assert len(directory.writes) == 1


def test_rename_and_remove_by_guid_preserve_identity_and_protection_workflow(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    first = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"name": "Policy", "precedence": 100, "protect_from_deletion": True},
    )[1]
    status, renamed = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"identity": first["object_guid"], "name": "Renamed"},
    )
    assert (
        status == 0
        and renamed["changed"]
        and renamed["object_guid"] == first["object_guid"]
    )
    assert renamed["distinguished_name"] == "CN=Renamed," + PSO_PATH
    status, removed = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"identity": first["object_guid"], "state": "absent"},
    )
    assert (
        status == 0
        and removed["changed"]
        and removed["object_guid"] == first["object_guid"]
    )
    assert not any(dn.endswith(PSO_PATH) for dn in directory.objects)


@pytest.mark.parametrize("mode", ["low_domain", "missing_schema"])
def test_unsupported_directory_capabilities_fail_before_changes(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    mode: str,
) -> None:
    if mode == "low_domain":
        directory.functional_level = 2
    else:
        directory.missing_schema.add("msds-minimumpasswordlength")
    status, result = _run(
        payload, monkeypatch, tmp_path, capsys, {"name": "Policy", "precedence": 100}
    )
    assert status == 1 and not result["changed"] and not directory.writes


@pytest.mark.parametrize(
    "arguments",
    [
        {"name": "Policy"},
        {"name": "Policy", "precedence": "bad"},
        {"name": "Policy", "precedence": 100, "path": USERS},
        {"name": "Policy", "precedence": 100, "subjects": ["missing"]},
    ],
)
def test_invalid_or_unresolved_requests_have_no_directory_side_effects(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    arguments: dict[str, Any],
) -> None:
    assert _run(payload, monkeypatch, tmp_path, capsys, arguments)[0] == 1
    assert not directory.writes


def test_passwords_are_redacted_even_on_validation_failures(
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
        {
            "name": "Policy",
            "precedence": "secret",
            "domain_username": "admin",
            "domain_password": "secret",
            "_ansible_inject_invocation": True,
        },
    )
    assert status == 1 and "secret" not in json.dumps(result) and not directory.writes


@pytest.mark.parametrize(
    "option,value",
    [
        ("precedence", -1),
        ("precedence", 0),
        ("min_password_length", -1),
        ("min_password_length", 256),
        ("lockout_threshold", -1),
        ("lockout_threshold", 65536),
    ],
)
def test_check_mode_matches_reference_whatif_without_invented_value_ranges(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    option: str,
    value: int,
) -> None:
    arguments = {
        "name": "Policy",
        "precedence": 100,
        "_ansible_check_mode": True,
        option: value,
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0 and result["changed"] and not directory.writes


@pytest.mark.parametrize(
    "option,value", [("precedence", 2**31), ("min_password_length", -(2**31) - 1)]
)
def test_int32_binding_failure_precedes_native_directory_operations(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    option: str,
    value: int,
) -> None:
    status, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"name": "Policy", "precedence": 100, option: value},
    )
    assert status == 1 and "signed 32-bit" in result["msg"] and not directory.writes
