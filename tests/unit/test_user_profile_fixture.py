"""Exercise owned profile journals, failure retention and fixture contracts."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Definitions are loaded without executing Windows fixture operations.
# pylint: disable=exec-used

import ast
import copy
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, cast
from unittest.mock import MagicMock, Mock

import pytest

# The pinned development environment supplies PyYAML without typing stubs.
import yaml  # type: ignore[import-untyped]
from ansible.parsing.dataloader import DataLoader  # type: ignore[import-untyped]
from ansible.template import (  # type: ignore[import-untyped]
    Templar,
    trust_as_template,
)

from tests.unit.payload_support import ROOT


def _document(name: str) -> Any:
    return yaml.safe_load(
        (ROOT / "tests/integration" / name).read_text(encoding="utf-8")
    )


@pytest.fixture(name="fixture")
def profile_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Load profile fixture definitions with private native substitutes.

    :param tmp_path: Isolated journal and profile root.
    :param monkeypatch: Scoped target module substitutes.
    :returns: Fixture namespace without target execution.
    """
    for name in (
        "winreg",
        "legacy_windows_account",
        "legacy_windows_user",
        "legacy_windows_owner",
    ):
        monkeypatch.setitem(sys.modules, name, ModuleType(name))
    monkeypatch.setattr(sys, "argv", ["fixture", str(tmp_path), "setup"])
    source = _document("vars/user_profile_fixture.yml")["user_profile_fixture"]
    namespace: dict[str, Any] = {"__name__": "fixture"}
    exec(compile(source, "user_profile_fixture.py", "exec"), namespace)
    root = tmp_path / "profiles"
    root.mkdir()
    namespace["profile_root"] = Mock(return_value=str(root))
    namespace["registry_tree"] = Mock(
        return_value={
            "values": {"ProfilesDirectory": [str(root), 2]},
            "children": {
                "S-1-5-18": {
                    "values": {"ProfileImagePath": ["system-profile", 1]},
                    "children": {},
                }
            },
        }
    )
    namespace["identities"] = Mock(return_value={"Existing": "S-1-5-21-100"})
    namespace["attributes"] = Mock(
        side_effect=lambda path: 16 if Path(path).exists() else None
    )
    namespace["userenv"] = Mock(return_value=Mock(CreateProfile=Mock()))
    local: dict[str, str] = {}
    user = namespace["users"]
    user.read_user = Mock(
        side_effect=lambda name: {"sid": local[name]} if name in local else None
    )

    def _create(name: str, password: str, flags: int) -> None:
        record = _journal(namespace)
        assert password == record["password"] and flags == 0x10200
        assert any(
            row["name"] == name and row["creating"]
            for row in record["accounts"].values()
        )
        local[name] = "S-1-5-21-" + str(1000 + len(local))

    user.create_user = Mock(side_effect=_create)
    user.delete_user = Mock(side_effect=local.pop)
    namespace["local"] = local
    namespace["delete_native"] = Mock()
    return namespace


def _journal(fixture: dict[str, Any]) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads(Path(fixture["journal_path"]).read_text(encoding="utf-8")),
    )


def test_complete_original_state_is_flushed_before_each_account_creation(
    fixture: dict[str, Any],
) -> None:
    setup = fixture["setup"]()
    record = _journal(fixture)
    assert setup["journaled"] and record["before"] == setup["before"]
    assert len(record["owned_sids"]) == 4
    assert len(set(record["owned_sids"])) == 4
    assert "password" not in setup["context"]
    assert "password" not in json.dumps(setup)


def test_existing_journal_is_never_overwritten(fixture: dict[str, Any]) -> None:
    fixture["setup"]()
    original = Path(fixture["journal_path"]).read_bytes()
    with pytest.raises(ValueError, match="must not be overwritten"):
        fixture["setup"]()
    assert Path(fixture["journal_path"]).read_bytes() == original


@pytest.mark.parametrize(
    "operation,error",
    [
        ("dump", KeyboardInterrupt),
        ("dump", OSError),
        ("fsync", OSError),
        ("replace", OSError),
    ],
)
def test_interrupted_journal_update_retains_previous_valid_recovery(
    fixture: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    error: type[BaseException],
) -> None:
    fixture["setup"]()
    previous = _journal(fixture)
    path = Path(fixture["journal_path"])
    original = path.read_bytes()
    updated = copy.deepcopy(previous)
    updated["pending_step"] = "not yet authorized by a flushed journal"

    def _interrupt(*arguments: Any, **_keywords: Any) -> None:
        if operation == "dump":
            arguments[1].write("{")
        raise error("Interrupted journal replacement")

    with monkeypatch.context() as patch:
        library = fixture["json"] if operation == "dump" else fixture["os"]
        patch.setattr(library, operation, _interrupt)
        with pytest.raises(error, match="Interrupted journal replacement"):
            fixture["write_journal"](updated)
    assert path.read_bytes() == original and _journal(fixture) == previous
    assert not list(path.parent.glob(".user-profile-recovery-*"))
    fixture["users"].delete_user.assert_not_called()
    assert fixture["cleanup"]()["restored"]


def test_failed_journal_flush_retains_previous_valid_recovery(
    fixture: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture["setup"]()
    path = Path(fixture["journal_path"])
    original = path.read_bytes()
    updated = _journal(fixture)
    updated["pending_step"] = "not yet flushed"
    temporary = fixture["tempfile"].NamedTemporaryFile

    def _failing_flush(*arguments: Any, **keywords: Any) -> Any:
        stream = temporary(*arguments, **keywords)
        stream.flush = Mock(side_effect=OSError("Journal flush failed"))
        return stream

    with monkeypatch.context() as patch:
        patch.setattr(fixture["tempfile"], "NamedTemporaryFile", _failing_flush)
        with pytest.raises(OSError, match="Journal flush failed"):
            fixture["write_journal"](updated)
    assert path.read_bytes() == original
    assert not list(path.parent.glob(".user-profile-recovery-*"))
    assert fixture["cleanup"]()["restored"]


def test_journal_replacement_occurs_only_after_complete_write_and_fsync(
    fixture: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture["setup"]()
    path = Path(fixture["journal_path"])
    original = path.read_bytes()
    updated = _journal(fixture)
    updated["pending_step"] = "fully recorded before target mutation"
    fsync = fixture["os"].fsync
    replace = fixture["os"].replace
    events: list[str] = []

    def _sync(descriptor: int) -> None:
        assert fixture["os"].fstat(descriptor).st_size == len(
            json.dumps(updated, sort_keys=True).encode("utf-8")
        )
        fsync(descriptor)
        events.append("flushed")

    def _replace(source: str, destination: str) -> None:
        assert events == ["flushed"] and destination == str(path)
        assert Path(source).parent == path.parent
        assert json.loads(Path(source).read_text(encoding="utf-8")) == updated
        assert path.read_bytes() == original
        replace(source, destination)
        events.append("replaced")

    with monkeypatch.context() as patch:
        patch.setattr(fixture["os"], "fsync", _sync)
        patch.setattr(fixture["os"], "replace", _replace)
        fixture["write_journal"](updated)
    assert events == ["flushed", "replaced"] and _journal(fixture) == updated
    assert not list(path.parent.glob(".user-profile-recovery-*"))


def test_preexisting_prefix_fails_before_accounts_or_journal(
    fixture: dict[str, Any],
) -> None:
    fixture["uuid"] = Mock(uuid4=Mock(return_value=Mock(hex="abcdefg0000")))
    fixture["identities"].return_value["lwup_abcdefg_0"] = "S-existing"
    with pytest.raises(ValueError, match="already exists"):
        fixture["setup"]()
    fixture["users"].create_user.assert_not_called()
    assert not Path(fixture["journal_path"]).exists()


@pytest.mark.parametrize("field", ["workspace", "roles", "root"])
def test_tampered_ownership_retains_journal_before_cleanup(
    fixture: dict[str, Any], field: str
) -> None:
    fixture["setup"]()
    record = _journal(fixture)
    record[field] = "unowned"
    fixture["write_journal"](record)
    with pytest.raises(ValueError):
        fixture["cleanup"]()
    fixture["delete_native"].assert_not_called()
    fixture["users"].delete_user.assert_not_called()
    assert Path(fixture["journal_path"]).exists()


def test_replaced_account_identity_is_not_deleted(fixture: dict[str, Any]) -> None:
    fixture["setup"]()
    record = _journal(fixture)
    fixture["local"][record["accounts"]["primary"]["name"]] = "S-replaced"
    with pytest.raises(ValueError, match="does not match journal"):
        fixture["cleanup"]()
    fixture["users"].delete_user.assert_not_called()
    assert Path(fixture["journal_path"]).exists()


def test_partially_created_owned_account_is_adopted_for_strict_cleanup(
    fixture: dict[str, Any],
) -> None:
    fixture["setup"]()
    record = _journal(fixture)
    row = record["accounts"]["primary"]
    record["owned_sids"].remove(row["sid"])
    row.update({"sid": None, "creating": True})
    fixture["write_journal"](record)
    assert fixture["cleanup"]()["restored"]
    assert not fixture["local"] and not Path(fixture["journal_path"]).exists()


def test_collision_marker_drift_is_not_deleted(fixture: dict[str, Any]) -> None:
    fixture["setup"]()
    record = _journal(fixture)
    marker = (
        Path(record["root"]) / record["bases"]["collision"] / "owned-collision-marker"
    )
    marker.write_bytes(b"unowned replacement")
    with pytest.raises(ValueError, match="marker identity changed"):
        fixture["cleanup"]()
    assert marker.read_bytes() == b"unowned replacement"
    assert Path(fixture["journal_path"]).exists()


def test_recreated_orphan_journals_incomplete_identity_before_creation(
    fixture: dict[str, Any],
) -> None:
    fixture["setup"]()
    record = _journal(fixture)
    row = record["accounts"]["orphan"]
    previous = row["sid"]
    fixture["local"].pop(row["name"])

    def _interrupted(name: str, *_args: Any) -> None:
        early = _journal(fixture)
        assert early["accounts"]["orphan"]["sid"] is None
        assert early["accounts"]["orphan"]["creating"]
        assert previous in early["owned_sids"]
        fixture["local"][name] = "S-1-5-21-new-orphan"
        raise OSError("Controller interrupted after native creation")

    fixture["users"].create_user.side_effect = _interrupted
    with pytest.raises(OSError, match="interrupted"):
        fixture["create_account"](record, "orphan")
    assert fixture["cleanup"]()["restored"]
    assert not Path(fixture["journal_path"]).exists()


def test_multiple_alias_original_values_are_flushed_before_write(
    fixture: dict[str, Any],
) -> None:
    fixture["setup"]()
    record = _journal(fixture)
    children = fixture["registry_tree"].return_value["children"]
    for role in ("primary", "multiple"):
        path = str(Path(record["root"]) / record["bases"][role])
        children[record["accounts"][role]["sid"]] = {
            "values": {"ProfileImagePath": [path, 1]},
            "children": {},
        }
    fixture["winreg"].HKEY_LOCAL_MACHINE = 0
    fixture["winreg"].KEY_SET_VALUE = 2
    fixture["winreg"].REG_EXPAND_SZ = 2
    fixture["winreg"].OpenKey = Mock(return_value=Mock())
    fixture["winreg"].OpenKey.return_value.__enter__ = Mock(return_value="key")
    fixture["winreg"].OpenKey.return_value.__exit__ = Mock(return_value=False)

    def _write(*_args: Any) -> None:
        aliases = _journal(fixture)["aliases"]
        assert len(aliases) == 2
        assert all(
            aliases[record["accounts"][role]["sid"]]
            == children[record["accounts"][role]["sid"]]["values"]["ProfileImagePath"]
            for role in ("primary", "multiple")
        )

    fixture["winreg"].SetValueEx = Mock(side_effect=_write)
    fixture["alias_multiple"](record)
    fixture["winreg"].SetValueEx.assert_called_once()


def test_outside_profile_path_is_rejected_before_native_deletion(
    fixture: dict[str, Any],
) -> None:
    fixture["setup"]()
    record = _journal(fixture)
    fixture["registry_tree"].return_value["children"][record["owned_sids"][0]] = {
        "values": {"ProfileImagePath": ["/preexisting-profile", 1]},
        "children": {},
    }
    with pytest.raises(ValueError, match="outside owned"):
        fixture["cleanup"]()
    fixture["delete_native"].assert_not_called()
    assert Path(fixture["journal_path"]).exists()


def test_exact_original_state_cleanup_removes_only_owned_users_and_guard(
    fixture: dict[str, Any],
) -> None:
    setup = fixture["setup"]()
    recovered = fixture["cleanup"]()
    assert recovered["restored"]
    assert all(
        recovered["after"][key] == setup["before"][key]
        for key in ("registry", "accounts", "directories")
    )
    assert fixture["users"].delete_user.call_count == 4
    fixture["delete_native"].assert_not_called()
    assert not Path(fixture["journal_path"]).exists()


def test_unrelated_state_drift_retains_journal(fixture: dict[str, Any]) -> None:
    fixture["setup"]()
    fixture["identities"].return_value["Unrelated"] = "S-new"
    with pytest.raises(ValueError, match="Pre-existing"):
        fixture["cleanup"]()
    assert Path(fixture["journal_path"]).exists()


def test_recovery_error_preserves_retryable_journal(fixture: dict[str, Any]) -> None:
    fixture["setup"]()
    fixture["delete_native"].side_effect = OSError("Native deletion failed")
    record = _journal(fixture)
    sid = record["owned_sids"][0]
    fixture["registry_tree"].return_value["children"][sid] = {
        "values": {
            "ProfileImagePath": [
                str(Path(record["root"]) / record["accounts"]["primary"]["name"]),
                1,
            ]
        },
        "children": {},
    }
    with pytest.raises(OSError, match="Native deletion failed"):
        fixture["cleanup"]()
    assert Path(fixture["journal_path"]).exists()


def _unregistered_profile(fixture: dict[str, Any]) -> tuple[dict[str, Any], str, str]:
    fixture["setup"]()
    record = _journal(fixture)
    sid = record["accounts"]["multiple"]["sid"]
    path = str(Path(record["root"]) / record["bases"]["multiple"])
    Path(path).mkdir()
    node = {
        "values": {"ProfileImagePath": [path, 1], "Sid": [{"hex": "0102"}, 3]},
        "children": {},
    }
    record["paths"][sid] = [path]
    record["profile_nodes"][sid] = {path: node}
    fixture["winreg"].HKEY_LOCAL_MACHINE = 0
    fixture["winreg"].KEY_SET_VALUE = 2
    fixture["winreg"].CreateKeyEx = MagicMock()
    fixture["winreg"].SetValueEx = Mock()
    return record, sid, path


def test_unregistered_directory_recovery_journals_captured_key_before_native_removal(
    fixture: dict[str, Any],
) -> None:
    record, sid, path = _unregistered_profile(fixture)
    children = fixture["registry_tree"].return_value["children"]
    restored: dict[str, Any] = {}

    def _register(*_args: Any) -> MagicMock:
        early = _journal(fixture)
        assert early["recovery_registrations"] == [{"sid": sid, "path": path}]
        assert early["profile_nodes"][sid][path] == record["profile_nodes"][sid][path]
        children[sid] = {"values": restored, "children": {}}
        return MagicMock()

    def _write(_key: Any, name: str, _reserved: int, kind: int, value: Any) -> None:
        restored[name] = [value, kind]

    def _delete(actual_sid: str) -> None:
        assert actual_sid == sid
        assert restored == {"ProfileImagePath": [path, 1], "Sid": [b"\x01\x02", 3]}
        children.pop(sid)
        Path(path).rmdir()

    fixture["winreg"].CreateKeyEx.side_effect = _register
    fixture["winreg"].SetValueEx.side_effect = _write
    fixture["delete_native"].side_effect = _delete
    fixture["recover_registration"](record, sid, path)
    fixture["delete_native"].assert_called_once_with(sid)
    assert not Path(path).exists()


@pytest.mark.parametrize(
    "invalid", ["missing-node", "children", "foreign-sid", "reparse"]
)
def test_unregistered_recovery_refuses_unproven_identity_or_junction_root(
    fixture: dict[str, Any], invalid: str
) -> None:
    record, sid, path = _unregistered_profile(fixture)
    if invalid == "missing-node":
        record["profile_nodes"] = {}
    elif invalid == "children":
        record["profile_nodes"][sid][path]["children"] = {"unexpected": {}}
    elif invalid == "foreign-sid":
        record["before"]["registry"]["children"][sid] = {"values": {}, "children": {}}
    else:
        fixture["attributes"].side_effect = None
        fixture["attributes"].return_value = 0x410
    with pytest.raises(ValueError, match="not journal-owned"):
        fixture["recover_registration"](record, sid, path)
    fixture["winreg"].CreateKeyEx.assert_not_called()
    fixture["delete_native"].assert_not_called()
    assert Path(fixture["journal_path"]).exists() and Path(path).exists()


def test_failed_unregistered_native_removal_retains_registration_and_journal(
    fixture: dict[str, Any],
) -> None:
    record, sid, path = _unregistered_profile(fixture)
    fixture["delete_native"].side_effect = OSError("Native recovery deletion failed")
    with pytest.raises(OSError, match="recovery deletion failed"):
        fixture["recover_registration"](record, sid, path)
    assert _journal(fixture)["recovery_registrations"] == [{"sid": sid, "path": path}]
    assert Path(path).exists()


def test_unowned_keys_values_and_identities_are_not_hidden(
    fixture: dict[str, Any],
) -> None:
    fixture["setup"]()
    record = _journal(fixture)
    observed = fixture["observe"](record)
    fixture["require_unowned_unchanged"](record, observed)
    drift = copy.deepcopy(observed)
    drift["registry"]["values"]["New"] = ["unexpected", 1]
    with pytest.raises(ValueError, match="Pre-existing"):
        fixture["require_unowned_unchanged"](record, drift)


def test_fixture_uses_target_syntax_and_never_recursive_profile_deletion() -> None:
    source = _document("vars/user_profile_fixture.yml")["user_profile_fixture"]
    ast.parse(source, feature_version=(3, 4))
    assert "shutil" not in source and "os.walk" not in source
    assert "DeleteProfileW" in source and "LoadUserProfileW" in source
    assert "UnloadUserProfile" in source and "CloseHandle" in source
    assert "SeBackupPrivilege" in source and "SeRestorePrivilege" in source


def test_every_fixture_assertion_is_a_string_or_boolean() -> None:
    def _visit(node: Any) -> None:
        if isinstance(node, dict):
            if "that" in node:
                assert isinstance(node["that"], list)
                assert all(isinstance(item, (str, bool)) for item in node["that"])
            for value in node.values():
                _visit(value)
        elif isinstance(node, list):
            for value in node:
                _visit(value)

    _visit(_document("win_user_profile.yml"))
    _visit(_document("tasks/win_user_profile_case.yml"))


def test_cases_cover_source_binding_shapes_and_owned_lifecycles() -> None:
    document = _document("vars/user_profile.yml")
    assert len(document["user_profile_binding_cases"]) == 14
    assert len(document["user_profile_lifecycle_cases"]) == 26
    assert len(document["user_profile_review_cases"]) == 10
    nulls = document["user_profile_review_cases"][:4]
    assert nulls[0]["params"] == {"username": None}
    assert {tuple(sorted(row["params"])) for row in nulls[1:]} == {
        ("name", "state"),
        ("state", "username"),
        ("name", "state", "username"),
    }
    assert len(document["user_profile_legacy_cases"]) == 9
    assert any(
        row["params"].get("state", "present") is None
        for row in document["user_profile_binding_cases"]
    )
    cases = document["user_profile_lifecycle_cases"]
    assert {row["prepare"] for row in cases if "prepare" in row} == {
        "alias-multiple",
        "delete-orphan",
    }


def test_complete_results_are_compared_without_field_exclusions() -> None:
    main = (ROOT / "tests/integration/win_user_profile.yml").read_text()
    case = (ROOT / "tests/integration/tasks/win_user_profile_case.yml").read_text()
    assert "native == original" in main
    assert "map(attribute='result')" in main
    assert "dict2items" not in main and "rejectattr" not in main
    assert case.index("Save complete public results before assertions") < case.index(
        "Verify public change failure and no-mutation behavior"
    )


def test_default_full_comparison_is_retained_when_no_trusted_scope_is_supplied() -> (
    None
):
    document = _document("win_user_profile.yml")
    source = (ROOT / "tests/integration/win_user_profile.yml").read_text()
    assert "user_profile_original_expected_count | default(50)" in source
    assert "native == original, native | length == 50" in source
    assert "user_profile_retained_comparison | default(false)" in source
    assert document[0]["hosts"] == "legacy_windows"


def test_predicted_path_uses_actual_ansible_escaping_without_duplicate_separator() -> (
    None
):
    document = _document("tasks/win_user_profile_case.yml")
    block = document[1]["block"]
    task = next(row for row in block if "expected_path" in row.get("vars", {}))
    templar = Templar(
        loader=DataLoader(),
        variables={
            "user_profile_names": {"root": r"C:\Users"},
            "user_profile_separator": _document("win_user_profile.yml")[0]["vars"][
                "user_profile_separator"
            ],
            "user_profile_case": {"predicted_name": "owned-profile"},
            "before": {},
            "after": {},
        },
    )
    actual = templar.template(trust_as_template(task["vars"]["expected_path"]))
    assert actual == r"C:\Users\owned-profile"
    assert actual.count("\\") == 2
