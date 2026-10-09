"""Check offline-hive ownership and edit cleanup without accessing Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Direct frontend calls expose result fields and native resource ordering.
# pylint: disable=protected-access

from types import ModuleType, SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

HIVE = r"C:\Owned\fixture.hive"
PATH = r"HKLM:\ANSIBLE\Settings"
WARNING = "hive already loaded at HKLM:\\ANSIBLE, had to unload hive for win_regedit to continue"


@pytest.fixture(name="payload")
def hive_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the frontend with comparison limited to this fixture's ASCII names.

    :param monkeypatch: Scoped import and native comparison substitutions.
    :returns: Imported registry payload.
    """
    payload = load_payload("win_regedit", monkeypatch)
    monkeypatch.setattr(
        payload.values, "_strings_equal", lambda left, right, _ignore: left == right
    )
    return payload


@pytest.fixture(name="native")
def hive_boundary(payload: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Mock:
    """Record native operations and handle closure in one ordered call history.

    :param payload: Imported frontend.
    :param monkeypatch: Scoped filesystem and registry substitutions.
    :returns: Native call recorder; tests provide their own open/read results.
    """
    native = Mock()
    native.exists.return_value = True
    native.hive_mount_exists.return_value = False
    native.open_key.return_value = None
    native.read_value.return_value = (None, None)
    for name in (
        "enable_hive_privileges",
        "hive_mount_exists",
        "open_key",
        "load_hive",
        "unload_hive",
        "set_value",
        "delete_value",
        "delete_tree",
    ):
        monkeypatch.setattr(payload.registry, name, getattr(native, name))
    monkeypatch.setattr(payload, "read_value", native.read_value)
    monkeypatch.setattr(
        payload, "os", SimpleNamespace(path=SimpleNamespace(exists=native.exists))
    )
    return native


def _edit(payload: ModuleType, check: bool = False, **options: Any) -> dict[str, Any]:
    arguments = {"path": PATH, "hive": HIVE, **options}
    return cast(dict[str, Any], payload._edit(payload._parameters(arguments), check))


def test_missing_file_fails_before_privileges_or_mount_access(
    payload: ModuleType, native: Mock
) -> None:
    native.exists.return_value = False
    result: dict[str, Any] = {"changed": False}
    assert payload._mount_hive(HIVE, result) is False
    assert result == {
        "changed": False,
        "failed": True,
        "msg": f"hive at path '{HIVE}' is not valid or accessible, cannot load hive",
    }
    assert native.mock_calls == [call.exists(HIVE)]


def test_privilege_failure_does_not_access_or_unload_the_mount(
    payload: ModuleType, native: Mock
) -> None:
    native.enable_hive_privileges.side_effect = OSError("privilege unavailable")
    result: dict[str, Any] = {"changed": False}
    assert payload._mount_hive(HIVE, result) is False
    assert result == {
        "changed": False,
        "failed": True,
        "msg": "failed to enable SeBackupPrivilege and SeRestorePrivilege "
        "for the current process: privilege unavailable",
    }
    assert native.mock_calls == [call.exists(HIVE), call.enable_hive_privileges()]


@pytest.mark.parametrize("privilege", ["SeBackupPrivilege", "SeRestorePrivilege"])
def test_missing_privilege_escapes_mount_handler_and_discards_edit_result_fields(
    payload: ModuleType,
    native: Mock,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    privilege: str,
) -> None:
    message = f"Cannot enable the privilege '{privilege}' as it has been removed from the token"
    # The native helper must distinguish an absent privilege from an API error:
    # upstream raises InvalidOperationException outside its Win32Exception catch.
    native.enable_hive_privileges.side_effect = ValueError(message)
    monkeypatch.setattr(
        payload,
        "read_arguments",
        Mock(
            return_value={
                "path": PATH,
                "hive": HIVE,
                "name": "entry",
                "_ansible_diff": True,
            }
        ),
    )
    code, result = invoke_payload(payload, capsys)
    assert code == 1 and result["failed"] is True and result["changed"] is False
    assert message in result["msg"]
    assert not {"data_changed", "data_type_changed", "diff"}.intersection(result)
    assert native.mock_calls == [call.exists(HIVE), call.enable_hive_privileges()]


def test_existing_mount_is_unloaded_before_loading_requested_hive(
    payload: ModuleType, native: Mock
) -> None:
    native.hive_mount_exists.return_value = True
    result: dict[str, Any] = {"changed": False, "warnings": ["earlier warning"]}
    assert payload._mount_hive(HIVE, result) is True
    assert result == {"changed": False, "warnings": ["earlier warning", WARNING]}
    assert native.mock_calls == [
        call.exists(HIVE),
        call.enable_hive_privileges(),
        call.hive_mount_exists(),
        call.unload_hive(),
        call.load_hive(HIVE),
    ]


def test_existing_mount_unload_failure_prevents_load_and_keeps_warning(
    payload: ModuleType, native: Mock
) -> None:
    native.hive_mount_exists.return_value = True
    native.unload_hive.side_effect = OSError("mount in use")
    result: dict[str, Any] = {"changed": False}
    assert payload._mount_hive(HIVE, result) is False
    assert result == {
        "changed": False,
        "warnings": [WARNING],
        "failed": True,
        "msg": f"failed to unload registry hive HKLM:\\ANSIBLE from {HIVE}: mount in use",
    }
    assert native.mock_calls[-2:] == [call.hive_mount_exists(), call.unload_hive()]
    native.load_hive.assert_not_called()


@pytest.mark.parametrize("mounted_before", [False, True])
def test_load_failure_does_not_restore_a_displaced_mount(
    payload: ModuleType, native: Mock, mounted_before: bool
) -> None:
    native.hive_mount_exists.return_value = mounted_before
    native.load_hive.side_effect = OSError("invalid hive file")
    result: dict[str, Any] = {"changed": False}
    assert payload._mount_hive(HIVE, result) is False
    assert result["changed"] is False and result["failed"] is True
    assert result["msg"] == (
        f"failed to load registry hive from '{HIVE}' to HKLM:\\ANSIBLE: invalid hive file"
    )
    assert result.get("warnings", []) == ([WARNING] if mounted_before else [])
    assert native.unload_hive.call_count == int(mounted_before)
    native.load_hive.assert_called_once_with(HIVE)
    assert native.mock_calls[-1] == call.load_hive(HIVE)


def test_mount_lookup_failure_propagates_before_loading(
    payload: ModuleType, native: Mock
) -> None:
    native.hive_mount_exists.side_effect = OSError("mount probe failed")
    with pytest.raises(OSError, match="mount probe failed"):
        payload._mount_hive(HIVE, {"changed": False})
    native.load_hive.assert_not_called()
    native.unload_hive.assert_not_called()


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize(
    "root,subkey", [("HKLM", r"ANSIBLE\Settings"), ("HKCU", r"Software\Owned")]
)
def test_edit_loads_and_unloads_even_for_check_mode_or_an_unrelated_target(
    payload: ModuleType, native: Mock, check: bool, root: str, subkey: str
) -> None:
    native.open_key.return_value = native.target_key
    path = root + ":\\" + subkey
    result = _edit(payload, check, path=path, name="entry", data="value")
    assert result == {
        "changed": True,
        "data_changed": False,
        "data_type_changed": False,
        "diff": {
            "before": {path: {}},
            "after": {path: {"entry": {"type": "String", "value": "value"}}},
        },
    }
    expected = [
        call.exists(HIVE),
        call.enable_hive_privileges(),
        call.hive_mount_exists(),
        call.load_hive(HIVE),
        call.open_key(root, subkey),
        call.read_value(native.target_key, "entry"),
    ]
    if not check:
        expected.append(call.set_value(native.target_key, "entry", "string", "value"))
    expected.extend([call.target_key.Close(), call.unload_hive()])
    assert native.mock_calls == expected


@pytest.mark.parametrize("check", [False, True])
def test_successful_mount_cycle_does_not_itself_report_changed(
    payload: ModuleType, native: Mock, check: bool
) -> None:
    native.open_key.return_value = native.target_key
    result = _edit(payload, check)
    assert result == {
        "changed": False,
        "data_changed": False,
        "data_type_changed": False,
        "diff": {"before": {PATH: {}}, "after": {PATH: {}}},
    }
    native.load_hive.assert_called_once_with(HIVE)
    native.unload_hive.assert_called_once_with()
    native.set_value.assert_not_called()
    assert native.mock_calls[-2:] == [call.target_key.Close(), call.unload_hive()]


def test_failed_mount_returns_without_editing_or_unloading_unowned_hive(
    payload: ModuleType, native: Mock
) -> None:
    native.load_hive.side_effect = OSError("load rejected")
    result = _edit(payload, name="entry", data="value")
    assert result["failed"] is True and result["changed"] is False
    assert result["data_changed"] is False and result["data_type_changed"] is False
    assert result["diff"] == {"before": "", "after": ""}
    native.hive_mount_exists.assert_called_once_with()
    native.open_key.assert_not_called()
    native.set_value.assert_not_called()
    native.unload_hive.assert_not_called()


@pytest.mark.parametrize("created_key", [False, True])
def test_write_failure_closes_the_key_and_unloads_without_losing_partial_result(
    payload: ModuleType, native: Mock, created_key: bool
) -> None:
    native.open_key.side_effect = (
        [None, native.target_key] if created_key else [native.target_key]
    )
    native.read_value.return_value = (None, None) if created_key else ("before", 1)
    native.set_value.side_effect = OSError("write denied")
    result = _edit(payload, name="entry", type="expandstring", data="after")
    assert result["failed"] is True
    assert result["changed"] is created_key
    assert result["data_changed"] is not created_key
    assert result["data_type_changed"] is not created_key
    assert "write denied" in result["msg"]
    assert result["diff"] == {
        "before": {} if created_key else {PATH: {}},
        "after": {PATH: {}},
    }
    if created_key:
        assert (
            call.open_key("HKLM", r"ANSIBLE\Settings", create=True) in native.mock_calls
        )
    assert native.mock_calls[-2:] == [call.target_key.Close(), call.unload_hive()]
    native.unload_hive.assert_called_once_with()


@pytest.mark.parametrize("stage", ["open", "read"])
def test_uncaught_operation_failure_still_unloads_owned_mount(
    payload: ModuleType, native: Mock, stage: str
) -> None:
    if stage == "open":
        native.open_key.side_effect = OSError("operation denied")
    else:
        native.open_key.return_value = native.target_key
        native.read_value.side_effect = OSError("operation denied")
    with pytest.raises(OSError, match="operation denied"):
        _edit(payload, name="entry", data="value")
    native.unload_hive.assert_called_once_with()
    if stage == "read":
        assert native.mock_calls[-2:] == [call.target_key.Close(), call.unload_hive()]
    else:
        native.target_key.Close.assert_not_called()


@pytest.mark.parametrize("write_fails", [False, True])
def test_final_unload_failure_propagates_after_handle_closure(
    payload: ModuleType, native: Mock, write_fails: bool
) -> None:
    native.open_key.return_value = native.target_key
    if write_fails:
        native.set_value.side_effect = OSError("write denied")
    native.unload_hive.side_effect = OSError("unload rejected")
    with pytest.raises(OSError, match="unload rejected"):
        _edit(payload, name="entry", data="value")
    native.set_value.assert_called_once_with(
        native.target_key, "entry", "string", "value"
    )
    assert native.mock_calls[-2:] == [call.target_key.Close(), call.unload_hive()]


def test_invalid_data_fails_before_any_offline_hive_access(
    payload: ModuleType, native: Mock
) -> None:
    result = _edit(payload, name="entry", type="dword", data=1.5)
    assert result["failed"] is True and "remainder" in result["msg"]
    assert native.mock_calls == []
