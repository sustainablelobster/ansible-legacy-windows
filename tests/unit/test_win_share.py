"""Exercise win_share JSON results, ordered operations, and recovery."""

# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, Callable
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

Request = Callable[[dict[str, Any]], tuple[int, dict[str, Any]]]
ShareStore = dict[str, dict[str, Any]]
NAME = "Owned Share"
PATH = "C:\\Owned\\Share"
OTHER_PATH = "C:\\Owned\\Other"


def _new_share(name: str, path: str) -> dict[str, Any]:
    return {
        "name": name,
        "path": path,
        "description": "",
        "list": True,
        "caching_mode": "Manual",
        "encrypt": False,
        "scope_name": "*",
        "access": [{"account": "Everyone", "control": "Allow", "right": "Read"}],
    }


@pytest.fixture(name="stored")
def stored_fixture() -> ShareStore:
    """Keep native share observations separate from module argument objects.

    :returns: Mutable owned-share store used by the fake native boundary.
    """
    return {}


@pytest.fixture(name="native")
def native_fixture(stored: ShareStore) -> Mock:
    """Model individual share operations and provider-like initial access.

    :param stored: Mutable owned-share snapshots.
    :returns: Mocked public share boundary.
    """
    native = Mock()
    native.get_share.side_effect = lambda name: copy.deepcopy(stored.get(name))
    native.create_share.side_effect = lambda name, path: stored.update(
        {name: _new_share(name, path)}
    )
    native.delete_share.side_effect = stored.pop
    native.set_property.side_effect = lambda name, field, value: stored[name].update(
        {field: value}
    )
    native.normalize_account.side_effect = lambda name: (
        name if "\\" in name or name == "Everyone" else "BUILTIN\\" + name
    )
    native.access_entries.side_effect = lambda share: copy.deepcopy(
        share["access"]
    ) or [{"account": "Everyone", "control": "Deny", "right": "Full"}]

    def change_access(
        name: str, identity: str, right: str, control: str, remove: bool = False
    ) -> None:
        entries = stored[name]["access"]
        entries[:] = [
            entry
            for entry in entries
            if not (entry["account"] == identity and entry["control"] == control)
        ]
        if not remove:
            entry = {"account": identity, "right": right, "control": control}
            if control == "Deny":
                entries.insert(0, entry)
            else:
                entries.append(entry)

    native.change_access.side_effect = change_access
    return native


@pytest.fixture(name="payload")
def payload_fixture(monkeypatch: pytest.MonkeyPatch, native: Mock) -> ModuleType:
    """Load the payload and substitute only its native operations and paths.

    :param monkeypatch: Scoped substitutions.
    :param native: Mock native share interface.
    :returns: Loaded target module.
    """
    module = load_payload("win_share", monkeypatch)
    monkeypatch.setattr(module, "shares", native)
    monkeypatch.setattr(
        module.sys,
        "getwindowsversion",
        lambda: SimpleNamespace(
            major=10, minor=0, service_pack_major=0, product_type=3
        ),
        raising=False,
    )
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    monkeypatch.setattr(
        module.environment,
        "values_equal",
        lambda left, right: (
            left is right
            if left is None or right is None
            else left.lower() == right.lower()
        ),
    )
    # pylint: enable=duplicate-code
    monkeypatch.setattr(
        module.os.path,
        "exists",
        lambda path: path in (PATH, OTHER_PATH, PATH + "\\", "C:\\"),
    )
    monkeypatch.setattr(module.os.path, "abspath", lambda path: path)
    return module


@pytest.fixture(name="run_request")
def request_fixture(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> Request:
    """Invoke the real JSON entry point for each public run_request.

    :param payload: Loaded target payload.
    :param monkeypatch: Scoped argv substitute.
    :param tmp_path: Isolated run_request directory.
    :param capsys: JSON stdout capture.
    :returns: Request runner returning status and whole result.
    """
    argument_file = tmp_path / "arguments.json"

    def _run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        argument_file.write_text(json.dumps(arguments), encoding="utf-8")
        monkeypatch.setattr(sys, "argv", ["win_share.py", str(argument_file)])
        return invoke_payload(payload, capsys)

    return _run


def test_missing_share_check_stops_after_creation(
    run_request: Request, native: Mock, stored: ShareStore
) -> None:
    status, result = run_request(
        {
            "name": NAME,
            "path": PATH,
            "description": "text",
            "full": "Administrators",
            "_ansible_check_mode": True,
            "_ansible_diff": True,
        }
    )
    assert status == 0
    assert result == {
        "changed": True,
        "actions": ["New-SmbShare -Name " + NAME + " -Path " + PATH],
    }
    assert not stored
    native.create_share.assert_not_called()
    native.access_entries.assert_not_called()


def test_create_repeat_and_remove_keep_directory(
    run_request: Request, stored: ShareStore, native: Mock
) -> None:
    arguments = {
        "name": NAME,
        "path": PATH,
        "description": "description",
        "full": "Administrators",
    }
    status, created = run_request(arguments)
    assert status == 0 and created["changed"]
    assert created["actions"] == [
        "New-SmbShare -Name " + NAME + " -Path " + PATH,
        "Set-SmbShare -Force -Name " + NAME + " -Description description",
        "Set-SmbShare -Force -Name " + NAME + " -FolderEnumerationMode AccessBased",
        "Revoke-SmbShareAccess -Force -Name " + NAME + " -AccountName Everyone",
        "Grant-SmbShareAccess -Force -Name "
        + NAME
        + " -AccountName BUILTIN\\Administrators -AccessRight Full",
    ]
    assert run_request(arguments) == (0, {"changed": False, "actions": []})
    before = copy.deepcopy(stored)
    assert run_request(
        {"name": NAME, "state": "absent", "_ansible_check_mode": True}
    ) == (
        0,
        {"changed": True, "actions": ["Remove-SmbShare -Force -Name " + NAME]},
    )
    assert stored == before
    assert run_request({"name": NAME, "state": "absent"}) == (
        0,
        {"changed": True, "actions": ["Remove-SmbShare -Force -Name " + NAME]},
    )
    assert run_request(
        {"name": NAME, "state": "absent", "path": None, "read": None}
    ) == (
        0,
        {"changed": False, "actions": []},
    )
    native.delete_share.assert_called_once_with(NAME)


def test_replace_path_check_uses_old_properties_and_access(
    run_request: Request, stored: ShareStore, native: Mock
) -> None:
    run_request(
        {"name": NAME, "path": PATH, "description": "old", "full": "Administrators"}
    )
    native.reset_mock()
    before = copy.deepcopy(stored)
    arguments = {
        "name": NAME,
        "path": OTHER_PATH,
        "description": "old",
        "full": "Administrators",
        "_ansible_check_mode": True,
    }
    assert run_request(arguments) == (
        0,
        {
            "changed": True,
            "actions": [
                "Remove-SmbShare -Force -Name " + NAME,
                "New-SmbShare -Name " + NAME + " -Path " + OTHER_PATH,
            ],
        },
    )
    assert stored == before
    native.delete_share.assert_not_called()
    native.create_share.assert_not_called()
    arguments["_ansible_check_mode"] = False
    status, result = run_request(arguments)
    assert status == 0 and result["changed"]
    assert len(result["actions"]) == 6
    assert stored[NAME]["path"] == OTHER_PATH


def test_property_order_and_case_only_noop(
    run_request: Request, stored: ShareStore, native: Mock
) -> None:
    run_request({"name": NAME, "path": PATH})
    arguments = {
        "name": NAME,
        "path": PATH,
        "description": "Changed",
        "list": True,
        "caching_mode": "Programs",
        "encrypt": True,
        "scope_name": "Scoped",
        "_ansible_check_mode": True,
    }
    snapshot = copy.deepcopy(stored)
    status, result = run_request(arguments)
    assert status == 0
    assert result["actions"] == [
        "Set-SmbShare -Force -Name " + NAME + " -Description Changed",
        "Set-SmbShare -Force -Name " + NAME + " -FolderEnumerationMode Unrestricted",
        "Set-SmbShare -Force -Name " + NAME + " -CachingMode Programs",
        "Set-SmbShare -Force -Name " + NAME + " -EncryptData True",
        "Set-SmbShare -Force -Name " + NAME + " -ScopeName Scoped",
    ]
    assert stored == snapshot
    arguments["_ansible_check_mode"] = False
    arguments.pop("scope_name")
    run_request(arguments)
    native.reset_mock()
    arguments.update(description="changed", caching_mode="programs")
    assert run_request(arguments) == (0, {"changed": False, "actions": []})
    native.set_property.assert_not_called()
    assert stored[NAME]["description"] == "Changed"


def test_permissions_cleanup_add_replace_and_duplicates(
    run_request: Request, stored: ShareStore
) -> None:
    run_request({"name": NAME, "path": PATH})
    arguments = {
        "name": NAME,
        "path": PATH,
        "read": "Guests,Administrators,Users",
        "change": "Users,Administrators",
        "full": "Administrators",
        "deny": "Remote Desktop Users",
    }
    status, result = run_request(arguments)
    assert status == 0
    assert [entry["right"] for entry in stored[NAME]["access"]] == [
        "Full",
        "Read",
        "Change",
        "Full",
    ]
    assert len(result["actions"]) == 4
    assert run_request(arguments) == (0, {"changed": False, "actions": []})
    added = {
        "name": NAME,
        "path": PATH,
        "change": "Remote Desktop Users",
        "rule_action": "add",
    }
    assert run_request(added)[1]["actions"] == [
        "Grant-SmbShareAccess -Force -Name "
        + NAME
        + " -AccountName BUILTIN\\Remote Desktop Users -AccessRight Change"
    ]
    assert run_request(added) == (0, {"changed": False, "actions": []})
    assert len(stored[NAME]["access"]) == 5
    cleared = run_request({"name": NAME, "path": PATH})[1]
    assert len(cleared["actions"]) == 5
    assert cleared["actions"][0].startswith("Unblock-SmbShareAccess")
    assert stored[NAME]["access"] == []
    assert run_request({"name": NAME, "path": PATH}) == (
        0,
        {"changed": False, "actions": []},
    )


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({}, "Get-AnsibleParam: Missing required argument: name"),
        ({"name": NAME}, "Get-AnsibleParam: Missing required argument: path"),
        (
            {"name": NAME, "state": "broken"},
            "Get-AnsibleParam: Argument state needs to be one of present,absent but was broken.",
        ),
        (
            {"name": NAME, "state": None},
            "Get-AnsibleParam: Argument state needs to be one of present,absent but was .",
        ),
        (
            {"name": NAME, "state": "absent", "rule_action": "broken"},
            "Get-AnsibleParam: Argument rule_action needs to be one of set,add but was broken.",
        ),
        (
            {"name": NAME, "path": PATH, "caching_mode": "broken"},
            "Get-AnsibleParam: Argument caching_mode needs to be one of "
            "BranchCache,Documents,Manual,None,Programs,Unknown but was broken.",
        ),
    ],
)
def test_argument_failure_does_not_write(
    run_request: Request, native: Mock, arguments: dict[str, Any], message: str
) -> None:
    status, result = run_request(arguments)
    assert status == 1
    assert result == {
        "changed": False,
        "failed": True,
        "msg": message,
        "exception": "(traceback unavailable)",
    }
    native.create_share.assert_not_called()
    native.delete_share.assert_not_called()
    native.set_property.assert_not_called()
    native.change_access.assert_not_called()


def test_missing_path_failure_keeps_actions(run_request: Request, native: Mock) -> None:
    assert run_request({"name": NAME, "path": "C:\\Missing"}) == (
        1,
        {
            "changed": False,
            "actions": [],
            "failed": True,
            "msg": "C:\\Missing directory does not exist on the host",
        },
    )
    native.create_share.assert_not_called()


@pytest.mark.parametrize(
    "value,expected",
    [
        (True, True),
        ("YES", True),
        ("on", True),
        (1, True),
        ("unexpected", False),
        (" true ", False),
    ],
)
def test_legacy_boolean_and_unknown_option_binding(
    run_request: Request, value: object, expected: bool
) -> None:
    status, result = run_request(
        {"name": NAME, "path": PATH, "list": value, "unsupported": "ignored"}
    )
    assert status == 0
    assert (
        any("FolderEnumerationMode" in action for action in result["actions"])
        is not expected
    )


def test_partial_failure_leaves_prior_changes_then_recovers(
    run_request: Request, native: Mock, stored: ShareStore
) -> None:
    native.change_access.side_effect = OSError(5, "denied")
    status, result = run_request(
        {
            "name": NAME,
            "path": PATH,
            "description": "completed",
            "full": "Administrators",
        }
    )
    assert status == 1 and result["failed"] and not result["changed"]
    assert result["msg"].endswith("denied")
    assert stored[NAME]["description"] == "completed"
    assert not stored[NAME]["list"]
    assert run_request({"name": NAME, "state": "absent"})[0] == 0
    assert not stored


@pytest.mark.parametrize(
    "arguments,message",
    [
        (
            {"name": None, "path": PATH},
            "Cannot validate argument on parameter 'Name'. "
            "The argument is null. Provide a valid value for the argument, "
            "and then try running the command again.",
        ),
        (
            {"name": NAME, "path": None},
            "Cannot bind argument to parameter 'LiteralPath' because it is null.",
        ),
        (
            {"name": NAME, "path": PATH, "read": None},
            "You cannot call a method on a null-valued expression.",
        ),
    ],
)
def test_measured_null_failures_keep_exact_schema_without_writes(
    run_request: Request, native: Mock, arguments: dict[str, Any], message: str
) -> None:
    arguments["_ansible_check_mode"] = True
    assert run_request(arguments) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "Unhandled exception while executing module: " + message,
            "exception": "(traceback unavailable)",
        },
    )
    native.create_share.assert_not_called()
    native.set_property.assert_not_called()
    native.change_access.assert_not_called()


def test_empty_name_prediction_is_accepted_without_writes(
    run_request: Request, native: Mock
) -> None:
    assert run_request({"name": "", "path": PATH, "_ansible_check_mode": True}) == (
        0,
        {"changed": True, "actions": ["New-SmbShare -Name  -Path " + PATH]},
    )
    native.create_share.assert_not_called()


def test_add_mode_replaces_existing_right_then_repeats(
    run_request: Request, stored: ShareStore
) -> None:
    run_request({"name": NAME, "path": PATH, "full": "Administrators"})
    arguments = {
        "name": NAME,
        "path": PATH,
        "rule_action": "add",
        "read": "Administrators",
    }
    assert run_request(arguments)[1]["actions"] == [
        "Grant-SmbShareAccess -Force -Name "
        + NAME
        + " -AccountName BUILTIN\\Administrators -AccessRight Read"
    ]
    assert stored[NAME]["access"] == [
        {"account": "BUILTIN\\Administrators", "control": "Allow", "right": "Read"}
    ]
    assert run_request(arguments) == (0, {"changed": False, "actions": []})
    arguments.pop("read")
    arguments["change"] = "Administrators"
    assert run_request(arguments)[1]["actions"] == [
        "Grant-SmbShareAccess -Force -Name "
        + NAME
        + " -AccountName BUILTIN\\Administrators -AccessRight Change"
    ]
    assert stored[NAME]["access"][0]["right"] == "Change"
    assert run_request(arguments) == (0, {"changed": False, "actions": []})


def test_measured_scope_failure_discards_actions_and_preserves_prior_state(
    run_request: Request, native: Mock, stored: ShareStore
) -> None:
    run_request({"name": NAME, "path": PATH, "change": "Administrators"})
    before = copy.deepcopy(stored)
    native.set_property.side_effect = ValueError(
        "Unhandled exception while executing module: measured scope query failure"
    )
    arguments = {
        "name": NAME,
        "path": PATH,
        "change": "Administrators",
        "scope_name": "Unbound",
        "_ansible_check_mode": True,
    }
    assert run_request(arguments) == (
        0,
        {
            "changed": True,
            "actions": ["Set-SmbShare -Force -Name " + NAME + " -ScopeName Unbound"],
        },
    )
    assert stored == before
    arguments["_ansible_check_mode"] = False
    assert run_request(arguments) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "Unhandled exception while executing module: measured scope query failure",
            "exception": "(traceback unavailable)",
        },
    )
    assert stored == before


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize(
    "version,parameters,message",
    [
        (
            (5, 1, 3),
            {},
            "Access-based enumeration requires Windows Server 2003 SP1 or later; "
            "set list=true on this target.",
        ),
        (
            (5, 2, 0),
            {},
            "Access-based enumeration requires Windows Server 2003 SP1 or later; "
            "set list=true on this target.",
        ),
        (
            (5, 1, 3),
            {"list": True, "encrypt": True},
            "Share encryption requires Windows 8 or Windows Server 2012 or later.",
        ),
        (
            (5, 2, 2),
            {"list": True, "encrypt": True},
            "Share encryption requires Windows 8 or Windows Server 2012 or later.",
        ),
        (
            (5, 1, 3),
            {"list": True, "caching_mode": "BranchCache"},
            "BranchCache requires Windows 7 or Windows Server 2008 R2 or later.",
        ),
        (
            (6, 0, 2),
            {"list": True, "caching_mode": "branchcache"},
            "BranchCache requires Windows 7 or Windows Server 2008 R2 or later.",
        ),
    ],
)
# Separate fixture arguments keep the request, native writes, and stored state visible.
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def test_unsupported_settings_fail_before_any_mutation(
    run_request: Request,
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    native: Mock,
    stored: ShareStore,
    version: tuple[int, int, int],
    parameters: dict[str, Any],
    message: str,
    check_mode: bool,
    existing: bool,
) -> None:
    if existing:
        stored[NAME] = _new_share(NAME, PATH)
    before = copy.deepcopy(stored)
    major, minor, service_pack_major = version
    monkeypatch.setattr(
        payload.sys,
        "getwindowsversion",
        lambda: SimpleNamespace(
            major=major,
            minor=minor,
            service_pack_major=service_pack_major,
            product_type=3,
        ),
    )
    arguments = dict(
        parameters,
        name=NAME,
        path=OTHER_PATH,
        description="must not be written",
        full="Administrators",
        _ansible_check_mode=check_mode,
    )
    assert run_request(arguments) == (
        1,
        {"changed": False, "actions": [], "failed": True, "msg": message},
    )
    assert stored == before
    native.create_share.assert_not_called()
    native.delete_share.assert_not_called()
    native.set_property.assert_not_called()
    native.change_access.assert_not_called()


@pytest.mark.parametrize("version", [(5, 1, 3), (5, 2, 0), (5, 2, 2)])
def test_legacy_supported_listing_and_absent_are_not_rejected(
    run_request: Request,
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    version: tuple[int, int, int],
) -> None:
    major, minor, service_pack_major = version
    monkeypatch.setattr(
        payload.sys,
        "getwindowsversion",
        lambda: SimpleNamespace(
            major=major,
            minor=minor,
            service_pack_major=service_pack_major,
            product_type=3,
        ),
    )
    assert run_request({"name": NAME, "path": PATH, "list": True})[0] == 0
    assert run_request({"name": NAME, "path": PATH, "list": True}) == (
        0,
        {"changed": False, "actions": []},
    )
    assert run_request({"name": NAME, "state": "absent"}) == (
        0,
        {"changed": True, "actions": ["Remove-SmbShare -Force -Name " + NAME]},
    )


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize(
    "version,parameters,property_action",
    [
        (
            (5, 2, 1),
            {"list": False},
            "-FolderEnumerationMode AccessBased",
        ),
        (
            (6, 0, 0),
            {"list": False},
            "-FolderEnumerationMode AccessBased",
        ),
        (
            (6, 1, 0),
            {"list": True, "caching_mode": "BranchCache"},
            "-CachingMode BranchCache",
        ),
        (
            (6, 2, 0),
            {"list": True, "encrypt": True},
            "-EncryptData True",
        ),
    ],
)
# Version cases and scoped fixtures expose both prediction and real-write behavior.
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def test_feature_version_boundaries_keep_supported_requests(
    run_request: Request,
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    native: Mock,
    stored: ShareStore,
    version: tuple[int, int, int],
    parameters: dict[str, Any],
    property_action: str,
    check_mode: bool,
) -> None:
    stored[NAME] = _new_share(NAME, PATH)
    before = copy.deepcopy(stored)
    monkeypatch.setattr(
        payload.sys,
        "getwindowsversion",
        lambda: SimpleNamespace(
            major=version[0],
            minor=version[1],
            service_pack_major=version[2],
            product_type=3,
        ),
    )
    status, result = run_request(
        dict(parameters, name=NAME, path=PATH, _ansible_check_mode=check_mode)
    )
    assert status == 0 and result["changed"]
    assert (
        "Set-SmbShare -Force -Name " + NAME + " " + property_action in result["actions"]
    )
    if check_mode:
        assert stored == before
        native.set_property.assert_not_called()
        native.change_access.assert_not_called()
    else:
        for field, value in parameters.items():
            assert stored[NAME][field] == value
    native.create_share.assert_not_called()
    native.delete_share.assert_not_called()


@pytest.mark.parametrize("check_mode", [False, True])
# Scoped fixtures let this removal test assert all native write calls explicitly.
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def test_absent_ignores_unavailable_present_only_settings(
    run_request: Request,
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    native: Mock,
    stored: ShareStore,
    check_mode: bool,
) -> None:
    stored[NAME] = _new_share(NAME, PATH)
    before = copy.deepcopy(stored)
    monkeypatch.setattr(
        payload.sys,
        "getwindowsversion",
        lambda: SimpleNamespace(major=5, minor=1, service_pack_major=3, product_type=1),
    )
    assert run_request(
        {
            "name": NAME,
            "state": "absent",
            "list": False,
            "encrypt": True,
            "caching_mode": "BranchCache",
            "_ansible_check_mode": check_mode,
        }
    ) == (
        0,
        {"changed": True, "actions": ["Remove-SmbShare -Force -Name " + NAME]},
    )
    if check_mode:
        assert stored == before
        native.delete_share.assert_not_called()
    else:
        assert not stored
        native.delete_share.assert_called_once_with(NAME)
    native.create_share.assert_not_called()
    native.set_property.assert_not_called()
    native.change_access.assert_not_called()


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("existing", [False, True])
# Expose the Windows fixture and every write interface for each before-write rejection.
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def test_xp_x64_does_not_inherit_server_2003_access_enumeration(
    run_request: Request,
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    native: Mock,
    stored: ShareStore,
    check_mode: bool,
    existing: bool,
) -> None:
    if existing:
        stored[NAME] = _new_share(NAME, PATH)
    before = copy.deepcopy(stored)
    monkeypatch.setattr(
        payload.sys,
        "getwindowsversion",
        lambda: SimpleNamespace(major=5, minor=2, service_pack_major=2, product_type=1),
    )
    assert run_request(
        {
            "name": NAME,
            "path": OTHER_PATH,
            "description": "must not be written",
            "_ansible_check_mode": check_mode,
        }
    ) == (
        1,
        {
            "changed": False,
            "actions": [],
            "failed": True,
            "msg": "Access-based enumeration requires Windows Server 2003 SP1 or later; "
            "set list=true on this target.",
        },
    )
    assert stored == before
    native.create_share.assert_not_called()
    native.delete_share.assert_not_called()
    native.set_property.assert_not_called()
    native.change_access.assert_not_called()
