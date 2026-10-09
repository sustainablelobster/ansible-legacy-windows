"""Exercise local-user results and write ordering without contacting Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Direct calls verify observable payload behavior independently of native ABIs.
# pylint: disable=protected-access

import copy
import json
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

USER = "Application"
USER_SID = "S-1-5-21-1-1001"
GROUPS = {"One": "S-1-5-21-1-2001", "Two": "S-1-5-21-1-2002"}
PASSWORD = "Fixture!NewPassword9"
OLD_PASSWORD = "Fixture!OldPassword8"
RequestRunner = Callable[..., tuple[int, dict[str, Any]]]


@pytest.fixture(name="stored")
def stored_users() -> dict[str, dict[str, Any]]:
    """Provide an isolated local-account store.

    :returns: Initially empty users indexed by canonical name.
    """
    return {}


@pytest.fixture(name="payload")
def user_payload(
    monkeypatch: pytest.MonkeyPatch, stored: dict[str, dict[str, Any]]
) -> ModuleType:
    """Replace native boundaries with account state and credential checks.

    :param monkeypatch: Scoped native-operation substitutions.
    :param stored: Accounts with native fields, direct groups and a password.
    :returns: The payload using this test's account store.
    """
    module = load_payload("win_user", monkeypatch)

    def create(name: str, password: str | None, flags: int) -> None:
        if name in stored:
            raise OSError(2224, "The account already exists.")
        stored[name] = {
            "name": name,
            "full_name": name,
            "comment": "",
            "home_dir": "",
            "script_path": "",
            "profile": "",
            "flags": flags | (0x800000 if password is None else 0),
            "password_expired": int(password is None),
            "acct_expires": 0xFFFFFFFF,
            "sid": USER_SID,
            "password": password,
            "groups": [],
        }

    def update(name: str, changes: dict[str, Any]) -> None:
        stored[name].update(changes)
        if stored[name]["flags"] & 65536:
            stored[name]["password_expired"] = 0

    def set_password(name: str, password: str) -> None:
        stored[name]["password"] = password
        stored[name]["password_expired"] = 0
        stored[name]["flags"] &= ~0x800000

    def _account_sid(name: str) -> str:
        if name.startswith("S-"):
            return name
        for group, sid in GROUPS.items():
            if name.lower() in (group.lower(), "machine\\" + group.lower()):
                return sid
        raise OSError(
            1332, "No mapping between account names and security IDs was done."
        )

    def add_member(group: str, sid: str) -> None:
        assert sid == USER_SID
        stored[USER]["groups"].append(group)

    def remove_member(group: str, sid: str) -> None:
        assert sid == USER_SID
        stored[USER]["groups"].remove(group)

    def _parse_expiration(value: str) -> tuple[int, int]:
        if value == "2040-10-27T14:30:00Z":
            return 20000000000, 0
        raise ValueError("Invalid date.")

    monkeypatch.setattr(
        module.accounts, "local_user_names", Mock(side_effect=lambda: list(stored))
    )
    monkeypatch.setattr(
        module.accounts, "local_group_sid", Mock(side_effect=GROUPS.__getitem__)
    )
    monkeypatch.setattr(module.accounts, "name_to_sid", Mock(side_effect=_account_sid))
    monkeypatch.setattr(
        module.accounts,
        "sid_to_name",
        Mock(
            side_effect=lambda sid: next(
                ("MACHINE\\" + name for name, value in GROUPS.items() if value == sid),
                sid,
            )
        ),
    )
    # Keep this comparison stub with the account-state fixture it isolates.
    # Sharing fixture internals between module tests would hide their inputs.
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
        module.users,
        "read_user",
        Mock(side_effect=lambda name: copy.deepcopy(stored.get(name))),
    )
    monkeypatch.setattr(module.users, "create_user", Mock(side_effect=create))
    monkeypatch.setattr(module.users, "update_user", Mock(side_effect=update))
    monkeypatch.setattr(module.users, "set_password", Mock(side_effect=set_password))
    monkeypatch.setattr(module.users, "delete_user", Mock(side_effect=stored.pop))
    monkeypatch.setattr(
        module.users,
        "password_matches",
        Mock(side_effect=lambda name, password: stored[name]["password"] == password),
    )
    monkeypatch.setattr(
        module.users,
        "local_group_names",
        Mock(side_effect=lambda name: list(stored[name]["groups"])),
    )
    monkeypatch.setattr(
        module.users,
        "account_path",
        Mock(side_effect=lambda name: "WinNT://WORKGROUP/MACHINE/" + name),
    )
    monkeypatch.setattr(
        module.groups,
        "list_groups",
        Mock(
            side_effect=lambda: [{"name": name, "description": ""} for name in GROUPS]
        ),
    )
    monkeypatch.setattr(module.groups, "add_member", Mock(side_effect=add_member))
    monkeypatch.setattr(module.groups, "remove_member", Mock(side_effect=remove_member))
    monkeypatch.setattr(
        module.user_time,
        "account_expiration_ticks",
        Mock(
            side_effect=lambda seconds: (
                None if seconds == 0xFFFFFFFF else seconds * 10000000
            )
        ),
    )
    monkeypatch.setattr(
        module.user_time,
        "account_expiration_seconds",
        Mock(side_effect=lambda ticks: ticks // 10000000),
    )
    monkeypatch.setattr(
        module.dates, "parse_account_expiration", Mock(side_effect=_parse_expiration)
    )
    monkeypatch.setattr(
        module.dates,
        "format_account_expiration",
        Mock(side_effect=lambda ticks, offset=None: f"time:{ticks}:{offset}"),
    )
    return module


def _apply(
    payload: ModuleType, *, check: bool = False, diff: bool = True, **options: object
) -> dict[str, Any]:
    result: dict[str, Any] = payload._user(
        payload._parameters({"name": USER, **options}), check, diff
    )
    return result


def _seed(
    payload: ModuleType, stored: dict[str, dict[str, Any]], **changes: object
) -> None:
    payload.users.create_user(USER, OLD_PASSWORD, 513)
    stored[USER].update(changes)


@pytest.fixture(name="run_request")
def request_runner(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> RequestRunner:
    """Run JSON requests against the current account state.

    :param payload: Payload with substituted native operations.
    :param monkeypatch: Scoped argument-file selection.
    :param tmp_path: Temporary directory containing request JSON.
    :param capsys: Captured JSON response output.
    :returns: A callable returning the exit status and decoded response.
    """
    argument_file = tmp_path / "arguments.json"
    monkeypatch.setattr(sys, "argv", ["win_user.py", str(argument_file)])

    def _run(**options: object) -> tuple[int, dict[str, Any]]:
        argument_file.write_text(
            json.dumps({"name": USER, "_ansible_diff": True, **options}),
            encoding="utf-8",
        )
        return invoke_payload(payload, capsys)

    return _run


def test_create_password_repeat_query_delete_and_repeat(
    payload: ModuleType, stored: dict[str, dict[str, Any]]
) -> None:
    created = _apply(
        payload,
        password=PASSWORD,
        fullname="Full Name",
        description="Description",
        groups=["One"],
    )
    assert created["changed"] is True
    assert created["state"] == "present"
    assert created["name"] == USER
    assert created["fullname"] == "Full Name"
    assert created["description"] == "Description"
    assert created["sid"] == USER_SID
    assert created["groups"] == [
        {"name": "One", "path": "WinNT://WORKGROUP/MACHINE/One"}
    ]
    assert created["diff"]["before"] == ""
    assert created["diff"]["after"]["password"] == "REDACTED"
    assert (
        _apply(
            payload,
            password=PASSWORD,
            fullname="Full Name",
            description="Description",
            groups=["One"],
        )["changed"]
        is False
    )
    queried = _apply(payload, state="query")
    assert queried["changed"] is False
    assert queried["msg"] == "Querying user 'Application'"
    assert queried["diff"]["before"] == queried["diff"]["after"]
    assert "home_directory" not in queried
    removed = _apply(payload, state="absent")
    assert removed["changed"] is True and removed["state"] == "absent"
    assert "sid" not in removed
    assert removed["diff"]["after"] == ""
    assert not stored
    assert _apply(payload, state="absent")["changed"] is False


def test_default_creation_reports_an_expired_password(payload: ModuleType) -> None:
    result = _apply(payload)
    assert result["password_expired"] is True
    assert result["fullname"] == USER
    assert result["groups"] == []


@pytest.mark.parametrize("password", [None, PASSWORD])
def test_new_check_skips_properties_credentials_and_group_lookup(
    payload: ModuleType, stored: dict[str, dict[str, Any]], password: str | None
) -> None:
    result = _apply(
        payload, check=True, password=password, fullname="Ignored", groups=["Missing"]
    )
    expected = {"name": USER}
    if password is not None:
        expected["password"] = "REDACTED"
    assert result == {
        "changed": True,
        "name": USER,
        "state": "present",
        "diff": {"before": "", "after": expected},
    }
    assert not stored
    payload.users.create_user.assert_not_called()
    payload.users.password_matches.assert_not_called()
    payload.groups.list_groups.assert_not_called()


@pytest.mark.parametrize("state", ["present", "absent"])
def test_existing_check_returns_stored_fields_even_when_state_is_absent(
    payload: ModuleType, stored: dict[str, dict[str, Any]], state: str
) -> None:
    _seed(payload, stored, comment="Before", groups=["One"])
    initial = copy.deepcopy(stored)
    result = _apply(
        payload,
        check=True,
        state=state,
        description="After",
        groups=["Two"],
        password=PASSWORD,
    )
    assert result["changed"] is True
    assert result["state"] == state
    assert result["description"] == "Before"
    assert result["groups"][0]["name"] == "One"
    assert result["sid"] == USER_SID
    assert stored == initial
    if state == "present":
        assert result["diff"]["after"]["description"] == "After"
        assert result["diff"]["after"]["password"] == "CHANGED REDACTED"
    else:
        assert result["diff"]["after"] == ""


def test_case_rules_clear_strings_and_preserve_supplied_result_name(
    payload: ModuleType, stored: dict[str, dict[str, Any]]
) -> None:
    _seed(
        payload,
        stored,
        full_name="Full Name",
        comment="Description",
        home_dir="C:\\Home",
        script_path="login.cmd",
        profile="C:\\Profile",
    )
    result = _apply(
        payload,
        name=USER.upper(),
        fullname="full name",
        description="DESCRIPTION",
        home_directory="c:\\home",
        login_script="LOGIN.CMD",
        profile="c:\\profile",
    )
    assert result["name"] == USER.upper()
    assert result["diff"]["before"]["name"] == USER
    assert result["fullname"] == "full name" and result["description"] == "DESCRIPTION"
    assert stored[USER]["home_dir"] == "C:\\Home"
    assert stored[USER]["script_path"] == "login.cmd"
    assert stored[USER]["profile"] == "C:\\Profile"
    _apply(
        payload,
        fullname="",
        description="",
        home_directory="",
        login_script="",
        profile="",
    )
    assert all(
        stored[USER][field] == ""
        for field in ("full_name", "comment", "home_dir", "script_path", "profile")
    )


@pytest.mark.parametrize("flags,expired", [(515, 0), (513, 1)])
def test_disabled_or_expired_users_force_password_reset(
    payload: ModuleType, stored: dict[str, dict[str, Any]], flags: int, expired: int
) -> None:
    _seed(payload, stored, flags=flags, password_expired=expired)
    result = _apply(payload, password=OLD_PASSWORD)
    assert result["changed"] is True
    assert result["diff"]["after"]["password"] == "CHANGED REDACTED"
    assert result["password_expired"] is False
    assert result["diff"]["after"]["password_expired"] is bool(expired)
    payload.users.password_matches.assert_not_called()


@pytest.mark.parametrize("desired", [False, True])
def test_password_reset_uses_initial_expired_flag_for_requested_property(
    payload: ModuleType, stored: dict[str, dict[str, Any]], desired: bool
) -> None:
    _seed(payload, stored, password_expired=1)
    result = _apply(payload, password=PASSWORD, password_expired=desired)
    assert result["password_expired"] is False
    assert result["diff"]["after"]["password_expired"] is desired
    assert stored[USER]["password"] == PASSWORD


@pytest.mark.parametrize("update", ["on_create", "ON_CREATE", None])
def test_on_create_or_null_update_does_not_validate_existing_password(
    payload: ModuleType, stored: dict[str, dict[str, Any]], update: str | None
) -> None:
    _seed(payload, stored)
    assert (
        _apply(payload, password=PASSWORD, update_password=update)["changed"] is False
    )
    assert stored[USER]["password"] == OLD_PASSWORD
    payload.users.password_matches.assert_not_called()


def test_expired_set_clear_and_conflicting_never_expire_diff(
    payload: ModuleType, stored: dict[str, dict[str, Any]]
) -> None:
    _seed(payload, stored)
    assert _apply(payload, password_expired=True)["password_expired"] is True
    assert _apply(payload, password_expired=False)["password_expired"] is False
    result = _apply(
        payload,
        password_expired=True,
        password_never_expires=True,
        account_disabled=True,
        user_cannot_change_password=True,
    )
    assert result["password_expired"] is False
    assert result["diff"]["after"]["password_expired"] is True
    assert result["password_never_expires"] is True
    assert result["account_disabled"] is True
    assert result["user_cannot_change_password"] is True
    assert (
        _apply(
            payload,
            account_disabled=False,
            password_never_expires=False,
            user_cannot_change_password=False,
        )["changed"]
        is True
    )


def test_empty_password_binding_depends_on_existing_account_flags(
    payload: ModuleType, stored: dict[str, dict[str, Any]]
) -> None:
    _seed(payload, stored)
    with pytest.raises(RuntimeError, match="parameter 'Password'"):
        _apply(payload, password="")
    payload.users.set_password.assert_not_called()
    stored[USER]["flags"] |= 2
    assert _apply(payload, password="")["changed"] is True
    payload.users.set_password.assert_called_once_with(USER, "")


def test_group_sid_deduplication_whitespace_and_removal_diff_quirk(
    payload: ModuleType, stored: dict[str, dict[str, Any]]
) -> None:
    _seed(payload, stored, groups=["One"])
    unchanged = _apply(payload, groups=["one", GROUPS["One"], "", "   "])
    assert unchanged["changed"] is False
    changed = _apply(payload, groups=["Two"])
    assert changed["groups"] == [
        {"name": "Two", "path": "WinNT://WORKGROUP/MACHINE/Two"}
    ]
    assert changed["diff"]["after"]["groups"] == ["MACHINE\\One", "Two"]
    cleared = _apply(payload, groups="")
    assert cleared["groups"] == []
    assert cleared["diff"]["after"]["groups"] == ["MACHINE\\Two"]


def test_missing_group_after_property_commit_preserves_partial_result(
    payload: ModuleType, stored: dict[str, dict[str, Any]]
) -> None:
    _seed(payload, stored, comment="Before")
    result = _apply(payload, description="After", groups=["One", "Missing"])
    assert result["failed"] and result["changed"]
    assert result["msg"] == "group 'Missing' not found"
    assert result["diff"]["after"]["description"] == "After"
    assert stored[USER]["comment"] == "After"
    assert stored[USER]["groups"] == []
    payload.groups.add_member.assert_not_called()
    assert _apply(payload, groups=["One"])["changed"] is True


def test_dot_qualified_group_is_not_normalized(
    payload: ModuleType, stored: dict[str, dict[str, Any]]
) -> None:
    _seed(payload, stored)
    result = _apply(payload, groups=[".\\One"])
    assert result["failed"] is True and result["changed"] is False
    assert result["msg"] == "group '.\\One' not found"
    payload.accounts.name_to_sid.assert_not_called()


def test_membership_failure_preserves_completed_additions_and_can_recover(
    payload: ModuleType, stored: dict[str, dict[str, Any]]
) -> None:
    _seed(payload, stored)
    add = payload.groups.add_member.side_effect

    def fail_second(group: str, sid: str) -> None:
        if group == "Two":
            raise OSError(5, "Access denied.")
        add(group, sid)

    payload.groups.add_member.side_effect = fail_second
    result = _apply(payload, groups=["One", "Two"])
    assert result["changed"] and result["failed"]
    assert result["msg"].startswith("Failed to add Two:")
    assert result["diff"]["after"]["groups"] == ["One"]
    assert stored[USER]["groups"] == ["One"]
    payload.groups.add_member.side_effect = add
    assert _apply(payload, groups=["One", "Two"])["changed"] is True
    assert stored[USER]["groups"] == ["One", "Two"]


@pytest.mark.parametrize(
    "name", [".\\Application", "MACHINE\\Application", "Application\0suffix", "One"]
)
@pytest.mark.parametrize("state", ["query", "absent"])
def test_lookup_uses_whole_local_user_names(
    payload: ModuleType, stored: dict[str, dict[str, Any]], name: str, state: str
) -> None:
    _seed(payload, stored)
    result = _apply(payload, name=name, state=state)
    assert result["state"] == "absent" and result["changed"] is False
    assert USER in stored
    payload.users.read_user.assert_not_called()


def test_expiration_parse_format_storage_and_repeated_local_ticks(
    payload: ModuleType, stored: dict[str, dict[str, Any]]
) -> None:
    _seed(payload, stored)
    result = _apply(payload, account_expires="2040-10-27T14:30:00Z")
    assert result["changed"] is True
    assert stored[USER]["acct_expires"] == 2000
    assert result["diff"]["after"]["account_expires"] == "time:20000000000:0"
    assert "account_expires" not in result
    repeated = _apply(payload, account_expires="2040-10-27T14:30:00Z")
    assert repeated["changed"] is False
    assert repeated["diff"]["before"]["account_expires"] == "time:20000000000:None"
    assert _apply(payload, account_expires="")["changed"] is False
    assert _apply(payload, account_expires="NEVER")["changed"] is True
    assert stored[USER]["acct_expires"] == 0xFFFFFFFF
    assert _apply(payload, account_expires="never")["changed"] is False


def test_check_mode_still_rejects_an_invalid_native_expiration(
    payload: ModuleType,
    stored: dict[str, dict[str, Any]],
    run_request: RequestRunner,
) -> None:
    _seed(payload, stored)
    initial = copy.deepcopy(stored)
    payload.user_time.account_expiration_seconds.side_effect = ValueError(
        "Not a legal OleAut date."
    )
    code, result = run_request(
        _ansible_check_mode=True, account_expires="2040-10-27T14:30:00Z"
    )
    assert code == 1 and result["failed"] and result["changed"] is False
    assert "Not a legal OleAut date" in result["msg"]
    assert "diff" not in result
    assert stored == initial
    payload.users.update_user.assert_not_called()


@pytest.mark.parametrize("state", ["present", "query", "absent"])
def test_locked_and_expiration_validation_precede_lookup(
    payload: ModuleType, state: str
) -> None:
    locked = _apply(payload, state=state, account_locked=True)
    assert locked["failed"] and locked["changed"] is False
    assert locked["msg"] == "account_locked must be set to 'no' if provided"
    invalid = _apply(payload, state=state, account_expires="invalid")
    assert invalid["failed"] and invalid["changed"] is False
    assert invalid["msg"].startswith("Failed to parse account_expires")
    assert invalid["diff"] == {"before": "", "after": ""}
    payload.accounts.local_user_names.assert_not_called()


def test_property_failure_discards_result_after_password_write(
    payload: ModuleType, stored: dict[str, dict[str, Any]], run_request: RequestRunner
) -> None:
    _seed(payload, stored)
    payload.users.update_user.side_effect = OSError(87, "Invalid parameter.")
    code, result = run_request(password=PASSWORD, description="After")
    assert code == 1 and result["failed"] and result["changed"] is False
    assert "diff" not in result
    assert stored[USER]["password"] == PASSWORD
    assert stored[USER]["comment"] == ""


def test_credential_failure_retains_diff_and_sanitizes_password(
    payload: ModuleType, stored: dict[str, dict[str, Any]], run_request: RequestRunner
) -> None:
    _seed(payload, stored)
    payload.users.password_matches.side_effect = OSError(
        1793, "Credential " + PASSWORD + " rejected."
    )
    code, result = run_request(password=PASSWORD, _ansible_inject_invocation=True)
    assert code == 1 and result["failed"] and result["changed"] is False
    assert result["msg"].startswith("Failed to validate the user's credentials:")
    assert "********" in result["msg"]
    assert result["diff"]["before"]["name"] == USER
    assert (
        result["invocation"]["module_args"]["password"]
        == "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
    )
    assert PASSWORD not in json.dumps(result)


def test_unsupported_argument_diagnostics_and_invocation_do_not_expose_password(
    run_request: RequestRunner,
) -> None:
    code, result = run_request(
        password=PASSWORD,
        _ansible_inject_invocation=True,
        **{"unknown_" + PASSWORD: PASSWORD},
    )
    assert code == 1 and result["failed"]
    assert "Unsupported parameters" in result["msg"]
    assert PASSWORD not in json.dumps(result)


def test_unexpected_failure_traceback_redacts_password(
    payload: ModuleType, run_request: RequestRunner
) -> None:
    payload.users.create_user.side_effect = RuntimeError("Secret " + PASSWORD)
    code, result = run_request(password=PASSWORD)
    assert code == 1 and result["failed"]
    assert PASSWORD not in json.dumps(result)
    assert "********" in result["exception"]


@pytest.mark.parametrize("name", [None, ""])
def test_empty_name_fails_before_native_lookup(
    payload: ModuleType, run_request: RequestRunner, name: str | None
) -> None:
    code, result = run_request(name=name)
    assert code == 1
    assert "parameter 'Name' because it is an empty string" in result["msg"]
    payload.accounts.local_user_names.assert_not_called()


def test_defaults_explicit_nulls_choices_and_scalar_coercions(
    payload: ModuleType, stored: dict[str, dict[str, Any]]
) -> None:
    assert payload._parameters({"name": USER})["state"] == "present"
    _seed(payload, stored, groups=["One"])
    query = _apply(payload, state=None, password=None, groups=None)
    assert query["changed"] is False and query["msg"].startswith("Querying user")
    replaced = _apply(payload, groups_action=None, groups=["Two"], state="PRESENT")
    assert replaced["changed"] is True and stored[USER]["groups"] == ["Two"]
    coerced = _apply(
        payload,
        check=True,
        fullname=True,
        description=123,
        home_directory=[],
        login_script={},
        profile=1.5,
    )
    after = coerced["diff"]["after"]
    assert after["fullname"] == "True" and after["description"] == "123"
    assert after["home_directory"] == "System.Object[]"
    assert after["login_script"] == "System.Collections.Hashtable"
    assert after["profile"] == "1.5"


@pytest.mark.parametrize(
    "arguments,match",
    [
        ({}, "missing required"),
        ({"name": USER, "state": "bad"}, "value of state"),
        ({"name": USER, "account_disabled": "bad"}, "boolean"),
        ({"name": USER, "groups": True}, "list"),
        ({"name": USER, "groups": [None]}, "null"),
    ],
)
def test_invalid_arguments_fail_before_account_work(
    payload: ModuleType, arguments: dict[str, Any], match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        payload._parameters(arguments)
    payload.accounts.local_user_names.assert_not_called()
