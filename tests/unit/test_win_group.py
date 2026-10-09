"""Check local-group payload behavior without Windows or lab access."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Direct payload calls exercise behavior independently of native API bindings.
# pylint: disable=protected-access

import copy
import json
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

ALPHA = "S-1-5-21-1-1001"
BETA = "S-1-5-21-1-1002"
GAMMA = "S-1-5-21-1-1003"
PEER = "S-1-5-21-1-2000"
GROUP = "S-1-5-21-1-2001"
GROUP_NAME = "Deployment"
RequestRunner = Callable[..., tuple[int, dict[str, Any]]]


@pytest.fixture(name="stored")
def stored_groups() -> dict[str, dict[str, Any]]:
    """Provide local group state indexed by canonical group name.

    :returns: An initially empty group store.
    """
    return {}


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.fixture(name="payload")
def group_payload(
    monkeypatch: pytest.MonkeyPatch, stored: dict[str, dict[str, Any]]
) -> ModuleType:
    """Replace native reads and writes with observable local account state.

    :param monkeypatch: Scoped native API substitutions.
    :param stored: Group descriptions, member SIDs, and group SIDs.
    :returns: The loaded payload using the isolated state.
    """
    module = load_payload("win_group", monkeypatch)
    monkeypatch.setenv("COMPUTERNAME", "MACHINE")
    member_names = {
        ALPHA: "MACHINE\\Alpha",
        BETA: "MACHINE\\beta",
        GAMMA: "MACHINE\\Gamma",
    }

    def _name_to_sid(name: str) -> str:
        if name.startswith("S-"):
            return name
        if name == "BA":
            return "S-1-5-32-544"
        if name == "Peer":
            return PEER
        for group_name, info in stored.items():
            if name == "MACHINE\\" + group_name:
                return str(info["sid"])
        qualified = name.replace(".\\", "MACHINE\\")
        for sid, member_name in member_names.items():
            if qualified.lower() in (
                member_name.lower(),
                member_name.split("\\")[1].lower(),
            ):
                return sid
        raise OSError(
            1332, "No mapping between account names and security IDs was done."
        )

    def create_group(name: str) -> None:
        if not name:
            raise OSError(87, "Invalid group name.")
        name = name.split("\0", 1)[0]
        if name in stored:
            raise OSError(1379, "The specified local group already exists.")
        stored[name] = {"description": "", "members": [], "sid": GROUP}

    def set_description(name: str, description: str) -> None:
        stored[name]["description"] = description.split("\0", 1)[0]

    def add_member(name: str, sid: str) -> None:
        if sid == PEER:
            raise OSError(1388, "The member has an invalid account type.")
        stored[name]["members"].append(sid)

    def remove_member(name: str, sid: str) -> None:
        stored[name]["members"].remove(sid)

    monkeypatch.setattr(
        module.groups,
        "list_groups",
        Mock(
            side_effect=lambda: [
                {"name": name, "description": info["description"]}
                for name, info in stored.items()
            ]
        ),
    )
    monkeypatch.setattr(
        module.groups,
        "member_sids",
        Mock(side_effect=lambda name: list(stored[name]["members"])),
    )
    monkeypatch.setattr(module.groups, "create_group", Mock(side_effect=create_group))
    monkeypatch.setattr(
        module.groups, "set_description", Mock(side_effect=set_description)
    )
    monkeypatch.setattr(module.groups, "delete_group", Mock(side_effect=stored.pop))
    monkeypatch.setattr(module.groups, "add_member", Mock(side_effect=add_member))
    monkeypatch.setattr(module.groups, "remove_member", Mock(side_effect=remove_member))
    monkeypatch.setattr(module.accounts, "name_to_sid", Mock(side_effect=_name_to_sid))
    monkeypatch.setattr(
        module.accounts, "account_name_to_sid", Mock(side_effect=_name_to_sid)
    )
    monkeypatch.setattr(
        module.accounts,
        "sid_to_name",
        Mock(side_effect=lambda sid: member_names.get(sid, sid)),
    )

    def _sort_names(names: list[str], unique: bool = False) -> list[str]:
        ordered = sorted(names, key=str.lower)
        if not unique:
            return ordered
        return [
            name
            for index, name in enumerate(ordered)
            if not index or name.lower() != ordered[index - 1].lower()
        ]

    monkeypatch.setattr(module.accounts, "sort_names", Mock(side_effect=_sort_names))
    # Native tests cover Windows collation; these behavioral fixtures use ASCII.
    monkeypatch.setattr(
        module.environment,
        "values_equal",
        lambda left, right: (
            left is right
            if left is None or right is None
            else left.lower() == right.lower()
        ),
    )
    return module


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def _apply(
    payload: ModuleType, *, check: bool = False, diff: bool = True, **options: object
) -> dict[str, Any]:
    parameters = payload._parameters({"name": GROUP_NAME, **options})
    result: dict[str, Any] = payload._group(parameters, check, diff)
    return result


# pylint: enable=duplicate-code


@pytest.fixture(name="run_request")
def request_runner(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> RequestRunner:
    """Exercise JSON requests with this test's existing native state.

    :param payload: Payload using substituted native operations.
    :param monkeypatch: Scoped command-line substitution.
    :param tmp_path: Directory for the argument file.
    :param capsys: Capture of the public entry point's JSON result.
    :returns: A runner accepting module options as keyword arguments.
    """
    argument_file = tmp_path / "arguments.json"
    monkeypatch.setattr(sys, "argv", ["win_group.py", str(argument_file)])

    def _run_request(**options: object) -> tuple[int, dict[str, Any]]:
        arguments = {"name": GROUP_NAME, "_ansible_diff": True, **options}
        argument_file.write_text(json.dumps(arguments), encoding="utf-8")
        return invoke_payload(payload, capsys)

    return _run_request


def test_create_repeat_describe_clear_delete_and_repeat(
    payload: ModuleType, stored: dict[str, dict[str, Any]]
) -> None:
    created = _apply(payload)
    assert created == {
        "changed": True,
        "sid": GROUP,
        "diff": {
            "before": None,
            "after": {"name": GROUP_NAME, "description": "", "members": []},
        },
    }
    assert stored[GROUP_NAME] == {"description": "", "members": [], "sid": GROUP}
    assert _apply(payload)["changed"] is False
    described = _apply(payload, description="Deployment users")
    assert described["changed"] is True
    assert described["diff"]["before"]["description"] == ""
    assert described["diff"]["after"]["description"] == "Deployment users"
    assert stored[GROUP_NAME]["description"] == "Deployment users"
    assert _apply(payload, description="Deployment users")["changed"] is False
    assert _apply(payload, description="")["changed"] is True
    assert _apply(payload, description="")["changed"] is False
    removed = _apply(payload, state="absent")
    assert removed == {
        "changed": True,
        "sid": None,
        "diff": {"before": created["diff"]["after"], "after": None},
    }
    assert not stored
    assert _apply(payload, state="absent") == {
        "changed": False,
        "sid": None,
        "diff": {"before": None, "after": None},
    }


@pytest.mark.parametrize("description", [None, "", "Description"])
@pytest.mark.parametrize("name", [GROUP_NAME, "", None])
def test_missing_group_check_skips_members_and_preserves_requested_description(
    payload: ModuleType,
    stored: dict[str, dict[str, Any]],
    name: str | None,
    description: str | None,
) -> None:
    result = _apply(
        payload,
        name=name,
        description=description,
        members={"set": ["Missing"]},
        check=True,
    )
    assert result == {
        "changed": True,
        "sid": "S-1-5-0000",
        "diff": {
            "before": None,
            "after": {"name": name, "description": description, "members": []},
        },
    }
    assert not stored
    payload.groups.create_group.assert_not_called()
    payload.groups.set_description.assert_not_called()
    payload.groups.add_member.assert_not_called()
    payload.accounts.name_to_sid.assert_not_called()


@pytest.mark.parametrize(
    "options",
    [
        {"description": "Updated"},
        {"members": {"set": ["beta", "Gamma"]}},
        {"members": {"add": ["Gamma"], "remove": ["Alpha"]}},
        {"members": {"set": []}},
        {"state": "absent"},
    ],
)
def test_existing_check_predicts_actual_result_without_mutating(
    payload: ModuleType, stored: dict[str, dict[str, Any]], options: dict[str, object]
) -> None:
    _apply(payload, description="Original", members={"set": ["Alpha", "beta"]})
    original = copy.deepcopy(stored)
    parameters = payload._parameters({"name": GROUP_NAME, **options})
    predicted = payload._group(parameters, True, True)
    assert stored == original
    assert payload._group(parameters, False, True) == predicted


def test_case_only_requests_preserve_stored_values_and_diff_spelling(
    payload: ModuleType, stored: dict[str, dict[str, Any]]
) -> None:
    _apply(payload, description="Original")
    result = _apply(
        payload, name=GROUP_NAME.lower(), description="original", state="PRESENT"
    )
    assert result["changed"] is False
    assert result["sid"] == GROUP
    assert result["diff"] == {
        "before": {
            "name": GROUP_NAME.lower(),
            "description": "Original",
            "members": [],
        },
        "after": {"name": GROUP_NAME.lower(), "description": "original", "members": []},
    }
    assert stored[GROUP_NAME]["description"] == "Original"


def test_discovered_names_are_used_for_every_native_operation(
    payload: ModuleType,
) -> None:
    _apply(payload, members={"set": ["Alpha"]})
    result = _apply(
        payload,
        name=GROUP_NAME.upper(),
        description="Updated",
        members={"add": ["beta"], "remove": ["Alpha"]},
    )
    assert result["diff"]["after"]["name"] == GROUP_NAME.upper()
    payload.groups.member_sids.assert_called_with(GROUP_NAME)
    payload.groups.set_description.assert_called_with(GROUP_NAME, "Updated")
    payload.groups.add_member.assert_called_with(GROUP_NAME, BETA)
    payload.groups.remove_member.assert_called_with(GROUP_NAME, ALPHA)
    _apply(payload, name=GROUP_NAME.lower(), state="absent")
    payload.groups.delete_group.assert_called_once_with(GROUP_NAME)


def test_group_sid_resolution_does_not_interpret_a_group_name_as_sddl(
    payload: ModuleType,
) -> None:
    result = _apply(payload, name="BA")
    assert result["sid"] == GROUP
    payload.accounts.account_name_to_sid.assert_called_once_with("MACHINE\\BA")
    payload.accounts.name_to_sid.assert_not_called()


def test_new_nul_name_uses_stored_prefix_and_retains_requested_diff(
    payload: ModuleType, stored: dict[str, dict[str, Any]]
) -> None:
    requested = GROUP_NAME + "\0suffix"
    result = _apply(payload, name=requested, description="Created")
    assert result["changed"] and result["sid"] == GROUP
    assert result["diff"]["after"]["name"] == requested
    assert stored[GROUP_NAME]["description"] == "Created"
    assert requested not in stored
    payload.accounts.account_name_to_sid.assert_called_once_with(
        "MACHINE\\" + GROUP_NAME
    )
    payload.groups.set_description.assert_called_once_with(GROUP_NAME, "Created")


def test_nul_name_colliding_with_existing_prefix_does_not_change_it(
    payload: ModuleType, stored: dict[str, dict[str, Any]]
) -> None:
    _apply(payload, description="Original")
    with pytest.raises(OSError, match="already exists"):
        _apply(payload, name=GROUP_NAME + "\0suffix", description="Unexpected")
    assert stored[GROUP_NAME]["description"] == "Original"


@pytest.mark.parametrize("state", ["present", "absent", None])
def test_multiple_collation_matches_fail_before_reading_or_changing_groups(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, state: str | None
) -> None:
    payload.groups.list_groups.return_value = None
    payload.groups.list_groups.side_effect = lambda: [
        {"name": "fold", "description": "First"},
        {"name": "f\u00adold", "description": "Second"},
    ]
    monkeypatch.setattr(
        payload.environment,
        "values_equal",
        lambda left, right: left.replace("\u00ad", "") == right,
    )
    with pytest.raises(ValueError, match="More than one local group"):
        _apply(payload, name="fold", state=state, description="Unexpected")
    payload.groups.member_sids.assert_not_called()
    payload.groups.create_group.assert_not_called()
    payload.groups.set_description.assert_not_called()
    payload.groups.delete_group.assert_not_called()


def test_builtin_identity_uses_unqualified_fallback_on_legacy_windows(
    payload: ModuleType,
) -> None:
    missing = OSError(1332, "No mapping")
    setattr(missing, "winerror", 1332)
    payload.accounts.account_name_to_sid.side_effect = [missing, "S-1-5-32-544"]
    assert payload.accounts.local_group_sid("Administrators") == "S-1-5-32-544"
    assert payload.accounts.account_name_to_sid.call_args_list == [
        call("MACHINE\\Administrators"),
        call("Administrators"),
    ]


@pytest.mark.parametrize(
    "error_code,fallback", [(5, None), (1332, ALPHA), (1332, "S-1-1-0")]
)
def test_group_identity_does_not_mask_errors_or_accept_unrelated_accounts(
    payload: ModuleType, error_code: int, fallback: str | None
) -> None:
    failure = OSError(error_code, "Lookup failed")
    setattr(failure, "winerror", error_code)
    payload.accounts.account_name_to_sid.side_effect = [failure, fallback]
    with pytest.raises(OSError) as raised:
        payload.accounts.local_group_sid(GROUP_NAME)
    assert raised.value is failure
    assert payload.accounts.account_name_to_sid.call_count == (
        2 if error_code == 1332 else 1
    )


@pytest.mark.parametrize("description", [None, ""])
def test_null_preserves_description_and_empty_string_clears(
    payload: ModuleType, stored: dict[str, dict[str, Any]], description: str | None
) -> None:
    _apply(payload, description="Original")
    result = _apply(payload, description=description)
    assert result["changed"] is (description == "")
    assert result["diff"]["after"]["description"] == (
        "Original" if description is None else ""
    )
    assert stored[GROUP_NAME]["description"] == result["diff"]["after"]["description"]


def test_nul_description_keeps_requested_diff_and_native_stored_prefix(
    payload: ModuleType, stored: dict[str, dict[str, Any]]
) -> None:
    result = _apply(payload, description="Prefix\0suffix")
    assert result["diff"]["after"]["description"] == "Prefix\0suffix"
    assert stored[GROUP_NAME]["description"] == "Prefix"
    assert _apply(payload)["diff"]["before"]["description"] == "Prefix"


def test_membership_add_aliases_remove_set_clear_and_repeat(
    payload: ModuleType, stored: dict[str, dict[str, Any]]
) -> None:
    added = _apply(payload, members={"add": ["beta", "Alpha", ".\\Alpha", ALPHA]})
    assert added["diff"]["after"]["members"] == ["MACHINE\\Alpha", "MACHINE\\beta"]
    assert stored[GROUP_NAME]["members"] == [BETA, ALPHA]
    assert _apply(payload, members={"add": ["Alpha", BETA]})["changed"] is False
    removed = _apply(payload, members={"remove": ["Alpha", "Alpha", "Gamma"]})
    assert removed["changed"] is True
    assert stored[GROUP_NAME]["members"] == [BETA]
    assert _apply(payload, members={"remove": ["Alpha"]})["changed"] is False
    replaced = _apply(payload, members={"set": ["Gamma", "Alpha", ALPHA]})
    assert replaced["diff"]["after"]["members"] == ["MACHINE\\Alpha", "MACHINE\\Gamma"]
    assert stored[GROUP_NAME]["members"] == [GAMMA, ALPHA]
    assert _apply(payload, members={"set": [ALPHA, GAMMA]})["changed"] is False
    assert _apply(payload, members={"set": []})["changed"] is True
    assert stored[GROUP_NAME]["members"] == []
    assert _apply(payload, members={"set": []})["changed"] is False


@pytest.mark.parametrize("existing", [[], [ALPHA]])
def test_add_remove_overlap_uses_original_membership(
    payload: ModuleType, stored: dict[str, dict[str, Any]], existing: list[str]
) -> None:
    _apply(payload, members={"set": existing})
    result = _apply(payload, members={"add": ["Alpha"], "remove": ["Alpha"]})
    assert result["changed"] is True
    assert stored[GROUP_NAME]["members"] == ([] if existing else [ALPHA])


@pytest.mark.parametrize(
    "members",
    [
        None,
        {},
        {"set": None},
        {"add": None},
        {"remove": None},
        {"add": [""]},
        {"remove": [""]},
    ],
)
def test_omitted_null_and_false_member_lists_preserve_members(
    payload: ModuleType, stored: dict[str, dict[str, Any]], members: object
) -> None:
    _apply(payload, members={"set": ["Alpha"]})
    assert _apply(payload, members=members)["changed"] is False
    assert stored[GROUP_NAME]["members"] == [ALPHA]


@pytest.mark.parametrize(
    "members", [{"set": [""]}, {"add": ["", "Alpha"]}, {"remove": ["Alpha", ""]}]
)
def test_empty_member_binding_fails_before_any_membership_write(
    payload: ModuleType,
    stored: dict[str, dict[str, Any]],
    members: dict[str, list[str]],
) -> None:
    _apply(payload, members={"set": ["beta"]})
    with pytest.raises(ValueError, match="empty string"):
        _apply(payload, members=members)
    assert stored[GROUP_NAME]["members"] == [BETA]


@pytest.mark.parametrize("state", [None, "absent"])
@pytest.mark.parametrize("existing", [False, True])
def test_nonpresent_states_ignore_desired_members_and_return_null_sid(
    payload: ModuleType,
    stored: dict[str, dict[str, Any]],
    state: str | None,
    existing: bool,
) -> None:
    if existing:
        _apply(payload, members={"set": ["Alpha"]})
    result = _apply(
        payload, state=state, members={"set": ["Missing"]}, description="Ignored"
    )
    assert result["changed"] is (existing and state == "absent")
    assert result["sid"] is None and result["diff"]["after"] is None
    assert (result["diff"]["before"] is not None) is existing
    assert bool(stored) is (existing and state is None)


def test_diffs_translate_and_sort_even_when_diff_output_is_disabled(
    payload: ModuleType,
) -> None:
    _apply(payload, members={"set": ["beta", "Alpha"]})
    payload.accounts.sort_names.reset_mock()
    result = _apply(payload, diff=False)
    assert result == {"changed": False, "sid": GROUP}
    assert payload.accounts.sort_names.call_args_list == [
        call(["MACHINE\\beta", "MACHINE\\Alpha"], False),
        call(["MACHINE\\beta", "MACHINE\\Alpha"], True),
    ]


def test_before_preserves_duplicate_names_while_after_deduplicates(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    _apply(payload, members={"set": [ALPHA, BETA]})
    monkeypatch.setattr(
        payload.accounts,
        "sid_to_name",
        lambda sid: "MACHINE\\Alias" if sid == ALPHA else "MACHINE\\alias",
    )
    result = _apply(payload)
    assert result["diff"]["before"]["members"] == ["MACHINE\\Alias", "MACHINE\\alias"]
    assert result["diff"]["after"]["members"] == ["MACHINE\\Alias"]


def test_unmapped_sid_remains_in_diff(payload: ModuleType) -> None:
    sid = "S-1-5-21-1-99999"
    assert _apply(payload, members={"set": [sid]})["diff"]["after"]["members"] == [sid]


@pytest.mark.parametrize(
    "members",
    [{"set": ["Alpha", "Missing"]}, {"add": ["Alpha"], "remove": ["Missing"]}],
)
def test_translation_failure_preserves_members_and_preceding_description_write(
    payload: ModuleType,
    stored: dict[str, dict[str, Any]],
    run_request: RequestRunner,
    members: dict[str, list[str]],
) -> None:
    _apply(payload, description="Original", members={"set": ["beta"]})
    code, failed = run_request(description="Updated", members=members)
    assert code == 1 and failed["failed"] is True and failed["changed"] is False
    assert "Failed to translate 'Missing' to a SecurityIdentifier" in failed["msg"]
    assert "sid" not in failed and "diff" not in failed
    assert stored[GROUP_NAME] == {
        "description": "Updated",
        "members": [BETA],
        "sid": GROUP,
    }
    recovered = _apply(payload, description="Updated", members={"set": ["Alpha"]})
    assert recovered["changed"] is True and stored[GROUP_NAME]["members"] == [ALPHA]
    assert (
        _apply(payload, description="Updated", members={"set": ["Alpha"]})["changed"]
        is False
    )


def test_failed_new_group_request_leaves_created_group_and_recovers(
    payload: ModuleType,
    stored: dict[str, dict[str, Any]],
    run_request: RequestRunner,
) -> None:
    code, failed = run_request(
        description="Retained",
        members={"set": ["Missing"]},
    )
    assert code == 1 and failed["changed"] is False
    assert stored[GROUP_NAME] == {
        "description": "Retained",
        "members": [],
        "sid": GROUP,
    }
    assert _apply(payload, description="Retained")["changed"] is False
    assert _apply(payload, state="absent")["changed"] is True
    assert not stored


@pytest.mark.parametrize(
    "add,retained", [(["Alpha", "Peer"], [BETA, ALPHA]), (["Peer", "Alpha"], [BETA])]
)
def test_add_failure_preserves_completed_additions_and_skips_removals(
    payload: ModuleType,
    stored: dict[str, dict[str, Any]],
    run_request: RequestRunner,
    add: list[str],
    retained: list[str],
) -> None:
    _apply(payload, members={"set": ["beta"]})
    code, failed = run_request(members={"add": add, "remove": ["beta"]})
    assert code == 1 and failed["changed"] is False
    assert "sid" not in failed and "diff" not in failed
    assert stored[GROUP_NAME]["members"] == retained
    payload.groups.remove_member.assert_not_called()
    assert _apply(payload, members={"set": ["Alpha"]})["changed"] is True
    assert stored[GROUP_NAME]["members"] == [ALPHA]


def test_remove_failure_preserves_prior_additions_and_recovers(
    payload: ModuleType,
    stored: dict[str, dict[str, Any]],
    run_request: RequestRunner,
) -> None:
    _apply(payload, members={"set": ["beta"]})
    remove = payload.groups.remove_member.side_effect
    payload.groups.remove_member.side_effect = OSError(5, "Access denied.")
    code, failed = run_request(members={"add": ["Alpha"], "remove": ["beta"]})
    assert code == 1 and failed["changed"] is False
    assert stored[GROUP_NAME]["members"] == [BETA, ALPHA]
    payload.groups.remove_member.side_effect = remove
    assert _apply(payload, members={"set": ["Alpha"]})["changed"] is True
    assert stored[GROUP_NAME]["members"] == [ALPHA]


def test_second_removal_failure_keeps_first_removal_and_recovers(
    payload: ModuleType,
    stored: dict[str, dict[str, Any]],
    run_request: RequestRunner,
) -> None:
    _apply(payload, members={"set": ["Alpha", "beta"]})
    remove = payload.groups.remove_member.side_effect

    def fail_second(name: str, sid: str) -> None:
        if sid == BETA:
            raise OSError(5, "Access denied.")
        remove(name, sid)

    payload.groups.remove_member.side_effect = fail_second
    code, failed = run_request(members={"remove": ["Alpha", "beta"]})
    assert code == 1 and failed["changed"] is False
    assert stored[GROUP_NAME]["members"] == [BETA]
    payload.groups.remove_member.side_effect = remove
    assert _apply(payload, members={"set": []})["changed"] is True
    assert stored[GROUP_NAME]["members"] == []


def test_description_failure_precedes_member_translation(
    payload: ModuleType, stored: dict[str, dict[str, Any]]
) -> None:
    _apply(payload, description="Original")
    payload.accounts.name_to_sid.reset_mock()
    payload.groups.set_description.side_effect = OSError(5, "Access denied.")
    with pytest.raises(OSError, match="Access denied"):
        _apply(payload, description="Updated", members={"add": ["Missing"]})
    assert stored[GROUP_NAME]["description"] == "Original"
    payload.accounts.name_to_sid.assert_not_called()
    payload.groups.add_member.assert_not_called()


def test_creation_failure_does_not_attempt_description_or_members(
    payload: ModuleType, stored: dict[str, dict[str, Any]]
) -> None:
    payload.groups.create_group.side_effect = OSError(5, "Access denied.")
    with pytest.raises(OSError, match="Access denied"):
        _apply(payload, description="Requested", members={"add": ["Missing"]})
    assert not stored
    payload.accounts.name_to_sid.assert_not_called()
    payload.groups.set_description.assert_not_called()


def test_deletion_failure_preserves_group_and_recovers(
    payload: ModuleType, stored: dict[str, dict[str, Any]]
) -> None:
    _apply(payload)
    delete = payload.groups.delete_group.side_effect
    payload.groups.delete_group.side_effect = OSError(5, "Access denied.")
    with pytest.raises(OSError, match="Access denied"):
        _apply(payload, state="absent")
    assert GROUP_NAME in stored
    payload.groups.delete_group.side_effect = delete
    assert _apply(payload, state="absent")["changed"] is True
    assert not stored


def test_existing_check_resolves_members_without_attempting_invalid_native_addition(
    payload: ModuleType, stored: dict[str, dict[str, Any]]
) -> None:
    _apply(payload)
    result = _apply(payload, members={"add": ["Peer"]}, check=True)
    assert result["changed"] is True and result["diff"]["after"]["members"] == [PEER]
    assert stored[GROUP_NAME]["members"] == []
    payload.groups.add_member.assert_not_called()
    with pytest.raises(ValueError, match="Failed to translate"):
        _apply(payload, members={"add": ["Missing"]}, check=True)


def test_existing_member_read_failure_prevents_deletion(
    payload: ModuleType, stored: dict[str, dict[str, Any]]
) -> None:
    _apply(payload, members={"set": ["Alpha"]})
    payload.accounts.sid_to_name.side_effect = OSError(5, "Access denied.")
    with pytest.raises(OSError):
        _apply(payload, state="absent", diff=False)
    assert GROUP_NAME in stored
    payload.groups.delete_group.assert_not_called()


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, None),
        ({}, {"add": [], "remove": [], "set": None}),
        ({"add": None}, {"add": None, "remove": [], "set": None}),
        ({"SET": []}, {"add": [], "remove": [], "set": []}),
        (
            {"add": " Alpha,\u2003beta "},
            {"add": ["Alpha", "beta"], "remove": [], "set": None},
        ),
        ({"add": 42}, {"add": ["42"], "remove": [], "set": None}),
        ('{"set": ["Alpha"]}', {"add": [], "remove": [], "set": ["Alpha"]}),
        ("add='Alpha,beta'", {"add": ["Alpha", "beta"], "remove": [], "set": None}),
        (
            {"set": [True, 1.5, [], {}]},
            {
                "add": [],
                "remove": [],
                "set": [
                    "True",
                    "1.5",
                    "System.Object[]",
                    "System.Collections.Hashtable",
                ],
            },
        ),
    ],
)
def test_member_argument_conversions(
    payload: ModuleType, value: object, expected: object
) -> None:
    assert (
        payload._parameters({"name": GROUP_NAME, "members": value})["members"]
        == expected
    )


@pytest.mark.parametrize("value", [True, False, 1.5, {}, 2**63, -(2**63) - 1, [None]])
def test_invalid_member_list_values_fail_before_native_access(
    payload: ModuleType, value: object
) -> None:
    with pytest.raises(ValueError):
        _apply(payload, members={"set": value})
    payload.groups.list_groups.assert_not_called()


@pytest.mark.parametrize("option", ["add", "remove", "set"])
@pytest.mark.parametrize("dictionary_string", [False, True])
def test_duplicate_member_option_casing_fails_without_changing_members(
    payload: ModuleType,
    stored: dict[str, dict[str, Any]],
    option: str,
    dictionary_string: bool,
) -> None:
    _apply(payload, members={"set": ["Alpha"]})
    payload.groups.list_groups.reset_mock()
    values = {option: ["Alpha"], option.upper(): []}
    members = json.dumps(values) if dictionary_string else values
    with pytest.raises(ValueError, match="must not differ only in case"):
        _apply(payload, members=members)
    assert stored[GROUP_NAME]["members"] == [ALPHA]
    payload.groups.list_groups.assert_not_called()


@pytest.mark.parametrize("other", ["add", "remove"])
@pytest.mark.parametrize("value", [None, [], ["Alpha"]])
def test_exclusive_member_options_are_checked_by_presence(
    payload: ModuleType, other: str, value: object
) -> None:
    with pytest.raises(
        ValueError, match="mutually exclusive: set, " + other + " found in members"
    ):
        _apply(payload, members={"set": None, other: value})
    payload.groups.list_groups.assert_not_called()


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({}, "missing required arguments: name"),
        ({"name": GROUP_NAME, "state": "other"}, "state must be one of"),
        (
            {"name": GROUP_NAME, "members": {"unexpected": []}},
            "Unsupported parameters.*found in members",
        ),
        ({"name": GROUP_NAME, "members": []}, "members must be a dictionary"),
    ],
)
def test_validation_precedes_native_access(
    payload: ModuleType, arguments: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        payload._parameters(arguments)
    payload.groups.list_groups.assert_not_called()


@pytest.mark.parametrize(
    "value,expected",
    [
        (True, "True"),
        (42, "42"),
        ([], "System.Object[]"),
        ({}, "System.Collections.Hashtable"),
        (None, None),
    ],
)
def test_string_parameters_use_shared_coercions(
    payload: ModuleType, value: object, expected: str | None
) -> None:
    parameters = payload._parameters({"name": value, "description": value})
    assert parameters["name"] == parameters["description"] == expected


def test_json_entry_point_normalizes_option_names_and_reports_invocation(
    run_request: RequestRunner,
) -> None:
    code, result = run_request(
        STATE="PRESENT",
        MEMBERS={"ADD": "Alpha"},
        _ansible_inject_invocation=True,
    )
    assert code == 0 and result["changed"] is True
    assert result["invocation"] == {
        "module_args": {
            "name": GROUP_NAME,
            "state": "PRESENT",
            "description": None,
            "members": {"add": ["Alpha"], "remove": [], "set": None},
        }
    }


def test_unknown_options_fail_or_follow_ignore_flag(
    payload: ModuleType,
    run_request: RequestRunner,
) -> None:
    code, failed = run_request(unexpected=True)
    assert code == 1 and failed["failed"] is True
    payload.groups.list_groups.assert_not_called()
    code, result = run_request(
        unexpected=True,
        members={"unexpected": []},
        _ansible_ignore_unknown_opts=True,
    )
    assert code == 0 and result["sid"] == GROUP


def test_unexpected_failure_still_returns_fresh_json(
    payload: ModuleType,
    run_request: RequestRunner,
) -> None:
    payload.groups.list_groups.side_effect = RuntimeError("unexpected fixture failure")
    code, failed = run_request()
    assert code == 1 and failed["changed"] is False and failed["failed"] is True
    assert (
        failed["msg"]
        == "Unhandled exception while executing module: unexpected fixture failure"
    )
    assert "RuntimeError" in failed["exception"]
