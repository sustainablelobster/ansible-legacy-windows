"""Exercise membership requests with observable account and group substitutes."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Private conversion calls isolate argument behavior from Windows API bindings.
# pylint: disable=protected-access

import json
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

GROUP_NAME = "Deployment"
ALPHA = "S-1-5-21-1-1001"
BETA = "S-1-5-21-1-1002"
DOMAIN = "S-1-5-21-2-1001"
PEER = "S-1-5-21-1-2000"
BUILTIN = "S-1-5-32-544"
RequestRunner = Callable[..., tuple[int, dict[str, Any]]]


@pytest.fixture(name="stored")
def stored_members() -> dict[str, list[str]]:
    """Provide existing local groups with mutable membership lists.

    :returns: Isolated local groups, initially empty.
    """
    return {GROUP_NAME: [], "Peer": [], "Administrators": []}


@pytest.fixture(name="payload")
def membership_payload(
    monkeypatch: pytest.MonkeyPatch, stored: dict[str, list[str]]
) -> ModuleType:
    """Load the payload with deterministic, observable Windows operations.

    :param monkeypatch: Scoped replacements for native boundaries.
    :param stored: Membership lists indexed by local group name.
    :returns: Payload whose account lookups and writes can be inspected.
    """
    module = load_payload("win_group_membership", monkeypatch)
    monkeypatch.setenv("COMPUTERNAME", "MACHINE")
    display = {
        ALPHA: "MACHINE\\Alpha",
        BETA: "MACHINE\\beta",
        DOMAIN: "DOMAIN\\Alpha",
        PEER: "MACHINE\\Peer",
        BUILTIN: "BUILTIN\\Administrators",
    }
    lookups = {name.lower(): sid for sid, name in display.items()}
    lookups.update(
        {
            "alpha": DOMAIN,
            "peer": PEER,
            "administrators": BUILTIN,
            "alpha@domain": DOMAIN,
        }
    )

    def _parse(name: str) -> str:
        if name.startswith("S-"):
            return name
        if name == "BA":
            return BUILTIN
        raise OSError(1337, "Invalid SID")

    def _lookup(name: str) -> str:
        if name.lower() in lookups:
            return lookups[name.lower()]
        raise OSError(
            1332, "No mapping between account names and security IDs was done."
        )

    def _add(group: str, sid: str) -> None:
        if sid in (PEER, BUILTIN):
            raise OSError(1388, "The member has an invalid account type.")
        stored[group].append(sid)

    def _same_name(existing: str | None, requested: str | None) -> bool:
        # Native tests cover collation; fixture names intentionally use ASCII.
        if existing is None or requested is None:
            return existing is requested
        return existing.lower() == requested.lower()

    monkeypatch.setattr(
        module.groups,
        "list_groups",
        Mock(
            side_effect=lambda: [{"name": name, "description": ""} for name in stored]
        ),
    )
    monkeypatch.setattr(
        module.groups, "member_sids", Mock(side_effect=lambda name: list(stored[name]))
    )
    monkeypatch.setattr(module.groups, "add_member", Mock(side_effect=_add))
    monkeypatch.setattr(
        module.groups,
        "remove_member",
        Mock(side_effect=lambda name, sid: stored[name].remove(sid)),
    )
    monkeypatch.setattr(module.accounts, "parse_sid", Mock(side_effect=_parse))
    monkeypatch.setattr(
        module.accounts, "account_name_to_sid", Mock(side_effect=_lookup)
    )
    monkeypatch.setattr(
        module.accounts,
        "sid_to_name",
        Mock(side_effect=lambda sid: display.get(sid, sid)),
    )
    monkeypatch.setattr(
        module.accounts, "local_user_names", Mock(return_value=["Alpha", "beta"])
    )
    monkeypatch.setattr(module.environment, "values_equal", _same_name)
    return module


@pytest.fixture(name="run_request")
def request_runner(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> RequestRunner:
    """Send JSON requests through the payload's actual public entry point.

    :param payload: Payload whose native operations use the membership fixture.
    :param monkeypatch: Scoped command-line substitution.
    :param tmp_path: Directory holding the request file.
    :param capsys: Capture of the response emitted by the payload.
    :returns: Request function with default group and empty member list.
    """
    request_file = tmp_path / "membership.json"
    monkeypatch.setattr(sys, "argv", ["win_group_membership.py", str(request_file)])

    def _run_request(**options: object) -> tuple[int, dict[str, Any]]:
        request_file.write_text(
            json.dumps(
                {"name": GROUP_NAME, "members": [], "_ansible_diff": True, **options}
            ),
            encoding="utf-8",
        )
        return invoke_payload(payload, capsys)

    return _run_request


def test_add_repeat_remove_replace_clear_and_repeat(
    run_request: RequestRunner, stored: dict[str, list[str]]
) -> None:
    status, added = run_request(members=["beta", "Alpha", ALPHA, ".\\Alpha"])
    assert status == 0
    assert added == {
        "changed": True,
        "name": GROUP_NAME,
        "added": ["MACHINE\\beta", "MACHINE\\Alpha"],
        "members": ["MACHINE\\beta", "MACHINE\\Alpha"],
    }
    assert run_request(members=[ALPHA, BETA])[1]["changed"] is False
    assert stored[GROUP_NAME] == [BETA, ALPHA]
    status, removed = run_request(members=["Alpha", "Alpha"], state="absent")
    assert status == 0
    assert removed == {
        "changed": True,
        "name": GROUP_NAME,
        "removed": ["MACHINE\\Alpha"],
        "members": ["MACHINE\\beta"],
    }
    assert run_request(members=[ALPHA], state="absent")[1]["changed"] is False
    status, replaced = run_request(members=["Alpha", "DOMAIN\\Alpha"], state="pure")
    assert status == 0
    assert replaced == {
        "changed": True,
        "name": GROUP_NAME,
        "added": ["MACHINE\\Alpha", "DOMAIN\\Alpha"],
        "removed": ["MACHINE\\beta"],
        "members": ["MACHINE\\Alpha", "DOMAIN\\Alpha"],
    }
    assert stored[GROUP_NAME] == [ALPHA, DOMAIN]
    assert run_request(members=[DOMAIN, ALPHA], state="pure")[1]["changed"] is False
    cleared = run_request(state="pure")[1]
    assert cleared["removed"] == ["MACHINE\\Alpha", "DOMAIN\\Alpha"]
    assert cleared["members"] == [] and cleared["added"] == []
    assert run_request(state="pure")[1]["changed"] is False


@pytest.mark.parametrize("state", ["present", "absent", "pure"])
def test_missing_group_returns_applicable_change_lists_before_resolving_members(
    run_request: RequestRunner, payload: ModuleType, state: str
) -> None:
    status, result = run_request(name="Missing", members=["Unknown"], state=state)
    assert status == 1 and result["failed"] and not result["changed"]
    assert result["name"] == "Missing"
    assert result["msg"] == "Could not find local group Missing"
    assert ("added" in result) is (state != "absent")
    assert ("removed" in result) is (state != "present")
    assert "members" not in result
    payload.accounts.parse_sid.assert_not_called()
    payload.groups.member_sids.assert_not_called()


def test_requested_spelling_and_unknown_options_do_not_change_group_identity(
    run_request: RequestRunner, payload: ModuleType
) -> None:
    status, result = run_request(
        NAME=GROUP_NAME.lower(), MEMBERS=["Alpha"], STATE="PRESENT", ignored={"a": 1}
    )
    assert status == 0 and result["name"] == GROUP_NAME.lower()
    assert result["added"] == ["MACHINE\\Alpha"]
    assert "diff" not in result and "invocation" not in result
    payload.groups.add_member.assert_called_once_with(GROUP_NAME, ALPHA)
    payload.groups.member_sids.assert_called_with(GROUP_NAME)


@pytest.mark.parametrize(
    "members,expected",
    [
        (["Alpha"], "MACHINE\\Alpha"),
        (["\\Alpha"], "MACHINE\\Alpha"),
        ([".\\Alpha"], "MACHINE\\Alpha"),
        (["MACHINE\\Alpha\\ignored"], "MACHINE\\Alpha"),
        (["DOMAIN\\Alpha\\ignored"], "DOMAIN\\Alpha"),
        (["Alpha@DOMAIN"], "Alpha@DOMAIN"),
        ([".\\Peer"], "Peer"),
        (["MACHINE\\Administrators"], "Administrators"),
    ],
)
def test_legacy_account_selection_precedes_native_lookup(
    run_request: RequestRunner, payload: ModuleType, members: list[str], expected: str
) -> None:
    status, result = run_request(members=members, _ansible_check_mode=True)
    assert status == 0 and result["changed"]
    payload.accounts.account_name_to_sid.assert_called_once_with(expected)


@pytest.mark.parametrize("member", [ALPHA, "BA", "DOMAIN\\Alpha", ".\\Alpha"])
def test_qualified_accounts_and_sid_forms_do_not_enumerate_local_users(
    run_request: RequestRunner, payload: ModuleType, member: str
) -> None:
    assert run_request(members=[member], _ansible_check_mode=True)[0] == 0
    payload.accounts.local_user_names.assert_not_called()


def test_requested_sid_aliases_deduplicate_and_reverse_resolve_once(
    run_request: RequestRunner, payload: ModuleType
) -> None:
    status, result = run_request(
        members=["BA", BUILTIN, "MACHINE\\Administrators"], _ansible_check_mode=True
    )
    assert status == 0
    assert result["added"] == ["BUILTIN\\Administrators"]
    assert payload.accounts.sid_to_name.call_args_list == [call(BUILTIN)]


@pytest.mark.parametrize("state", ["present", "absent", "pure"])
@pytest.mark.parametrize("check", [False, True])
def test_invalid_later_member_fails_before_reading_or_mutating_membership(
    run_request: RequestRunner,
    payload: ModuleType,
    stored: dict[str, list[str]],
    state: str,
    check: bool,
) -> None:
    stored[GROUP_NAME] = [BETA]
    status, result = run_request(
        members=["Alpha", "Unknown"], state=state, _ansible_check_mode=check
    )
    assert status == 1 and result["failed"] and not result["changed"]
    assert (
        "account_name Unknown is not a valid account, cannot get SID" in result["msg"]
    )
    assert set(result) == {"failed", "changed", "msg"}
    assert stored[GROUP_NAME] == [BETA]
    payload.groups.member_sids.assert_not_called()
    payload.groups.add_member.assert_not_called()
    payload.groups.remove_member.assert_not_called()


@pytest.mark.parametrize("state", ["present", "absent", "pure"])
def test_unmapped_requested_sid_fails_even_when_absent_or_in_check_mode(
    run_request: RequestRunner, payload: ModuleType, state: str
) -> None:
    status, result = run_request(
        members=["S-1-5-21-1-9999"], state=state, _ansible_check_mode=True
    )
    assert status == 1 and not result["changed"]
    assert result["msg"].startswith(
        "failed to convert sid 'S-1-5-21-1-9999' to a logon name:"
    )
    assert set(result) == {"failed", "changed", "msg"}
    payload.groups.member_sids.assert_not_called()


@pytest.mark.parametrize("state", ["present", "absent", "pure"])
def test_existing_orphan_sid_is_reported_and_can_be_removed_by_pure(
    run_request: RequestRunner, stored: dict[str, list[str]], state: str
) -> None:
    orphan = "S-1-5-21-111-222-333-9999"
    stored[GROUP_NAME] = [orphan, ALPHA]
    status, result = run_request(state=state)
    assert status == 0
    if state == "pure":
        assert result["removed"] == [orphan, "MACHINE\\Alpha"]
        assert result["members"] == [] and stored[GROUP_NAME] == []
    else:
        assert not result["changed"]
        assert result["members"] == [orphan, "MACHINE\\Alpha"]


def test_check_pure_removes_orphan_in_prediction_only(
    run_request: RequestRunner, stored: dict[str, list[str]]
) -> None:
    orphan = "S-1-5-21-111-222-333-9999"
    stored[GROUP_NAME] = [orphan, ALPHA]
    status, result = run_request(
        members=[ALPHA], state="pure", _ansible_check_mode=True
    )
    assert status == 0 and result["changed"]
    assert result["removed"] == [orphan] and result["members"] == "MACHINE\\Alpha"
    assert stored[GROUP_NAME] == [orphan, ALPHA]


def test_explicit_orphan_removal_fails_before_changing_the_stored_orphan(
    run_request: RequestRunner, stored: dict[str, list[str]]
) -> None:
    orphan = "S-1-5-21-111-222-333-9999"
    stored[GROUP_NAME] = [orphan]
    status, result = run_request(members=[orphan], state="absent")
    assert status == 1 and not result["changed"]
    assert result["msg"].startswith("failed to convert sid")
    assert stored[GROUP_NAME] == [orphan]


@pytest.mark.parametrize("state", ["present", "pure"])
def test_later_add_failure_retains_completed_changes_and_allows_recovery(
    run_request: RequestRunner, stored: dict[str, list[str]], state: str
) -> None:
    stored[GROUP_NAME] = [BETA]
    status, failed = run_request(members=["Alpha", "Peer"], state=state)
    assert status == 1 and failed["failed"] and failed["changed"]
    assert failed["name"] == GROUP_NAME and failed["added"] == ["MACHINE\\Alpha"]
    assert "members" not in failed
    assert stored[GROUP_NAME] == [BETA, ALPHA]
    if state == "pure":
        assert failed["removed"] == []
    status, recovered = run_request(members=["Alpha"], state="pure")
    assert status == 0 and recovered["added"] == []
    assert recovered["removed"] == ["MACHINE\\beta"]
    assert stored[GROUP_NAME] == [ALPHA]


@pytest.mark.parametrize("state", ["absent", "pure"])
def test_later_remove_failure_retains_completed_removals(
    run_request: RequestRunner,
    payload: ModuleType,
    stored: dict[str, list[str]],
    state: str,
) -> None:
    stored[GROUP_NAME] = [ALPHA, BETA]

    def _remove(group: str, sid: str) -> None:
        if sid == BETA:
            raise OSError(5, "Access denied")
        stored[group].remove(sid)

    payload.groups.remove_member.side_effect = _remove
    status, result = run_request(
        members=["Alpha", "beta"] if state == "absent" else [], state=state
    )
    assert status == 1 and result["changed"] and result["failed"]
    assert result["removed"] == ["MACHINE\\Alpha"]
    assert stored[GROUP_NAME] == [BETA] and "members" not in result


def test_first_mutation_failure_preserves_empty_changes_and_false_changed(
    run_request: RequestRunner, stored: dict[str, list[str]]
) -> None:
    status, result = run_request(members=["Peer"])
    assert status == 1 and not result["changed"] and result["added"] == []
    assert result["name"] == GROUP_NAME and "members" not in result
    assert stored[GROUP_NAME] == []


def test_final_enumeration_failure_drops_accumulated_result_but_keeps_mutations(
    run_request: RequestRunner, payload: ModuleType, stored: dict[str, list[str]]
) -> None:
    payload.groups.member_sids.side_effect = [[], OSError(5, "Final read failed")]
    status, result = run_request(members=["Alpha"])
    assert status == 1 and not result["changed"]
    assert set(result) == {"changed", "failed", "msg"}
    assert stored[GROUP_NAME] == [ALPHA]


@pytest.mark.parametrize(
    "options,expected",
    [
        (
            {"state": "present", "members": ["Alpha"]},
            ["MACHINE\\beta", "MACHINE\\Alpha"],
        ),
        ({"state": "absent", "members": ["beta"]}, None),
        ({"state": "pure", "members": ["Alpha"]}, "MACHINE\\Alpha"),
        (
            {"state": "pure", "members": ["Alpha", "DOMAIN\\Alpha"]},
            ["MACHINE\\Alpha", "DOMAIN\\Alpha"],
        ),
    ],
)
def test_check_mode_predicts_membership_without_writes_and_retains_scalar_quirks(
    run_request: RequestRunner,
    payload: ModuleType,
    stored: dict[str, list[str]],
    options: dict[str, object],
    expected: object,
) -> None:
    stored[GROUP_NAME] = [BETA]
    status, result = run_request(**options, _ansible_check_mode=True)
    assert status == 0 and result["changed"] and result["members"] == expected
    assert stored[GROUP_NAME] == [BETA]
    payload.groups.add_member.assert_not_called()
    payload.groups.remove_member.assert_not_called()


@pytest.mark.parametrize("state", ["present", "absent", "pure"])
@pytest.mark.parametrize("existing", [[], [ALPHA]])
def test_unchanged_check_mode_members_always_remain_lists(
    run_request: RequestRunner,
    stored: dict[str, list[str]],
    state: str,
    existing: list[str],
) -> None:
    stored[GROUP_NAME] = list(existing)
    requested = existing if state == "pure" else []
    status, result = run_request(
        members=requested, state=state, _ansible_check_mode=True
    )
    assert status == 0 and not result["changed"]
    assert result["members"] == (["MACHINE\\Alpha"] if existing else [])


def test_present_returns_fresh_native_order_instead_of_request_order(
    run_request: RequestRunner, payload: ModuleType
) -> None:
    payload.groups.member_sids.side_effect = [[], [ALPHA, BETA]]
    status, result = run_request(members=["beta", "Alpha"])
    assert status == 0
    assert result["added"] == ["MACHINE\\beta", "MACHINE\\Alpha"]
    assert result["members"] == ["MACHINE\\Alpha", "MACHINE\\beta"]


def test_pure_reenumerates_after_additions_before_selecting_removals(
    run_request: RequestRunner, payload: ModuleType
) -> None:
    payload.groups.member_sids.side_effect = [[BETA], [BETA, DOMAIN, ALPHA], [ALPHA]]
    payload.groups.remove_member.side_effect = None
    status, result = run_request(members=["Alpha"], state="pure")
    assert status == 0
    assert result["removed"] == ["MACHINE\\beta", "DOMAIN\\Alpha"]
    assert payload.groups.remove_member.call_args_list == [
        call(GROUP_NAME, BETA),
        call(GROUP_NAME, DOMAIN),
    ]


@pytest.mark.parametrize("members", [" beta , Alpha ", ["beta", "Alpha"]])
def test_string_members_split_trim_and_preserve_order(
    run_request: RequestRunner, members: object
) -> None:
    status, result = run_request(members=members)
    assert status == 0 and result["added"] == ["MACHINE\\beta", "MACHINE\\Alpha"]


@pytest.mark.parametrize(
    "members,expected",
    [
        ([["Alpha"]], ["MACHINE\\Alpha"]),
        ([["Alpha", "beta"]], ["MACHINE\\Alpha", "MACHINE\\beta"]),
        ([[["Alpha"]]], ["MACHINE\\Alpha"]),
        ([[["Alpha"], "beta"]], ["MACHINE\\Alpha", "MACHINE\\beta"]),
    ],
)
def test_nested_list_entries_bind_to_a_string_array(
    run_request: RequestRunner, members: list[object], expected: list[str]
) -> None:
    status, result = run_request(members=members)
    assert status == 0 and result["added"] == expected


def test_deeper_array_string_conversion_joins_names_before_lookup(
    run_request: RequestRunner, payload: ModuleType
) -> None:
    status, result = run_request(members=[[["Alpha", "beta"]]])
    assert status == 1 and not result["changed"]
    assert result["msg"].startswith("account_name Alpha beta is not a valid account")
    payload.accounts.account_name_to_sid.assert_called_once_with("Alpha beta")
    payload.groups.add_member.assert_not_called()


@pytest.mark.parametrize(
    "members,reason",
    [
        ([[]], "an empty array"),
        ([[""]], "an empty string"),
        ([["Unknown", ""]], "an empty string"),
        ([["Unknown", None]], "null"),
    ],
)
def test_nested_argument_binding_validates_the_whole_array_before_resolution(
    run_request: RequestRunner, payload: ModuleType, members: list[object], reason: str
) -> None:
    status, result = run_request(members=members)
    assert status == 1 and not result["changed"]
    assert result["msg"].endswith("because it is " + reason + ".")
    payload.accounts.parse_sid.assert_not_called()


@pytest.mark.parametrize("member", [-(2**31), 0, 2**31 - 1])
def test_int32_scalar_members_reach_account_lookup(
    run_request: RequestRunner, payload: ModuleType, member: int
) -> None:
    status, result = run_request(members=member)
    assert status == 1
    assert result["msg"].startswith("account_name " + str(member))
    payload.accounts.account_name_to_sid.assert_called_once_with(str(member))


@pytest.mark.parametrize("members", [True, 1.5, {}, 2**31, -(2**31) - 1])
def test_invalid_list_types_fail_before_group_lookup(
    run_request: RequestRunner, payload: ModuleType, members: object
) -> None:
    status, result = run_request(members=members)
    assert status == 1 and not result["changed"]
    assert result["msg"] == "Get-AnsibleParam: Parameter 'members' is not a YAML list."
    payload.groups.list_groups.assert_not_called()


@pytest.mark.parametrize("members", [None, "", [""], [None], ["Alpha", None]])
def test_invalid_pipeline_binding_fails_after_group_lookup_before_writes(
    run_request: RequestRunner, payload: ModuleType, members: object
) -> None:
    status, result = run_request(members=members)
    assert status == 1 and not result["changed"]
    assert result["msg"].startswith(
        "Unhandled exception while executing module: Cannot bind argument to parameter 'Member'"
    )
    assert "exception" in result
    payload.groups.member_sids.assert_not_called()
    payload.groups.add_member.assert_not_called()


@pytest.mark.parametrize("missing", ["name", "members"])
def test_missing_required_argument_is_distinct_from_null(
    payload: ModuleType, missing: str
) -> None:
    arguments = {"name": GROUP_NAME, "members": []}
    del arguments[missing]
    with pytest.raises(
        ValueError, match="Get-AnsibleParam: Missing required argument: " + missing
    ):
        payload._parameters(arguments)


@pytest.mark.parametrize("state", [None, "", "other", ["present", "absent"], {}])
def test_invalid_state_fails_before_native_reads(
    run_request: RequestRunner, payload: ModuleType, state: object
) -> None:
    status, result = run_request(state=state)
    assert status == 1 and not result["changed"]
    assert result["msg"].startswith(
        "Get-AnsibleParam: Argument state needs to be one of present,absent,pure but was"
    )
    payload.groups.list_groups.assert_not_called()


@pytest.mark.parametrize("check", [False, True])
def test_singleton_state_array_validates_then_performs_no_changes(
    run_request: RequestRunner, stored: dict[str, list[str]], check: bool
) -> None:
    stored[GROUP_NAME] = [ALPHA]
    status, result = run_request(
        members=["Alpha", "beta"], state=["present"], _ansible_check_mode=check
    )
    assert status == 0
    assert result == {
        "changed": False,
        "name": GROUP_NAME,
        "members": ["MACHINE\\Alpha"],
    }
    assert stored[GROUP_NAME] == [ALPHA]


def test_singleton_state_array_still_resolves_requested_accounts(
    run_request: RequestRunner,
) -> None:
    status, result = run_request(members=["Unknown"], state=["present"])
    assert status == 1 and not result["changed"]
    assert result["msg"].startswith("account_name Unknown")
