"""Exercise the user-profile public interface and partial effects."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

SID = "S-1-5-21-1-2-3-1001"
PATH = r"C:\Users\fixture"


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.fixture(name="runner")
def profile_runner(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> Any:
    """Supply observable profile operations while retaining public JSON output.

    :param monkeypatch: Scoped native-interface replacements.
    :param capsys: Output capture for each public request.
    :returns: Runner and native-operation mocks.
    """
    module = load_payload("win_user_profile", monkeypatch)
    records: list[dict[str, str]] = []
    native = SimpleNamespace(
        profile_sids=Mock(side_effect=lambda: [entry["sid"] for entry in records]),
        profile_path=Mock(
            side_effect=lambda sid: next(
                entry["path"] for entry in records if entry["sid"] == sid
            )
        ),
        profiles_directory=Mock(return_value=r"C:\Users"),
        create_profile=Mock(return_value=PATH),
        delete_profile=Mock(),
    )
    for name, function in vars(native).items():
        monkeypatch.setattr(module.profiles, name, function)
    resolve = Mock(return_value=SID)
    reverse = Mock(return_value=r"COMPUTER\fixture")
    monkeypatch.setattr(module.accounts, "name_to_sid", resolve)
    monkeypatch.setattr(module.accounts, "sid_to_name", reverse)
    monkeypatch.setattr(
        module.environment,
        "values_equal",
        lambda left, right: left.casefold() == right.casefold(),
    )

    def _run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        monkeypatch.setattr(module, "read_arguments", lambda *_args: arguments)
        return invoke_payload(module, capsys)

    return SimpleNamespace(
        run=_run,
        module=module,
        native=native,
        records=records,
        resolve=resolve,
        reverse=reverse,
    )


# pylint: enable=duplicate-code


@pytest.mark.parametrize("arguments", [{}, {"state": "absent"}, {"state": "unknown"}])
def test_required_selector_and_state_fail_before_native_queries(
    runner: Any, arguments: dict[str, Any]
) -> None:
    status, result = runner.run(arguments)
    assert status == 1 and result["failed"] and not result["changed"]
    runner.native.profile_sids.assert_not_called()


@pytest.mark.parametrize("check", [False, True])
def test_existing_profile_is_idempotent_without_reverse_lookup(
    runner: Any, check: bool
) -> None:
    runner.records.append({"sid": SID, "path": PATH})
    assert runner.run(
        {"username": SID, "name": "ignored", "_ansible_check_mode": check}
    ) == (0, {"changed": False, "path": PATH})
    runner.reverse.assert_not_called()
    runner.native.create_profile.assert_not_called()


@pytest.mark.parametrize("state,changed", [("Present", False), ("ABSENT", True)])
def test_mixed_case_states_match_measured_original_choices(
    runner: Any, state: str, changed: bool
) -> None:
    runner.records.append({"sid": SID, "path": PATH})
    assert runner.run(
        {"username": SID, "state": state, "_ansible_check_mode": True}
    ) == (0, {"changed": changed, "path": PATH})
    runner.native.create_profile.assert_not_called()
    runner.native.delete_profile.assert_not_called()


def test_create_and_repeat_preserve_the_native_collision_path(runner: Any) -> None:
    actual = PATH + ".000"
    runner.native.create_profile.return_value = actual
    assert runner.run({"username": "fixture"}) == (0, {"changed": True, "path": actual})
    runner.native.create_profile.assert_called_once_with(SID, "fixture")
    runner.records.append({"sid": SID, "path": actual})
    assert runner.run({"username": "fixture"}) == (
        0,
        {"changed": False, "path": actual},
    )
    assert runner.native.create_profile.call_count == 1


def test_creation_check_predicts_unsuffixed_path_without_writing(runner: Any) -> None:
    assert runner.run(
        {"username": SID, "name": "custom", "_ansible_check_mode": True}
    ) == (0, {"changed": True, "path": r"C:\Users\custom"})
    runner.native.create_profile.assert_not_called()


@pytest.mark.parametrize(
    "name,expected",
    [
        (r"\fixture", r"C:\Users\fixture"),
        ("/fixture", r"C:\Users\fixture"),
        (r"\\fixture", r"C:\Users\\fixture"),
        (r"C:\fixture", r"C:\Users\C:\fixture"),
        (r".\fixture", r"C:\Users\.\fixture"),
        (r"..\fixture", r"C:\Users\..\fixture"),
    ],
)
def test_preview_uses_measured_provider_relative_join(
    runner: Any, name: str, expected: str
) -> None:
    assert runner.run({"username": SID, "name": name, "_ansible_check_mode": True}) == (
        0,
        {"changed": True, "path": expected},
    )
    runner.native.create_profile.assert_not_called()


@pytest.mark.parametrize("name", [r"\fixture", "/fixture"])
def test_absent_rooted_selector_matches_only_the_profile_root_child(
    runner: Any, name: str
) -> None:
    outside = "S-1-5-21-1-2-3-1002"
    runner.records.extend(
        [{"sid": SID, "path": PATH}, {"sid": outside, "path": r"C:\fixture"}]
    )
    assert runner.run({"name": name, "state": "absent"}) == (
        0,
        {"changed": True, "path": PATH},
    )
    runner.native.delete_profile.assert_called_once_with(SID)


@pytest.mark.parametrize(
    "arguments",
    [
        {"state": "absent", "name": None},
        {"state": "absent", "username": None},
        {"state": "absent", "username": None, "name": None},
    ],
)
def test_explicit_null_absent_selector_reaches_empty_basename_matching(
    runner: Any, arguments: dict[str, Any]
) -> None:
    assert runner.run(arguments) == (0, {"changed": False, "path": None})
    runner.native.profile_sids.assert_called_once()
    runner.native.profiles_directory.assert_called_once()
    runner.native.delete_profile.assert_not_called()


@pytest.mark.parametrize("state", ["present", "Present"])
def test_explicit_null_present_sid_preserves_unhandled_original_boundary(
    runner: Any, state: str
) -> None:
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    assert runner.run({"username": None, "state": state, "name": "fixture"}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "exception": "(traceback unavailable)",
            "msg": "Unhandled exception while executing module: "
            "You cannot call a method on a null-valued expression.",
        },
    )
    # pylint: enable=duplicate-code
    runner.native.profile_sids.assert_called_once()
    runner.native.profiles_directory.assert_not_called()
    runner.reverse.assert_not_called()


def test_unmapped_sid_can_be_removed_but_not_created(runner: Any) -> None:
    runner.reverse.return_value = SID
    assert runner.run({"username": SID})[1] == {
        "changed": False,
        "path": None,
        "failed": True,
        "msg": "Fail to map the account '" + SID + "' to a valid user",
    }
    runner.records.append({"sid": SID, "path": PATH})
    assert runner.run({"username": SID, "state": "absent"}) == (
        0,
        {"changed": True, "path": PATH},
    )
    runner.native.delete_profile.assert_called_once_with(SID)


@pytest.mark.parametrize("check", [False, True])
def test_name_selection_is_case_insensitive_and_does_not_resolve_an_account(
    runner: Any, check: bool
) -> None:
    runner.records.extend(
        [
            {"sid": SID, "path": PATH},
            {"sid": "S-1-5-21-9", "path": PATH + ".000"},
        ]
    )
    assert runner.run(
        {"name": "FIXTURE", "state": "absent", "_ansible_check_mode": check}
    ) == (0, {"changed": True, "path": PATH})
    runner.resolve.assert_not_called()
    assert runner.native.delete_profile.call_count == (0 if check else 1)


def test_username_selection_takes_precedence_over_name(runner: Any) -> None:
    runner.records.append({"sid": SID, "path": PATH + ".000"})
    assert (
        runner.run({"username": SID, "name": "other", "state": "absent"})[1]["path"]
        == PATH + ".000"
    )
    runner.native.profiles_directory.assert_not_called()


def test_multiple_matches_require_permission_before_any_deletion(runner: Any) -> None:
    runner.records.extend(
        [
            {"sid": SID, "path": PATH},
            {"sid": "S-1-5-21-1-2-3-1002", "path": PATH},
        ]
    )
    status, result = runner.run({"name": "fixture", "state": "absent"})
    assert status == 1 and not result["changed"] and result["path"] is None
    assert result["msg"] == (
        "Found multiple profiles matching the path '"
        + PATH
        + "', set 'remove_multiple=True' to remove all the profiles for this match"
    )
    runner.native.delete_profile.assert_not_called()
    assert runner.run({"name": "fixture", "state": "absent", "remove_multiple": True})[
        1
    ] == {"changed": True, "path": PATH}
    assert [call.args[0] for call in runner.native.delete_profile.call_args_list] == [
        entry["sid"] for entry in runner.records
    ]


def test_partial_delete_failure_keeps_the_completed_change_visible(runner: Any) -> None:
    runner.records.extend(
        [
            {"sid": SID, "path": PATH},
            {"sid": "S-1-5-21-1-2-3-1002", "path": PATH},
        ]
    )
    error = OSError(5, "Access is denied.")
    setattr(error, "winerror", 5)
    runner.native.delete_profile.side_effect = [None, error]
    status, result = runner.run(
        {"name": "fixture", "state": "absent", "remove_multiple": True}
    )
    assert status == 1 and result["changed"] and result["path"] == PATH
    assert result["msg"].endswith("Access is denied. (Win32 ErrorCode 5 - 0x00000005)")


def test_absent_missing_profile_has_null_path_without_mutation(runner: Any) -> None:
    assert runner.run({"username": SID, "state": "absent"}) == (
        0,
        {"changed": False, "path": None},
    )
    runner.native.delete_profile.assert_not_called()


@pytest.mark.parametrize(
    "username,detail",
    [
        ("", "String cannot be of zero length.\r\nParameter name: name"),
        ("does-not-exist", "Some or all identity references could not be translated."),
    ],
)
def test_sid_binding_preserves_measured_original_diagnostics(
    runner: Any, username: str, detail: str
) -> None:
    error = OSError(1332, "native mapping failure")
    setattr(error, "winerror", 1332)
    runner.resolve.side_effect = error
    assert runner.run({"username": username})[1] == {
        "changed": False,
        "failed": True,
        "msg": (
            "argument for username is of type System.String and we were unable "
            "to convert to sid: " + detail
        ),
    }
    runner.native.profile_sids.assert_not_called()


def test_dot_qualified_account_retains_original_binding_failure(runner: Any) -> None:
    assert runner.run({"username": r".\fixture"}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": (
                "argument for username is of type System.String and we were "
                "unable to convert to sid: Some or all identity references "
                "could not be translated."
            ),
        },
    )
    runner.resolve.assert_not_called()
    runner.native.profile_sids.assert_not_called()
    runner.native.create_profile.assert_not_called()
    runner.native.delete_profile.assert_not_called()


@pytest.mark.parametrize(
    "value,kind",
    [
        (1, "System.Int32"),
        (True, "System.Boolean"),
        ([], "System.Object[]"),
    ],
)
def test_sid_diagnostic_retains_the_original_argument_type(
    runner: Any, value: Any, kind: str
) -> None:
    error = OSError(1332, "mapping failure")
    setattr(error, "winerror", 1332)
    runner.resolve.side_effect = error
    assert runner.run({"username": value})[1]["msg"] == (
        "argument for username is of type "
        + kind
        + " and we were unable to convert to sid: "
        "Some or all identity references could not be translated."
    )


def test_null_state_enumerates_keys_but_never_reads_paths_or_changes_profiles(
    runner: Any,
) -> None:
    assert runner.run({"state": None}) == (0, {"changed": False, "path": None})
    runner.native.profile_sids.assert_called_once_with()
    runner.native.profile_path.assert_not_called()
    runner.native.create_profile.assert_not_called()
    runner.native.delete_profile.assert_not_called()


def test_sid_request_does_not_read_unselected_profile_paths(runner: Any) -> None:
    runner.records.extend(
        [
            {"sid": "unrelated-profile-without-an-image-path"},
            {"sid": SID, "path": PATH},
        ]
    )
    assert runner.run({"username": SID}) == (0, {"changed": False, "path": PATH})
    runner.native.profile_path.assert_called_once_with(SID)


def test_new_profile_provider_boundary_does_not_invalidate_preview(runner: Any) -> None:
    runner.native.create_profile.side_effect = ValueError("creation API unavailable")
    assert runner.run({"username": SID})[0] == 1
    assert runner.run({"username": SID, "_ansible_check_mode": True}) == (
        0,
        {"changed": True, "path": PATH},
    )


def test_real_argument_reader_rejects_unknown_parameters(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    module = load_payload("win_user_profile", monkeypatch)
    arguments = tmp_path / "arguments.json"
    arguments.write_text(json.dumps({"unsupported_option": True}), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["win_user_profile.py", str(arguments)])
    status, result = invoke_payload(module, capsys)
    assert status == 1 and "Unsupported parameters" in result["msg"]
