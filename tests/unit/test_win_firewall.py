"""Exercise configured-profile public results, ordering, failures, and check mode."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes exercise behavior without establishing Windows support.
# pylint: disable=protected-access

import copy
from contextlib import nullcontext
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload


@pytest.fixture(name="runner")
def firewall_runner(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> Any:
    """Run public JSON calls with observable configured-profile state.

    :param monkeypatch: Scoped native replacements.
    :param capsys: Scoped public JSON output capture.
    :returns: Runner, native calls, and mutable configured state.
    """
    module = load_payload("win_firewall", monkeypatch)
    state = {
        name: {
            "Name": name,
            "Enabled": 1,
            "DefaultInboundAction": 0,
            "DefaultOutboundAction": 0,
            "__PATH": "native:" + name,
        }
        for name in module.firewall.PROFILES
    }
    events: list[tuple[Any, ...]] = []

    def _read(name: str) -> dict[str, Any]:
        events.append(("read", name))
        return copy.deepcopy(state[name])

    def _set(profile: dict[str, Any], name: str, value: int) -> None:
        events.append(("set", profile["Name"], name, value))
        state[profile["Name"]][name] = value

    native = SimpleNamespace(
        read=Mock(side_effect=_read),
        set_property=Mock(side_effect=_set),
        available_profiles=module.firewall.PROFILES,
        validate_request=Mock(),
    )
    constructor = Mock(side_effect=lambda: nullcontext(native))
    monkeypatch.setattr(module.firewall, "FirewallProfiles", constructor)

    # Keep argument injection in this fixture's lifetime so unrelated hotfix
    # tests cannot affect the firewall payload's native-policy substitutes.
    # pylint: disable=duplicate-code
    def _run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        monkeypatch.setattr(
            module, "read_arguments", lambda *_args, **_kwargs: arguments
        )
        return invoke_payload(module, capsys)

    return SimpleNamespace(
        run=_run,
        state=state,
        native=native,
        events=events,
        constructor=constructor,
        module=module,
    )


# pylint: enable=duplicate-code
def _observation(
    current: int, selected: bool, enabled: bool | None = None
) -> dict[str, Any]:
    return {
        "currentstate": current,
        "considered": selected,
        "enabled": current == 1 if enabled is None else enabled,
    }


def test_default_profiles_read_every_profile_and_report_configured_state(
    runner: Any,
) -> None:
    assert runner.run({"state": "enabled"}) == (
        0,
        {
            "changed": False,
            "restart_required": False,
            "profiles": ["Domain", "Private", "Public"],
            "state": "enabled",
            "Domain": _observation(1, True),
            "Private": _observation(1, True),
            "Public": _observation(1, True),
        },
    )
    assert runner.events == [("read", name) for name in ("Domain", "Private", "Public")]
    runner.native.set_property.assert_not_called()


def test_requested_order_case_duplicates_do_not_change_native_order(
    runner: Any,
) -> None:
    profiles = ["pUbLiC", "dOmAiN", "PUBLIC"]
    code, result = runner.run({"state": "DISABLED", "profiles": profiles})
    assert (
        code == 0 and result["profiles"] == profiles and result["state"] == "DISABLED"
    )
    assert result["changed"] and result["Domain"] == _observation(1, True, False)
    assert result["Private"] == _observation(1, False)
    assert result["Public"] == _observation(1, True, False)
    assert runner.events == [
        ("read", "Domain"),
        ("set", "Domain", "Enabled", 0),
        ("read", "Private"),
        ("read", "Public"),
        ("set", "Public", "Enabled", 0),
    ]


@pytest.mark.parametrize("profiles", [[], None])
def test_empty_and_null_profiles_select_none_but_still_read_all(
    runner: Any, profiles: Any
) -> None:
    code, result = runner.run(
        {"state": "enabled", "profiles": profiles, "inbound_action": "block"}
    )
    assert code == 0 and not result["changed"] and result["profiles"] == profiles
    assert all(
        not result[name]["considered"] for name in ("Domain", "Private", "Public")
    )
    assert runner.native.read.call_count == 3
    runner.native.set_property.assert_not_called()


def test_enabled_status_then_inbound_then_outbound_and_repeat(runner: Any) -> None:
    runner.state["Domain"]["Enabled"] = 0
    arguments = {
        "profiles": "Domain",
        "state": "enabled",
        "inbound_action": "allow",
        "outbound_action": "block",
    }
    code, result = runner.run(arguments)
    assert (
        code == 0
        and result["changed"]
        and result["Domain"] == _observation(0, True, True)
    )
    assert runner.events == [
        ("read", "Domain"),
        ("set", "Domain", "Enabled", 1),
        ("set", "Domain", "DefaultInboundAction", 2),
        ("set", "Domain", "DefaultOutboundAction", 4),
        ("read", "Private"),
        ("read", "Public"),
    ]
    assert runner.run(arguments)[1]["changed"] is False


@pytest.mark.parametrize(
    "state,current,predicted", [("enabled", 0, True), ("disabled", 1, False)]
)
def test_check_mode_predicts_status_but_never_writes(
    runner: Any, state: str, current: int, predicted: bool
) -> None:
    runner.state["Domain"]["Enabled"] = current
    before = copy.deepcopy(runner.state)
    code, result = runner.run(
        {
            "profiles": ["Domain"],
            "state": state,
            "inbound_action": "block",
            "outbound_action": "allow",
            "_ansible_check_mode": True,
        }
    )
    assert code == 0 and result["changed"]
    assert result["Domain"] == _observation(current, True, predicted)
    assert runner.state == before
    runner.native.set_property.assert_not_called()


def test_check_mode_action_change_keeps_current_enabled_enum(runner: Any) -> None:
    result = runner.run(
        {"state": "enabled", "inbound_action": "block", "_ansible_check_mode": True}
    )[1]
    assert result["changed"]
    assert all(result[name] == _observation(1, True) for name in runner.state)
    assert all(row["DefaultInboundAction"] == 0 for row in runner.state.values())


@pytest.mark.parametrize("state", ["disabled", None])
def test_disabled_and_explicit_null_state_ignore_both_valid_actions(
    runner: Any, state: Any
) -> None:
    arguments = {
        "state": state,
        "profiles": ["Domain"],
        "inbound_action": "allow",
        "outbound_action": "block",
    }
    result = runner.run(arguments)[1]
    assert result["state"] == state and result["Domain"] == _observation(1, True, False)
    assert runner.state["Domain"]["DefaultInboundAction"] == 0
    assert runner.state["Domain"]["DefaultOutboundAction"] == 0
    assert runner.run(arguments)[1]["changed"] is False


@pytest.mark.parametrize("state", ["enabled", "disabled"])
def test_not_configured_enabled_state_is_left_unchanged(
    runner: Any, state: str
) -> None:
    runner.state["Domain"]["Enabled"] = 2
    result = runner.run({"profiles": ["Domain"], "state": state})[1]
    assert not result["changed"] and result["Domain"] == _observation(2, True)
    runner.native.set_property.assert_not_called()


def test_actions_still_apply_when_enabled_enum_is_not_configured(runner: Any) -> None:
    runner.state["Domain"]["Enabled"] = 2
    result = runner.run(
        {"profiles": ["Domain"], "state": "enabled", "inbound_action": "block"}
    )[1]
    assert result["changed"] and result["Domain"] == _observation(2, True)
    assert runner.events[1] == ("set", "Domain", "DefaultInboundAction", 4)


def test_configured_not_configured_is_not_the_effective_block_or_allow_default(
    runner: Any,
) -> None:
    arguments = {"profiles": ["Domain"], "state": "enabled", "inbound_action": "block"}
    assert runner.run(arguments)[1]["changed"]
    assert not runner.run(arguments)[1]["changed"]
    arguments["inbound_action"] = "NOT_CONFIGURED"
    assert runner.run(arguments)[1]["changed"]
    assert runner.state["Domain"]["DefaultInboundAction"] == 0
    assert not runner.run(arguments)[1]["changed"]


def test_later_property_failure_retains_earlier_writes_and_public_observation(
    runner: Any,
) -> None:
    runner.state["Domain"]["Enabled"] = 0
    ordinary_set = runner.native.set_property.side_effect

    def _set(profile: dict[str, Any], name: str, value: int) -> None:
        if name == "DefaultOutboundAction":
            raise OSError("Observed setter denial")
        ordinary_set(profile, name, value)

    runner.native.set_property.side_effect = _set
    code, result = runner.run(
        {
            "profiles": ["Domain"],
            "state": "enabled",
            "inbound_action": "allow",
            "outbound_action": "block",
        }
    )
    assert code == 1 and result["failed"] and result["changed"]
    assert result["Domain"] == _observation(0, True, True)
    assert "Private" not in result and "Public" not in result
    assert result["msg"] == (
        "an error occurred when attempting to change firewall status "
        "for profile Domain Observed setter denial"
    )
    assert runner.state["Domain"]["Enabled"] == 1
    assert runner.state["Domain"]["DefaultInboundAction"] == 2
    assert runner.state["Domain"]["DefaultOutboundAction"] == 0


def test_first_setter_failure_does_not_predict_a_completed_change(runner: Any) -> None:
    runner.native.set_property.side_effect = OSError("Denied")
    code, result = runner.run({"state": "disabled"})
    assert code == 1 and result["failed"] and not result["changed"]
    assert result["Domain"] == _observation(1, True)
    assert runner.state["Domain"]["Enabled"] == 1


def test_later_profile_read_failure_retains_completed_earlier_profile(
    runner: Any,
) -> None:
    ordinary_read = runner.native.read.side_effect

    def _read(name: str) -> dict[str, Any]:
        if name == "Private":
            raise OSError("Observed profile read failure")
        return dict(ordinary_read(name))

    runner.native.read.side_effect = _read
    code, result = runner.run({"profiles": ["Public", "Domain"], "state": "disabled"})
    assert code == 1 and result["changed"] and result["failed"]
    assert result["Domain"] == _observation(1, True, False)
    assert "Private" not in result and "Public" not in result
    assert "profile Private Observed profile read failure" in result["msg"]
    assert runner.state["Public"]["Enabled"] == 1


@pytest.mark.parametrize("profiles", [[], None, ["Domain"]])
def test_unavailable_provider_fails_before_any_read_or_write(
    runner: Any, profiles: Any
) -> None:
    runner.constructor.side_effect = OSError("Native provider unavailable")
    code, result = runner.run({"profiles": profiles, "state": "enabled"})
    assert code == 1 and result == {
        "failed": True,
        "changed": False,
        "restart_required": False,
        "state": "enabled",
        "profiles": profiles,
        "msg": "Native provider unavailable",
    }
    runner.native.read.assert_not_called()
    runner.native.set_property.assert_not_called()


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({}, "missing required arguments: state"),
        (
            {"state": "invalid"},
            "value of state must be one of: disabled, enabled. Got no match for: invalid",
        ),
        (
            {"state": "disabled", "inbound_action": "invalid"},
            "value of inbound_action must be one of: allow, block, not_configured. "
            "Got no match for: invalid",
        ),
        (
            {"state": "enabled", "profiles": [" Domain "]},
            "value of profiles must be one or more of: Domain, Private, Public. "
            "Got no match for:  Domain ",
        ),
        ({"state": "enabled", "profiles": "Domain,"}, "Got no match for: "),
        (
            {"state": "enabled", "profiles": [None]},
            "profiles must not contain null entries.",
        ),
    ],
)
def test_validation_fails_before_firewall_access(
    runner: Any, arguments: Any, message: str
) -> None:
    code, result = runner.run(arguments)
    assert code == 1 and result["failed"] and not result["changed"]
    assert message in result["msg"]
    runner.constructor.assert_not_called()


def test_comma_separated_profile_string_is_trimmed_and_preserved(runner: Any) -> None:
    result = runner.run({"state": "ENABLED", "profiles": "Public, dOmAiN,Public"})[1]
    assert result["profiles"] == ["Public", "dOmAiN", "Public"]
    assert result["state"] == "ENABLED" and not result["changed"]


def test_duplicate_invalid_profile_choices_are_reported_once(runner: Any) -> None:
    result = runner.run({"state": "enabled", "profiles": ["Other", "OTHER", "Second"]})[
        1
    ]
    assert result["msg"].endswith("Got no match for: Other, Second")


def _classic(runner: Any) -> None:
    native = runner.module.firewall._ComProfiles()
    native._classic = True
    native.available_profiles = ("Domain",)
    runner.native.available_profiles = native.available_profiles
    runner.native.validate_request.side_effect = native.validate_request


def test_classic_domain_state_check_repeat_and_unavailable_objects(runner: Any) -> None:
    _classic(runner)
    arguments = {"profiles": ["dOmAiN", "DOMAIN"], "state": "disabled"}
    before = copy.deepcopy(runner.state)
    preview = runner.run({**arguments, "_ansible_check_mode": True})[1]
    assert preview["changed"] and preview["Domain"] == _observation(1, True, False)
    assert runner.state == before
    result = runner.run(arguments)[1]
    assert result["changed"] and result["Domain"] == _observation(1, True, False)
    assert result["profiles"] == ["dOmAiN", "DOMAIN"]
    assert "Private" not in result and "Public" not in result
    assert runner.run(arguments)[1]["changed"] is False


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({"state": "enabled"}, "Private/Public profiles are unavailable"),
        ({"profiles": ["Domain", "Private"], "state": "disabled"}, "Private/Public"),
        (
            {"profiles": ["Domain"], "state": "enabled", "inbound_action": "block"},
            "cannot configure default",
        ),
        (
            {"profiles": ["Domain"], "state": "enabled", "outbound_action": "allow"},
            "cannot configure default",
        ),
    ],
)
def test_classic_unsupported_requests_fail_before_reading_or_writing(
    runner: Any,
    arguments: dict[str, Any],
    message: str,
) -> None:
    _classic(runner)
    code, result = runner.run(arguments)
    assert code == 1 and result["failed"] and not result["changed"]
    assert message in result["msg"]
    runner.native.read.assert_not_called()
    runner.native.set_property.assert_not_called()


def test_classic_disabling_ignores_actions_and_empty_selection_is_read_only(
    runner: Any,
) -> None:
    _classic(runner)
    code, result = runner.run(
        {"profiles": [], "state": "enabled", "inbound_action": "not_configured"}
    )
    assert code == 0 and not result["changed"]
    assert result["Domain"] == _observation(1, False)
    code, result = runner.run(
        {
            "profiles": ["Domain"],
            "state": "disabled",
            "inbound_action": "allow",
            "outbound_action": "block",
        }
    )
    assert code == 0 and result["changed"]
    assert runner.state["Domain"]["Enabled"] == 0
