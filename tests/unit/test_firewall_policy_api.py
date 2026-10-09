"""Exercise installed firewall COM capabilities and native value boundaries."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes check behavior; they are not Windows execution evidence.
# pylint: disable=protected-access

import ctypes
import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="policy")
def policy_api(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Supply only the fixed Windows COM calls used by the firewall helper.

    :param monkeypatch: Scoped native API replacements.
    :returns: Helper, observable calls and mutable native profile values.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    helper = load_module(
        ROOT / "plugins/module_utils/legacy_windows_firewall.py",
        "tested_firewall_policy_api",
    )
    events: list[tuple[Any, ...]] = []
    values = {profile: {8: -1, 23: 0, 25: 1} for profile in (1, 2, 4)}
    state = SimpleNamespace(classic=False, initialization=0, denied=None)

    def _create(
        class_id: Any, _outer: Any, context: int, interface_id: Any, output: Any
    ) -> int:
        identifier = str(uuid.UUID(bytes_le=bytes(class_id._obj)))
        interface = str(uuid.UUID(bytes_le=bytes(interface_id._obj)))
        events.append(("create", identifier, interface, context))
        if identifier == helper._POLICY2_CLASS:
            assert interface == helper._POLICY2_INTERFACE
            if state.classic:
                return 0x80040154
            output._obj.value = 10
        else:
            assert identifier == helper._MANAGER_CLASS
            assert interface == helper._MANAGER_INTERFACE
            output._obj.value = 20
        return 0

    def _method(pointer: Any, slot: int, _result: Any, _arguments: Any) -> Any:
        def _invoke(_this: Any, *arguments: Any) -> int:
            events.append(("invoke", pointer.value, slot, arguments))
            if state.denied == (pointer.value, slot):
                return 0x80070005
            if slot == 2:
                return 0
            if pointer.value == 20 and slot == 7:
                arguments[0]._obj.value = 30
            elif pointer.value == 30 and slot == 8:
                assert arguments[0] == 0  # Genuine Domain, never Standard.
                arguments[1]._obj.value = 40
            else:
                profile = 1 if pointer.value == 40 else arguments[0]
                assert pointer.value in (10, 40)
                if slot in (8, 23, 25):
                    arguments[-1]._obj.value = values[profile][slot]
                else:
                    assert slot in (9, 24, 26)
                    values[profile][slot - 1] = arguments[-1]
            return 0

        return _invoke

    ole = SimpleNamespace(
        CoInitializeEx=Mock(side_effect=lambda *_args: state.initialization),
        CoUninitialize=Mock(),
        CoCreateInstance=Mock(side_effect=_create),
    )
    monkeypatch.setattr(helper, "_ole_library", lambda: ole)
    monkeypatch.setattr(helper, "_method", _method)
    return SimpleNamespace(
        helper=helper, events=events, values=values, state=state, ole=ole
    )


@pytest.mark.parametrize("name,mask", [("Domain", 1), ("Private", 2), ("Public", 4)])
def test_advanced_policy_reads_genuine_local_profiles(
    policy: Any, name: str, mask: int
) -> None:
    with policy.helper._ComProfiles() as native:
        assert native.available_profiles == policy.helper.PROFILES
        assert native.read(name) == {
            "Name": name,
            "Enabled": 1,
            "DefaultInboundAction": 4,
            "DefaultOutboundAction": 2,
        }
    reads = [event for event in policy.events if event[0] == "invoke" and event[2] != 2]
    assert [(event[2], event[3][0]) for event in reads] == [
        (8, mask),
        (23, mask),
        (25, mask),
    ]
    policy.ole.CoUninitialize.assert_called_once_with()


@pytest.mark.parametrize(
    "name,value,slot,native_value",
    [
        ("Enabled", 0, 9, 0),
        ("Enabled", 1, 9, -1),
        ("DefaultInboundAction", 2, 24, 1),
        ("DefaultInboundAction", 4, 24, 0),
        ("DefaultOutboundAction", 2, 26, 1),
        ("DefaultOutboundAction", 4, 26, 0),
    ],
)
def test_advanced_policy_writes_exact_profile_and_native_value(
    policy: Any,
    name: str,
    value: int,
    slot: int,
    native_value: int,
) -> None:
    with policy.helper._ComProfiles() as native:
        native.set_property({"Name": "Private"}, name, value)
    assert ("invoke", 10, slot, (2, native_value)) in policy.events
    assert policy.values[2][slot - 1] == native_value


def test_classic_policy_exposes_domain_without_aliasing_standard(policy: Any) -> None:
    policy.state.classic = True
    with policy.helper._ComProfiles() as native:
        assert native.available_profiles == ("Domain",)
        assert native.read("Domain") == {
            "Name": "Domain",
            "Enabled": 1,
            "DefaultInboundAction": None,
            "DefaultOutboundAction": None,
        }
        native.set_property({"Name": "Domain"}, "Enabled", 0)
        with pytest.raises(ValueError, match="Unknown installed"):
            native.read("Private")
    assert policy.values[1][8] == 0
    releases = [
        event[1]
        for event in policy.events
        if event[:1] == ("invoke",) and event[2] == 2
    ]
    assert releases == [40, 40, 30, 20]


@pytest.mark.parametrize(
    "classic,actions,message",
    [
        (True, {"inbound_action": "block"}, "cannot configure default"),
        (True, {"outbound_action": "allow"}, "cannot configure default"),
        (False, {"inbound_action": "not_configured"}, "NotConfigured"),
        (False, {"outbound_action": "not_configured"}, "NotConfigured"),
    ],
)
def test_unrepresentable_actions_fail_before_native_writes(
    policy: Any,
    classic: bool,
    actions: dict[str, str],
    message: str,
) -> None:
    policy.state.classic = classic
    parameters = {
        "profiles": ["Domain"],
        "state": "enabled",
        "inbound_action": None,
        "outbound_action": None,
        **actions,
    }
    with policy.helper._ComProfiles() as native:
        with pytest.raises(policy.helper.FirewallUnavailableError, match=message):
            native.validate_request(parameters)
    assert not any(
        event[0] == "invoke" and event[2] in (9, 24, 26) for event in policy.events
    )


@pytest.mark.parametrize("enabled,action", [(2, 0), (-1, 3)])
def test_invalid_native_values_do_not_become_public_profile_defaults(
    policy: Any,
    enabled: int,
    action: int,
) -> None:
    policy.values[1].update({8: enabled, 23: action})
    with policy.helper._ComProfiles() as native:
        with pytest.raises(OSError, match="invalid"):
            native.read("Domain")


@pytest.mark.parametrize(
    "name,value",
    [
        ("Enabled", True),
        ("Enabled", 1.0),
        ("Enabled", 2),
        ("DefaultInboundAction", 0),
        ("DefaultOutboundAction", 1),
        ("Unknown", 0),
    ],
)
def test_invalid_native_setter_values_are_rejected(
    policy: Any, name: str, value: Any
) -> None:
    with policy.helper._ComProfiles() as native:
        with pytest.raises(ValueError, match="cannot represent"):
            native.set_property({"Name": "Domain"}, name, value)
    assert not any(
        event[0] == "invoke" and event[2] in (9, 24, 26) for event in policy.events
    )


def test_borrowed_apartment_is_not_uninitialized(policy: Any) -> None:
    policy.state.initialization = 0x80010106
    with policy.helper._ComProfiles():
        pass
    policy.ole.CoUninitialize.assert_not_called()


def test_native_denial_preserves_error_and_releases_owned_interfaces(
    policy: Any,
) -> None:
    policy.state.denied = (10, 9)
    with pytest.raises(OSError, match="0x80070005"):
        with policy.helper._ComProfiles() as native:
            native.set_property({"Name": "Domain"}, "Enabled", 0)
    policy.ole.CoUninitialize.assert_called_once_with()
    assert policy.events[-1][:3] == ("invoke", 10, 2)


def test_guid_layout_is_native_on_both_pointer_widths(policy: Any) -> None:
    assert ctypes.sizeof(policy.helper._Guid) == 16
    assert ctypes.alignment(policy.helper._Guid) == 4
