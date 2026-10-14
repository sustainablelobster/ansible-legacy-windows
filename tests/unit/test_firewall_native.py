"""Exercise the fixed configured-profile WMI boundary without Windows access."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes do not establish target-runtime execution support.
# pylint: disable=protected-access

import copy
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock, call

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="native")
def firewall_native(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load the helper with a scoped native connection substitute.

    :param monkeypatch: Scoped import and native replacements.
    :returns: Helper and observable WMI connection.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    helper = load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_firewall.py",
        "tested_firewall_native",
    )
    connection = MagicMock()
    constructor = Mock(return_value=connection)
    monkeypatch.setattr(helper, "WmiConnection", constructor)
    return SimpleNamespace(
        helper=helper, connection=connection, constructor=constructor
    )


def _row(name: str = "Domain") -> dict[str, Any]:
    return {
        "Name": name,
        "Enabled": 1,
        "DefaultInboundAction": 4,
        "DefaultOutboundAction": 2,
        "__PATH": "native:" + name,
    }


@pytest.mark.parametrize("name", ["Domain", "Private", "Public"])
def test_native_reads_configured_enums_with_locatable_identity(
    native: Any, name: str
) -> None:
    row = _row(name)
    native.connection.query.return_value = [row]
    with native.helper.FirewallProfiles() as profiles:
        assert profiles.read(name) == row
    native.constructor.assert_called_once_with(r"ROOT\StandardCimv2")
    assert native.connection.query.call_args_list == [
        call("SELECT Name FROM MSFT_NetFirewallProfile", ["Name"]),
        call(
            "SELECT * FROM MSFT_NetFirewallProfile WHERE Name='" + name + "'",
            [
                "Name",
                "Enabled",
                "DefaultInboundAction",
                "DefaultOutboundAction",
                "__PATH",
            ],
        ),
    ]
    native.connection.__enter__.assert_called_once_with()
    native.connection.__exit__.assert_called_once_with(None, None, None)


@pytest.mark.parametrize(
    "name,value",
    [
        ("Enabled", 0),
        ("Enabled", 1),
        ("Enabled", 2),
        ("DefaultInboundAction", 0),
        ("DefaultInboundAction", 2),
        ("DefaultInboundAction", 4),
        ("DefaultOutboundAction", 0),
        ("DefaultOutboundAction", 2),
        ("DefaultOutboundAction", 4),
    ],
)
def test_native_updates_one_exact_enum_on_the_observed_instance(
    native: Any, name: str, value: int
) -> None:
    row = _row()
    before = copy.deepcopy(row)
    with native.helper.FirewallProfiles() as profiles:
        profiles.set_property(row, name, value)
    native.connection.set_integer_property.assert_called_once_with(
        "native:Domain", name, value
    )
    assert row == before
    native.connection.query.assert_called_once_with(
        "SELECT Name FROM MSFT_NetFirewallProfile", ["Name"]
    )


@pytest.mark.parametrize(
    "name", ["Standard", "Domain' OR Name='Public", "domain", None]
)
def test_unknown_profile_cannot_reach_a_native_query(native: Any, name: Any) -> None:
    with native.helper.FirewallProfiles() as profiles:
        with pytest.raises(ValueError, match="Unknown Windows Firewall profile"):
            profiles.read(name)
    native.connection.query.assert_called_once_with(
        "SELECT Name FROM MSFT_NetFirewallProfile", ["Name"]
    )


@pytest.mark.parametrize("rows", [[], [_row(), _row()], [_row("Public")]])
def test_missing_ambiguous_or_wrong_provider_profile_fails(
    native: Any, rows: Any
) -> None:
    native.connection.query.return_value = rows
    with native.helper.FirewallProfiles() as profiles:
        with pytest.raises(OSError, match="no unique Domain profile"):
            profiles.read("Domain")
    native.connection.set_integer_property.assert_not_called()


@pytest.mark.parametrize("value", [None, "", 42])
def test_missing_native_identity_fails_before_update(native: Any, value: Any) -> None:
    row = _row()
    row["__PATH"] = value
    native.connection.query.return_value = [row]
    with native.helper.FirewallProfiles() as profiles:
        with pytest.raises(OSError, match="no native profile identity"):
            profiles.read("Domain")


@pytest.mark.parametrize(
    "property_name,value",
    [
        ("Enabled", None),
        ("Enabled", True),
        ("Enabled", 3),
        ("DefaultInboundAction", 1),
        ("DefaultOutboundAction", "2"),
    ],
)
def test_invalid_configured_provider_enum_is_not_treated_as_an_effective_default(
    native: Any, property_name: str, value: Any
) -> None:
    row = _row()
    row[property_name] = value
    native.connection.query.return_value = [row]
    with native.helper.FirewallProfiles() as profiles:
        with pytest.raises(OSError, match="invalid " + property_name + " enum"):
            profiles.read("Domain")


@pytest.mark.parametrize(
    "name,value",
    [
        ("Enabled", True),
        ("Enabled", 3),
        ("DefaultInboundAction", 1),
        ("DefaultOutboundAction", None),
        ("AllowInboundRules", 1),
    ],
)
def test_invalid_write_is_rejected_before_mutation(
    native: Any, name: str, value: Any
) -> None:
    with native.helper.FirewallProfiles() as profiles:
        with pytest.raises(ValueError, match="Invalid configured firewall enum"):
            profiles.set_property(_row(), name, value)
    native.connection.set_integer_property.assert_not_called()


def _hresult(value: int) -> OSError:
    error = OSError("Native namespace failure")
    setattr(error, "hresult", value)
    return error


def test_missing_namespace_selects_installed_firewall_policy_api(
    native: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native.connection.__enter__.side_effect = _hresult(0x8004100E)
    com = MagicMock()
    com.available_profiles = ("Domain",)
    monkeypatch.setattr(native.helper, "_ComProfiles", Mock(return_value=com))
    with native.helper.FirewallProfiles() as profiles:
        assert profiles.available_profiles == ("Domain",)
        profiles.read("Domain")
        profiles.set_property(_row(), "Enabled", 0)
    com.read.assert_called_once_with("Domain")
    com.set_property.assert_called_once_with(_row(), "Enabled", 0)
    com.__exit__.assert_called_once_with(None, None, None)
    native.connection.query.assert_not_called()
    native.connection.set_integer_property.assert_not_called()
    native.connection.__exit__.assert_not_called()


def test_missing_profile_class_closes_wmi_before_selecting_policy_api(
    native: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = _hresult(0x80041010)
    native.connection.query.side_effect = error
    com = MagicMock()
    com.available_profiles = native.helper.PROFILES
    monkeypatch.setattr(native.helper, "_ComProfiles", Mock(return_value=com))
    with native.helper.FirewallProfiles() as profiles:
        assert profiles.available_profiles == native.helper.PROFILES
    assert native.connection.__exit__.call_args.args[:2] == (OSError, error)
    com.__enter__.assert_called_once_with()


def test_other_connection_errors_are_not_misreported_as_legacy_support_limits(
    native: Any,
) -> None:
    error = _hresult(0x80041003)
    native.connection.__enter__.side_effect = error
    with pytest.raises(OSError) as observed:
        with native.helper.FirewallProfiles():
            pytest.fail("Denied connection must not enter the context")
    assert observed.value is error


def test_native_update_failure_leaves_cleanup_and_exception_visible(
    native: Any,
) -> None:
    error = OSError("Observed native update denial")
    native.connection.set_integer_property.side_effect = error
    with pytest.raises(OSError) as observed:
        with native.helper.FirewallProfiles() as profiles:
            profiles.set_property(_row(), "Enabled", 0)
    assert observed.value is error
    arguments = native.connection.__exit__.call_args.args
    assert arguments[0] is OSError and arguments[1] is error
