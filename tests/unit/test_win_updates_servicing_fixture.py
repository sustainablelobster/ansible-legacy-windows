"""Keep the measured pending-install qualification exact and non-mutating."""

# SPDX-License-Identifier: GPL-3.0-or-later
# pylint: disable=protected-access

from types import ModuleType

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="fixture")
def servicing_fixture() -> ModuleType:
    """Load the dedicated servicing fixture without native calls.

    :returns: The isolated fixture's pure protection checks.
    """
    return load_module(
        ROOT / "tests/integration/fixtures/win_updates_servicing.py",
        "servicing_fixture",
    )


def test_only_measured_pending_install_change_is_retained_not_normalized(
    fixture: ModuleType,
) -> None:
    before = [{"Name": "TrustedInstaller", "StartMode": "Manual", "State": "Stopped"}]
    after = [{"Name": "TrustedInstaller", "StartMode": "Auto", "State": "Running"}]
    assert fixture._service_effects(before, after, "installed") == [
        {"before": before[0], "current": after[0]}
    ]
    assert before[0]["StartMode"] == "Manual"
    assert after[0]["StartMode"] == "Auto"


@pytest.mark.parametrize("change", ["download", "name", "removed", "other_mode"])
def test_no_other_configuration_change_is_qualified(
    fixture: ModuleType, change: str
) -> None:
    before = [{"Name": "TrustedInstaller", "StartMode": "Manual", "State": "Stopped"}]
    after = [{"Name": "TrustedInstaller", "StartMode": "Auto", "State": "Running"}]
    state = "downloaded" if change == "download" else "installed"
    if change == "name":
        after[0]["Name"] = "other"
    elif change == "removed":
        after.clear()
    elif change == "other_mode":
        after[0]["StartMode"] = "Disabled"
    with pytest.raises(OSError):
        fixture._service_effects(before, after, state)
