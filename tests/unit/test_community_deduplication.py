"""Exercise native volume state, setting defaults, preview and role restarts."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Provider boundaries are substituted; the public state transitions are real.
# pylint: disable=protected-access

from types import ModuleType
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module


@pytest.fixture(name="payload")
def dedup_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the payload around independent storage and deduplication providers.

    :param monkeypatch: Scoped provider substitutions.
    :returns: The real module with its external native boundaries substituted.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    module = load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_data_deduplication.py",
        "tested_deduplication",
    )
    storage, dedup = MagicMock(), MagicMock()
    storage.__enter__.return_value = storage
    dedup.__enter__.return_value = dedup
    storage.query.return_value = [{"DeviceID": "owned-volume"}]
    current = {
        "__PATH": "owned-dedup-instance",
        "Volume": "Z:",
        "VolumeId": "owned-volume",
        "Enabled": True,
        "MinimumFileSize": 32768,
        "MinimumFileAgeDays": 2,
        "NoCompress": False,
        "OptimizeInUseFiles": False,
        "Verify": False,
    }
    dedup.query.return_value = [current]
    dedup.call_method.return_value = {"ReturnValue": 0}
    monkeypatch.setattr(
        module.wmi,
        "WmiConnection",
        Mock(side_effect=lambda *args: dedup if args else storage),
    )
    monkeypatch.setattr(
        module.features,
        "manage",
        Mock(return_value={"success": True, "changed": False}),
    )
    monkeypatch.setattr(module, "_set_settings", Mock())
    return module


def _provider(payload: ModuleType) -> MagicMock:
    provider: MagicMock = payload.wmi.WmiConnection("dedup")
    return provider


def test_existing_defaults_are_idempotent_and_role_is_still_ensured(
    payload: ModuleType,
) -> None:
    assert payload._manage({"drive_letter": "z", "settings": {}}) == {
        "changed": False,
        "reboot_required": False,
        "msg": "",
    }
    payload.features.manage.assert_called_once()
    _provider(payload).call_method.assert_not_called()
    payload._set_settings.assert_not_called()


def test_enable_uses_only_the_selected_volume_and_reads_new_defaults(
    payload: ModuleType,
) -> None:
    dedup = _provider(payload)
    current = dedup.query.return_value
    dedup.query.side_effect = [[], current]
    result = payload._manage({"drive_letter": "Z", "settings": {}})
    assert result["changed"] is True
    dedup.call_method.assert_called_once_with(
        "MSFT_DedupVolume", "Enable", ("ReturnValue",), {"Volume": ["Z:"]}
    )
    payload._set_settings.assert_not_called()


def test_disable_ignores_settings_and_repeat_does_not_disable_twice(
    payload: ModuleType,
) -> None:
    options = {"drive_letter": "Z", "state": "absent", "settings": {"verify": True}}
    dedup = _provider(payload)
    current = dedup.query.return_value[0]
    assert payload._manage(options)["changed"] is True
    dedup.call_method.assert_called_once_with(
        "MSFT_DedupVolume", "Disable", ("ReturnValue",), {"Volume": ["Z:"]}
    )
    current["Enabled"] = False
    assert payload._manage(options)["changed"] is False
    assert dedup.call_method.call_count == 1
    payload._set_settings.assert_not_called()


def test_settings_include_nested_defaults_clamp_and_preserve_unsigned_range(
    payload: ModuleType,
) -> None:
    assert payload._settings(
        {"minimum_file_size": -1, "minimum_file_age_days": 0xFFFFFFFF, "verify": "yes"}
    ) == {
        "MinimumFileSize": 32768,
        "MinimumFileAgeDays": 0xFFFFFFFF,
        "NoCompress": False,
        "OptimizeInUseFiles": False,
        "Verify": True,
    }


@pytest.mark.parametrize("display_name", ["Z:", "different-letter:", "volume-guid"])
def test_volume_identity_not_display_name_selects_the_enabled_volume(
    payload: ModuleType, display_name: str
) -> None:
    volume_id = "\\\\?\\Volume{ABCD}\\"
    payload.wmi.WmiConnection().query.return_value = [{"DeviceID": volume_id}]
    dedup = _provider(payload)
    current = dedup.query.return_value[0]
    current.update(Volume=display_name, VolumeId=volume_id.lower().rstrip("\\"))
    unrelated = dict(current, Volume="Z:", VolumeId="unrelated-volume")
    dedup.query.return_value = [unrelated, current]

    assert payload._manage({"drive_letter": "Z", "settings": {}})["changed"] is False
    assert payload._manage({"drive_letter": "Z", "state": "absent"})["changed"] is True
    dedup.call_method.assert_called_once_with(
        "MSFT_DedupVolume", "Disable", ("ReturnValue",), {"Volume": ["Z:"]}
    )
    payload._set_settings.assert_not_called()


def test_enable_reads_guid_named_volume_before_setting_its_properties(
    payload: ModuleType,
) -> None:
    dedup = _provider(payload)
    current = dedup.query.return_value[0]
    current["Volume"] = current["VolumeId"]
    dedup.query.side_effect = [[], [current]]
    assert (
        payload._manage({"drive_letter": "Z", "settings": {"verify": True}})["changed"]
        is True
    )
    dedup.call_method.assert_called_once_with(
        "MSFT_DedupVolume", "Enable", ("ReturnValue",), {"Volume": ["Z:"]}
    )
    payload._set_settings.assert_called_once_with(
        dedup, "owned-dedup-instance", {"Verify": True}
    )


def test_setting_update_is_scoped_and_repeat_is_unchanged(payload: ModuleType) -> None:
    options = {"drive_letter": "Z", "settings": {"verify": True, "no_compress": True}}
    assert payload._manage(options)["changed"] is True
    payload._set_settings.assert_called_once_with(
        _provider(payload), "owned-dedup-instance", {"NoCompress": True, "Verify": True}
    )
    _provider(payload).query.return_value[0].update(NoCompress=True, Verify=True)
    assert payload._manage(options)["changed"] is False
    assert payload._set_settings.call_count == 1


@pytest.mark.parametrize("enabled", [True, False])
def test_preview_never_installs_changes_state_or_writes_settings(
    payload: ModuleType, enabled: bool
) -> None:
    dedup = _provider(payload)
    dedup.query.return_value[0]["Enabled"] = enabled
    assert (
        payload._manage(
            {
                "drive_letter": "Z",
                "settings": {"verify": True},
                "_ansible_check_mode": True,
            }
        )["changed"]
        is True
    )
    payload.features.manage.assert_not_called()
    dedup.call_method.assert_not_called()
    payload._set_settings.assert_not_called()


@pytest.mark.parametrize(
    "invalid",
    [
        {"drive_letter": "C:"},
        {"drive_letter": "Z' OR '1'='1"},
        {"drive_letter": None},
        {"state": "unexpected"},
        {"settings": []},
        {"settings": {"unexpected": 1}},
        {"settings": {"minimum_file_age_days": -1}},
        {"settings": {"minimum_file_size": 2**32}},
        {"settings": {"minimum_file_size": True}},
    ],
)
def test_invalid_input_fails_before_feature_servicing(
    payload: ModuleType, invalid: dict[str, Any]
) -> None:
    with pytest.raises((ValueError, TypeError)):
        payload._manage({"drive_letter": "Z", **invalid})
    payload.features.manage.assert_not_called()
    payload.wmi.WmiConnection.assert_not_called()


def test_restart_required_stops_before_touching_any_volume(payload: ModuleType) -> None:
    payload.features.manage.return_value = {
        "success": True,
        "changed": True,
        "reboot_required": True,
    }
    result = payload._manage({"drive_letter": "Z"})
    assert result["failed"] and result["changed"] and result["reboot_required"]
    payload.wmi.WmiConnection.assert_not_called()


def test_feature_failure_is_returned_without_querying_volume(
    payload: ModuleType,
) -> None:
    payload.features.manage.return_value = {
        "success": False,
        "msg": "native feature error",
    }
    result = payload._manage({"drive_letter": "Z"})
    assert result["failed"] and result["msg"] == "native feature error"
    payload.wmi.WmiConnection.assert_not_called()


def test_missing_volume_fails_instead_of_selecting_another_drive(
    payload: ModuleType,
) -> None:
    payload.wmi.WmiConnection().query.return_value = []
    with pytest.raises(ValueError, match="No unique local volume"):
        payload._manage({"drive_letter": "Z"})
    _provider(payload).call_method.assert_not_called()


def test_native_enable_failure_is_actionable_and_does_not_change_settings(
    payload: ModuleType,
) -> None:
    dedup = _provider(payload)
    dedup.query.return_value = []
    dedup.call_method.return_value = {"ReturnValue": 87}
    with pytest.raises(OSError, match="Enable returned 87 for Z:"):
        payload._manage({"drive_letter": "Z", "settings": {}})
    payload._set_settings.assert_not_called()
