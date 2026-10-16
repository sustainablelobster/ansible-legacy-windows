"""Verify native volume selection, destructive-operation guards and repeat state."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# The WMI boundary is substituted; selection and formatting decisions are real.
# pylint: disable=protected-access

from types import ModuleType
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module


@pytest.fixture(name="payload")
def format_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load formatting with independent legacy and modern provider substitutes.

    :param monkeypatch: Scoped imports and provider substitutions.
    :returns: Loaded payload.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    module = load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_format.py",
        "tested_community_format",
    )
    legacy, modern = MagicMock(), MagicMock()
    legacy.__enter__.return_value = legacy
    modern.__enter__.return_value = modern
    legacy.query.return_value = [
        {
            "__PATH": "system-volume",
            "DeviceID": "system-guid",
            "DriveLetter": "C:",
            "Label": "System",
            "FileSystem": "NTFS",
            "Capacity": "1000000",
            "BlockSize": "4096",
        },
        {
            "__PATH": "owned-volume",
            "DeviceID": "owned-guid",
            "DriveLetter": "Z:",
            "Label": "Owned",
            "FileSystem": "NTFS",
            "Capacity": "64000000",
            "BlockSize": "4096",
        },
    ]
    modern.query.return_value = [{"__PATH": "modern-owned", "Path": "owned-guid"}]
    modern.call_method.return_value = {"ReturnValue": 0, "ExtendedStatus": None}
    legacy.call_method.return_value = {"ReturnValue": 0}
    monkeypatch.setattr(
        module,
        "WmiConnection",
        Mock(side_effect=lambda *args: modern if args else legacy),
    )
    return module


def _providers(payload: ModuleType) -> tuple[MagicMock, MagicMock]:
    return payload.WmiConnection(), payload.WmiConnection("modern")


@pytest.mark.parametrize(
    "selector", [{"drive_letter": "z"}, {"label": "OWNED"}, {"path": "owned-GUID"}]
)
def test_existing_matching_volume_is_unchanged_without_formatting(
    payload: ModuleType, selector: dict[str, str]
) -> None:
    legacy, modern = _providers(payload)
    assert payload._manage(
        {**selector, "file_system": "ntfs", "new_label": "Owned"}
    ) == {"changed": False}
    legacy.call_method.assert_not_called()
    modern.call_method.assert_not_called()


def test_modern_format_selects_only_requested_volume_and_repeats_stably(
    payload: ModuleType,
) -> None:
    legacy, modern = _providers(payload)
    options = {
        "drive_letter": "Z",
        "file_system": "ntfs",
        "new_label": "New owned",
        "allocation_unit_size": 4096,
        "compress": True,
        "large_frs": True,
    }
    assert payload._manage(options) == {"changed": True}
    modern.call_method.assert_called_once_with(
        "modern-owned",
        "Format",
        ("ReturnValue", "ExtendedStatus"),
        {
            "Full": False,
            "FileSystemLabel": "New owned",
            "FileSystem": "ntfs",
            "Compress": True,
            "UseLargeFRS": True,
            "AllocationUnitSize": "4096",
        },
    )
    legacy.call_method.assert_not_called()
    legacy.query.return_value[1]["Label"] = "New owned"
    assert payload._manage(options) == {"changed": False}
    assert modern.call_method.call_count == 1


def test_preview_never_calls_either_provider_format(payload: ModuleType) -> None:
    legacy, modern = _providers(payload)
    assert payload._manage(
        {"drive_letter": "Z", "new_label": "New owned", "_ansible_check_mode": True}
    ) == {"changed": True}
    legacy.call_method.assert_not_called()
    modern.call_method.assert_not_called()


def test_force_reformats_on_every_run(payload: ModuleType) -> None:
    _, modern = _providers(payload)
    assert payload._manage({"label": "Owned", "force": True}) == {"changed": True}
    assert payload._manage({"label": "Owned", "force": True}) == {"changed": True}
    assert modern.call_method.call_count == 2


def test_case_only_label_change_is_unchanged_without_erasing_volume(
    payload: ModuleType,
) -> None:
    legacy, modern = _providers(payload)
    assert payload._manage(
        {"drive_letter": "Z", "file_system": "ntfs", "new_label": "owned"}
    ) == {"changed": False}
    assert legacy.query.return_value[1]["Label"] == "Owned"
    legacy.call_method.assert_not_called()
    modern.call_method.assert_not_called()


def test_unformatted_zero_capacity_string_is_not_mistaken_for_existing_volume(
    payload: ModuleType,
) -> None:
    legacy, modern = _providers(payload)
    legacy.query.return_value[1].update(
        Capacity="0", BlockSize="0", FileSystem=None, Label=None
    )
    assert payload._manage(
        {"drive_letter": "Z", "file_system": "ntfs", "allocation_unit_size": 4096}
    ) == {"changed": True}
    assert modern.call_method.call_args.args[3]["FileSystemLabel"] == ""


def test_missing_modern_namespace_uses_native_legacy_format(
    payload: ModuleType,
) -> None:
    legacy, modern = _providers(payload)
    error = OSError("Missing namespace")
    setattr(error, "hresult", 0x8004100E)
    modern.__enter__.side_effect = error
    assert payload._manage(
        {
            "path": "owned-guid",
            "new_label": "New owned",
            "file_system": "ntfs",
            "full": True,
            "allocation_unit_size": 4096,
        }
    ) == {"changed": True}
    legacy.call_method.assert_called_once_with(
        "owned-volume",
        "Format",
        ("ReturnValue",),
        {
            "QuickFormat": False,
            "Label": "New owned",
            "FileSystem": "ntfs",
            "ClusterSize": "4096",
        },
    )


def test_access_denied_does_not_retry_destructive_work_through_another_provider(
    payload: ModuleType,
) -> None:
    legacy, modern = _providers(payload)
    error = OSError("Access denied")
    setattr(error, "hresult", 0x80041003)
    modern.__enter__.side_effect = error
    with pytest.raises(OSError, match="Access denied"):
        payload._manage({"drive_letter": "Z", "new_label": "New owned"})
    legacy.call_method.assert_not_called()


def test_legacy_unsupported_flags_fail_before_any_format(payload: ModuleType) -> None:
    legacy, modern = _providers(payload)
    error = OSError("Missing namespace")
    setattr(error, "hresult", 0x8004100E)
    modern.__enter__.side_effect = error
    with pytest.raises(ValueError, match="large_frs"):
        payload._manage(
            {"drive_letter": "Z", "new_label": "New owned", "large_frs": True}
        )
    legacy.call_method.assert_not_called()


def test_ambiguous_label_never_selects_first_disk(payload: ModuleType) -> None:
    legacy, modern = _providers(payload)
    legacy.query.return_value[0]["Label"] = "Owned"
    with pytest.raises(ValueError, match="More than one"):
        payload._manage({"label": "Owned", "force": True})
    legacy.call_method.assert_not_called()
    modern.call_method.assert_not_called()


@pytest.mark.parametrize(
    "options",
    [
        {},
        {"drive_letter": "Z", "label": "Owned"},
        {"drive_letter": "Z:"},
        {"drive_letter": "Z", "file_system": "invalid"},
        {"drive_letter": "Z", "integrity_streams": True, "file_system": "ntfs"},
        {"drive_letter": "Z", "compress": True, "file_system": "fat32"},
        {
            "drive_letter": "Z",
            "compress": True,
            "file_system": "ntfs",
            "allocation_unit_size": 8192,
        },
        {"drive_letter": "Z", "allocation_unit_size": 0},
        {"drive_letter": "Z", "allocation_unit_size": "oops"},
    ],
)
def test_invalid_requests_fail_before_native_queries(
    payload: ModuleType, options: dict[str, object]
) -> None:
    payload.WmiConnection.reset_mock()
    with pytest.raises(ValueError):
        payload._manage(options)
    payload.WmiConnection.assert_not_called()


@pytest.mark.parametrize(
    "options", [{"file_system": "fat32"}, {"allocation_unit_size": 8192}]
)
def test_changes_to_existing_file_system_or_cluster_size_require_force(
    payload: ModuleType, options: dict[str, object]
) -> None:
    legacy, modern = _providers(payload)
    with pytest.raises(ValueError, match="force must be true"):
        payload._manage({"drive_letter": "Z", **options})
    legacy.call_method.assert_not_called()
    modern.call_method.assert_not_called()


def test_native_format_error_is_not_reported_as_success(payload: ModuleType) -> None:
    _, modern = _providers(payload)
    modern.call_method.return_value = {
        "ReturnValue": 5,
        "ExtendedStatus": {"Message": "Cannot format volume"},
    }
    with pytest.raises(OSError, match="status 5"):
        payload._manage({"drive_letter": "Z", "force": True})
