"""Exercise released partition transitions and native backend call boundaries."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Native providers are substituted; argument binding and mutation plans are real.
# pylint: disable=protected-access

from types import ModuleType
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module

_DIRECTORY = ROOT / "legacy_community_windows/plugins/module_utils"


@pytest.fixture(name="payload")
def partition_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the concrete partition helper with only native boundaries replaced.

    :param monkeypatch: Scoped target-helper import paths.
    :returns: The real common partition behavior.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(str(_DIRECTORY))
    return load_module(
        _DIRECTORY / "legacy_community_windows_partition.py", "tested_partition"
    )


def _part(**values: Any) -> dict[str, Any]:
    return {
        "disk_number": 7,
        "number": 1,
        "size": 20 * 1048576,
        "offset": 1048576,
        "drive_letter": "Z",
        "mbr_type": 7,
        "gpt_type": None,
        "read_only": False,
        "active": False,
        "hidden": False,
        "offline": False,
        "path": "owned-partition",
        **values,
    }


def _provider(*parts: dict[str, Any]) -> MagicMock:
    provider = MagicMock()
    provider.partitions.return_value = list(parts)
    provider.maximum.return_value = 62 * 1048576
    provider.disk.return_value = {
        "style": 1,
        "maximum": 62 * 1048576,
        "path": "owned-disk",
    }
    provider.create.side_effect = (
        lambda _disk, options: provider.partitions.return_value.append(
            _part(
                disk_number=options["disk_number"], drive_letter=options["drive_letter"]
            )
        )
    )
    return provider


def test_matching_partition_has_no_mutation(payload: ModuleType) -> None:
    provider = _provider(_part())
    options = payload._options(
        {"drive_letter": "z", "partition_size": "20 MiB", "active": False}
    )
    assert payload._manage(provider, options) == {"changed": False}
    provider.update.assert_not_called()
    provider.create.assert_not_called()


def test_numeric_selector_takes_precedence_over_requested_new_letter(
    payload: ModuleType,
) -> None:
    provider = _provider(_part(), _part(disk_number=2, number=3, drive_letter="Y"))
    options = payload._options(
        {"disk_number": 7, "partition_number": 1, "drive_letter": "X"}
    )
    assert payload._manage(provider, options)["changed"]
    provider.update.assert_called_once_with(_part(), {"drive_letter": "X"})


def test_disk_number_zero_is_a_valid_creation_selector(payload: ModuleType) -> None:
    provider = _provider()
    options = payload._options({"disk_number": 0, "partition_size": "20 MiB"})
    assert payload._manage(provider, options)["changed"]
    provider.disk.assert_called_once_with(0)
    provider.create.assert_called_once()


@pytest.mark.parametrize("attribute", ["read_only", "hidden", "offline", "active"])
def test_creation_updates_only_the_new_extent_when_existing_numbers_change(
    payload: ModuleType, attribute: str
) -> None:
    existing = _part(offset=40 * 1048576, path="existing-partition")
    created = _part(path="new-partition", drive_letter=None)
    renumbered = dict(existing, number=2)
    provider = _provider(existing)
    provider.partitions.side_effect = [[existing], [created, renumbered]]
    provider.create.side_effect = None

    options = payload._options(
        {"disk_number": 7, "partition_size": "20 MiB", attribute: True}
    )
    assert payload._manage(provider, options) == {"changed": True}
    provider.update.assert_called_once_with(created, {attribute: True})


def test_drive_letter_selection_ignores_remote_cluster_representations(
    payload: ModuleType,
) -> None:
    local = _part()
    remote = _part(disk_number=None, path="remote-partition")
    provider = _provider(remote, local)
    options = payload._options({"drive_letter": "Z", "read_only": True})
    assert payload._manage(provider, options) == {"changed": True}
    provider.update.assert_called_once_with(local, {"read_only": True})


def test_remote_only_letter_does_not_select_or_modify_a_cluster_partition(
    payload: ModuleType,
) -> None:
    provider = _provider(_part(disk_number=None))
    options = payload._options({"drive_letter": "Z", "state": "absent"})
    assert payload._manage(provider, options) == {"changed": False}
    provider.remove.assert_not_called()


@pytest.mark.parametrize(
    "size,expected",
    [("10 KB", 10000), ("10 KiB", 10240), ("2 gb", 2_000_000_000), ("-1", -1)],
)
def test_size_units_preserve_decimal_and_binary_meaning(
    payload: ModuleType, size: str, expected: int
) -> None:
    assert payload._size(size) == expected


@pytest.mark.parametrize(
    "size", ["1", "1.5GiB", "0 B", "-20MB", "2 PB", str(2**64) + " B"]
)
def test_invalid_partition_sizes_are_rejected(payload: ModuleType, size: str) -> None:
    with pytest.raises(ValueError):
        payload._size(size)


@pytest.mark.parametrize("name", ["disk_number", "partition_number"])
@pytest.mark.parametrize("value", [True, False, 1.9, -0.1, 1.0, "1.9", 2**31])
def test_invalid_numbers_are_not_silently_redirected_to_another_disk_or_partition(
    payload: ModuleType, name: str, value: object
) -> None:
    with pytest.raises(ValueError, match="nonnegative integer"):
        payload._options({"disk_number": 7, name: value})


def test_resize_maximum_and_tolerance_match_released_behavior(
    payload: ModuleType,
) -> None:
    provider = _provider(_part())
    options = payload._options({"drive_letter": "Z", "partition_size": -1})
    assert payload._manage(provider, options)["changed"]
    provider.update.assert_called_once_with(_part(), {"size": 62 * 1048576})
    provider.update.reset_mock()
    options["size"] = _part()["size"] + 1049000
    assert payload._manage(provider, options) == {"changed": False}
    provider.update.assert_not_called()


def test_resize_read_only_fails_before_even_a_requested_writable_update(
    payload: ModuleType,
) -> None:
    provider = _provider(_part(read_only=True))
    options = payload._options(
        {"drive_letter": "Z", "partition_size": -1, "read_only": False}
    )
    with pytest.raises(ValueError, match="read only"):
        payload._manage(provider, options)
    provider.update.assert_not_called()


@pytest.mark.parametrize("preview", [False, True])
def test_delete_and_absent_repeat(payload: ModuleType, preview: bool) -> None:
    provider = _provider(_part())
    options = payload._options(
        {"drive_letter": "Z", "state": "absent", "_ansible_check_mode": preview}
    )
    assert payload._manage(provider, options)["changed"]
    assert provider.remove.call_count == (0 if preview else 1)
    provider.partitions.return_value = []
    assert payload._manage(provider, options) == {"changed": False}


def test_creation_preview_has_no_native_writes(payload: ModuleType) -> None:
    provider = _provider()
    options = payload._options(
        {"disk_number": 7, "partition_size": "20 MiB", "_ansible_check_mode": True}
    )
    assert payload._manage(provider, options)["changed"]
    provider.create.assert_not_called()
    provider.update.assert_not_called()


def test_existing_preview_validates_but_never_writes(payload: ModuleType) -> None:
    provider = _provider(_part())
    options = payload._options(
        {"drive_letter": "Z", "hidden": True, "_ansible_check_mode": True}
    )
    assert payload._manage(provider, options)["changed"]
    provider.validate_changes.assert_called_once_with(_part(), {"hidden": True})
    provider.update.assert_not_called()


def test_new_partition_does_not_resize_after_creation(payload: ModuleType) -> None:
    provider = _provider()
    options = payload._options({"disk_number": 7, "partition_size": "20 MiB"})
    assert payload._manage(provider, options)["changed"]
    provider.maximum.assert_not_called()
    provider.update.assert_not_called()


@pytest.mark.parametrize(
    "options_data",
    [
        {"disk_number": 7},
        {"disk_number": 7, "partition_size": "100 MiB"},
        {"disk_number": 7, "partition_size": "20 MiB", "gpt_type": "basic_data"},
    ],
)
def test_invalid_creation_does_not_touch_disk(
    payload: ModuleType, options_data: dict[str, Any]
) -> None:
    provider = _provider()
    with pytest.raises(ValueError):
        payload._manage(provider, payload._options(options_data))
    provider.create.assert_not_called()


def test_existing_partition_type_cannot_be_changed(payload: ModuleType) -> None:
    provider = _provider(_part())
    with pytest.raises(ValueError, match="existing partitions"):
        payload._manage(
            provider, payload._options({"drive_letter": "Z", "mbr_type": "fat32"})
        )
    provider.update.assert_not_called()


@pytest.mark.parametrize(
    "status,legacy", [(0x8004100E, True), (0x80041010, True), (0x80041003, False)]
)
def test_fallback_is_based_on_capability_not_access_denial(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, status: int, legacy: bool
) -> None:
    error = OSError("native provider")
    setattr(error, "hresult", status)
    modern, provider = MagicMock(), _provider()
    modern.__enter__.side_effect = error
    monkeypatch.setattr(payload, "WmiConnection", Mock(return_value=modern))
    factory = Mock(return_value=provider)
    monkeypatch.setattr(payload, "LegacyPartitions", factory)
    options = {"disk_number": 7, "partition_number": 1, "state": "absent"}
    if legacy:
        assert payload.manage(options) == {"changed": False}
        factory.assert_called_once()
    else:
        with pytest.raises(OSError):
            payload.manage(options)
        factory.assert_not_called()


def test_modern_update_uses_exact_instance_and_only_changed_attributes(
    payload: ModuleType,
) -> None:
    connection = MagicMock()
    connection.call_method.return_value = {"ReturnValue": 0}
    provider = payload.StoragePartitions(connection)
    provider.update(_part(), {"size": 40 * 1048576, "active": True, "offline": False})
    assert [call.args[:2] for call in connection.call_method.call_args_list] == [
        ("owned-partition", "Resize"),
        ("owned-partition", "Online"),
        ("owned-partition", "SetAttributes"),
    ]
    assert connection.call_method.call_args_list[0].args[3] == {
        "Size": str(40 * 1048576)
    }
    assert connection.call_method.call_args_list[-1].args[3] == {"IsActive": True}


def test_native_error_code_is_not_claimed_as_success(payload: ModuleType) -> None:
    connection = MagicMock()
    connection.call_method.return_value = {"ReturnValue": 40001}
    with pytest.raises(OSError, match="DeleteObject returned 40001"):
        payload.StoragePartitions(connection).remove(_part())


def test_parameterless_storage_methods_do_not_request_an_input_signature(
    payload: ModuleType,
) -> None:
    connection = MagicMock()
    connection.call_method.return_value = {"ReturnValue": 0, "SizeMax": "67108864"}
    provider = payload.StoragePartitions(connection)
    assert provider.maximum(_part()) == 67108864
    provider.remove(_part())
    assert connection.call_method.call_args_list[0].args[3] is None
    assert connection.call_method.call_args_list[1].args[3] is None


def test_legacy_basic_mbr_attributes_cannot_change_another_partition(
    payload: ModuleType,
) -> None:
    provider = payload.LegacyPartitions()
    provider.partitions = Mock(
        return_value=[_part(), _part(number=2, drive_letter="Y")]
    )
    with pytest.raises(ValueError, match="all volumes"):
        provider.validate_changes(_part(), {"read_only": True})


def test_legacy_unknown_capability_is_not_assumed_false(payload: ModuleType) -> None:
    provider = payload.LegacyPartitions()
    with pytest.raises(ValueError, match="cannot read offline"):
        provider.validate_changes(_part(offline=None), {"offline": False})


def test_hidden_partition_is_read_through_native_alias_without_a_mount_link(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    legacy = __import__("legacy_community_windows_partition_legacy")
    monkeypatch.setattr(legacy, "_volumes", Mock(return_value=[]))
    monkeypatch.setattr(
        legacy,
        "describe_disk",
        Mock(
            return_value={
                "partitions": [
                    {"number": 1, "offset": 1048576, "size": 33554432, "mbr_type": 7}
                ]
            }
        ),
    )
    native_read = Mock(
        return_value={"hidden": True, "offline": False, "read_only": False}
    )
    monkeypatch.setattr(legacy, "_volume_state", native_read)
    provider = payload.LegacyPartitions()
    provider._disks = Mock(return_value=[{"Index": 7, "DeviceID": "owned-disk"}])
    part = provider.partitions()[0]
    assert part["hidden"] is True and part["drive_letter"] is None
    native_read.assert_called_once_with(
        r"\\?\GLOBALROOT\Device\Harddisk7\Partition1", (7, 1048576)
    )


def test_legacy_resize_and_letter_plan_use_no_caller_script_text(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    legacy = __import__("legacy_community_windows_partition_legacy")
    run = Mock()
    monkeypatch.setattr(legacy, "_run", run)
    provider = payload.LegacyPartitions()
    provider.partitions = Mock(
        return_value=[_part(size=40 * 1048576, drive_letter="X")]
    )
    provider.update(_part(), {"size": 40 * 1048576, "drive_letter": "X"})
    run.assert_called_once_with(
        [
            "select disk 7",
            "select partition 1",
            "extend size=20",
            "remove letter=Z",
            "assign letter=X",
        ]
    )


@pytest.mark.usefixtures("payload")
def test_unrelated_cd_volume_without_disk_extents_does_not_block_partitions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy = __import__("legacy_community_windows_partition_legacy")
    kernel = MagicMock()
    kernel.FindFirstVolumeW.return_value = 42
    kernel.FindNextVolumeW.return_value = False
    monkeypatch.setattr(legacy, "_volume_kernel", Mock(return_value=kernel))
    monkeypatch.setattr(legacy.ctypes, "get_last_error", lambda: 18, raising=False)
    error = OSError("The CD volume does not expose physical disk extents.")
    setattr(error, "winerror", 1)
    monkeypatch.setattr(legacy, "_volume_state", Mock(side_effect=error))
    assert legacy._volumes() == []
    kernel.FindVolumeClose.assert_called_once_with(42)
