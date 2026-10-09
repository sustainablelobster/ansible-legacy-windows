"""Exercise package identity ABI, provider selection and deployment ownership."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native ABI storage is inspected directly rather than replaced with a schema.
# pylint: disable=protected-access

import ctypes
import sys
import zipfile
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import load_module


@pytest.fixture(name="helper")
def msix_helper() -> Any:
    """Load the private provider without requiring Windows on the controller.

    :returns: Real target-compatible helper module.
    """
    return load_module(
        Path(__file__).resolve().parents[2]
        / "plugins/module_utils/legacy_windows_package_msix.py",
        "tested_msix",
    )


def test_win32_and_runtime_versions_have_distinct_measured_field_orders(
    helper: Any,
) -> None:
    native = helper._Win32Version(4, 3, 2, 1)
    runtime = helper._RuntimeVersion(1, 2, 3, 4)
    assert bytes(native) == b"\x04\x00\x03\x00\x02\x00\x01\x00"
    assert bytes(runtime) == b"\x01\x00\x02\x00\x03\x00\x04\x00"
    assert ctypes.sizeof(native) == ctypes.sizeof(runtime) == 8


@pytest.mark.parametrize("codes", [[0], [1], [-2147417850, 1]])
def test_activation_balances_native_runtime_initialization_with_existing_msi_sta(
    helper: Any, monkeypatch: pytest.MonkeyPatch, codes: list[int]
) -> None:
    manager = helper.PackageManager.__new__(helper.PackageManager)
    manager.pointer, manager.initialized = None, False

    def _activate(_name: int, output: Any) -> int:
        output._obj.value = 1
        return 0

    manager.runtime = SimpleNamespace(
        RoInitialize=Mock(side_effect=codes),
        RoUninitialize=Mock(),
        RoActivateInstance=_activate,
    )

    @contextmanager
    def _string(_value: str) -> Any:
        yield 3

    manager._string = _string
    monkeypatch.setattr(helper, "_query", lambda *_args: 2)
    release = Mock()
    monkeypatch.setattr(helper, "_release", release)
    with manager as active:
        assert active.pointer == 2 and active.initialized
    assert [item.args[0] for item in manager.runtime.RoInitialize.call_args_list] == (
        [1, 0] if len(codes) == 2 else [1]
    )
    manager.runtime.RoUninitialize.assert_called_once()
    assert [item.args[0] for item in release.call_args_list] == [1, 2]


@pytest.mark.parametrize(
    "version,expected",
    [("1", (0, 0, 0, 1)), ("1.2", (0, 0, 2, 1)), ("1.2.3.4", (4, 3, 2, 1))],
)
def test_native_full_name_uses_exact_abi_and_two_call_buffer(
    helper: Any,
    monkeypatch: pytest.MonkeyPatch,
    version: str,
    expected: tuple[int, ...],
) -> None:
    seen = []

    def _convert(identity: Any, size: Any, buffer: Any) -> int:
        record = identity._obj
        seen.append(record)
        assert (
            record.version.revision,
            record.version.build,
            record.version.minor,
            record.version.major,
        ) == expected
        assert record.architecture == 9 and record.name == "Owned"
        assert record.publisher == "CN=Owned" and record.resource == "language"
        if buffer is None:
            size._obj.value = 11
            return 122
        assert len(buffer) == 11
        buffer.value = "owned_name"
        return 0

    library = SimpleNamespace(PackageFullNameFromId=Mock(side_effect=_convert))
    monkeypatch.setattr(
        helper.ctypes, "WinDLL", lambda *_a, **_kw: library, raising=False
    )
    assert (
        helper.full_name(
            {
                "Name": "Owned",
                "Publisher": "CN=Owned",
                "Version": version,
                "ProcessorArchitecture": "X64",
                "ResourceId": "language",
            }
        )
        == "owned_name"
    )
    assert len(seen) == 2


@pytest.mark.parametrize(
    "name,bundle",
    [
        ("AppxManifest.xml", False),
        ("APPXMANIFEST.XML", False),
        ("AppxMetadata/AppxBundleManifest.xml", True),
        ("APPXMETADATA/APPXBUNDLEMANIFEST.XML", True),
    ],
)
def test_archive_manifest_matching_is_case_insensitive_but_preserves_source_resource_branch(
    helper: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    name: str,
    bundle: bool,
) -> None:
    source = (
        '<Bundle xmlns="urn:bundle"><Identity Name="Owned" Publisher="CN=Owned"/>'
        '<Packages><Package Version="1.2.3.4" Architecture="x64" ResourceId="lang"/>'
        "</Packages></Bundle>"
        if bundle
        else '<Package xmlns="urn:app"><Identity Name="Owned" Publisher="CN=Owned" '
        'Version="1.2.3.4" ProcessorArchitecture="x64" ResourceId="lang"/></Package>'
    )
    path = tmp_path / "owned.appx"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(name, source)
    convert = Mock(return_value="full_name")
    monkeypatch.setattr(helper, "full_name", convert)
    assert helper.manifest_identities(str(path)) == ["full_name"]
    if bundle:
        assert convert.call_args.kwargs == {"architecture_attribute": "Architecture"}
        assert convert.call_args.args[0]["ResourceId"] == "lang"
    else:
        assert convert.call_args.kwargs == {"resource": False}


def test_deployment_wait_preserves_completion_and_closes_both_owned_interfaces(
    helper: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    statuses = iter([0, 0, 1])
    released = Mock()
    calls = []

    def _output(pointer: int, slot: int, _kind: Any = None) -> int:
        assert (pointer, slot) in [(2, 7), (3, 8)]
        return next(statuses) if pointer == 2 else 0

    def _call(pointer: int, slot: int, _types: Any, *values: Any) -> int:
        calls.append((pointer, slot))
        if pointer == 1:
            values[0]._obj.value = 3
        return 0

    monkeypatch.setattr(helper, "_query", lambda *_a: 2)
    monkeypatch.setattr(helper, "_output", _output)
    monkeypatch.setattr(helper, "_call", _call)
    monkeypatch.setattr(helper, "_release", released)
    monkeypatch.setattr(helper.time, "sleep", Mock())
    manager = helper.PackageManager.__new__(helper.PackageManager)
    manager._complete(1)
    assert calls == [(1, 10), (2, 10)]
    assert [value.args[0] for value in released.call_args_list] == [3, 2]
    assert helper.time.sleep.call_count == 2


def test_get_results_failure_still_closes_async_info_and_does_not_free_an_absent_result(
    helper: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    released = Mock()
    calls = []
    monkeypatch.setattr(helper, "_query", lambda *_a: 2)
    monkeypatch.setattr(helper, "_output", lambda *_a: 3)
    monkeypatch.setattr(helper, "_release", released)

    def _call(pointer: int, slot: int, _types: Any, *_values: Any) -> int:
        calls.append((pointer, slot))
        return -2147024891 if pointer == 1 else 0

    monkeypatch.setattr(helper, "_call", _call)
    manager = helper.PackageManager.__new__(helper.PackageManager)
    with pytest.raises(helper.PackageApiError) as error:
        manager._complete(1)
    assert error.value.hresult == -2147024891
    assert calls == [(1, 10), (2, 10)]
    assert [value.args[0] for value in released.call_args_list] == [None, 2]


@pytest.mark.parametrize(
    "general,exception_code,description",
    [
        (-2147009296, -2147024894, "Package could not be opened."),
        (-2147009255, -2146233088, "An error occurred because a user was logged off."),
        (-2147024891, -2147024891, "Access is denied."),
    ],
)
def test_deployment_error_uses_general_code_actual_activity_and_measured_exception_mapping(
    helper: Any,
    monkeypatch: pytest.MonkeyPatch,
    general: int,
    exception_code: int,
    description: str,
) -> None:
    formatter = Mock(return_value=description + "\r\n")
    monkeypatch.setattr(helper.ctypes, "FormatError", formatter, raising=False)
    error = helper._deployment_failure(
        general, "Detailed package failure.", "00000000-0000-0000-0000-000000000001"
    )
    assert error.hresult == exception_code
    assert str(error) == (
        f"Deployment failed with HRESULT: 0x{general & 0xFFFFFFFF:08X}, {description}\r\n\r\n"
        "Detailed package failure.\n\n"
        "NOTE: For additional information, look for [ActivityId] "
        "00000000-0000-0000-0000-000000000001 "
        "in the Event Log or use the command line Get-AppPackageLog -ActivityID "
        "00000000-0000-0000-0000-000000000001\n"
    )
    formatter.assert_called_once_with(general & 0xFFFF)


@pytest.mark.parametrize(
    "general,extended,expected",
    [
        (-2147009296, -2147024883, -2147024894),
        (-2147009255, -2147009295, -2146233088),
        # Contract cases only, not claimed as observed Windows deployment outcomes.
        (-2147024891, 0, -2147024891),
        (-2147024891, 1, -2147024891),
    ],
)
def test_terminal_error_uses_general_hresult_independently_of_extended_detail(
    helper: Any,
    monkeypatch: pytest.MonkeyPatch,
    general: int,
    extended: int,
    expected: int,
) -> None:
    values = {(2, 7): 3, (2, 8): general, (3, 8): extended, (3, 6): 4}
    released = Mock()
    calls = []

    def _call(pointer: int, slot: int, _types: Any, *arguments: Any) -> int:
        calls.append((pointer, slot))
        if (pointer, slot) == (1, 10):
            arguments[0]._obj.value = 3
        elif (pointer, slot) == (3, 7):
            arguments[0]._obj[:] = bytes(range(16))
        return 0

    monkeypatch.setattr(helper, "_query", lambda *_args: 2)
    monkeypatch.setattr(
        helper, "_output", lambda pointer, slot, *_args: values[(pointer, slot)]
    )
    monkeypatch.setattr(helper, "_call", _call)
    monkeypatch.setattr(helper, "_release", released)
    monkeypatch.setattr(
        helper.ctypes,
        "FormatError",
        lambda _code: "Native system description.\r\n",
        raising=False,
    )
    manager = helper.PackageManager.__new__(helper.PackageManager)
    manager._read_string = Mock(return_value="exact native detail")
    with pytest.raises(helper.PackageApiError) as failure:
        manager._complete(1)
    assert failure.value.hresult == expected
    assert "exact native detail" in str(failure.value)
    assert f"0x{general & 0xFFFFFFFF:08X}" in str(failure.value)
    assert "03020100-0504-0706-0809-0a0b0c0d0e0f" in str(failure.value)
    assert calls == [(1, 10), (3, 7), (2, 10)]
    assert [value.args[0] for value in released.call_args_list] == [3, 2]


def test_current_user_selection_filters_resource_and_bundle_then_resolves_full_name(
    helper: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    records = [
        {
            "Name": "Owned",
            "PackageFullName": "Owned_Full",
            "IsBundle": False,
            "IsResourcePackage": False,
        },
        {
            "Name": "Resource",
            "PackageFullName": "Resource_Full",
            "IsBundle": False,
            "IsResourcePackage": True,
        },
        {
            "Name": "Bundle",
            "PackageFullName": "Bundle_Full",
            "IsBundle": True,
            "IsResourcePackage": False,
        },
    ]
    manager = Mock()
    manager.__enter__ = Mock(return_value=SimpleNamespace(packages=lambda: records))
    manager.__exit__ = Mock()
    monkeypatch.setattr(helper, "PackageManager", lambda: manager)
    matcher = SimpleNamespace(
        matches=lambda name, patterns: name.lower() == patterns[0].lower()
    )
    monkeypatch.setitem(sys.modules, "legacy_windows_find_match", matcher)
    assert helper.installed_status(None, "oWnEd") == {
        "id": "Owned_Full",
        "installed": True,
    }
    assert helper.installed_status(None, "OWNED_FULL") == {
        "id": "Owned_Full",
        "installed": True,
    }
    assert helper.installed_status(None, "Resource") == {
        "id": "Resource",
        "installed": False,
    }
