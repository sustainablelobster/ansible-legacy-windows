"""Exercise native Windows Installer identity, buffer and handle ownership."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native-output substitutes must inspect the by-reference ABI storage.
# pylint: disable=protected-access

from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="provider")
def installer_provider(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Supply observable native resource boundaries without claiming Windows support.

    :param monkeypatch: Scoped native-library substitutions.
    :returns: Loaded helper, library and COM boundary.
    """
    module = load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_package_msi.py",
        "tested_msi",
    )
    ole = SimpleNamespace(
        CoInitializeEx=Mock(return_value=0),
        CoUninitialize=Mock(),
        GetClassFile=Mock(return_value=1),
    )

    def _open(_path: str, options: int, output: Any) -> int:
        assert options == 1
        output._obj.value = 73
        return 0

    def _property(_handle: Any, _name: str, buffer: Any, size: Any) -> int:
        value = "{223D9A13-653B-4231-A365-EDDC30B4F226}"
        if size._obj.value == 0:
            size._obj.value = len(value)
            return 234
        assert size._obj.value == len(value) + 1
        buffer.value = value
        size._obj.value = len(value)
        return 0

    library = SimpleNamespace(
        MsiOpenPackageExW=Mock(side_effect=_open),
        MsiGetPropertyW=Mock(side_effect=_property),
        MsiCloseHandle=Mock(return_value=0),
        MsiQueryProductStateW=Mock(return_value=5),
        MsiGetSummaryInformationW=Mock(return_value=0),
        MsiSummaryInfoGetPropertyW=Mock(return_value=0),
        MsiEnumPatchesExW=Mock(return_value=259),
        MsiGetPatchInfoExW=Mock(return_value=1647),
    )
    monkeypatch.setattr(module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        module.ctypes,
        "WinDLL",
        lambda name: ole if name == "ole32" else library,
        raising=False,
    )
    monkeypatch.setattr(
        module.ctypes,
        "WinError",
        lambda code: OSError(code, "native failure"),
        raising=False,
    )
    return SimpleNamespace(module=module, library=library, ole=ole)


def test_safe_package_open_reads_identity_and_closes_before_com_exit(
    provider: Any,
) -> None:
    with provider.module.WindowsInstaller() as installer:
        assert (
            installer.product_code("renamed.bin")
            == "{223D9A13-653B-4231-A365-EDDC30B4F226}"
        )
        assert installer.product_state("other") == 5
    provider.library.MsiOpenPackageExW.assert_called_once()
    assert provider.library.MsiGetPropertyW.call_count == 2
    assert provider.library.MsiCloseHandle.call_args.args[0].value == 73
    provider.ole.CoUninitialize.assert_called_once()


def test_summary_string_buffer_includes_terminator_and_owned_handle(
    provider: Any,
) -> None:
    """Exercise the tuple-call syntax supported by the actual Python 3.4 target."""

    def _summary(_database: int, _path: str, _count: int, output: Any) -> int:
        output._obj.value = 97
        return 0

    def _property(
        handle: Any,
        field: int,
        kind: Any,
        _number: Any,
        _time: Any,
        buffer: Any,
        size: Any,
    ) -> int:
        assert handle.value == 97 and field == 7
        kind._obj.value = 30
        if size._obj.value == 0:
            size._obj.value = len("Intel;1033")
            return 234
        assert size._obj.value == len("Intel;1033") + 1
        buffer.value = "Intel;1033"
        return 0

    provider.library.MsiGetSummaryInformationW.side_effect = _summary
    provider.library.MsiSummaryInfoGetPropertyW.side_effect = _property
    with provider.module.WindowsInstaller() as installer:
        assert installer.summary_property("good.msi", 7) == "Intel;1033"
    assert provider.library.MsiCloseHandle.call_args.args[0].value == 97
    assert provider.library.MsiSummaryInfoGetPropertyW.call_count == 2


@pytest.mark.parametrize("status,release", [(0, True), (1, True), (-2147417850, False)])
def test_com_ownership_preserves_an_existing_thread_apartment(
    provider: Any, status: int, release: bool
) -> None:
    provider.ole.CoInitializeEx.return_value = status
    with provider.module.WindowsInstaller():
        pass
    assert provider.ole.CoUninitialize.call_count == int(release)


def test_com_initialization_failure_does_not_release_an_unacquired_apartment(
    provider: Any,
) -> None:
    provider.ole.CoInitializeEx.return_value = -1
    with pytest.raises(OSError, match="CoInitializeEx failed"):
        with provider.module.WindowsInstaller():
            pass
    provider.ole.CoUninitialize.assert_not_called()


@pytest.mark.parametrize("operation", ["MsiOpenPackageExW", "MsiGetPropertyW"])
def test_native_read_failure_closes_only_a_successfully_opened_handle(
    provider: Any, operation: str
) -> None:
    function = getattr(provider.library, operation)
    function.side_effect = None
    function.return_value = 5
    with pytest.raises(OSError):
        with provider.module.WindowsInstaller() as installer:
            installer.product_code("package.msi")
    assert provider.library.MsiCloseHandle.call_count == int(
        operation == "MsiGetPropertyW"
    )
    provider.ole.CoUninitialize.assert_called_once()


def test_unreadable_compound_file_does_not_infer_msi_from_extension(
    provider: Any,
) -> None:
    with provider.module.WindowsInstaller() as installer:
        assert installer.package_type("misleading.msi") is None


@pytest.mark.parametrize(
    "identifier,kind",
    [
        ("000c1084-0000-0000-c000-000000000046", "msi"),
        ("000c1086-0000-0000-c000-000000000046", "msp"),
        ("00000000-0000-0000-0000-000000000000", None),
    ],
)
def test_compound_class_id_not_the_filename_selects_package_type(
    provider: Any, identifier: str, kind: str | None
) -> None:
    def _class(_path: str, output: Any) -> int:
        value = provider.module.uuid.UUID(identifier).bytes_le
        provider.module.ctypes.memmove(
            provider.module.ctypes.byref(output._obj), value, 16
        )
        return 0

    provider.ole.GetClassFile.side_effect = _class
    with provider.module.WindowsInstaller() as installer:
        assert installer.package_type("installer.exe") == kind


def test_patch_enumeration_retries_sid_buffer_without_skipping_or_reordering(
    provider: Any,
) -> None:
    # The substitute follows the native ten-argument ABI rather than hiding it
    # behind an opaque positional tuple.
    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def _enum(
        product: Any,
        user: Any,
        context: int,
        state: int,
        index: int,
        patch: Any,
        output_product: Any,
        output_context: Any,
        sid: Any,
        length: Any,
    ) -> int:
        assert product is None and user is None and context == 7 and state == 15
        if index == 2:
            return 259
        patch.value = "Patch" + str(index)
        output_product.value = "Product" + str(index)
        output_context._obj.value = 4 if index == 0 else 2
        if index == 1:
            if length._obj.value == 0:
                length._obj.value = len("S-1-5-21-1")
                return 234
            assert length._obj.value == len("S-1-5-21-1") + 1
            sid.value = "S-1-5-21-1"
        return 0

    provider.library.MsiEnumPatchesExW.side_effect = _enum
    with provider.module.WindowsInstaller() as installer:
        assert installer.patches() == [
            {"patch": "Patch0", "product": "Product0", "context": 4, "sid": None},
            {
                "patch": "Patch1",
                "product": "Product1",
                "context": 2,
                "sid": "S-1-5-21-1",
            },
        ]
    assert provider.library.MsiEnumPatchesExW.call_count == 4
    provider.library.MsiCloseHandle.assert_not_called()


def test_patch_state_two_call_buffer_matches_source_initial_error_handling(
    provider: Any,
) -> None:
    # Keep the seven native arguments individually named for the ABI assertions.
    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def _state(
        patch: str,
        product: str,
        sid: Any,
        context: int,
        field: str,
        buffer: Any,
        size: Any,
    ) -> int:
        assert (patch, product, sid, context, field) == (
            "Patch",
            "Product",
            None,
            4,
            "State",
        )
        if size._obj.value == 0:
            size._obj.value = 1
            return 234
        assert size._obj.value == 2
        buffer.value = "1"
        return 0

    provider.library.MsiGetPatchInfoExW.side_effect = _state
    with provider.module.WindowsInstaller() as installer:
        assert installer.patch_state("Patch", "Product", 4) == 1
    provider.library.MsiCloseHandle.assert_not_called()


@pytest.mark.parametrize("operation", ["MsiEnumPatchesExW", "MsiGetPatchInfoExW"])
def test_patch_native_failure_releases_com_without_metadata_handle_leak(
    provider: Any, operation: str
) -> None:
    getattr(provider.library, operation).return_value = 5
    with pytest.raises(OSError):
        with provider.module.WindowsInstaller() as installer:
            if operation == "MsiEnumPatchesExW":
                installer.patches()
            else:
                installer.patch_state("Patch", "Product", 4)
    provider.ole.CoUninitialize.assert_called_once()
    provider.library.MsiCloseHandle.assert_not_called()
