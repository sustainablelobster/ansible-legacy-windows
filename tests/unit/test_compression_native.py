"""Check compression queries and provider delegation without touching Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ntpath
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="helper")
def compression_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the target helper against the Windows path rules.

    :param monkeypatch: Scoped helper imports and OS substitute.
    :returns: Compression helper loaded by the development interpreter.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    module = load_module(
        ROOT / "plugins/module_utils/legacy_windows_compression.py",
        "tested_native_compression",
    )
    monkeypatch.setattr(module, "os", SimpleNamespace(path=ntpath))
    return module


@pytest.fixture(name="connection")
def wmi_connection(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """Replace the shared WMI boundary while preserving context ownership.

    :param helper: Loaded native compression helper.
    :param monkeypatch: Scoped native WMI substitute.
    :returns: Context-managed WMI query/method substitute.
    """
    instance = MagicMock()
    instance.__enter__.return_value = instance
    monkeypatch.setattr(helper, "WmiConnection", lambda: instance)
    return instance


@pytest.mark.parametrize(("filesystem", "supported"), [("NTFS", True), ("FAT", False)])
def test_volume_reports_provider_capability(
    helper: ModuleType, connection: MagicMock, filesystem: str, supported: bool
) -> None:
    connection.query.return_value = [
        {"FileSystem": filesystem, "SupportsFileBasedCompression": supported}
    ]
    assert helper.volume_info(r"D:\work\file.txt") == {
        "filesystem": filesystem,
        "supports_compression": supported,
    }
    connection.query.assert_called_once_with(
        "SELECT FileSystem, SupportsFileBasedCompression FROM Win32_LogicalDisk "
        "WHERE DeviceID='D:'",
        ["FileSystem", "SupportsFileBasedCompression"],
    )
    connection.call_method.assert_not_called()
    connection.__exit__.assert_called_once()


@pytest.mark.parametrize(
    "rows",
    [
        [],
        [{"FileSystem": None, "SupportsFileBasedCompression": True}],
        [{"FileSystem": "NTFS", "SupportsFileBasedCompression": None}],
        [{"FileSystem": "NTFS", "SupportsFileBasedCompression": 1}],
    ],
)
def test_unavailable_volume_information_is_not_invented(
    helper: ModuleType, connection: MagicMock, rows: list[dict[str, object]]
) -> None:
    connection.query.return_value = rows
    with pytest.raises(OSError, match="WMI.*path.*work"):
        helper.volume_info(r"D:\work\file.txt")
    connection.call_method.assert_not_called()
    connection.__exit__.assert_called_once()


@pytest.mark.parametrize("directory", [False, True])
@pytest.mark.parametrize("compressed", [False, True])
@pytest.mark.parametrize("recursive", [False, True])
def test_compression_uses_exact_provider_method_and_discovered_path(
    helper: ModuleType,
    connection: MagicMock,
    directory: bool,
    compressed: bool,
    recursive: bool,
) -> None:
    path = r"C:\work\folder\..\O'Brien 雪"
    object_path = r'\\machine\root\cimv2:CIM_DataFile.Name="C:\\work\\O\'Brien 雪"'
    connection.query.return_value = [{"__PATH": object_path}]
    connection.call_method.return_value = {"ReturnValue": 0}
    assert helper.set_compression(path, directory, compressed, recursive) == 0
    class_name = "Win32_Directory" if directory else "CIM_LogicalFile"
    connection.query.assert_called_once_with(
        "SELECT Name FROM " + class_name + " WHERE Name='C:\\\\work\\\\O\\'Brien 雪'",
        ["__PATH"],
    )
    connection.call_method.assert_called_once_with(
        object_path,
        "CompressEx" if compressed else "UnCompressEx",
        ["ReturnValue"],
        {"Recursive": recursive},
    )
    connection.__exit__.assert_called_once()


@pytest.mark.parametrize("code", [0, 2, 8, 9, 11, 15, 17, 21, 4278190080])
def test_provider_failure_codes_are_not_translated(
    helper: ModuleType, connection: MagicMock, code: int
) -> None:
    connection.query.return_value = [{"__PATH": "provider path"}]
    connection.call_method.return_value = {"ReturnValue": code}
    assert helper.set_compression(r"C:\file", False, True, False) == code


@pytest.mark.parametrize("rows", [[], [{"__PATH": None}], [{"__PATH": ""}]])
def test_missing_wmi_file_instance_fails_before_mutation(
    helper: ModuleType, connection: MagicMock, rows: list[dict[str, object]]
) -> None:
    connection.query.return_value = rows
    with pytest.raises(OSError, match="no CIM_LogicalFile instance"):
        helper.set_compression(r"C:\file", False, True, False)
    connection.call_method.assert_not_called()
    connection.__exit__.assert_called_once()


@pytest.mark.parametrize("code", [None, "0", True, 0.0])
def test_missing_provider_return_code_is_not_success(
    helper: ModuleType, connection: MagicMock, code: object
) -> None:
    connection.query.return_value = [{"__PATH": "provider path"}]
    connection.call_method.return_value = {"ReturnValue": code}
    with pytest.raises(OSError, match="CompressEx returned no integer ReturnValue"):
        helper.set_compression(r"C:\file", False, True, False)
    connection.__exit__.assert_called_once()


@pytest.mark.parametrize("operation", ["query", "call_method"])
def test_provider_errors_propagate_and_release_connection(
    helper: ModuleType, connection: MagicMock, operation: str
) -> None:
    connection.query.return_value = [{"__PATH": "provider path"}]
    getattr(connection, operation).side_effect = OSError("native provider failed")
    with pytest.raises(OSError, match="native provider failed"):
        helper.set_compression(r"C:\file", False, True, False)
    connection.__exit__.assert_called_once()
