"""Exercise native stat results and resource ownership without Windows access."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes expose failures and allocated resources for these tests.
# pylint: disable=protected-access

import ctypes
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module, native_error


@pytest.fixture(name="helper")
def stat_helper() -> ModuleType:
    """Import the target helper without loading any Windows libraries.

    :returns: The imported Python 3.4-compatible module.
    """
    source = ROOT / "legacy_windows/plugins/module_utils/legacy_windows_stat.py"
    return load_module(source, "tested_stat_native")


@pytest.fixture(name="native")
def native_libraries(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Mock:
    """Provide controllable native APIs without opening Windows handles.

    :param helper: Imported target helper.
    :param monkeypatch: Scoped replacements for Windows-only ctypes facilities.
    :returns: One parent mock containing each library and its ordered calls.
    """
    native = Mock()
    native.kernel.CreateFileW.return_value = 123
    native.kernel.GetFileType.return_value = 1
    native.kernel.FindFirstFileW.return_value = 456
    libraries = {
        "kernel32": native.kernel,
        "advapi32": native.security,
        "netapi32": native.network,
    }
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        helper.ctypes, "WinDLL", lambda name, **_kwargs: libraries[name], raising=False
    )
    monkeypatch.setattr(
        helper.ctypes, "get_last_error", Mock(return_value=5), raising=False
    )
    monkeypatch.setattr(helper.ctypes, "WinError", native_error, raising=False)
    return native


def test_metadata_preserves_link_bits_timestamps_and_large_size(
    helper: ModuleType, native: Mock
) -> None:
    def _attributes(path: str, level: int, pointer: Any) -> int:
        assert path == "C:\\雪 [link]"
        assert level == 0
        data = ctypes.cast(pointer, ctypes.POINTER(helper._AttributeData)).contents
        data.attributes = 0x411
        data.creation_time.high = 1
        data.creation_time.low = 3
        data.access_time.high = 2
        data.access_time.low = 5
        data.modification_time.high = 3
        data.modification_time.low = 7
        data.size_high = 4
        data.size_low = 9
        return 1

    native.kernel.GetFileAttributesExW.side_effect = _attributes

    assert helper.file_info("C:\\雪 [link]") == {
        "attributes": 0x411,
        "creation_time": (1 << 32) + 3,
        "access_time": (2 << 32) + 5,
        "modification_time": (3 << 32) + 7,
        "size": (4 << 32) + 9,
    }
    native.kernel.CreateFileW.assert_not_called()
    native.kernel.FindFirstFileW.assert_not_called()


@pytest.mark.parametrize("error", [2, 3, 21])
def test_missing_and_not_ready_do_not_retry_attributes(
    helper: ModuleType, native: Mock, error: int
) -> None:
    native.kernel.GetFileAttributesExW.return_value = 0
    helper.ctypes.get_last_error.return_value = error

    assert helper.file_info("A:\\missing") is None
    native.kernel.FindFirstFileW.assert_not_called()


@pytest.mark.parametrize("error", [5, 32, 87])
def test_other_attribute_failures_retry_enumeration_and_suppress_retry_errors(
    helper: ModuleType, native: Mock, error: int
) -> None:
    native.kernel.GetFileAttributesExW.return_value = 0
    helper.ctypes.get_last_error.return_value = error
    native.kernel.FindFirstFileW.return_value = helper._INVALID_HANDLE

    assert helper.file_info("C:\\locked\\") is None
    native.kernel.FindFirstFileW.assert_called_once()
    assert native.kernel.FindFirstFileW.call_args.args[0] == "C:\\locked"
    native.kernel.FindClose.assert_not_called()


def test_locked_file_enumeration_returns_metadata_and_closes(
    helper: ModuleType, native: Mock
) -> None:
    native.kernel.GetFileAttributesExW.return_value = 0

    def _find(_path: str, pointer: Any) -> int:
        data = ctypes.cast(pointer, ctypes.POINTER(helper._FindData)).contents
        data.attributes = 6
        data.size_high = 1
        data.size_low = 5
        data.creation_time.low = 123
        return 456

    native.kernel.FindFirstFileW.side_effect = _find

    info = helper.file_info("C:\\pagefile.sys")
    assert info["attributes"] == 6
    assert info["size"] == (1 << 32) + 5
    assert info["creation_time"] == 123
    native.kernel.FindClose.assert_called_once_with(456)


@pytest.mark.parametrize(
    ("attributes", "expected"),
    [
        (0, "0"),
        (35, "ReadOnly, Hidden, Archive"),
        (0x410, "Directory, ReparsePoint"),
        (0xFFFF, "65535"),
        (0x80000000, "-2147483648"),
        (0xFFFFFFFF, "-1"),
    ],
)
def test_attribute_names_preserve_flag_order_and_signed_unknown_values(
    helper: ModuleType, attributes: int, expected: str
) -> None:
    assert helper.attribute_names(attributes) == expected


@pytest.mark.parametrize("count", [0, 1, 2, 0xFFFFFFFF])
def test_hardlink_count_reads_native_record_without_requesting_file_data(
    helper: ModuleType, native: Mock, count: int
) -> None:
    def _information(handle: int, pointer: Any) -> int:
        assert handle == 123
        # BY_HANDLE_FILE_INFORMATION stores nNumberOfLinks after ten DWORDs.
        # Write the native layout independently of the helper's declaration.
        record = (ctypes.c_uint32 * 13)(0x20, 1, 2, 3, 4, 5, 6, 7, 8, 9, count, 11, 12)
        ctypes.memmove(pointer, record, ctypes.sizeof(record))
        return 1

    native.kernel.GetFileInformationByHandle.side_effect = _information

    assert helper.hardlink_count("C:\\雪 [locked]") == count
    native.kernel.CreateFileW.assert_called_once_with(
        "C:\\雪 [locked]", 0, 7, None, 3, 0x02000000, None
    )
    native.kernel.CloseHandle.assert_called_once_with(123)
    native.kernel.ReadFile.assert_not_called()


def test_hardlink_open_failure_does_not_query_or_close_invalid_handle(
    helper: ModuleType, native: Mock
) -> None:
    native.kernel.CreateFileW.return_value = helper._INVALID_HANDLE

    with pytest.raises(OSError) as failure:
        helper.hardlink_count("C:\\missing")

    assert failure.value.errno == 5
    native.kernel.GetFileInformationByHandle.assert_not_called()
    native.kernel.CloseHandle.assert_not_called()


def test_hardlink_query_failure_retains_error_before_closing(
    helper: ModuleType, native: Mock
) -> None:
    native.kernel.GetFileInformationByHandle.return_value = 0

    def _close(_handle: int) -> int:
        helper.ctypes.get_last_error.return_value = 6
        return 1

    native.kernel.CloseHandle.side_effect = _close

    with pytest.raises(OSError) as failure:
        helper.hardlink_count("C:\\fixture")

    assert failure.value.errno == 5
    native.kernel.CloseHandle.assert_called_once_with(123)


def test_absolute_path_preserves_native_casing_and_retries_buffer(
    helper: ModuleType, native: Mock
) -> None:
    absolute = "C:\\MiXeD\\" + "a" * 280

    def _full(path: str, capacity: int, buffer: Any, final: Any) -> int:
        assert path == ".\\MiXeD\\file"
        assert final is None
        if capacity <= len(absolute):
            return len(absolute) + 1
        buffer.value = absolute
        return len(absolute)

    native.kernel.GetFullPathNameW.side_effect = _full

    assert helper.full_path(".\\MiXeD\\file") == absolute
    assert native.kernel.GetFullPathNameW.call_count == 2
    native.kernel.GetLongPathNameW.assert_not_called()


@pytest.mark.parametrize("expands", [False, True])
def test_short_names_expand_when_windows_can_resolve_them(
    helper: ModuleType, native: Mock, expands: bool
) -> None:
    short = "C:\\MIXED\\LONGDI~1\\file"
    long = "C:\\MIXED\\Long directory\\file"

    def _full(_path: str, _capacity: int, buffer: Any, _final: Any) -> int:
        buffer.value = short
        return len(short)

    def _long(path: str, buffer: Any, _capacity: int) -> int:
        assert path == short
        if not expands:
            return 0
        buffer.value = long
        return len(long)

    native.kernel.GetFullPathNameW.side_effect = _full
    native.kernel.GetLongPathNameW.side_effect = _long

    assert helper.full_path(short) == (long if expands else short)


def test_path_resolution_failure_is_retained(helper: ModuleType, native: Mock) -> None:
    native.kernel.GetFullPathNameW.return_value = 0
    with pytest.raises(OSError) as failure:
        helper.full_path("C:\\bad")
    assert failure.value.errno == 5


def _security_descriptor(native: Mock) -> None:
    # Keep the native signature visible to check requested sections and outputs.
    def _get(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        path: str,
        kind: int,
        requested: int,
        sid: Any,
        group: Any,
        dacl: Any,
        sacl: Any,
        descriptor: Any,
    ) -> int:
        assert path == "C:\\fixture"
        assert kind == 1
        assert requested == 7
        assert group is dacl is sacl is None
        ctypes.cast(sid, ctypes.POINTER(ctypes.c_void_p)).contents.value = 100
        ctypes.cast(descriptor, ctypes.POINTER(ctypes.c_void_p)).contents.value = 200
        return 0

    native.security.GetNamedSecurityInfoW.side_effect = _get


@pytest.mark.parametrize("domain", ["HOST", ""])
def test_owner_returns_account_and_frees_security_descriptor(
    helper: ModuleType, native: Mock, domain: str
) -> None:
    _security_descriptor(native)

    # Account lookup has two independent buffers and lengths in its native ABI.
    def _lookup(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        system: Any,
        sid: Any,
        name: Any,
        name_size: Any,
        domain_buffer: Any,
        domain_size: Any,
        _kind: Any,
    ) -> int:
        assert system is None
        assert sid.value == 100
        if name is None:
            ctypes.cast(name_size, ctypes.POINTER(ctypes.c_uint32)).contents.value = 8
            ctypes.cast(domain_size, ctypes.POINTER(ctypes.c_uint32)).contents.value = 8
            helper.ctypes.get_last_error.return_value = 122
            return 0
        name.value = "account"
        domain_buffer.value = domain
        return 1

    native.security.LookupAccountSidW.side_effect = _lookup

    assert helper.owner("C:\\fixture") == (domain + "\\" if domain else "") + "account"
    assert [call.args[0].value for call in native.kernel.LocalFree.call_args_list] == [
        200
    ]
    native.security.ConvertSecurityDescriptorToStringSecurityDescriptorW.assert_not_called()


def test_unmapped_owner_returns_owner_only_sddl_and_frees_both_buffers(
    helper: ModuleType, native: Mock
) -> None:
    _security_descriptor(native)
    native.security.LookupAccountSidW.return_value = 0
    helper.ctypes.get_last_error.return_value = 1332
    sddl = ctypes.create_unicode_buffer("O:S-1-5-21-42")

    def _convert(
        descriptor: Any, revision: int, information: int, output: Any, length: Any
    ) -> int:
        assert descriptor.value == 200
        assert revision == information == 1
        assert length is None
        ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p)).contents.value = (
            ctypes.addressof(sddl)
        )
        return 1

    native.security.ConvertSecurityDescriptorToStringSecurityDescriptorW.side_effect = (
        _convert
    )

    assert helper.owner("C:\\fixture") == sddl.value
    assert [call.args[0].value for call in native.kernel.LocalFree.call_args_list] == [
        ctypes.addressof(sddl),
        200,
    ]


@pytest.mark.parametrize("stage", ["security", "lookup", "conversion"])
def test_owner_failure_preserves_error_and_releases_allocated_descriptor(
    helper: ModuleType, native: Mock, stage: str
) -> None:
    _security_descriptor(native)
    native.security.LookupAccountSidW.return_value = 0
    if stage == "security":
        native.security.GetNamedSecurityInfoW.side_effect = None
        native.security.GetNamedSecurityInfoW.return_value = 5
    elif stage == "conversion":
        helper.ctypes.get_last_error.side_effect = [1332, 5]
        native.security.ConvertSecurityDescriptorToStringSecurityDescriptorW.return_value = (
            0
        )

    with pytest.raises(OSError) as failure:
        helper.owner("C:\\fixture")

    assert failure.value.errno == 5
    assert native.kernel.LocalFree.call_count == (0 if stage == "security" else 1)


def test_shares_collect_multiple_matches_in_paged_native_order_and_free_each_page(
    helper: ModuleType, native: Mock
) -> None:
    pages = [
        (helper._ShareInfo * 3)(
            helper._ShareInfo(name="first", path="c:\\FIXTURE"),
            helper._ShareInfo(name="printer", path=None),
            helper._ShareInfo(name="unrelated", path="C:\\other"),
        ),
        (helper._ShareInfo * 1)(helper._ShareInfo(name="second", path="C:\\fixture")),
    ]

    # The enum's separate counts and resume pointer are part of the page contract.
    def _enumerate(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        server: Any,
        level: int,
        buffer: Any,
        maximum: int,
        received: Any,
        _total: Any,
        resume: Any,
    ) -> int:
        assert server is None
        assert level == 2
        assert maximum == 0xFFFFFFFF
        cursor = ctypes.cast(resume, ctypes.POINTER(ctypes.c_uint32)).contents
        page = pages[cursor.value]
        ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p)).contents.value = (
            ctypes.addressof(page)
        )
        ctypes.cast(received, ctypes.POINTER(ctypes.c_uint32)).contents.value = len(
            page
        )
        cursor.value += 1
        return 234 if cursor.value == 1 else 0

    native.network.NetShareEnum.side_effect = _enumerate

    assert helper.shares("C:\\fixture") == ["first", "second"]
    assert [
        call.args[0].value for call in native.network.NetApiBufferFree.call_args_list
    ] == [ctypes.addressof(page) for page in pages]


def test_share_failure_releases_returned_native_buffer(
    helper: ModuleType, native: Mock
) -> None:
    def _enumerate(*args: Any) -> int:
        ctypes.cast(args[2], ctypes.POINTER(ctypes.c_void_p)).contents.value = 333
        return 5

    native.network.NetShareEnum.side_effect = _enumerate

    with pytest.raises(OSError) as failure:
        helper.shares("C:\\fixture")
    assert failure.value.errno == 5
    assert native.network.NetApiBufferFree.call_args.args[0].value == 333


def test_directory_entries_snapshot_metadata_without_sorting_or_following(
    helper: ModuleType, native: Mock
) -> None:
    entries = iter(
        [(".", 0x10), ("..", 0x10), ("z.txt", 0x20), ("A", 0x410), ("雪", 2)]
    )
    sequence = 0

    def _populate(pointer: Any) -> int:
        nonlocal sequence
        item = next(entries, None)
        if item is None:
            helper.ctypes.get_last_error.return_value = 18
            return 0
        name, attributes = item
        sequence += 1
        data = ctypes.cast(pointer, ctypes.POINTER(helper._FindData)).contents
        data.name = name
        data.attributes = attributes
        data.creation_time.high = sequence
        data.creation_time.low = 3
        data.access_time.high = sequence + 1
        data.access_time.low = 5
        data.modification_time.high = sequence + 2
        data.modification_time.low = 7
        data.size_high = sequence + 3
        data.size_low = 9
        return 1

    def _first(path: str, pointer: Any) -> int:
        assert path == "C:\\fixture\\*"
        assert _populate(pointer)
        return 456

    native.kernel.FindFirstFileW.side_effect = _first
    native.kernel.FindNextFileW.side_effect = lambda _handle, pointer: _populate(
        pointer
    )

    assert helper.directory_entries("C:\\fixture") == [
        {
            "name": name,
            "attributes": attributes,
            "creation_time": (index << 32) + 3,
            "access_time": ((index + 1) << 32) + 5,
            "modification_time": ((index + 2) << 32) + 7,
            "size": ((index + 3) << 32) + 9,
        }
        for index, (name, attributes) in enumerate(
            [("z.txt", 0x20), ("A", 0x410), ("雪", 2)], start=3
        )
    ]
    native.kernel.FindClose.assert_called_once_with(456)
    native.kernel.CreateFileW.assert_not_called()
    native.kernel.GetFileAttributesExW.assert_not_called()


@pytest.mark.parametrize("error", [2, 3, 5, 123])
def test_directory_entries_distinguish_empty_search_from_path_and_access_errors(
    helper: ModuleType, native: Mock, error: int
) -> None:
    native.kernel.FindFirstFileW.return_value = helper._INVALID_HANDLE
    helper.ctypes.get_last_error.return_value = error

    if error == 2:
        assert helper.directory_entries("C:\\fixture") == []
    else:
        with pytest.raises(OSError) as failure:
            helper.directory_entries("C:\\fixture")
        assert failure.value.errno == error

    native.kernel.FindNextFileW.assert_not_called()
    native.kernel.FindClose.assert_not_called()


@pytest.mark.parametrize("error", [2, 3, 5])
def test_directory_entries_never_return_partial_success_after_traversal_failure(
    helper: ModuleType, native: Mock, error: int
) -> None:
    native.kernel.FindNextFileW.return_value = 0
    helper.ctypes.get_last_error.return_value = error

    with pytest.raises(OSError) as failure:
        helper.directory_entries("C:\\fixture")

    assert failure.value.errno == error
    native.kernel.FindClose.assert_called_once_with(456)


def test_directory_entries_close_after_snapshot_failure(
    helper: ModuleType, native: Mock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper, "_entry_info", Mock(side_effect=ValueError("snapshot")))

    with pytest.raises(ValueError, match="snapshot"):
        helper.directory_entries("C:\\fixture")

    native.kernel.FindClose.assert_called_once_with(456)
    native.kernel.FindNextFileW.assert_not_called()


def test_directory_size_counts_hidden_and_hardlink_names_and_descends_junctions(
    helper: ModuleType, native: Mock
) -> None:
    entries = {
        "C:\\fixture\\*": [
            (".", 0x10, 0),
            ("..", 0x10, 0),
            ("hidden", 2, 15),
            ("hardlink", 0x20, 15),
            ("junction", 0x410, 0),
        ],
        "C:\\fixture\\junction\\*": [("large", 0x20, (1 << 32) + 7)],
    }
    active: list[tuple[str, int, int]] = []

    def _populate(pointer: Any) -> int:
        if not active:
            helper.ctypes.get_last_error.return_value = 18
            return 0
        name, attributes, size = active.pop(0)
        data = ctypes.cast(pointer, ctypes.POINTER(helper._FindData)).contents
        data.name = name
        data.attributes = attributes
        data.size_low = size & 0xFFFFFFFF
        data.size_high = size >> 32
        return 1

    def _first(path: str, pointer: Any) -> int:
        active.extend(entries[path])
        assert _populate(pointer)
        return 456

    native.kernel.FindFirstFileW.side_effect = _first
    native.kernel.FindNextFileW.side_effect = lambda _handle, pointer: _populate(
        pointer
    )

    assert helper.directory_size("C:\\fixture") == (1 << 32) + 37
    assert native.kernel.FindClose.call_count == 2


@pytest.mark.parametrize("stage", ["first", "next"])
def test_directory_enumeration_errors_raise_and_close_only_valid_handles(
    helper: ModuleType, native: Mock, stage: str
) -> None:
    if stage == "first":
        native.kernel.FindFirstFileW.return_value = helper._INVALID_HANDLE
    native.kernel.FindNextFileW.return_value = 0

    with pytest.raises(OSError) as failure:
        helper.directory_size("C:\\fixture")
    assert failure.value.errno == 5
    assert native.kernel.FindClose.call_count == (1 if stage == "next" else 0)


def _hash_handles(native: Mock, provider_type: int = 24) -> None:
    def _acquire(
        pointer: Any, container: Any, provider: Any, kind: int, flags: int
    ) -> int:
        assert container is provider is None
        assert kind == provider_type
        assert flags == 0xF0000000
        ctypes.cast(pointer, ctypes.POINTER(ctypes.c_size_t)).contents.value = 222
        return 1

    def _create(
        context: Any, _algorithm: int, key: int, flags: int, pointer: Any
    ) -> int:
        assert context.value == 222
        assert key == flags == 0
        ctypes.cast(pointer, ctypes.POINTER(ctypes.c_size_t)).contents.value = 333
        return 1

    native.security.CryptAcquireContextW.side_effect = _acquire
    native.security.CryptCreateHash.side_effect = _create


@pytest.mark.parametrize(
    ("algorithm", "identifier", "provider_type"),
    [
        ("md5", 0x8003, 1),
        ("sha1", 0x8004, 1),
        ("sha256", 0x800C, 24),
        ("sha384", 0x800D, 24),
        ("sha512", 0x800E, 24),
    ],
)
def test_checksum_streams_exact_chunks_and_returns_native_digest(
    helper: ModuleType,
    native: Mock,
    algorithm: str,
    identifier: int,
    provider_type: int,
) -> None:
    _hash_handles(native, provider_type)
    contents = [b"binary\0\xff", b"second", b""]
    hashed = []

    def _read(
        handle: int, buffer: Any, length: int, received: Any, overlap: Any
    ) -> int:
        assert handle == 123
        assert length == 65536
        assert overlap is None
        data = contents.pop(0)
        ctypes.memmove(buffer, data, len(data))
        ctypes.cast(received, ctypes.POINTER(ctypes.c_uint32)).contents.value = len(
            data
        )
        return 1

    def _hash(handle: Any, buffer: Any, length: int, flags: int) -> int:
        assert handle.value == 333
        assert flags == 0
        hashed.append(buffer.raw[:length])
        return 1

    def _digest(
        handle: Any, parameter: int, buffer: Any, length: Any, flags: int
    ) -> int:
        assert handle.value == 333
        assert parameter == 2
        assert flags == 0
        ctypes.cast(length, ctypes.POINTER(ctypes.c_uint32)).contents.value = 4
        if buffer is not None:
            ctypes.memmove(buffer, b"\x00\x7f\xaa\xff", 4)
        return 1

    native.kernel.ReadFile.side_effect = _read
    native.security.CryptHashData.side_effect = _hash
    native.security.CryptGetHashParam.side_effect = _digest

    assert helper.checksum("C:\\original [path]", algorithm) == "007faaff"
    assert hashed == [b"binary\0\xff", b"second"]
    assert native.security.CryptCreateHash.call_args.args[1] == identifier
    native.kernel.CreateFileW.assert_called_once_with(
        "C:\\original [path]", 0x80000000, 3, None, 3, 0x00100000, None
    )
    names = [call[0] for call in native.mock_calls]
    assert names.index("security.CryptCreateHash") < names.index("kernel.CreateFileW")
    native.kernel.CloseHandle.assert_called_once_with(123)
    assert native.security.CryptDestroyHash.call_args.args[0].value == 333
    assert native.security.CryptReleaseContext.call_args.args[0].value == 222


@pytest.mark.parametrize(
    "stage", ["provider", "hash", "open", "read", "update", "digest"]
)
def test_checksum_failures_release_only_acquired_resources(
    helper: ModuleType, native: Mock, stage: str
) -> None:
    _hash_handles(native)
    native.kernel.ReadFile.return_value = 0
    if stage == "provider":
        native.security.CryptAcquireContextW.side_effect = None
        native.security.CryptAcquireContextW.return_value = 0
    elif stage == "hash":
        native.security.CryptCreateHash.side_effect = None
        native.security.CryptCreateHash.return_value = 0
    elif stage == "open":
        native.kernel.CreateFileW.return_value = helper._INVALID_HANDLE
    elif stage in ("update", "digest"):

        def _read(
            _handle: int, _buffer: Any, _length: int, received: Any, _overlap: Any
        ) -> int:
            ctypes.cast(received, ctypes.POINTER(ctypes.c_uint32)).contents.value = (
                1 if stage == "update" else 0
            )
            return 1

        native.kernel.ReadFile.side_effect = _read
        native.security.CryptHashData.return_value = 0
        native.security.CryptGetHashParam.return_value = 0

    with pytest.raises(OSError) as failure:
        helper.checksum("C:\\fixture", "sha256")

    assert failure.value.errno == 5
    assert native.security.CryptReleaseContext.call_count == (stage != "provider")
    assert native.security.CryptDestroyHash.call_count == (
        stage not in ("provider", "hash")
    )
    assert native.kernel.CloseHandle.call_count == (
        stage in ("read", "update", "digest")
    )


@pytest.mark.parametrize("algorithm", [None, "unknown"])
def test_invalid_checksum_algorithm_never_initializes_or_opens(
    helper: ModuleType, native: Mock, algorithm: object
) -> None:
    with pytest.raises(ValueError, match="Unsupported hash algorithm"):
        helper.checksum("C:\\fixture", algorithm)
    native.security.CryptAcquireContextW.assert_not_called()
    native.kernel.CreateFileW.assert_not_called()


def test_checksum_rejects_device_and_releases_resources(
    helper: ModuleType, native: Mock
) -> None:
    _hash_handles(native, provider_type=1)
    native.kernel.GetFileType.return_value = 2

    with pytest.raises(ValueError, match="Only disk"):
        helper.checksum("NUL", "md5")

    native.kernel.CloseHandle.assert_called_once_with(123)
    native.kernel.ReadFile.assert_not_called()
    native.security.CryptDestroyHash.assert_called_once()
    native.security.CryptReleaseContext.assert_called_once()
