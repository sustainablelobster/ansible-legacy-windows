"""Exercise native WinINet configuration and ownership without Windows access."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These tests inspect the fixed C records sent across the native boundary.
# pylint: disable=protected-access

import ctypes
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="helper")
def inet_helper() -> ModuleType:
    """Load the helper without calling Windows libraries.

    :returns: A fresh helper under the development interpreter.
    """
    return load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_inet_proxy.py",
        "tested_inet_proxy_native",
    )


@pytest.fixture(name="native")
def native_boundaries(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Replace native entry points while retaining returned string buffers.

    :param helper: Imported helper.
    :param monkeypatch: Scoped native boundary substitutions.
    :returns: Call recorders, buffers and the current native error code.
    """
    state = SimpleNamespace(
        library=SimpleNamespace(
            InternetQueryOptionW=Mock(return_value=1),
            InternetSetOptionW=Mock(return_value=1),
        ),
        kernel=SimpleNamespace(GlobalFree=Mock()),
        buffers=[],
        addresses=[],
        error=87,
    )
    monkeypatch.setattr(helper, "_wininet", Mock(return_value=state.library))
    monkeypatch.setattr(helper, "_kernel", Mock(return_value=state.kernel))
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    monkeypatch.setattr(
        helper.ctypes, "get_last_error", lambda: state.error, raising=False
    )
    monkeypatch.setattr(
        helper.ctypes,
        "FormatError",
        Mock(return_value="Native failure.\r\n"),
        raising=False,
    )
    # pylint: enable=duplicate-code
    return state


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def _fill(native: Any, listing: Any, flags: int, strings: list[str | None]) -> None:
    listing.options[0].value.number = flags
    for index, value in enumerate(strings, 1):
        if value is not None:
            buffer = ctypes.create_unicode_buffer(value)
            native.buffers.append(buffer)
            address = ctypes.addressof(buffer)
            native.addresses.append(address)
            listing.options[index].value.text = address


# pylint: enable=duplicate-code


def test_native_layout_and_binding(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    width = ctypes.sizeof(ctypes.c_void_p)
    assert ctypes.sizeof(helper._OptionValue) == 8
    assert helper._Option.value.offset == width
    assert ctypes.sizeof(helper._Option) == 8 + width
    assert ctypes.sizeof(helper._OptionList) == (32 if width == 8 else 20)
    assert helper._OptionList.connection.offset == width
    assert helper._OptionList.options.offset == (24 if width == 8 else 16)
    library = Mock()
    loader = Mock(return_value=library)
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(helper.ctypes, "WinDLL", loader, raising=False)
    assert helper._wininet() is library
    loader.assert_called_with("wininet", use_last_error=True)
    assert library.InternetQueryOptionW.restype is ctypes.c_int32
    assert library.InternetQueryOptionW.argtypes == [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    assert library.InternetSetOptionW.restype is ctypes.c_int32
    assert library.InternetSetOptionW.argtypes == [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
    ]
    assert helper._kernel() is library
    assert library.GlobalFree.restype is ctypes.c_void_p
    assert library.GlobalFree.argtypes == [ctypes.c_void_p]


@pytest.mark.parametrize(
    "operation,arguments",
    [
        ("get_proxy", []),
        ("set_proxy", [{}]),
        ("valid_connection", ["name"]),
    ],
)
def test_operations_require_windows(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    arguments: list[Any],
) -> None:
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="posix"))
    loader = Mock()
    monkeypatch.setattr(helper.ctypes, "WinDLL", loader, raising=False)
    with pytest.raises(OSError, match="require a Windows target"):
        getattr(helper, operation)(*arguments)
    loader.assert_not_called()


@pytest.mark.parametrize("flags", [0, 1, 2, 4, 8, 15])
@pytest.mark.parametrize("connection", [None, "Owned connection 雪"])
def test_reads_only_active_strings_and_frees_every_allocation(
    helper: ModuleType,
    native: Any,
    flags: int,
    connection: str | None,
) -> None:
    def _query(_handle: Any, number: int, pointer: Any, size: Any) -> int:
        listing = pointer._obj
        assert number == 75
        assert listing.connection == connection
        assert listing.size == size._obj.value == ctypes.sizeof(listing)
        assert listing.count == 4
        assert [listing.options[i].option for i in range(4)] == [10, 4, 2, 3]
        _fill(native, listing, flags, ["http://例.invalid/a.pac", "雪:80", "<local>"])
        return 1

    native.library.InternetQueryOptionW.side_effect = _query
    assert helper.get_proxy(connection) == {
        "auto_detect": bool(flags & 8),
        "auto_config_url": "http://例.invalid/a.pac" if flags & 4 else None,
        "proxy": "雪:80" if flags & 2 else None,
        "bypass": "<local>" if flags & 2 else None,
    }
    assert native.kernel.GlobalFree.call_args_list == [
        call(p) for p in native.addresses
    ]
    native.library.InternetSetOptionW.assert_not_called()


def test_legacy_query_frees_partial_strings_before_retry(
    helper: ModuleType, native: Any
) -> None:
    seen = []

    def _query(_handle: Any, _number: int, pointer: Any, _size: Any) -> int:
        listing = pointer._obj
        seen.append(listing.options[0].option)
        if len(seen) == 1:
            _fill(native, listing, 0, ["partial", None, None])
            return 0
        assert native.kernel.GlobalFree.call_args_list == [call(native.addresses[0])]
        assert listing.options[0].option == 1
        _fill(native, listing, 3, [None, "proxy", None])
        return 1

    native.library.InternetQueryOptionW.side_effect = _query
    assert helper.get_proxy()["proxy"] == "proxy"
    assert seen == [10, 1]
    assert native.kernel.GlobalFree.call_args_list == [
        call(p) for p in native.addresses
    ]


@pytest.mark.parametrize("code,calls", [(5, 1), (87, 2)])
def test_query_errors_are_not_swallowed_and_allocations_freed(
    helper: ModuleType,
    native: Any,
    code: int,
    calls: int,
) -> None:
    native.error = code

    def _query(_handle: Any, _number: int, pointer: Any, _size: Any) -> int:
        _fill(
            native, pointer._obj, 0, ["partial PAC", "partial proxy", "partial bypass"]
        )
        return 0

    native.library.InternetQueryOptionW.side_effect = _query
    with pytest.raises(OSError, match=f"Win32ErrorCode {code}"):
        helper.get_proxy()
    assert native.library.InternetQueryOptionW.call_count == calls
    assert native.kernel.GlobalFree.call_args_list == [
        call(p) for p in native.addresses
    ]


def test_decode_failure_frees_all_strings(
    helper: ModuleType, native: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _query(_handle: Any, _number: int, pointer: Any, _size: Any) -> int:
        _fill(native, pointer._obj, 15, ["PAC", "proxy", "bypass"])
        return 1

    native.library.InternetQueryOptionW.side_effect = _query
    monkeypatch.setattr(
        helper.ctypes, "wstring_at", Mock(side_effect=UnicodeError("decode failed"))
    )
    with pytest.raises(UnicodeError, match="decode failed"):
        helper.get_proxy()
    assert native.kernel.GlobalFree.call_args_list == [
        call(p) for p in native.addresses
    ]


@pytest.mark.parametrize(
    "status,exists", [(183, True), (0, False), (5, False), (123, False)]
)
def test_connection_validation_matches_upstream_status_test(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    exists: bool,
) -> None:
    library = Mock()
    library.RasValidateEntryNameW.return_value = status
    loader = Mock(return_value=library)
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(helper.ctypes, "WinDLL", loader, raising=False)
    assert helper.valid_connection("Existing 雪") is exists
    loader.assert_called_once_with("rasapi32", use_last_error=True)
    library.RasValidateEntryNameW.assert_called_once_with(None, "Existing 雪")
    assert library.RasValidateEntryNameW.restype is ctypes.c_uint32
    assert library.RasValidateEntryNameW.argtypes == [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
    ]


@pytest.mark.parametrize(
    "config,flags",
    [
        (
            {
                "auto_config_url": None,
                "auto_detect": False,
                "proxy": None,
                "bypass": None,
            },
            1,
        ),
        ({"auto_config_url": "", "auto_detect": True, "proxy": "", "bypass": ""}, 9),
        (
            {
                "auto_config_url": "http://例/a.pac",
                "auto_detect": False,
                "proxy": None,
                "bypass": None,
            },
            5,
        ),
        (
            {
                "auto_config_url": None,
                "auto_detect": False,
                "proxy": "雪:80",
                "bypass": "<local>",
            },
            3,
        ),
        (
            {
                "auto_config_url": "http://例/a.pac",
                "auto_detect": True,
                "proxy": "雪:80",
                "bypass": "<local>",
            },
            15,
        ),
    ],
)
def test_write_flags_borrowed_strings_and_notification(
    helper: ModuleType,
    native: Any,
    config: dict[str, Any],
    flags: int,
) -> None:
    seen = []

    def _set(_handle: Any, number: int, pointer: Any, size: int) -> int:
        seen.append(number)
        if number == 75:
            listing = pointer._obj
            assert listing.connection == "Owned connection"
            assert size == listing.size == ctypes.sizeof(listing)
            assert [listing.options[i].option for i in range(4)] == [4, 2, 3, 10]
            assert listing.options[3].value.number == flags
            for index, name in enumerate(("auto_config_url", "proxy", "bypass")):
                address = listing.options[index].value.text
                assert (ctypes.wstring_at(address) if address else None) == (
                    config[name] or None
                )
        else:
            assert number == 95 and pointer is None and size == 0
        return 1

    native.library.InternetSetOptionW.side_effect = _set
    helper.set_proxy(config, "Owned connection")
    assert seen == [75, 95]
    native.kernel.GlobalFree.assert_not_called()
    native.library.InternetQueryOptionW.assert_not_called()


@pytest.mark.parametrize("code,fallback", [(87, True), (5, False)])
def test_write_uses_legacy_flags_only_for_invalid_parameter(
    helper: ModuleType,
    native: Any,
    code: int,
    fallback: bool,
) -> None:
    native.error = code
    seen = []

    def _set(_handle: Any, number: int, pointer: Any, _size: int) -> int:
        seen.append((number, pointer._obj.options[3].option if pointer else None))
        return int(len(seen) != 1)

    native.library.InternetSetOptionW.side_effect = _set
    config = {
        "auto_config_url": None,
        "auto_detect": True,
        "proxy": "proxy",
        "bypass": None,
    }
    if fallback:
        helper.set_proxy(config)
        assert seen == [(75, 10), (75, 1), (95, None)]
    else:
        with pytest.raises(OSError, match="Win32ErrorCode 5"):
            helper.set_proxy(config)
        assert seen == [(75, 10)]


@pytest.mark.parametrize("failure_call,code", [(2, 5), (3, 87)])
def test_failed_legacy_write_or_notification_stays_actionable(
    helper: ModuleType,
    native: Any,
    failure_call: int,
    code: int,
) -> None:
    count = 0

    def _set(_handle: Any, _number: int, _pointer: Any, _size: int) -> int:
        nonlocal count
        count += 1
        native.error = 87 if count == 1 else code
        return int(count not in (1, failure_call))

    native.library.InternetSetOptionW.side_effect = _set
    with pytest.raises(OSError, match=f"Win32ErrorCode {code}"):
        helper.set_proxy(
            {
                "auto_config_url": None,
                "auto_detect": False,
                "proxy": None,
                "bypass": None,
            }
        )
    assert count == failure_call
