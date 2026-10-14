"""Exercise WinHTTP native ownership and configuration without Windows hosts."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native-boundary assertions inspect the fixed records passed to Windows.
# pylint: disable=protected-access

import ctypes
from collections.abc import Callable, Sequence
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="helper")
def proxy_helper() -> ModuleType:
    """Load the native helper without calling a Windows library.

    :returns: Fresh helper imported using the development interpreter.
    """
    return load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_http_proxy.py",
        "tested_http_proxy_native",
    )


@pytest.fixture(name="native")
def native_boundaries(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Replace native calls and keep returned string allocations alive.

    :param helper: Imported helper.
    :param monkeypatch: Scoped Windows API substitutions.
    :returns: Native call recorders and backing buffers.
    """
    state = SimpleNamespace(
        library=SimpleNamespace(
            WinHttpGetDefaultProxyConfiguration=Mock(return_value=1),
            WinHttpGetIEProxyConfigForCurrentUser=Mock(return_value=1),
            WinHttpSetDefaultProxyConfiguration=Mock(return_value=1),
        ),
        kernel=SimpleNamespace(GlobalFree=Mock(return_value=None)),
        buffers=[],
        addresses=[],
    )
    monkeypatch.setattr(helper, "_winhttp", Mock(return_value=state.library))
    monkeypatch.setattr(helper, "_kernel", Mock(return_value=state.kernel))
    monkeypatch.setattr(
        helper.ctypes, "get_last_error", Mock(return_value=5), raising=False
    )
    monkeypatch.setattr(
        helper.ctypes,
        "FormatError",
        Mock(return_value="Access is denied.\r\n"),
        raising=False,
    )
    return state


def _returned_strings(
    native: Any, names: Sequence[str], values: Sequence[str | None]
) -> Callable[[Any], int]:
    def _fill(pointer: Any) -> int:
        record = pointer._obj
        for name, value in zip(names, values):
            if value is not None:
                buffer = ctypes.create_unicode_buffer(value)
                native.buffers.append(buffer)
                address = ctypes.addressof(buffer)
                native.addresses.append(address)
                setattr(record, name, address)
        return 1

    return _fill


def test_native_record_layout_and_signatures(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    width = ctypes.sizeof(ctypes.c_void_p)
    assert helper._ProxyInfo.proxy.offset == width
    assert helper._ProxyInfo.bypass.offset == width * 2
    assert ctypes.sizeof(helper._ProxyInfo) == width * 3
    assert helper._IEProxyConfig.auto_config_url.offset == width
    assert helper._IEProxyConfig.proxy.offset == width * 2
    assert helper._IEProxyConfig.bypass.offset == width * 3
    assert ctypes.sizeof(helper._IEProxyConfig) == width * 4
    library = Mock()
    loader = Mock(return_value=library)
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(helper.ctypes, "WinDLL", loader, raising=False)
    assert helper._winhttp() is library
    loader.assert_called_once_with("winhttp", use_last_error=True)
    for function in (
        library.WinHttpGetDefaultProxyConfiguration,
        library.WinHttpSetDefaultProxyConfiguration,
    ):
        assert function.restype is ctypes.c_int32
        assert function.argtypes == [ctypes.POINTER(helper._ProxyInfo)]
    assert library.WinHttpGetIEProxyConfigForCurrentUser.restype is ctypes.c_int32
    assert library.WinHttpGetIEProxyConfigForCurrentUser.argtypes == [
        ctypes.POINTER(helper._IEProxyConfig)
    ]
    loader.reset_mock()
    assert helper._kernel() is library
    loader.assert_called_once_with("kernel32", use_last_error=True)
    assert library.GlobalFree.restype is ctypes.c_void_p
    assert library.GlobalFree.argtypes == [ctypes.c_void_p]


@pytest.mark.parametrize("operation", ["get_proxy", "get_ie_proxy", "set_proxy"])
def test_operations_require_windows(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    loader = Mock()
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(helper.ctypes, "WinDLL", loader, raising=False)
    with pytest.raises(OSError, match="require a Windows target"):
        getattr(helper, operation)(*([None, None] if operation == "set_proxy" else []))
    loader.assert_not_called()


@pytest.mark.parametrize("operation", ["get_proxy", "get_ie_proxy"])
@pytest.mark.parametrize(
    "proxy,bypass",
    [(None, None), ("", ""), ("Proxy:8080", None), ("雪:80", "例;<local>")],
)
def test_reads_preserve_nullable_strings_and_free_allocations(
    helper: ModuleType,
    native: Any,
    operation: str,
    proxy: str | None,
    bypass: str | None,
) -> None:
    if operation == "get_proxy":
        reader = native.library.WinHttpGetDefaultProxyConfiguration
        names, values = ["proxy", "bypass"], [proxy, bypass]
    else:
        reader = native.library.WinHttpGetIEProxyConfigForCurrentUser
        names, values = ["auto_config_url", "proxy", "bypass"], [
            "http://pac.invalid/",
            proxy,
            bypass,
        ]
    reader.side_effect = _returned_strings(native, names, values)
    assert getattr(helper, operation)() == {"proxy": proxy, "bypass": bypass}
    assert native.kernel.GlobalFree.call_args_list == [
        call(address) for address in native.addresses
    ]
    native.library.WinHttpSetDefaultProxyConfiguration.assert_not_called()


@pytest.mark.parametrize("operation", ["get_proxy", "get_ie_proxy"])
def test_failed_read_frees_allocations_and_can_retry(
    helper: ModuleType, native: Any, operation: str
) -> None:
    if operation == "get_proxy":
        api = "WinHttpGetDefaultProxyConfiguration"
        names, values = ["proxy", "bypass"], ["old", "old-bypass"]
    else:
        api = "WinHttpGetIEProxyConfigForCurrentUser"
        names, values = ["auto_config_url", "proxy", "bypass"], [
            "pac",
            "old",
            "old-bypass",
        ]
    reader = getattr(native.library, api)
    fill = _returned_strings(native, names, values)

    def _fail(pointer: Any) -> int:
        fill(pointer)
        return 0

    reader.side_effect = _fail
    with pytest.raises(OSError) as raised:
        getattr(helper, operation)()
    assert str(raised.value) == f"{api}() failed (Access is denied, Win32ErrorCode 5)"
    assert native.kernel.GlobalFree.call_args_list == [
        call(address) for address in native.addresses
    ]
    native.kernel.GlobalFree.reset_mock()
    native.addresses.clear()
    reader.side_effect = fill
    assert getattr(helper, operation)() == {"proxy": "old", "bypass": "old-bypass"}
    assert native.kernel.GlobalFree.call_args_list == [
        call(address) for address in native.addresses
    ]


@pytest.mark.parametrize("operation", ["get_proxy", "get_ie_proxy"])
def test_decode_failure_still_frees_every_allocated_string(
    helper: ModuleType, native: Any, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    if operation == "get_proxy":
        reader = native.library.WinHttpGetDefaultProxyConfiguration
        names, values = ["proxy", "bypass"], ["proxy", "bypass"]
    else:
        reader = native.library.WinHttpGetIEProxyConfigForCurrentUser
        names, values = ["auto_config_url", "proxy", "bypass"], [
            "pac",
            "proxy",
            "bypass",
        ]
    reader.side_effect = _returned_strings(native, names, values)
    monkeypatch.setattr(
        helper.ctypes, "wstring_at", Mock(side_effect=UnicodeError("decode failed"))
    )
    with pytest.raises(UnicodeError, match="decode failed"):
        getattr(helper, operation)()
    assert native.kernel.GlobalFree.call_args_list == [
        call(address) for address in native.addresses
    ]


@pytest.mark.parametrize(
    "proxy,bypass,access",
    [
        (None, None, 1),
        ("", "ignored", 1),
        ("Proxy:8080", None, 3),
        ("Proxy:8080", "", 3),
        ("雪:80", "例;<local>", 3),
    ],
)
def test_setter_passes_live_owned_strings_without_freeing_them(
    helper: ModuleType, native: Any, proxy: str | None, bypass: str | None, access: int
) -> None:
    def _inspect(pointer: Any) -> int:
        info = pointer._obj
        assert info.access_type == access
        assert (ctypes.wstring_at(info.proxy) if info.proxy else None) == (
            proxy or None
        )
        assert (ctypes.wstring_at(info.bypass) if info.bypass else None) == (
            bypass if proxy and bypass else None
        )
        return 1

    native.library.WinHttpSetDefaultProxyConfiguration.side_effect = _inspect
    assert helper.set_proxy(proxy, bypass) is None
    native.library.WinHttpGetDefaultProxyConfiguration.assert_not_called()
    native.library.WinHttpGetIEProxyConfigForCurrentUser.assert_not_called()
    native.kernel.GlobalFree.assert_not_called()


def test_failed_set_reports_native_operation_and_can_retry(
    helper: ModuleType, native: Any
) -> None:
    writer = native.library.WinHttpSetDefaultProxyConfiguration
    writer.return_value = 0
    with pytest.raises(OSError) as raised:
        helper.set_proxy("proxy:80", "bypass")
    assert (
        str(raised.value)
        == "WinHttpSetDefaultProxyConfiguration() failed (Access is denied, Win32ErrorCode 5)"
    )
    writer.return_value = 1
    assert helper.set_proxy("proxy:80", "bypass") is None
    native.kernel.GlobalFree.assert_not_called()
