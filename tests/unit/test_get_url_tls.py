"""Exercise native TLS capability selection and diagnostic lifetime locally."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutions are controller evidence, not Windows execution proof.
# pylint: disable=protected-access

import ctypes
import threading
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module, native_error

# Reuse the observed WinHTTP boundary without duplicating its request lifecycle.
# pylint: disable=unused-import
from tests.unit.test_get_url_native import native_download, native_http

# pylint: enable=unused-import


@pytest.mark.parametrize("code", [0x80090326, -2146893018])
def test_high_bit_native_errors_preserve_the_hresult_without_format_overflow(
    native: Any, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    helper, _options, _request = native
    errors = load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_get_url.py",
        "tested_hresult_errors",
    )
    formatted: list[int] = []

    def format_error(value: int) -> str:
        """Model Python 3.4's signed native argument.

        :param value: Native signed long passed to FormatError.
        :returns: The Windows message for the supplied HRESULT.
        :raises OverflowError: If the unsigned integer cannot fit in a C long.
        """
        if not -(2**31) <= value < 2**31:
            raise OverflowError("Python int too large to convert to C long")
        formatted.append(value)
        return "The message received was unexpected or badly formatted.\r\n"

    monkeypatch.setattr(helper.ctypes, "FormatError", format_error, raising=False)
    error = errors._error(code)
    assert formatted == [-2146893018]
    assert error.errno == 0x80090326
    assert error.strerror == (
        "The message received was unexpected or badly formatted "
        "(Windows error 2148074278 / 0x80090326)"
    )


def protocol_boundary(
    http: Any, monkeypatch: pytest.MonkeyPatch, supported: set[int]
) -> tuple[list[tuple[int, int]], list[str]]:
    """Observe unconnected capability probes and the owned protocol option.

    :param http: Maintained native response fixture.
    :param monkeypatch: Scoped native error substitutions.
    :param supported: Protocol bits accepted by the probe session.
    :returns: Written handle/mask pairs and native operation sequence.
    """
    helper, _options, library = http
    writes: list[tuple[int, int]] = []
    operations: list[str] = []
    last_error = [0]
    library.WinHttpOpen.side_effect = [101, 104]
    native_close = library.WinHttpCloseHandle.side_effect

    def write(handle: int, option: int, pointer: Any, size: int) -> bool:
        """Supply native acceptance only for the observed TLS option.

        :param handle: Session or request handle.
        :param option: Native option identifier.
        :param pointer: Caller-owned option DWORD.
        :param size: Input byte count.
        :returns: Whether the capability is accepted.
        """
        if option != 84:
            return True
        assert handle in (101, 104) and size == 4
        value = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32))[0]
        writes.append((handle, value))
        operations.append("write")
        last_error[0] = 87 if handle == 104 and value not in supported else 0
        return not last_error[0]

    def close(handle: int) -> bool:
        """Observe probe lifetime while retaining request-close completion.

        :param handle: Owned native handle.
        :returns: Native close success.
        """
        if handle == 104:
            operations.append("probe close")
        return bool(native_close(handle))

    library.WinHttpSetOption.side_effect = write
    library.WinHttpCloseHandle.side_effect = close

    def connect(*_arguments: Any) -> int:
        """Record the point at which a request's child handle is created.

        :param _arguments: Native connection arguments.
        :returns: Owned connection handle.
        """
        operations.append("connect")
        return 102

    library.WinHttpConnect.side_effect = connect
    monkeypatch.setattr(helper, "_configured_secure_protocols", lambda: False)
    monkeypatch.setattr(helper.ctypes, "get_last_error", lambda: last_error[0])
    monkeypatch.setattr(helper, "_error", native_error)
    return writes, operations


@pytest.mark.parametrize(
    "supported,expected",
    [
        ({0x2000, 0x800, 0x200}, [(104, 0x2000)]),
        ({0x800, 0x200}, [(104, 0x2000), (104, 0x800), (104, 0x200), (101, 0xAA0)]),
        ({0x800}, [(104, 0x2000), (104, 0x800), (104, 0x200), (101, 0x8A0)]),
        ({0x200}, [(104, 0x2000), (104, 0x800), (104, 0x200), (101, 0x2A0)]),
        (set(), [(104, 0x2000), (104, 0x800), (104, 0x200)]),
    ],
)
def test_https_probes_capabilities_without_overwriting_current_native_defaults(
    http: Any,
    monkeypatch: pytest.MonkeyPatch,
    supported: set[int],
    expected: list[tuple[int, int]],
) -> None:
    helper, options, library = http
    writes, operations = protocol_boundary(http, monkeypatch, supported)
    response = helper._HttpResponse("https://example.test/payload", options, {})
    response.close()
    assert writes == expected
    assert operations.index("probe close") < operations.index("connect")
    assert all(call.args[0] != 104 for call in library.WinHttpConnect.call_args_list)
    assert [call.args[0] for call in library.WinHttpCloseHandle.call_args_list] == [
        104,
        103,
        102,
        101,
    ]
    assert library.WinHttpOpen.call_args.args[-1] == 0


@pytest.mark.parametrize("url", ["http://example.test", "https://example.test"])
def test_explicit_policy_and_plain_http_do_not_probe_or_modify_protocols(
    http: Any, url: str
) -> None:
    helper, options, library = http
    response = helper._HttpResponse(url, options, {})
    response.close()
    library.WinHttpOpen.assert_called_once()
    assert all(call.args[1] != 84 for call in library.WinHttpSetOption.call_args_list)


@pytest.mark.parametrize("code", [87, 12009, 5, 6, 12175])
def test_protocol_probe_ignores_only_established_unsupported_errors_and_closes(
    http: Any, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    helper, options, library = http
    protocol_boundary(http, monkeypatch, set())
    native_write = library.WinHttpSetOption.side_effect

    def fail(*arguments: Any) -> bool:
        """Fail probe option calls, leaving other native boundaries unchanged.

        :param arguments: Native option arguments.
        :returns: Whether the option was accepted.
        """
        return bool(native_write(*arguments)) if arguments[1] != 84 else False

    library.WinHttpSetOption.side_effect = fail
    monkeypatch.setattr(helper.ctypes, "get_last_error", lambda: code)
    if code in (87, 12009):
        response = helper._HttpResponse("https://example.test", options, {})
        response.close()
        library.WinHttpConnect.assert_called_once()
    else:
        with pytest.raises(OSError) as caught:
            helper._HttpResponse("https://example.test", options, {})
        assert caught.value.errno == code
        library.WinHttpConnect.assert_not_called()
        assert [call.args[0] for call in library.WinHttpCloseHandle.call_args_list] == [
            104,
            101,
        ]


@pytest.mark.parametrize("code", [2, 3, 5])
def test_native_registry_policy_read_ignores_only_missing_key_or_value(
    native: Any, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    helper, _options, _request = native
    key = Mock(__enter__=Mock(return_value=501), __exit__=Mock(return_value=False))
    registry = SimpleNamespace(
        HKEY_LOCAL_MACHINE=123,
        KEY_READ=456,
        OpenKey=Mock(return_value=key),
        QueryValueEx=Mock(side_effect=OSError(code, "registry failure")),
    )
    monkeypatch.setattr(helper, "winreg", registry)
    if code in (2, 3):
        assert not helper._configured_secure_protocols()
    else:
        with pytest.raises(OSError) as caught:
            helper._configured_secure_protocols()
        assert caught.value.errno == code
    registry.OpenKey.assert_called_once_with(
        123,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp",
        0,
        456,
    )
    registry.QueryValueEx.assert_called_once_with(501, "DefaultSecureProtocols")
    key.__exit__.assert_called_once()


@pytest.mark.parametrize("value", [0, 0x80, 0x800, 0x2800])
def test_native_registry_policy_presence_is_respected_even_without_new_tls(
    native: Any, monkeypatch: pytest.MonkeyPatch, value: int
) -> None:
    helper, _options, _request = native
    registry = SimpleNamespace(
        HKEY_LOCAL_MACHINE=123,
        KEY_READ=456,
        OpenKey=Mock(
            return_value=Mock(
                __enter__=Mock(return_value=501), __exit__=Mock(return_value=False)
            )
        ),
        QueryValueEx=Mock(return_value=(value, 4)),
    )
    monkeypatch.setattr(helper, "winreg", registry)
    assert helper._configured_secure_protocols()


def test_secure_failure_notification_copies_flags_without_completing_a_request(
    http: Any,
) -> None:
    helper, _options, _library = http
    response = helper._HttpResponse.__new__(helper._HttpResponse)
    response.ready = threading.Event()
    response.secure_failure = 0
    flags = ctypes.c_uint32(0x80000008)
    response._notify(103, 1, 0x10000, ctypes.byref(flags), ctypes.sizeof(flags))
    flags.value = 0
    assert response.secure_failure == 0x80000008
    assert not response.ready.is_set()
    response._notify(103, 1, 0x10000, None, 0)
    assert response.secure_failure == 0x80000008


@pytest.mark.parametrize("asynchronous", [False, True])
def test_secure_failure_reasons_reach_both_native_error_paths_and_cleanup(
    http: Any, monkeypatch: pytest.MonkeyPatch, asynchronous: bool
) -> None:
    helper, options, library = http
    errors = load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_get_url.py",
        "tested_tls_errors",
    )
    monkeypatch.setattr(helper, "_error", errors._error)
    monkeypatch.setattr(helper.ctypes, "get_last_error", lambda: 12175)

    def fail(*_arguments: Any) -> bool:
        """Emit secure details, then the actual native request failure.

        :param _arguments: Native send arguments.
        :returns: Whether asynchronous initiation succeeded.
        """
        flags = ctypes.c_uint32(0x80000008)
        library.callback(103, 1, 0x10000, ctypes.byref(flags), 4)
        flags.value = 0
        if asynchronous:
            error = helper._AsyncResult(1, 12175)
            library.callback(
                103, 1, 0x200000, ctypes.byref(error), ctypes.sizeof(error)
            )
        return asynchronous

    library.WinHttpSendRequest.side_effect = fail
    with pytest.raises(OSError) as caught:
        helper._HttpResponse("https://example.test", options, {})
    assert caught.value.errno == 12175
    assert caught.value.strerror == (
        "Could not establish the SSL/TLS secure connection (WinHTTP 12175): "
        "untrusted certificate authority; secure-channel error "
        "(WinHTTP flags 0x80000008)"
    )
    assert library.WinHttpSetStatusCallback.call_args.args[2] & 0x10000
    library.WinHttpSendRequest.assert_called_once()
    library.WinHttpReceiveResponse.assert_not_called()
    assert [call.args[0] for call in library.WinHttpCloseHandle.call_args_list] == [
        103,
        102,
        101,
    ]
