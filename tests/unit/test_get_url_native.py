"""Test download decisions and protocol ownership with local substitutions."""

# SPDX-License-Identifier: GPL-3.0-or-later
# This uses the developer interpreter, not a Windows compatibility proof.
# pylint: disable=protected-access

import ctypes
import hashlib
import io
import shutil
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module, load_payload


class Response:
    """Observe stream use and closure without making a network request."""

    def __init__(
        self,
        body: bytes = b"resource",
        status: int = 200,
        message: str = "OK",
        modified: float | None = None,
    ):
        self.stream = io.BytesIO(body)
        self.status, self.message, self.timestamp = status, message, modified
        self.closed = False

    def read(self, size: int = 65536) -> bytes:
        """Read the next bounded fixture block.

        :param size: Requested maximum size.
        :returns: Fixture bytes.
        """
        return self.stream.read(size)

    def modified(self) -> float | None:
        """Return the fixture's metadata timestamp.

        :returns: Timestamp or None.
        """
        return self.timestamp

    def close(self) -> None:
        """Record closure of the observed stream."""
        self.closed = True


def install_async_callbacks(helper: Any, library: Any, monkeypatch: Any) -> None:
    """Emit actual ABI completion notifications from the fake native calls.

    :param helper: Loaded Windows payload helper.
    :param library: Observed fake DLL boundary.
    :param monkeypatch: Scoped ctypes platform substitutes.
    """
    monkeypatch.setattr(helper.ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE, raising=False)
    monkeypatch.setattr(helper.ctypes, "get_last_error", lambda: 0, raising=False)
    library.callback = None

    def register(_handle: int, callback: Any, _flags: int, _context: int) -> None:
        library.callback = callback

    library.WinHttpSetStatusCallback = Mock(side_effect=register)

    def complete(operation: Any, status: int) -> Any:
        """Build the callback-emitting fake operation.

        :param operation: Observed native operation.
        :param status: Completion notification identifier.
        :returns: Callable native boundary substitute.
        """

        def call(*_arguments: Any) -> bool:
            """Emit the requested successful completion.

            :param _arguments: Native API arguments retained by the mock.
            :returns: The configured native success indicator.
            """
            if operation.return_value:
                library.callback(103, 1, status, None, 0)
            return bool(operation.return_value)

        return call

    library.WinHttpSendRequest.side_effect = complete(
        library.WinHttpSendRequest, 0x400000
    )
    library.WinHttpReceiveResponse.side_effect = complete(
        library.WinHttpReceiveResponse, 0x20000
    )

    def close(handle: int) -> bool:
        """Emit the final lifetime notification.

        :param handle: Owned native handle.
        :returns: Native close success.
        """
        if handle == 103 and library.callback is not None:
            library.callback(handle, 1, 0x800, None, 0)
        return True

    library.WinHttpCloseHandle.side_effect = close


def test_response_deadline_cancels_async_request_without_waiting_for_headers(
    http: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper, options, library = http
    options["url_timeout"] = 1
    monkeypatch.setattr(helper.time, "monotonic", Mock(side_effect=[10, 10, 12]))
    library.WinHttpReceiveResponse.side_effect = lambda *_args: True
    failure = Mock(return_value=OSError("deadline expired"))
    monkeypatch.setattr(helper, "_error", failure)
    with pytest.raises(OSError, match="deadline expired"):
        helper._HttpResponse(options["url"], options, {})
    failure.assert_called_once_with(12002)
    assert [call.args[0] for call in library.WinHttpCloseHandle.call_args_list] == [
        103,
        102,
        101,
    ]
    assert library.WinHttpOpen.call_args.args[-1] == 0x10000000


def test_async_native_error_is_copied_before_callback_memory_changes(
    http: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper, options, library = http
    native_error = helper._AsyncResult(1, 12030)

    def fail(*_arguments: Any) -> bool:
        """Report native failure using temporary callback memory.

        :param _arguments: Native response-receive arguments.
        :returns: Successful asynchronous initiation.
        """
        library.callback(
            103, 1, 0x200000, ctypes.byref(native_error), ctypes.sizeof(native_error)
        )
        native_error.error = 0
        return True

    library.WinHttpReceiveResponse.side_effect = fail
    failure = Mock(return_value=OSError("connection closed"))
    monkeypatch.setattr(helper, "_error", failure)
    with pytest.raises(OSError, match="connection closed"):
        helper._HttpResponse(options["url"], options, {})
    failure.assert_called_once_with(12030)


def test_async_read_preserves_callback_length_and_observed_eof(http: Any) -> None:
    helper, options, library = http
    response = helper._HttpResponse(options["url"], options, {})
    blocks = iter([b"abc", b""])

    def read(_handle: int, buffer: Any, _size: int, count: Any) -> bool:
        """Complete an owned asynchronous read.

        :param buffer: Caller-owned bounded read buffer.
        :param count: Unused asynchronous count pointer.
        :returns: Successful asynchronous initiation.
        """
        assert count is None
        data = next(blocks)
        ctypes.memmove(buffer, data, len(data))
        library.callback(103, 1, 0x80000, buffer, len(data))
        return True

    library.WinHttpReadData = Mock(side_effect=read)
    assert response.read(8) == b"abc"
    assert response.read(8) == b""
    response.close()


@pytest.fixture(name="native")
def native_download(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    """Substitute only networking and Windows copy; keep real hashes and files.

    :param monkeypatch: Scoped boundary substitutions.
    :param tmp_path: Owned temporary files.
    :returns: Native helper, bound parameters and observed request boundary.
    """
    module: ModuleType = load_payload("win_get_url", monkeypatch)
    helper = module.get_url
    request = Mock(return_value=Response())
    monkeypatch.setattr(helper, "open_resource", request)
    monkeypatch.setattr(
        helper.copying,
        "copy_file",
        lambda source, dest, **_opts: shutil.copy2(source, dest),
    )
    create = helper.tempfile.mkstemp
    monkeypatch.setattr(
        helper.tempfile, "mkstemp", lambda **options: create(dir=tmp_path, **options)
    )
    options = module._parameters(
        {
            "url": "http://example.test/payload.bin",
            "dest": str(tmp_path / "dest"),
            "use_proxy": False,
        }
    )
    return helper, options, request


@pytest.fixture(name="http")
def native_http(native: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Keep the actual HTTP decision tree while replacing its native DLL.

    :param native: Bound request options and file-operation substitutes.
    :param monkeypatch: Scoped WinHTTP and response-header substitutes.
    :returns: Fresh helper, options and observed native WinHTTP calls.
    """
    _helper, options, _request = native
    # This fixture explicitly exercises the WinHTTP path. Direct anonymous HTTP
    # is covered independently through real stdlib connections and wire captures.
    options = dict(options, use_proxy=True, proxy_url="http://native.proxy:8080")
    helper = load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_get_url.py",
        "tested_http_boundary",
    )
    library = SimpleNamespace(
        WinHttpOpen=Mock(return_value=101),
        WinHttpSetTimeouts=Mock(return_value=True),
        WinHttpConnect=Mock(return_value=102),
        WinHttpOpenRequest=Mock(return_value=103),
        WinHttpSetOption=Mock(return_value=True),
        WinHttpSendRequest=Mock(return_value=True),
        WinHttpReceiveResponse=Mock(return_value=True),
        WinHttpCloseHandle=Mock(return_value=True),
        WinHttpGetIEProxyConfigForCurrentUser=Mock(return_value=True),
        WinHttpGetProxyForUrl=Mock(return_value=True),
        WinHttpSetCredentials=Mock(return_value=True),
    )
    install_async_callbacks(helper, library, monkeypatch)
    monkeypatch.setattr(helper, "_winhttp", lambda: library)
    monkeypatch.setattr(helper, "_configured_secure_protocols", lambda: True)
    monkeypatch.setattr(helper, "_error", lambda *_args: OSError("native failed"))
    monkeypatch.setattr(
        helper._HttpResponse,
        "header",
        lambda _self, number: {19: "200", 20: "OK", 33: None}[number],
    )
    return helper, options, library


@pytest.mark.parametrize("algorithm", ["md5", "sha1", "sha256", "sha384", "sha512"])
def test_create_idempotence_and_exact_checksum(
    native: Any, tmp_path: Path, algorithm: str
) -> None:
    helper, options, request = native
    options["checksum_algorithm"] = algorithm
    result = helper.download(options)
    expected = hashlib.new(algorithm, b"resource").hexdigest()
    assert (
        result["changed"]
        and result["checksum_src"] == result["checksum_dest"] == expected
    )
    assert (
        result["size"] == 8 and result["status_code"] == 200 and result["msg"] == "OK"
    )
    assert request.return_value.closed
    request.return_value = Response()
    repeated = helper.download(options)
    assert not repeated["changed"] and repeated["checksum_dest"] == expected
    assert set(tmp_path.iterdir()) == {Path(options["dest"])}


@pytest.mark.parametrize("existing", [False, True])
def test_check_mode_downloads_but_preserves_destination(
    native: Any, tmp_path: Path, existing: bool
) -> None:
    helper, options, request = native
    dest = Path(options["dest"])
    if existing:
        dest.write_bytes(b"old")
    result = helper.download(options, True)
    assert (
        result["changed"]
        and result["checksum_src"] == hashlib.sha1(b"resource").hexdigest()
    )
    if existing:
        assert dest.read_bytes() == b"old"
        assert (
            result["checksum_dest"] == hashlib.sha1(b"old").hexdigest()
            and result["size"] == 3
        )
    else:
        assert (
            not dest.exists() and "checksum_dest" not in result and "size" not in result
        )
    assert request.return_value.closed and not list(tmp_path.glob("legacy-get-url-*"))


def test_matching_expected_checksum_skips_every_request(native: Any) -> None:
    helper, options, request = native
    Path(options["dest"]).write_bytes(b"resource")
    options.update(force=False, checksum=hashlib.sha1(b"resource").hexdigest())
    result = helper.download(options)
    assert result == {
        "changed": False,
        "elapsed": 0,
        "url": options["url"],
        "dest": options["dest"],
        "checksum_dest": options["checksum"],
        "size": 8,
    }
    request.assert_not_called()


@pytest.mark.parametrize("newer", [False, True])
def test_force_false_uses_head_and_only_downloads_newer_content(
    native: Any, newer: bool
) -> None:
    helper, options, request = native
    dest = Path(options["dest"])
    dest.write_bytes(b"old")
    modified = dest.stat().st_mtime + (1 if newer else -1)
    replies = [Response(modified=modified)]
    if newer:
        replies.append(Response())
    request.side_effect = replies
    options["force"] = False
    result = helper.download(options)
    assert result["changed"] == newer
    assert request.call_args_list[0].args[-1] is True
    assert all(reply.closed for reply in replies)
    assert dest.read_bytes() == (b"resource" if newer else b"old")


def test_bad_checksum_retains_partial_result_and_existing_file(
    native: Any, tmp_path: Path
) -> None:
    helper, options, request = native
    dest = Path(options["dest"])
    dest.write_bytes(b"old")
    options["checksum"] = "bad"
    result = helper.download(options)
    assert result["failed"] and not result["changed"]
    assert result["checksum_src"] == hashlib.sha1(b"resource").hexdigest()
    assert result["status_code"] == 200 and result["elapsed"] >= 0
    assert result["elapsed"] == 0
    assert "did not match 'bad'" in result["msg"]
    assert dest.read_bytes() == b"old" and request.return_value.closed
    assert not list(tmp_path.glob("legacy-get-url-*"))


def test_http_failure_keeps_status_and_removes_temporary_file(
    native: Any, tmp_path: Path
) -> None:
    helper, options, request = native
    request.return_value = Response(status=404, message="Not Found")
    result = helper.download(options)
    assert result["failed"] and not result["changed"] and result["status_code"] == 404
    assert result["msg"].endswith(
        "The remote server returned an error: (404) Not Found."
    )
    assert not Path(options["dest"]).exists() and not list(tmp_path.iterdir())
    assert request.return_value.closed


@pytest.mark.parametrize(
    "basename,record",
    [
        ("payload.bin", b"abc  ./payload.bin\n"),
        ("a[1].bin", b"abc  a[1].bin\r\n"),
        ("payload.bin", b"ABC  PAYLOAD.BIN\n"),
    ],
)
def test_checksum_record_uses_literal_basename_and_first_matching_line(
    native: Any, basename: str, record: bytes
) -> None:
    helper, _options, _request = native
    assert (
        helper._checksum_record(
            Response(body=record),
            "http://example.test/" + basename,
            "http://example.test/checksum",
        )
        == record[:3].decode()
    )


def test_uri_path_preserves_encoded_slashes_without_double_encoding(
    native: Any,
) -> None:
    helper, _options, _request = native
    assert (
        helper._uri("http://example.test/a%2fb%20c?q=a%2Fb")
        == "http://example.test/a%2fb%20c?q=a%2Fb"
    )


@pytest.mark.parametrize("failure", [False, True])
def test_http_native_handles_close_on_success_and_send_failure(
    native: Any, monkeypatch: pytest.MonkeyPatch, failure: bool
) -> None:
    helper, options, _request = native
    library = SimpleNamespace(
        WinHttpOpen=Mock(return_value=101),
        WinHttpSetTimeouts=Mock(return_value=True),
        WinHttpConnect=Mock(return_value=102),
        WinHttpOpenRequest=Mock(return_value=103),
        WinHttpSetOption=Mock(return_value=True),
        WinHttpSendRequest=Mock(return_value=not failure),
        WinHttpReceiveResponse=Mock(return_value=True),
        WinHttpCloseHandle=Mock(return_value=True),
    )
    install_async_callbacks(helper, library, monkeypatch)
    monkeypatch.setattr(helper, "_winhttp", lambda: library)
    monkeypatch.setattr(helper, "_error", lambda *_args: OSError("send failed"))
    monkeypatch.setattr(
        helper._HttpResponse,
        "header",
        lambda _self, number: {19: "200", 20: "OK"}[number],
    )
    if failure:
        with pytest.raises(OSError, match="send failed"):
            helper._HttpResponse(options["url"], options, {})
    else:
        response = helper._HttpResponse(options["url"], options, {})
        assert response.status == 200 and response.message == "OK"
        response.close()
    assert [call.args[0] for call in library.WinHttpCloseHandle.call_args_list] == [
        103,
        102,
        101,
    ]
    assert library.WinHttpOpenRequest.call_args.args[-1] == 0


@pytest.mark.parametrize("mode,expected", [(False, 2), (True, 1)])
def test_http_default_credential_policy_uses_the_requested_native_level(
    native: Any, monkeypatch: pytest.MonkeyPatch, mode: bool, expected: int
) -> None:
    helper, options, _request = native
    options["use_default_credential"] = mode
    library = SimpleNamespace(
        WinHttpOpen=Mock(return_value=101),
        WinHttpSetTimeouts=Mock(return_value=True),
        WinHttpConnect=Mock(return_value=102),
        WinHttpOpenRequest=Mock(return_value=103),
        WinHttpSetOption=Mock(return_value=True),
        WinHttpSendRequest=Mock(return_value=True),
        WinHttpReceiveResponse=Mock(return_value=True),
        WinHttpCloseHandle=Mock(return_value=True),
    )
    install_async_callbacks(helper, library, monkeypatch)
    values = []

    def set_option(handle: int, number: int, pointer: Any, size: int) -> bool:
        """Copy caller-owned DWORD options before the temporary disappears.

        :param handle: Native request handle.
        :param number: Option identifier.
        :param pointer: Address of the temporary native DWORD.
        :param size: DWORD byte size.
        :returns: Native-success substitute.
        """
        assert handle == 103 and size == (
            ctypes.sizeof(ctypes.c_size_t) if number == 45 else 4
        )
        values.append(
            (number, ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32))[0])
        )
        return True

    library.WinHttpSetOption.side_effect = set_option
    monkeypatch.setattr(helper, "_winhttp", lambda: library)
    monkeypatch.setattr(
        helper._HttpResponse,
        "header",
        lambda _self, number: {19: "200", 20: "OK"}[number],
    )
    response = helper._HttpResponse(options["url"], options, {})
    response.close()
    assert (77, expected) in values
    assert (63, 3 if mode else 7) in values


@pytest.mark.parametrize("previous_elapsed", [0, 4.25])
def test_immediate_module_failure_preserves_already_serialized_elapsed(
    native: Any, monkeypatch: pytest.MonkeyPatch, previous_elapsed: float
) -> None:
    helper, options, request = native
    clock = Mock(side_effect=[10, 99])
    monkeypatch.setattr(helper.time, "time", clock)
    result = {"elapsed": previous_elapsed}
    callback = Mock(side_effect=helper._ModuleFailure("immediate failure"))
    with pytest.raises(helper._ModuleFailure, match="immediate failure"):
        helper._response(result, options["url"], options, [], callback)
    assert result == {"elapsed": previous_elapsed, "msg": "OK", "status_code": 200}
    assert request.return_value.closed
    clock.assert_called_once_with()


@pytest.mark.parametrize("error", [OSError("callback IO"), ValueError("callback data")])
def test_callback_failure_closes_response_and_records_completed_elapsed(
    native: Any, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    helper, options, request = native
    monkeypatch.setattr(helper.time, "time", Mock(side_effect=[10, 12.5]))
    result: dict[str, Any] = {"elapsed": 0}
    with pytest.raises(type(error), match=str(error)):
        helper._response(result, options["url"], options, [], Mock(side_effect=error))
    assert request.return_value.closed
    assert result == {"elapsed": 2.5, "msg": "OK", "status_code": 200}


@pytest.mark.parametrize("previous_status", [None, 200])
def test_open_failure_returns_null_status_and_elapsed_without_callback(
    native: Any, monkeypatch: pytest.MonkeyPatch, previous_status: int | None
) -> None:
    helper, options, request = native
    request.side_effect = OSError("open failed")
    monkeypatch.setattr(helper.time, "time", Mock(side_effect=[10, 13]))
    callback = Mock()
    result: dict[str, Any] = {"elapsed": 0, "status_code": previous_status}
    with pytest.raises(OSError, match="open failed"):
        helper._response(result, options["url"], options, [], callback)
    assert result == {"elapsed": 3, "status_code": None}
    callback.assert_not_called()


@pytest.mark.parametrize("failure", ["read", "copy"])
def test_download_failure_closes_response_removes_temporary_and_preserves_dest(
    native: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str
) -> None:
    helper, options, request = native
    destination = Path(options["dest"])
    destination.write_bytes(b"protected original")
    if failure == "read":
        request.return_value.read = Mock(
            side_effect=[b"partial", OSError("read failed")]
        )
    else:
        monkeypatch.setattr(
            helper.copying, "copy_file", Mock(side_effect=OSError("copy failed"))
        )
    result = helper.download(options)
    assert result["failed"] and not result["changed"]
    assert failure + " failed" in result["msg"]
    assert result["status_code"] == 200
    assert request.return_value.closed
    assert destination.read_bytes() == b"protected original"
    assert set(tmp_path.iterdir()) == {destination}


@pytest.mark.parametrize(
    ("operation", "closed"),
    [
        ("WinHttpSetTimeouts", [103, 102, 101]),
        ("WinHttpConnect", [101]),
        ("WinHttpOpenRequest", [102, 101]),
        ("WinHttpSetOption", [103, 102, 101]),
        ("WinHttpReceiveResponse", [103, 102, 101]),
    ],
)
def test_partial_http_construction_closes_every_acquired_handle(
    http: Any, operation: str, closed: list[int]
) -> None:
    helper, options, library = http
    getattr(library, operation).return_value = 0
    with pytest.raises(OSError, match="native failed"):
        helper._HttpResponse(options["url"], options, {})
    assert [
        entry.args[0] for entry in library.WinHttpCloseHandle.call_args_list
    ] == closed


@pytest.mark.parametrize("timeout", [7, 30])
def test_http_timeout_is_configured_in_milliseconds_for_every_native_phase(
    http: Any, timeout: int
) -> None:
    helper, options, library = http
    options["url_timeout"] = timeout
    values: list[tuple[int, int]] = []

    def _option(_handle: int, number: int, pointer: Any, _size: int) -> bool:
        values.append(
            (number, ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32))[0])
        )
        return True

    library.WinHttpSetOption.side_effect = _option
    response = helper._HttpResponse(
        "https://example.test:9443/a?q=b#fragment", options, {}
    )
    response.close()
    library.WinHttpSetTimeouts.assert_called_once_with(103, *([timeout * 1000] * 4))
    library.WinHttpConnect.assert_called_once_with(101, "example.test", 9443, 0)
    library.WinHttpOpenRequest.assert_called_once_with(
        102, "GET", "/a?q=b", None, None, None, 0x800000
    )
    assert [value for number, value in values if number == 7] == (
        [timeout * 1000] if timeout else []
    )


@pytest.mark.parametrize("credentials", [False, True])
def test_redirect_credentials_flag_disables_authentication_at_native_boundary(
    http: Any, credentials: bool
) -> None:
    helper, options, library = http
    options.update(url_username="fixture", url_password="secret", force_basic_auth=True)
    values: list[tuple[int, int]] = []

    def _option(_handle: int, number: int, pointer: Any, _size: int) -> bool:
        values.append(
            (number, ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32))[0])
        )
        return True

    library.WinHttpSetOption.side_effect = _option
    response = helper._HttpResponse(options["url"], options, {}, credentials)
    response.close()
    assert (63, 3 if credentials else 7) in values
    headers = library.WinHttpSendRequest.call_args.args[1]
    assert headers == (
        "Authorization: Basic Zml4dHVyZTpzZWNyZXQ=\r\n" if credentials else ""
    )


def test_default_credentials_take_precedence_over_forced_basic_header(
    http: Any,
) -> None:
    helper, options, library = http
    options.update(
        url_username="fixture",
        url_password="secret",
        force_basic_auth=True,
        use_default_credential=True,
    )
    response = helper._HttpResponse(options["url"], options, {})
    response.close()
    assert library.WinHttpSendRequest.call_args.args[1] == ""


@pytest.mark.parametrize(
    "error", [OSError("Location query failed"), KeyboardInterrupt()]
)
def test_location_header_failure_closes_constructed_response_native_handles(
    http: Any, monkeypatch: pytest.MonkeyPatch, error: BaseException
) -> None:
    helper, options, library = http

    def _header(_response: Any, number: int) -> str:
        if number == 33:
            raise error
        return {19: "200", 20: "OK"}[number]

    monkeypatch.setattr(helper._HttpResponse, "header", _header)
    with pytest.raises(type(error)):
        helper.open_resource(options["url"], options, [])
    assert [entry.args[0] for entry in library.WinHttpCloseHandle.call_args_list] == [
        103,
        102,
        101,
    ]


def test_redirects_drop_server_credentials_and_authorization_at_every_hop(
    http: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper, options, _library = http
    options.update(
        url_username="fixture-user",
        url_password="fixture-secret",
        use_default_credential=True,
        force_basic_auth=True,
        headers={"aUtHoRiZaTiOn": "Bearer private", "X-Keep": "visible"},
    )
    responses = [Response(status=302), Response(status=307), Response()]
    for response, location in zip(
        responses, ["/second", "https://other.test/third", None]
    ):
        monkeypatch.setattr(
            response, "header", Mock(return_value=location), raising=False
        )
    factory = Mock(side_effect=responses)
    monkeypatch.setattr(helper, "_HttpResponse", factory)
    result = helper.open_resource(options["url"], options, [])
    assert result is responses[-1]
    assert [entry.args[0] for entry in factory.call_args_list] == [
        options["url"],
        "http://example.test/second",
        "https://other.test/third",
    ]
    assert [entry.args[3] for entry in factory.call_args_list] == [True, False, False]
    assert factory.call_args_list[0].args[2] == options["headers"]
    for entry in factory.call_args_list[1:]:
        assert entry.args[2] == {"X-Keep": "visible"}
        assert entry.args[1]["url_username"] == "fixture-user"
    assert all(response.closed for response in responses[:-1])
    assert not result.closed
    assert options["headers"]["aUtHoRiZaTiOn"] == "Bearer private"
    result.close()


@pytest.mark.parametrize(
    "case",
    [
        ("none", "GET", 50, False, False),
        ("safe", "GET", 50, False, True),
        ("safe", "POST", 50, False, False),
        ("all", "POST", 50, False, True),
        ("safe", "POST", 50, True, True),
        ("all", "GET", 0, False, False),
    ],
)
def test_redirect_policy_uses_effective_method_and_zero_limit(
    http: Any,
    monkeypatch: pytest.MonkeyPatch,
    case: tuple[str, str, int, bool, bool],
) -> None:
    helper, options, _library = http
    policy, method, limit, timestamp, follows = case
    options.update(
        follow_redirects=policy, url_method=method, maximum_redirection=limit
    )
    redirect, final = Response(status=302), Response()
    monkeypatch.setattr(redirect, "header", Mock(return_value="/next"), raising=False)
    monkeypatch.setattr(final, "header", Mock(return_value=None), raising=False)
    factory = Mock(side_effect=[redirect, final])
    monkeypatch.setattr(helper, "_HttpResponse", factory)
    result = helper.open_resource(options["url"], options, [], timestamp)
    assert factory.call_count == (2 if follows else 1)
    assert factory.call_args_list[0].args[1]["url_method"] == (
        "HEAD" if timestamp else method
    )
    assert result is (final if follows else redirect)
    assert redirect.closed == follows
    result.close()


def test_redirect_limit_failure_closes_every_received_response(
    http: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper, options, _library = http
    options["maximum_redirection"] = 1
    responses = [Response(status=302), Response(status=302)]
    for response in responses:
        monkeypatch.setattr(
            response, "header", Mock(return_value="/next"), raising=False
        )
    factory = Mock(side_effect=responses)
    monkeypatch.setattr(helper, "_HttpResponse", factory)
    monkeypatch.setattr(helper.time, "time", Mock(side_effect=[10, 12]))
    result = {"elapsed": 0, "status_code": 200}
    callback = Mock()
    with pytest.raises(OSError, match="Too many automatic redirections"):
        helper._response(result, options["url"], options, [], callback)
    assert factory.call_count == 2 and all(response.closed for response in responses)
    assert result == {"elapsed": 2, "status_code": 302}
    callback.assert_not_called()


@pytest.mark.parametrize("status", [300, 301, 302, 303, 307])
@pytest.mark.parametrize("method", ["GET", "HEAD", "POST"])
def test_released_redirect_statuses_preserve_bodyless_methods(
    http: Any, monkeypatch: pytest.MonkeyPatch, status: int, method: str
) -> None:
    helper, options, _library = http
    options.update(follow_redirects="all", url_method=method)
    responses = [Response(status=status), Response()]
    for response, location in zip(responses, ["/next", None]):
        monkeypatch.setattr(
            response, "header", Mock(return_value=location), raising=False
        )
    factory = Mock(side_effect=responses)
    monkeypatch.setattr(helper, "_HttpResponse", factory)
    result = helper.open_resource(options["url"], options, [])
    assert result is responses[-1] and responses[0].closed
    assert [entry.args[1]["url_method"] for entry in factory.call_args_list] == [
        method,
        method,
    ]
    assert (
        factory.call_args_list[0].kwargs["deadline"]
        == factory.call_args_list[1].kwargs["deadline"]
    )
    result.close()


@pytest.mark.parametrize(
    "status,location,expected_reason",
    [(305, "/next", "Use Proxy Redirect"), (308, "/next", ""), (302, None, "Redirect")],
)
def test_automatic_redirect_failures_preserve_status_and_close_response(
    http: Any,
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    location: str | None,
    expected_reason: str,
) -> None:
    helper, options, _library = http
    reason = "" if status == 308 else "fixture reason"
    response = Response(status=status, message=reason)
    monkeypatch.setattr(response, "header", Mock(return_value=location), raising=False)
    factory = Mock(return_value=response)
    monkeypatch.setattr(helper, "_HttpResponse", factory)
    result = {"elapsed": 0}
    with pytest.raises(OSError, match="The remote server returned an error") as caught:
        helper._response(result, options["url"], options, [], Mock())
    suffix = f" {expected_reason}" if expected_reason else ""
    assert (
        str(caught.value) == f"The remote server returned an error: ({status}){suffix}."
    )
    assert result["status_code"] == status
    assert response.closed and factory.call_count == 1


def test_expired_shared_deadline_does_not_send_another_request(
    http: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper, options, library = http
    monkeypatch.setattr(helper.time, "monotonic", Mock(return_value=12))
    monkeypatch.setattr(
        helper, "_error", Mock(return_value=OSError("deadline expired"))
    )
    with pytest.raises(OSError, match="deadline expired"):
        helper._HttpResponse(options["url"], options, {}, deadline=11)
    library.WinHttpSendRequest.assert_not_called()
    assert [entry.args[0] for entry in library.WinHttpCloseHandle.call_args_list] == [
        103,
        102,
        101,
    ]


@pytest.mark.parametrize("proxy", [False, True])
def test_explicit_proxy_is_request_local_and_disabled_proxy_skips_discovery(
    http: Any, proxy: bool
) -> None:
    helper, options, library = http
    options.update(use_proxy=proxy, proxy_url="http://proxy.test:8080")
    observed = []

    def _set_option(_handle: int, number: int, pointer: Any, _size: int) -> bool:
        if number == 38:
            info = ctypes.cast(pointer, ctypes.POINTER(helper._ProxyInfo)).contents
            observed.append(
                (
                    info.access_type,
                    ctypes.wstring_at(info.proxy),
                    ctypes.wstring_at(info.bypass),
                )
            )
        return True

    library.WinHttpSetOption.side_effect = _set_option
    response = helper._HttpResponse(options["url"], options, {})
    response.close()
    assert observed == ([(3, "proxy.test:8080", "<local>")] if proxy else [])
    library.WinHttpGetIEProxyConfigForCurrentUser.assert_not_called()
    library.WinHttpGetProxyForUrl.assert_not_called()


@pytest.mark.parametrize("automatic", [False, True])
def test_default_proxy_falls_back_to_static_and_releases_allocated_strings(
    http: Any, monkeypatch: pytest.MonkeyPatch, automatic: bool
) -> None:
    helper, options, library = http
    options.update(use_proxy=True, proxy_url=None, proxy_use_default_credential=True)
    buffers = [ctypes.create_unicode_buffer(text) for text in ("static:8080", "bypass")]
    observed: list[tuple[int, str, str]] = []

    def _configuration(pointer: Any) -> bool:
        config = ctypes.cast(pointer, ctypes.POINTER(helper._IEProxyConfig)).contents
        config.auto_detect = automatic
        config.proxy = ctypes.cast(buffers[0], ctypes.c_void_p).value
        config.bypass = ctypes.cast(buffers[1], ctypes.c_void_p).value
        return True

    def _automatic(_session: int, _url: str, pointer: Any, _info: Any) -> bool:
        value = ctypes.cast(pointer, ctypes.POINTER(helper._AutoProxyOptions)).contents
        assert value.flags == 1 and value.detect_flags == 3 and value.auto_logon
        return False

    def _option(_handle: int, number: int, pointer: Any, _size: int) -> bool:
        if number == 38:
            info = ctypes.cast(pointer, ctypes.POINTER(helper._ProxyInfo)).contents
            observed.append(
                (
                    info.access_type,
                    ctypes.wstring_at(info.proxy),
                    ctypes.wstring_at(info.bypass),
                )
            )
        return True

    freed = Mock()
    monkeypatch.setattr(helper, "_free_strings", freed)
    monkeypatch.setattr(helper.ctypes, "get_last_error", lambda: 12180, raising=False)
    library.WinHttpGetIEProxyConfigForCurrentUser.side_effect = _configuration
    library.WinHttpGetProxyForUrl.side_effect = _automatic
    library.WinHttpSetOption.side_effect = _option
    response = helper._HttpResponse(options["url"], options, {})
    response.close()
    assert observed == [(3, "static:8080", "bypass")]
    assert library.WinHttpGetProxyForUrl.call_count == int(automatic)
    assert [entry.args[1] for entry in freed.call_args_list] == (
        [("proxy", "bypass")] if automatic else []
    ) + [("proxy", "bypass", "auto_config_url")]


def test_proxy_native_allocation_free_skips_null_fields(
    http: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper, _options, _library = http
    kernel = SimpleNamespace(GlobalFree=Mock())
    monkeypatch.setattr(
        helper.ctypes, "WinDLL", Mock(return_value=kernel), raising=False
    )
    config = helper._IEProxyConfig(0, 303, 301, None)
    helper._free_strings(config, ("proxy", "bypass", "auto_config_url"))
    assert [entry.args[0] for entry in kernel.GlobalFree.call_args_list] == [301, 303]
