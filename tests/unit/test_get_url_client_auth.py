"""Exercise native optional client-certificate selection without Windows calls."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes verify retry boundaries, not actual TLS support.
# These tests address the private native request and callback lifetime directly.
# pylint: disable=protected-access

from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit import test_get_url_native as http_fixtures

native_download = http_fixtures.native_download
native_http = http_fixtures.native_http


@pytest.mark.parametrize("failure", [False, True])
def test_client_certificate_context_remains_owned_until_native_request_closes(
    http: Any, monkeypatch: pytest.MonkeyPatch, failure: bool
) -> None:
    helper, options, library = http
    options.update(client_cert=r"Cert:\CurrentUser\My\thumbprint")
    collection = Mock()
    collection.__enter__ = Mock(
        return_value=SimpleNamespace(
            records=[{"context": 501, "has_private_key": True}]
        )
    )
    events: list[Any] = []
    collection.__exit__ = Mock(side_effect=lambda *_args: events.append("certificate"))
    opened = Mock(return_value=collection)
    matching = Mock(side_effect=lambda records, _thumbprint: records)
    monkeypatch.setattr(helper.certificates, "open_store", opened)
    monkeypatch.setattr(helper.certificates, "matches", matching)
    close = library.WinHttpCloseHandle.side_effect

    def close_and_record(handle: int) -> bool:
        """Record the owned native close without dropping its notification.

        :param handle: Owned native handle.
        :returns: Native close success.
        """
        events.append(handle)
        return bool(close(handle))

    library.WinHttpCloseHandle.side_effect = close_and_record
    library.WinHttpSendRequest.return_value = not failure
    if failure:
        with pytest.raises(OSError, match="native failed"):
            helper._HttpResponse(options["url"], options, {})
    else:
        response = helper._HttpResponse(options["url"], options, {})
        collection.__exit__.assert_not_called()
        response.close()
    opened.assert_called_once_with("My", "CurrentUser", "system", True)
    assert any(
        entry.args[:3] == (103, 47, 501)
        for entry in library.WinHttpSetOption.call_args_list
    )
    assert events == [103, 102, 101, "certificate"]
    collection.__exit__.assert_called_once()
    assert collection.__exit__.call_args.args[-3:] == (None, None, None)


@pytest.mark.parametrize("records", [[], [{"context": 500, "has_private_key": False}]])
def test_client_certificate_file_requires_a_private_key(
    http: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    records: list[dict[str, Any]],
) -> None:
    helper, _options, _library = http
    path = tmp_path / "owned.pfx"
    path.write_bytes(b"substituted cryptographic boundary")
    collection = Mock()
    collection.__enter__ = Mock(return_value=SimpleNamespace(records=records))
    collection.__exit__ = Mock(return_value=False)
    imported = Mock(return_value=collection)
    monkeypatch.setattr(helper.certificates, "read_file", imported)
    with ExitStack() as stack:
        with pytest.raises(ValueError, match="private key|does not exist"):
            helper._client_certificate(stack, str(path), "fixture")
        collection.__exit__.assert_not_called()
    imported.assert_called_once_with(
        str(path), "fixture", True, "default", persist=False
    )
    collection.__exit__.assert_called_once()


def test_client_certificate_bundle_owns_the_selected_key_until_request_cleanup(
    http: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    helper, _options, _library = http
    path = tmp_path / "bundle.pfx"
    path.write_bytes(b"substituted cryptographic boundary")
    leaf = {"context": 501, "has_private_key": True}
    collection = Mock(
        __enter__=Mock(
            return_value=SimpleNamespace(
                records=[{"context": 500, "has_private_key": False}, leaf]
            )
        ),
        __exit__=Mock(return_value=False),
    )
    imported = Mock(return_value=collection)
    monkeypatch.setattr(helper.certificates, "read_file", imported)
    events = []
    credential = Mock(
        __enter__=Mock(return_value=601),
        __exit__=Mock(side_effect=lambda *_args: events.append("key")),
    )
    copied = Mock(return_value=credential)
    monkeypatch.setattr(helper.http_certificate, "temporary_certificate", copied)
    collection.__exit__.side_effect = lambda *_args: events.append("collection")
    with ExitStack() as stack:
        assert helper._client_certificate(stack, str(path), "fixture") == 601
        imported.assert_called_once_with(
            str(path), "fixture", True, "default", persist=False
        )
        copied.assert_called_once_with(collection.__enter__.return_value, leaf)
        credential.__exit__.assert_not_called()
        collection.__exit__.assert_not_called()
    collection.__exit__.assert_called_once()
    assert events == ["key", "collection"]


@pytest.mark.parametrize("boundary", ["WinHttpSendRequest", "WinHttpReceiveResponse"])
def test_optional_client_certificate_is_declined_once_at_either_native_boundary(
    http: Any,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    helper, options, library = http
    options.update(url="https://localhost/payload.bin", client_cert=None)
    original = helper._HttpResponse._call
    challenge = OSError(12044, "client certificate requested")
    challenged: list[bool] = []

    def _call(response: Any, operation: Any, timeout: Any, *arguments: Any) -> None:
        if operation is getattr(library, boundary) and not challenged:
            challenged.append(True)
            raise challenge
        original(response, operation, timeout, *arguments)

    monkeypatch.setattr(helper._HttpResponse, "_call", _call)
    response = helper._HttpResponse(options["url"], options, {}, body=b"owned body")
    response.close()
    assert challenged == [True]
    assert library.WinHttpSetOption.call_args_list.count(call(103, 47, None, 0)) == 1
    assert library.WinHttpSendRequest.call_count == (
        1 if boundary == "WinHttpSendRequest" else 2
    )
    assert response.body.value == b"owned body"
    assert [item.args[0] for item in library.WinHttpCloseHandle.call_args_list][
        -3:
    ] == [
        103,
        102,
        101,
    ]


@pytest.mark.parametrize(
    "code,provided", [(12044, True), (12175, False), (12002, False)]
)
def test_supplied_certificate_and_other_failures_never_trigger_anonymous_retry(
    http: Any,
    monkeypatch: pytest.MonkeyPatch,
    code: int,
    provided: bool,
) -> None:
    helper, options, library = http
    options.update(
        url="https://localhost/payload.bin",
        client_cert="owned.pfx" if provided else None,
    )
    monkeypatch.setattr(helper, "_client_certificate", Mock(return_value=501))
    failure = OSError(code, "retained native error")
    monkeypatch.setattr(helper._HttpResponse, "_call", Mock(side_effect=failure))
    with pytest.raises(OSError) as caught:
        helper._HttpResponse(options["url"], options, {})
    assert caught.value is failure
    assert call(103, 47, None, 0) not in library.WinHttpSetOption.call_args_list


def test_repeated_client_certificate_challenge_does_not_loop(
    http: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper, options, library = http
    options.update(url="https://localhost/payload.bin", client_cert=None)
    failure = OSError(12044, "client certificate requested")
    sending = Mock(side_effect=failure)
    monkeypatch.setattr(helper._HttpResponse, "_call", sending)
    with pytest.raises(OSError) as caught:
        helper._HttpResponse(options["url"], options, {})
    assert caught.value is failure
    assert sending.call_count == 2
    assert library.WinHttpSetOption.call_args_list.count(call(103, 47, None, 0)) == 1
