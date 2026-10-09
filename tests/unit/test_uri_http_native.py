"""Test URI uploads through the existing WinHTTP ABI and redirect lifetime."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Developer-runtime native substitutes do not establish Windows support.
# pylint: disable=protected-access

import ctypes
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit import test_get_url_native as get_url_fixtures

# Reuse the maintained native ABI stand-ins with their declared fixture names.
native_download = get_url_fixtures.native_download
native_http = get_url_fixtures.native_http


@pytest.mark.parametrize(
    "body", [b"", b"fixture\x00\xff", b"a" * 65536], ids=["empty", "binary", "64KiB"]
)
def test_native_upload_buffer_exact_length_headers_and_owned_lifetime(
    http: Any, body: bytes
) -> None:
    helper, options, library = http
    options["url_method"] = "POST"
    response = helper._HttpResponse(options["url"], options, {}, body=body)
    sent = library.WinHttpSendRequest.call_args.args
    assert sent[4:6] == (len(body), len(body))
    assert ctypes.string_at(sent[3], len(body)) == body
    assert "Content-Length: " + str(len(body)) + "\r\n" in sent[1]
    assert ("Expect: 100-continue\r\n" in sent[1]) is bool(body)
    assert response.url == options["url"] and response.method == "POST"
    assert response.body is sent[3]
    response.close()
    assert ctypes.string_at(response.body, len(body)) == body
    assert [call.args[0] for call in library.WinHttpCloseHandle.call_args_list] == [
        103,
        102,
        101,
    ]


def test_upload_authentication_retry_keeps_same_native_buffer(
    http: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper, options, library = http
    options["url_method"] = "PUT"
    statuses = iter([401, 200])
    monkeypatch.setattr(
        helper._HttpResponse,
        "header",
        lambda _self, number: str(next(statuses)) if number == 19 else "fixture",
    )
    monkeypatch.setattr(helper._HttpResponse, "_authenticate", lambda *_args: True)
    response = helper._HttpResponse(options["url"], options, {}, body=b"owned upload")
    first, second = library.WinHttpSendRequest.call_args_list
    assert first.args[3] is second.args[3] is response.body
    assert first.args[4:6] == second.args[4:6] == (12, 12)
    response.close()


@pytest.mark.parametrize("method", ["POST", "PUT"])
@pytest.mark.parametrize("status", [300, 301, 302, 303, 307])
@pytest.mark.parametrize("body", [b"", b"fixture"])
def test_redirect_discards_or_replays_exact_upload_bytes(
    http: Any,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    status: int,
    body: bytes,
) -> None:
    helper, options, _library = http
    options.update(
        url_method=method, follow_redirects="all", headers={"X-Fixture": "retained"}
    )
    redirect = SimpleNamespace(
        status=status,
        message="redirect",
        header=Mock(return_value="/next"),
        close=Mock(),
    )
    final = SimpleNamespace(status=200, header=Mock(return_value=None), close=Mock())
    factory = Mock(side_effect=[redirect, final])
    monkeypatch.setattr(helper, "_HttpResponse", factory)
    assert helper.open_resource(options["url"], options, [], body=body) is final
    first, second = factory.call_args_list
    discard = status in (300, 303) or status in (301, 302) and method == "POST"
    assert first.kwargs["body"] is body
    assert ("body" not in second.kwargs) is discard
    if not discard:
        assert second.kwargs["body"] is body
    assert second.args[1]["url_method"] == ("GET" if discard else method)
    assert first.kwargs["deadline"] == second.kwargs["deadline"]
    assert first.args[2] == second.args[2] == {"X-Fixture": "retained"}
    redirect.close.assert_called_once_with()
    final.close.assert_not_called()


def test_default_http_send_has_no_upload_or_new_constructor_keywords(
    http: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper, options, library = http
    response = helper._HttpResponse(options["url"], options, {})
    assert library.WinHttpSendRequest.call_args.args[3:6] == (None, 0, 0)
    response.close()
    final = SimpleNamespace(status=200, header=Mock(return_value=None), close=Mock())
    factory = Mock(return_value=final)
    monkeypatch.setattr(helper, "_HttpResponse", factory)
    assert helper.open_resource(options["url"], options, []) is final
    assert set(factory.call_args.kwargs) == {"deadline"}


@pytest.mark.parametrize("body", ["text", bytearray(b"bytes"), 1])
def test_nonbytes_upload_is_rejected_before_native_open(
    http: Any, monkeypatch: pytest.MonkeyPatch, body: Any
) -> None:
    helper, options, _library = http
    factory = Mock()
    monkeypatch.setattr(helper, "_HttpResponse", factory)
    with pytest.raises(ValueError, match="Request body must be bytes or None"):
        helper.open_resource(options["url"], options, [], body=body)
    factory.assert_not_called()
