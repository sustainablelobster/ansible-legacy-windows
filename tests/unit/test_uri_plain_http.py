"""Exercise direct HTTP header control through real standard-library sockets."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These controller-local sockets do not establish Windows execution support.
# pylint: disable=protected-access

import base64
import json
import socket
import threading
import time
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit import test_get_url_native as get_url_fixtures
from tests.unit import test_uri_fixture as uri_fixtures

native_download = get_url_fixtures.native_download
native_http = get_url_fixtures.native_http
uri_fixture_server = uri_fixtures.uri_fixture_server


def direct_options(options: dict[str, Any], client: Any, path: str) -> dict[str, Any]:
    """Bind the maintained real fixture to the anonymous direct HTTP path.

    :param options: Fully bound module request options.
    :param client: Fixture client carrying its independent host and port.
    :param path: Owned request path.
    :returns: Direct request options without inherited proxy selection.
    """
    return dict(
        options,
        url=f"http://{client.host}:{client.port}{path}",
        use_proxy=False,
        proxy_url=None,
        follow_redirects="all",
    )


@pytest.mark.parametrize("body", [None, b"", b"fixture\x00\xff"])
def test_direct_post_preserves_caller_body_and_controls_automatic_headers(
    http: Any, server: Any, body: bytes | None
) -> None:
    helper, options = http[:2]
    client, journal = server
    options = direct_options(options, client, "/echo")
    options.update(url_method="POST", headers={"X-Fixture": "literal"})
    response = helper.open_resource(options["url"], options, [], body=body)
    try:
        content = json.loads(response.read())
        assert content["body_base64"] == base64.b64encode(body or b"").decode("ascii")
        assert content["headers"]["X-Fixture"] == "literal"
        assert content["headers"]["Connection"] == "Keep-Alive"
        assert "Accept-Encoding" not in content["headers"]
        assert ("Content-Length" in content["headers"]) is (body is not None)
        assert ("Expect" in content["headers"]) is bool(body)
        assert response.method == "POST" and response.url == options["url"]
        assert response.header(11) == "Sat, 01 Jan 2000 00:00:00 GMT"
        assert response.modified() == 946684800
    finally:
        response.close()
    assert response.connection.sock is None
    assert response.response.isclosed()
    assert len(journal.read_text().splitlines()) == 1


@pytest.mark.parametrize("status", [302, 303, 307])
@pytest.mark.parametrize(
    "method,body",
    [
        ("GET", None),
        ("HEAD", None),
        ("POST", None),
        ("POST", b""),
        ("POST", b"fixture"),
        ("PUT", None),
        ("PUT", b""),
        ("PUT", b"fixture"),
    ],
)
def test_direct_redirects_preserve_common_policy_and_literal_final_headers(
    http: Any, server: Any, status: int, method: str, body: bytes | None
) -> None:
    helper, options = http[:2]
    client, journal = server
    options = direct_options(options, client, f"/redirect/{status}")
    options["url_method"] = method
    response = helper.open_resource(options["url"], options, [], body=body)
    try:
        response.read()
        discard = body is not None and (
            status == 303 or status == 302 and method == "POST"
        )
        final_method = "GET" if discard else method
        assert response.method == final_method
        assert response.url.endswith("/echo")
    finally:
        response.close()
    requests = [json.loads(line) for line in journal.read_text().splitlines()]
    assert [row["method"] for row in requests] == [method, final_method]
    assert requests[0]["headers"]["Connection"] == "Keep-Alive"
    final = requests[1]
    assert "Connection" not in final["headers"]
    assert "Accept-Encoding" not in final["headers"]
    final_body = None if discard else body
    assert final["body_base64"] == base64.b64encode(final_body or b"").decode("ascii")
    assert ("Content-Length" in final["headers"]) is (final_body is not None)
    assert ("Expect" in final["headers"]) is bool(final_body)


@pytest.mark.parametrize(
    "overrides,plain",
    [
        ({}, True),
        ({"use_proxy": True}, False),
        ({"url": "https://example.test/payload"}, False),
        ({"url": "http://user:secret@example.test/payload"}, False),
        ({"url_username": "fixture"}, False),
        ({"use_default_credential": True}, False),
        ({"proxy_username": "fixture"}, False),
        ({"proxy_use_default_credential": True}, False),
        ({"client_cert": "C:\\fixture.pfx"}, False),
        ({"headers": {"Transfer-Encoding": "chunked"}}, False),
    ],
)
def test_direct_route_keeps_tls_proxy_and_automatic_credentials_native(
    http: Any,
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, Any],
    plain: bool,
) -> None:
    helper, options, _library = http
    options = dict(options, use_proxy=False, proxy_url=None)
    options.update(overrides)
    response = Mock(status=200)
    response.header.return_value = None
    native, standard = Mock(return_value=response), Mock(return_value=response)
    monkeypatch.setattr(helper, "_HttpResponse", native)
    monkeypatch.setattr(helper.plain_http, "PlainHttpResponse", standard)
    assert helper.open_resource(options["url"], options, []) is response
    assert standard.call_count == int(plain)
    assert native.call_count == int(not plain)
    if not plain:
        assert set(native.call_args.kwargs) == {"deadline"}
        assert len(native.call_args.args) == 4


@pytest.mark.parametrize(
    "error,message",
    [
        (
            socket.gaierror(11001, "getaddrinfo failed"),
            "The remote name could not be resolved: 'example.test'",
        ),
        (
            ConnectionRefusedError(10061, "refused"),
            "Unable to connect to the remote server",
        ),
        (socket.timeout("timeout"), "The operation has timed out"),
    ],
)
def test_direct_connection_errors_preserve_measured_source_message_and_cleanup(
    http: Any,
    monkeypatch: pytest.MonkeyPatch,
    error: OSError,
    message: str,
) -> None:
    helper, options = http[:2]
    connection = Mock(host="example.test")
    connection.connect.side_effect = error
    factory = Mock(return_value=connection)
    monkeypatch.setattr(helper.plain_http.http.client, "HTTPConnection", factory)
    with pytest.raises(OSError) as raised:
        helper.plain_http.PlainHttpResponse(options["url"], options, {}, deadline=None)
    actual = raised.value
    assert (actual.strerror or str(actual)) == message
    connection.close.assert_called_once_with()


def test_direct_header_deadline_does_not_reset_for_trickled_header_lines(
    http: Any,
) -> None:
    helper, options = http[:2]
    options = dict(options, url_method="GET")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(1)
    port = listener.getsockname()[1]

    def trickle() -> None:
        """Keep making progress while a single absolute deadline must still expire."""
        connection, _address = listener.accept()
        try:
            connection.settimeout(1)
            request = b""
            while b"\r\n\r\n" not in request:
                block = connection.recv(4096)
                if not block:
                    return
                request += block
            connection.sendall(b"HTTP/1.1 200 OK\r\n")
            for _index in range(20):
                connection.sendall(b"X-Fixture: progress\r\n")
                time.sleep(0.04)
            connection.sendall(b"Content-Length: 0\r\n\r\n")
        except OSError:
            pass  # The tested deadline deliberately closes only this socket.
        finally:
            connection.close()

    thread = threading.Thread(target=trickle)
    thread.start()
    started = time.monotonic()
    try:
        with pytest.raises(OSError) as raised:
            helper.plain_http.PlainHttpResponse(
                f"http://127.0.0.1:{port}/", options, {}, deadline=started + 0.15
            )
        assert raised.value.errno == 12002
        assert time.monotonic() - started < 0.5
    finally:
        thread.join(timeout=2)
        listener.close()
        assert not thread.is_alive()


@pytest.mark.parametrize("mode", ["http10", "close", "keep-alive"])
def test_direct_body_read_outlives_header_deadline_for_each_connection_lifetime(
    http: Any, server: Any, mode: str
) -> None:
    helper, options = http[:2]
    client, journal = server
    options = direct_options(options, client, "/slow-body/" + mode)
    options["url_method"] = "GET"
    started = time.monotonic()
    response = helper.plain_http.PlainHttpResponse(
        options["url"], options, {}, deadline=started + 0.15
    )
    try:
        assert time.monotonic() - started < 0.15
        assert (response.connection.sock is None) is (mode != "keep-alive")
        assert response.read() == b"legacy download fixture\x00\xff\n"
        assert time.monotonic() - started >= 1.3
    finally:
        response.close()
    assert response.connection.sock is None
    assert response.response.isclosed()
    assert len(journal.read_text().splitlines()) == 1


@pytest.mark.parametrize(
    "authority,expected",
    [
        ("example.test", "example.test"),
        ("example.test:80", "example.test"),
        ("example.test:8080", "example.test:8080"),
        ("[::1]", "[0000:0000:0000:0000:0000:0000:0000:0001]"),
        ("[::1]:80", "[0000:0000:0000:0000:0000:0000:0000:0001]"),
        ("[::1]:8080", "[0000:0000:0000:0000:0000:0000:0000:0001]:8080"),
    ],
)
@pytest.mark.parametrize(
    "explicit_host", [None, "caller.example:80", "[::1]:80", "[2001:db8::ABcd]:80"]
)
def test_direct_host_omits_only_the_automatic_default_port(
    http: Any,
    monkeypatch: pytest.MonkeyPatch,
    authority: str,
    expected: str,
    explicit_host: str | None,
) -> None:
    helper, options = http[:2]
    options = dict(options, url_method="GET")
    connection = Mock()
    connection.getresponse.return_value.status = 200
    connection.getresponse.return_value.reason = "OK"
    monkeypatch.setattr(
        helper.plain_http.http.client, "HTTPConnection", Mock(return_value=connection)
    )
    headers = {} if explicit_host is None else {"Host": explicit_host}
    response = helper.plain_http.PlainHttpResponse(
        "http://" + authority + "/", options, headers, deadline=None
    )
    try:
        sent = dict(call.args for call in connection.putheader.call_args_list)
        caller_hosts = {
            "[::1]:80": "[0000:0000:0000:0000:0000:0000:0000:0001]:80",
            "[2001:db8::ABcd]:80": "[2001:0DB8:0000:0000:0000:0000:0000:ABCD]:80",
        }
        assert sent["Host"] == (
            expected
            if explicit_host is None
            else caller_hosts.get(explicit_host, explicit_host)
        )
        response_authority = expected
        if explicit_host is not None:
            response_authority = caller_hosts.get(explicit_host, explicit_host)
            response_authority = response_authority.rsplit(":", 1)[0]
        assert response.url == "http://" + response_authority + "/"
    finally:
        response.close()
