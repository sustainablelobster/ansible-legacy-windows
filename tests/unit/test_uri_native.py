"""Test URI response projection, files and failures without Windows access."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These developer-runtime substitutions do not prove Windows compatibility.
# pylint: disable=protected-access

import datetime
import io
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import load_payload


class Response:
    """Retain observable response bytes and stream ownership."""

    def __init__(
        self, body: bytes = b"fixture", status: int = 200, message: str = "OK"
    ):
        self.stream = io.BytesIO(body)
        self.status, self.message = status, message
        self.closed = False
        self.raw = (
            f"HTTP/1.1 {status} {message}\r\nServer: fixture\r\n"
            "Date: Sat, 01 Jan 2000 00:00:00 GMT\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Last-Modified: Sat, 01 Jan 2000 00:00:00 GMT\r\n\r\n"
        )

    def header(self, number: int) -> str:
        """Return the captured raw header block.

        :param number: Native query number.
        :returns: Raw response header text.
        """
        assert number == 22
        return self.raw

    def read(self, size: int = 65536) -> bytes:
        """Read bounded fixture bytes.

        :param size: Maximum byte count.
        :returns: Next bytes, or empty bytes at EOF.
        """
        return self.stream.read(size)

    def close(self) -> None:
        """Record release of the owned stream."""
        self.closed = True


@pytest.fixture(name="native")
def uri_native(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Keep real URI behavior while substituting the native request boundary.

    :param monkeypatch: Scoped native-boundary substitutions.
    :returns: URI helper, bound options and observed response factory.
    """
    payload = load_payload("win_uri", monkeypatch)
    options = payload._parameters({"url": "http://example.test/a", "use_proxy": False})
    request = Mock(return_value=Response())
    monkeypatch.setattr(payload.uri.web, "open_resource", request)
    return SimpleNamespace(helper=payload.uri, options=options, request=request)


def test_full_http_properties_header_types_and_order(native: Any) -> None:
    result = native.helper.request(native.options)
    elapsed = result.pop("elapsed")
    assert isinstance(elapsed, float) and elapsed >= 0
    assert result == {
        "changed": False,
        "url": "http://example.test/a",
        "msg": "OK",
        "status_code": 200,
        "character_set": "",
        "content_encoding": "",
        "content_length": "7",
        "content_type": "application/octet-stream",
        "cookies": [],
        "headers": [
            "Content-Length",
            "Content-Type",
            "Date",
            "Last-Modified",
            "Server",
        ],
        "is_from_cache": False,
        "is_mutually_authenticated": False,
        "last_modified": "Sat, 01 Jan 2000 00:00:00 GMT",
        "method": "GET",
        "protocol_version": {
            "Major": 1,
            "Minor": 1,
            "Build": -1,
            "Revision": -1,
            "MajorRevision": -1,
            "MinorRevision": -1,
        },
        "response_uri": "http://example.test/a",
        "server": "fixture",
        "status_description": "OK",
        "supports_headers": True,
        "date": "Sat, 01 Jan 2000 00:00:00 GMT",
    }
    assert native.request.return_value.closed
    assert native.request.return_value.stream.tell() == 0


def test_duplicate_custom_headers_and_promoted_header_names(native: Any) -> None:
    native.request.return_value.raw += (
        "X-Test-Value: first\r\nx-test-value: second\r\n"
        "ETag: fixture\r\nSet-Cookie: item=value\r\n"
    )
    result = native.helper.request(native.options)
    assert result["headers"] == [
        "X-Test-Value",
        "Content-Length",
        "Content-Type",
        "Date",
        "ETag",
        "Last-Modified",
        "Set-Cookie",
        "Server",
    ]
    assert result["x_test_value"] == "first,second"
    assert result["e_tag"] == "fixture" and result["set_cookie"] == "item=value"
    assert result["cookies"] == []


@pytest.mark.parametrize(
    "body,returned",
    [
        (b"null", False),
        (b"false", False),
        (b"0", False),
        (b"[]", False),
        (b"{}", True),
        (b'""', False),
        (b"[false]", False),
        (b"[7]", True),
        (b"[null,false]", True),
        (b"{oops", False),
    ],
)
def test_json_truthiness_and_invalid_content(
    native: Any, body: bytes, returned: bool
) -> None:
    response = Response(body)
    response.raw = response.raw.replace(
        "application/octet-stream", "application/json; charset=utf-8"
    )
    native.request.return_value = response
    native.options["return_content"] = True
    result = native.helper.request(native.options)
    assert result["content"] == body.decode("utf-8")
    assert ("json" in result) is returned
    assert response.closed


def test_content_decodes_as_utf8_regardless_of_declared_character_set(
    native: Any,
) -> None:
    response = Response(b"fixture\x00\xff\n")
    response.raw = response.raw.replace(
        "application/octet-stream", "text/plain; charset=iso-8859-1"
    )
    native.request.return_value = response
    native.options["return_content"] = True
    result = native.helper.request(native.options)
    assert result["character_set"] == "iso-8859-1"
    assert result["content"] == "fixture\x00\ufffd\n"


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("existing", [False, True])
def test_destination_write_check_mode_and_idempotence(
    native: Any, tmp_path: Path, check: bool, existing: bool
) -> None:
    destination = tmp_path / "result.bin"
    if existing:
        destination.write_bytes(b"fixture")
    native.options["dest"] = str(destination)
    result = native.helper.request(native.options, check)
    assert result["changed"] is not existing
    assert destination.exists() is (existing or not check)
    if destination.exists():
        assert destination.read_bytes() == b"fixture"
    assert native.request.return_value.closed


def test_destination_is_written_before_unaccepted_status_failure(
    native: Any, tmp_path: Path
) -> None:
    native.request.return_value = Response(b"failure body", 404, "Not Found")
    destination = tmp_path / "result.bin"
    native.options.update(dest=str(destination), return_content=True)
    result = native.helper.request(native.options)
    assert result["changed"] and result["failed"]
    assert result["elapsed"] == 0 and result["status_code"] == 404
    assert (
        result["content"] == "failure body"
        and destination.read_bytes() == b"failure body"
    )
    assert (
        result["msg"]
        == "Status code of request '404' is not in list of valid status codes 200 : NotFound'."
    )
    assert native.request.return_value.closed


@pytest.mark.parametrize(
    "status,name",
    [
        (100, "Continue"),
        (101, "SwitchingProtocols"),
        (200, "OK"),
        (201, "Created"),
        (202, "Accepted"),
        (203, "NonAuthoritativeInformation"),
        (204, "NoContent"),
        (205, "ResetContent"),
        (206, "PartialContent"),
        (300, "MultipleChoices"),
        (301, "MovedPermanently"),
        (302, "Redirect"),
        (303, "SeeOther"),
        (304, "NotModified"),
        (305, "UseProxy"),
        (306, "Unused"),
        (307, "TemporaryRedirect"),
        (400, "BadRequest"),
        (401, "Unauthorized"),
        (402, "PaymentRequired"),
        (403, "Forbidden"),
        (404, "NotFound"),
        (405, "MethodNotAllowed"),
        (406, "NotAcceptable"),
        (407, "ProxyAuthenticationRequired"),
        (408, "RequestTimeout"),
        (409, "Conflict"),
        (410, "Gone"),
        (411, "LengthRequired"),
        (412, "PreconditionFailed"),
        (413, "RequestEntityTooLarge"),
        (414, "RequestUriTooLong"),
        (415, "UnsupportedMediaType"),
        (416, "RequestedRangeNotSatisfiable"),
        (417, "ExpectationFailed"),
        (426, "UpgradeRequired"),
        (500, "InternalServerError"),
        (501, "NotImplemented"),
        (502, "BadGateway"),
        (503, "ServiceUnavailable"),
        (504, "GatewayTimeout"),
        (505, "HttpVersionNotSupported"),
        (102, "102"),
        (103, "103"),
        (207, "207"),
        (208, "208"),
        (226, "226"),
        (308, "308"),
        (418, "418"),
        (421, "421"),
        (425, "425"),
        (451, "451"),
        (599, "599"),
        (-1, "-1"),
    ],
)
def test_unaccepted_status_uses_released_enum_not_wire_reason(
    native: Any, status: int, name: str
) -> None:
    response = Response(b"retained response", status, "unrelated wire reason")
    native.request.return_value = response
    native.options.update(status_code=[999], return_content=True)
    result = native.helper.request(native.options)
    assert result["failed"] is True and result["changed"] is False
    assert result["status_code"] == status and result["elapsed"] == 0
    assert result["status_description"] == "unrelated wire reason"
    assert result["content"] == "retained response"
    assert result["msg"] == (
        f"Status code of request '{status}' is not in list of valid "
        f"status codes 999 : {name}'."
    )
    assert response.closed and response.stream.tell() == len(b"retained response")


def test_accepted_partial_content_preserves_wire_description(native: Any) -> None:
    response = Response(b"partial bytes", 206, "Partial Content")
    native.request.return_value = response
    native.options.update(status_code=[206], return_content=True)
    result = native.helper.request(native.options)
    assert result.get("failed", False) is False
    assert result["msg"] == result["status_description"] == "Partial Content"
    assert result["content"] == "partial bytes" and result["status_code"] == 206
    assert response.closed


class FtpResponseFixture:
    """Expose raw FTP replies without an HTTP header query."""

    timestamp = None

    def __init__(self, status: int = 150):
        self.status = status
        self.content_length = -1 if status in (125, 150) else 0
        self.message = f"{status} Preliminary reply\r\n"
        self.banner_message = "220 First line\n220 Second line"
        self.welcome_message = "230 Logged in"
        self.stream = io.BytesIO(b"fixture\x00\xff\n")
        self.closed = False

    def read(self, size: int = 65536) -> bytes:
        """Read bytes and expose the final control reply at EOF.

        :param size: Maximum data bytes.
        :returns: Data, or empty bytes after updating the final status.
        """
        data = self.stream.read(size)
        if not data and self.status in (125, 150):
            self.status, self.message = 226, "226 Transfer complete\r\n"
        return data

    def close(self) -> None:
        """Record exact response ownership release."""
        self.closed = True


@pytest.mark.parametrize("preliminary", [125, 150])
@pytest.mark.parametrize("read_content", [False, True])
def test_ftp_properties_and_final_membership_keep_preliminary_public_status(
    native: Any, preliminary: int, read_content: bool
) -> None:
    response = FtpResponseFixture(preliminary)
    native.request.return_value = response
    native.options.update(
        url="ftp://example.test/resource",
        url_method="RETR",
        status_code=[226 if read_content else preliminary],
        return_content=read_content,
    )
    result = native.helper.request(native.options)
    elapsed = result.pop("elapsed")
    assert isinstance(elapsed, float) and elapsed >= 0
    expected = {
        "changed": False,
        "url": "ftp://example.test/resource",
        "msg": f"{preliminary} Preliminary reply\r\n",
        "status_code": preliminary,
        "banner_message": "220 First line\r\n220 Second line\r\n",
        "welcome_message": "230 Logged in\r\n",
        "exit_message": "",
        "content_length": -1,
        "content_type": None,
        "headers": [],
        "is_from_cache": False,
        "is_mutually_authenticated": False,
        "last_modified": "0001-01-01T00:00:00.0000000",
        "response_uri": "ftp://example.test/resource",
        "status_description": f"{preliminary} Preliminary reply\r\n",
        "supports_headers": True,
    }
    if read_content:
        expected["content"] = "fixture\x00\ufffd\n"
    assert result == expected
    assert response.closed
    assert response.stream.tell() == (10 if read_content else 0)


@pytest.mark.parametrize("preliminary", [125, 150])
@pytest.mark.parametrize("read_content", [False, True])
def test_ftp_advertised_length_survives_consumption(
    native: Any, preliminary: int, read_content: bool
) -> None:
    response = FtpResponseFixture(preliminary)
    response.content_length = 10
    response.message = f"{preliminary} Transfer starting. (10 bytes).\r\n"
    native.request.return_value = response
    native.options.update(
        url="ftp://example.test/resource",
        url_method="RETR",
        status_code=[226 if read_content else preliminary],
        return_content=read_content,
    )
    result = native.helper.request(native.options)
    assert not result.get("failed", False)
    assert result["content_length"] == 10 and result["status_code"] == preliminary
    assert (
        result["status_description"]
        == f"{preliminary} Transfer starting. (10 bytes).\r\n"
    )
    assert ("content" in result) is read_content
    assert response.closed and response.content_length == 10
    assert response.status == (226 if read_content else preliminary)


def test_ftp_unaccepted_final_status_retains_content_and_preliminary_fields(
    native: Any,
) -> None:
    response = FtpResponseFixture()
    native.request.return_value = response
    native.options.update(
        url="ftp://example.test/resource", url_method="RETR", return_content=True
    )
    result = native.helper.request(native.options)
    assert result["failed"] is True and result["elapsed"] == 0
    assert result["status_code"] == 150
    assert result["status_description"] == "150 Preliminary reply\r\n"
    assert result["content"] == "fixture\x00\ufffd\n"
    assert result["msg"] == (
        "Status code of request '226' is not in list of valid "
        "status codes 200 : ClosingData'."
    )
    assert response.closed


def test_ftp_retains_existing_connect_login_replies_without_extra_commands(
    native: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = SimpleNamespace(
        connect=Mock(return_value="220 Banner"),
        login=Mock(return_value="230 Welcome"),
        sendcmd=Mock(return_value='257 "/"'),
        close=Mock(),
    )
    monkeypatch.setattr(native.helper.web.ftp, "_FtpClient", Mock(return_value=client))
    response = native.helper.web.ftp.FtpResponse(
        "ftp://example.test/path", dict(native.options, url_method="PWD")
    )
    assert response.banner_message == "220 Banner"
    assert response.welcome_message == "230 Welcome"
    client.connect.assert_called_once_with("example.test", 21, 30)
    client.login.assert_called_once_with("anonymous", "")
    client.sendcmd.assert_called_once_with("PWD")
    response.close()
    client.close.assert_called_once_with()


@pytest.mark.parametrize(
    "method,status,message",
    [
        ("MDTM", 213, "213 20000101000000\r\n"),
        ("PWD", 257, '257 "/" is the current directory.\r\n'),
    ],
)
def test_ftp_empty_response_content_and_metadata(
    native: Any,
    method: str,
    status: int,
    message: str,
) -> None:
    response = FtpResponseFixture(status)
    response.message = message
    response.stream = io.BytesIO()
    native.request.return_value = response
    native.options.update(
        url="ftp://example.test/resource",
        url_method=method,
        status_code=[status],
        return_content=True,
    )
    result = native.helper.request(native.options)
    assert result["content"] == "" and result["content_length"] == 0
    assert result["status_description"] == message and result["status_code"] == status
    assert result["content_type"] is None and result["headers"] == []
    assert response.closed


def test_ftp_timestamp_uses_offset_at_metadata_date(
    native: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The actual datetime arithmetic is retained; substitute only timezone
    # conversion so the controller's own zone cannot establish Windows evidence.
    observed = SimpleNamespace(
        fromtimestamp=Mock(return_value=datetime.datetime(1999, 12, 31, 16)),
        utcfromtimestamp=Mock(return_value=datetime.datetime(2000, 1, 1)),
    )
    monkeypatch.setattr(native.helper, "datetime", SimpleNamespace(datetime=observed))
    assert native.helper._ftp_last_modified(946684800) == (
        "1999-12-31T16:00:00.0000000-08:00"
    )
    observed.fromtimestamp.assert_called_once_with(946684800)
    observed.utcfromtimestamp.assert_called_once_with(946684800)
    assert native.helper._ftp_last_modified(None) == "0001-01-01T00:00:00.0000000"


@pytest.mark.parametrize("method", ["GET", "HEAD", "CONNECT"])
@pytest.mark.parametrize("body", ["", False, [], {}])
def test_disallowed_body_failure_has_no_status_and_zero_elapsed(
    native: Any, method: str, body: Any
) -> None:
    native.options.update(url_method=method, body=body)
    result = native.helper.request(native.options)
    assert result == {
        "changed": False,
        "elapsed": 0,
        "url": "http://example.test/a",
        "failed": True,
        "msg": (
            "Unhandled exception occurred when sending web request. Exception: "
            'Exception calling "GetRequestStream" with "0" argument(s): '
            '"Cannot send a content-body with this verb-type."'
        ),
    }
    native.request.assert_not_called()


@pytest.mark.parametrize(
    "body,expected",
    [
        (None, None),
        (False, b"False"),
        (0, b"0"),
        ("", b""),
        ({"key": "<>&'"}, b'{"key":"<>&\'"}'),
        ([7, False, None, "<>&"], b'[7,false,null,"<>&"]'),
    ],
)
def test_request_body_serialization(
    native: Any, body: Any, expected: bytes | None
) -> None:
    assert native.helper._body(body) == expected


def test_content_type_override_and_upload_body_use_existing_http_boundary(
    native: Any,
) -> None:
    native.options.update(
        url_method="post",
        body="fixture",
        content_type="application/custom",
        headers={"content-type": "ignored", "X-Fixture": "value"},
    )
    result = native.helper.request(native.options)
    assert not result.get("failed", False)
    args, kwargs = native.request.call_args
    assert args[1]["url_method"] == "POST"
    assert args[1]["headers"] == {
        "Content-Type": "application/custom",
        "X-Fixture": "value",
    }
    assert kwargs == {"body": b"fixture"}


@pytest.mark.parametrize("name,exists", [("creates", True), ("removes", False)])
def test_skip_precedes_uri_setup(
    native: Any, tmp_path: Path, name: str, exists: bool
) -> None:
    path = tmp_path / "marker"
    if exists:
        path.mkdir()
    native.options.update(url="invalid-uri", **{name: str(path)})
    result = native.helper.request(native.options)
    assert result["skipped"] and result["elapsed"] == 0
    assert result["url"] == "invalid-uri" and not result["changed"]
    native.request.assert_not_called()


def test_invalid_method_is_rejected_before_creates_skip(
    native: Any, tmp_path: Path
) -> None:
    native.options.update(url_method="GET SPACE", creates=str(tmp_path))
    result = native.helper.request(native.options)
    assert result["failed"] and result["elapsed"] == 0
    assert "skipped" not in result
    native.request.assert_not_called()


def test_final_redirect_method_and_uri_are_projected(native: Any) -> None:
    native.request.return_value.url = "http://example.test/final"
    native.request.return_value.method = "GET"
    native.options["url_method"] = "POST"
    result = native.helper.request(native.options)
    assert result["url"] == "http://example.test/a"
    assert (
        result["response_uri"] == "http://example.test/final"
        and result["method"] == "GET"
    )


@pytest.mark.parametrize("accepted", [[200], [0], [0, 200, 404], []])
def test_file_response_keeps_public_200_but_missing_status_always_fails(
    native: Any, tmp_path: Path, accepted: list[int]
) -> None:
    path = tmp_path / "source.bin"
    path.write_bytes(b"fixture")
    native.request.return_value = native.helper.web._FileResponse(str(path))
    native.options.update(
        url="file:///C:/source.bin", return_content=True, status_code=accepted
    )
    result = native.helper.request(native.options)
    assert result["failed"] and result["elapsed"] == 0
    assert result["status_code"] == 200 and result["content_length"] == "7"
    assert result["msg"] == (
        "Status code of request '0' is not in list of valid status codes "
        + " ".join(map(str, accepted))
        + " : '."
    )
    assert "method" not in result and "status_description" not in result
    assert native.request.return_value.stream.closed


@pytest.mark.parametrize("status", [530, 550])
@pytest.mark.parametrize("accepted", [False, True])
@pytest.mark.parametrize("check", [False, True])
def test_ftp_failed_response_uses_complete_public_projection_and_membership(
    native: Any,
    status: int,
    accepted: bool,
    check: bool,
) -> None:
    response = FtpResponseFixture(status)
    response.stream = io.BytesIO()
    response.message = str(status) + " Original server reason\r\n"
    if status == 530:
        response.welcome_message = ""
    error: Any = OSError("Preserved GetURL protocol error")
    error.response = response
    native.request.side_effect = error
    native.options.update(
        url="ftp://example.test/resource",
        url_method="RETR",
        status_code=[status if accepted else 226],
        return_content=True,
    )
    result = native.helper.request(native.options, check)
    assert bool(result.get("failed", False)) is not accepted
    assert (
        result["status_code"] == status
        and result["status_description"] == response.message
    )
    assert result["content"] == "" and result["content_length"] == 0
    assert result["content_type"] is None and result["headers"] == []
    assert result["banner_message"] == "220 First line\r\n220 Second line\r\n"
    assert result["welcome_message"] == ("" if status == 530 else "230 Logged in\r\n")
    assert result["changed"] is False and response.closed
    if accepted:
        assert result["msg"] == response.message
        assert isinstance(result["elapsed"], float) and result["elapsed"] >= 0
    else:
        assert isinstance(result["elapsed"], int) and result["elapsed"] == 0
        assert "Unhandled exception" not in result["msg"]


def test_http_error_cannot_be_reinterpreted_as_an_ftp_response(native: Any) -> None:
    error: Any = OSError("HTTP transport failure")
    error.response = FtpResponseFixture(550)
    native.request.side_effect = error
    result = native.helper.request(native.options)
    assert result["failed"] is True
    assert result["msg"].endswith("HTTP transport failure")
    assert "banner_message" not in result and "content_length" not in result
