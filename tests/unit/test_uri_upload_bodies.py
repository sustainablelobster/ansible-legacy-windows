"""Exercise URI uploads and their owned FTP stream lifetime locally."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These developer-runtime tests do not establish Windows target compatibility.
# pylint: disable=protected-access

import ftplib
import io
import socket
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import load_payload


@pytest.fixture(name="upload")
def upload_boundary(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Keep URI serialization and response handling around an observed socket.

    :param monkeypatch: Scoped FTP client substitution.
    :returns: Payload, public options, control client and upload socket.
    """
    payload = load_payload("win_uri", monkeypatch)
    data = SimpleNamespace(close=Mock(), settimeout=Mock(), sendall=Mock())
    client = SimpleNamespace(
        cwd=Mock(return_value="250 Directory changed"),
        connect=Mock(return_value="220 Fixture ready"),
        login=Mock(return_value="230 Logged in"),
        voidcmd=Mock(return_value="200 Binary mode"),
        transfercmd=Mock(return_value=data),
        voidresp=Mock(return_value="226 Transfer complete"),
        close=Mock(),
        response="150 Open data connection",
    )
    monkeypatch.setattr(payload.uri.web.ftp, "_FtpClient", Mock(return_value=client))
    options = payload._parameters(
        {
            "url": "ftp://example.test/upload.bin",
            "method": "STOR",
            "body": "upload 中😀\n",
            "status_code": [226],
            "return_content": True,
            "use_proxy": False,
        }
    )
    return SimpleNamespace(payload=payload, options=options, client=client, data=data)


@pytest.mark.parametrize("method", ["STOR", "STOU", "APPE"])
@pytest.mark.parametrize("body", ["upload 中😀\n", ""])
@pytest.mark.parametrize("check", [False, True])
def test_public_upload_sends_exact_utf8_and_retains_final_reply(
    upload: Any, method: str, body: str, check: bool
) -> None:
    upload.options.update(url_method=method, body=body)
    result = upload.payload.uri.request(upload.options, check)
    assert not result.get("failed") and not result["changed"]
    assert result["status_code"] == 226
    assert result["status_description"] == "226 Transfer complete\r\n"
    assert result["content"] == "" and result["content_length"] == 0
    expected = body.encode("utf-8")
    assert (
        b"".join(call.args[0] for call in upload.data.sendall.call_args_list)
        == expected
    )
    upload.data.settimeout.assert_called_once_with(300)
    upload.data.close.assert_called_once_with()
    upload.client.voidresp.assert_called_once_with()
    upload.client.close.assert_called_once_with()
    upload.client.transfercmd.assert_called_once_with(
        "STOU" if method == "STOU" else method + " /upload.bin"
    )


def test_large_body_is_sent_in_bounded_chunks_before_final_reply(upload: Any) -> None:
    body = b"a" * 65536 + b"b" * 65536 + b"tail"
    events = []
    upload.data.sendall.side_effect = lambda data: events.append(("send", data))
    upload.data.close.side_effect = lambda: events.append(("close", None))

    def final_reply() -> str:
        """Record the control read.

        :returns: Successful final FTP reply.
        """
        events.append(("reply", None))
        return "226 Transfer complete"

    upload.client.voidresp.side_effect = final_reply
    response = upload.payload.uri.web.open_resource(
        upload.options["url"], upload.options, [], body=body
    )
    assert events == [
        ("send", b"a" * 65536),
        ("send", b"b" * 65536),
        ("send", b"tail"),
        ("close", None),
        ("reply", None),
    ]
    assert response.read() == b""
    response.close()
    upload.client.close.assert_called_once_with()


@pytest.mark.parametrize("method", ["RETR", "LIST", "NLST", "DELE", "PWD"])
def test_nonupload_ftp_body_fails_before_connecting(upload: Any, method: str) -> None:
    upload.options["url_method"] = method
    result = upload.payload.uri.request(upload.options)
    assert result["failed"] and not result["changed"]
    assert "FTP request bodies require STOR, STOU or APPE" in result["msg"]
    upload.client.connect.assert_not_called()
    upload.data.sendall.assert_not_called()


def test_upload_denied_before_stream_has_no_response_metadata(upload: Any) -> None:
    upload.client.transfercmd.side_effect = ftplib.error_perm("550 Upload denied")
    result = upload.payload.uri.request(upload.options)
    assert result["failed"] and result["status_code"] is None
    assert "550" in result["msg"] and "content_length" not in result
    upload.data.sendall.assert_not_called()
    upload.client.close.assert_called_once_with()


@pytest.mark.parametrize("stage", ["connect", "login"])
@pytest.mark.parametrize("body", ["upload 中😀", ""])
def test_connection_and_login_errors_cannot_be_accepted_as_uploads(
    upload: Any,
    stage: str,
    body: str,
) -> None:
    upload.options.update(body=body, status_code=[530])
    getattr(upload.client, stage).side_effect = ftplib.error_perm(
        "530 Incorrect credentials"
    )
    result = upload.payload.uri.request(upload.options)
    assert result["failed"] and not result["changed"]
    assert result["status_code"] is None and "530" in result["msg"]
    assert "content_length" not in result and "status_description" not in result
    upload.client.transfercmd.assert_not_called()
    upload.data.sendall.assert_not_called()
    upload.client.close.assert_called_once_with()


def test_bodyless_login_error_retains_accepted_response(upload: Any) -> None:
    upload.options.update(body=None, status_code=[530])
    upload.client.login.side_effect = ftplib.error_perm("530 Incorrect credentials")
    result = upload.payload.uri.request(upload.options)
    assert not result.get("failed") and result["status_code"] == 530
    assert result["content"] == "" and result["content_length"] == 0
    upload.client.transfercmd.assert_not_called()
    assert upload.client.close.call_count == 2


def test_unique_upload_uses_directory_and_parameterless_command(upload: Any) -> None:
    upload.options.update(url="ftp://example.test/owned/", url_method="STOU")
    result = upload.payload.uri.request(upload.options)
    assert not result.get("failed")
    upload.client.cwd.assert_called_once_with("/owned/")
    upload.client.transfercmd.assert_called_once_with("STOU")


@pytest.mark.parametrize(
    "failure", [socket.timeout("upload timed out"), OSError("connection reset")]
)
def test_partial_send_failure_closes_both_connections(
    upload: Any, failure: OSError
) -> None:
    upload.options["body"] = "a" * 65537
    upload.data.sendall.side_effect = [None, failure]
    result = upload.payload.uri.request(upload.options)
    assert result["failed"] and not result["changed"]
    assert str(failure) in result["msg"]
    assert upload.data.sendall.call_count == 2
    upload.data.close.assert_called_once_with()
    upload.client.close.assert_called_once_with()
    upload.client.voidresp.assert_not_called()


def test_final_protocol_failure_retains_response_after_upload(upload: Any) -> None:
    upload.client.voidresp.side_effect = ftplib.error_temp("426 Transfer interrupted")
    result = upload.payload.uri.request(upload.options)
    assert result["failed"] and not result["changed"]
    assert result["status_code"] == 426
    assert result["status_description"] == "426 Transfer interrupted\r\n"
    assert upload.data.sendall.call_args.args == ("upload 中😀\n".encode("utf-8"),)
    upload.data.close.assert_called_once_with()
    assert upload.client.close.call_count == 2


def test_existing_no_body_upload_still_closes_without_sending(upload: Any) -> None:
    upload.options["body"] = None
    result = upload.payload.uri.request(upload.options)
    assert result["status_code"] == 226 and not result.get("failed")
    upload.data.sendall.assert_not_called()
    upload.data.settimeout.assert_not_called()
    upload.data.close.assert_called_once_with()


def test_download_stream_behavior_is_unchanged(upload: Any) -> None:
    upload.options.update(body=None, url_method="RETR", status_code=[226])
    upload.data.makefile = Mock(return_value=io.BytesIO(b"download"))
    result = upload.payload.uri.request(upload.options)
    assert result["content"] == "download" and not result.get("failed")
    assert result["status_code"] == 150
    upload.data.sendall.assert_not_called()
    upload.client.voidresp.assert_called_once_with()
    upload.data.close.assert_called_once_with()


@pytest.mark.parametrize(
    "file_upload",
    [
        (method, body)
        for method in ("PUT", "POST", "DELETE")
        for body in ("upload 中😀", "")
    ],
)
@pytest.mark.parametrize("check", [False, True])
def test_file_upload_rejects_without_replacing_existing_bytes(
    upload: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    file_upload: tuple[str, str],
    check: bool,
) -> None:
    method, body = file_upload
    path = tmp_path / "upload.bin"
    path.write_bytes(b"baseline")
    monkeypatch.setattr(upload.payload.uri.web, "_file_path", lambda _url: str(path))
    upload.options.update(url="file:///C:/upload.bin", url_method=method, body=body)
    result = upload.payload.uri.request(upload.options, check)
    assert path.read_bytes() == b"baseline"
    assert result["failed"] and not result["changed"]
    assert result["elapsed"] == 0 and "status_code" not in result
    assert "file:// requests with a body are not supported" in result["msg"]


@pytest.mark.parametrize("body", ["new 中😀", ""])
@pytest.mark.parametrize("check", [False, True])
def test_file_upload_rejects_without_creating_a_resource(
    upload: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    body: str,
    *,
    check: bool,
) -> None:
    path = tmp_path / "new.bin"
    monkeypatch.setattr(upload.payload.uri.web, "_file_path", lambda _url: str(path))
    upload.options.update(
        url="file:///C:/new.bin", url_method="PUT", body=body, status_code=[0]
    )
    result = upload.payload.uri.request(upload.options, check)
    assert result["failed"] and not result["changed"]
    assert not path.exists()
    assert "use win_copy" in result["msg"]


@pytest.mark.parametrize("method", ["GET", "HEAD", "CONNECT"])
def test_file_read_method_body_rejects_before_replacing_resource(
    upload: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
) -> None:
    path = tmp_path / "upload.bin"
    path.write_bytes(b"baseline")
    monkeypatch.setattr(upload.payload.uri.web, "_file_path", lambda _url: str(path))
    upload.options.update(
        url="file:///C:/upload.bin", url_method=method, body="rejected"
    )
    result = upload.payload.uri.request(upload.options)
    assert result["failed"] and "file:// requests with a body" in result["msg"]
    assert path.read_bytes() == b"baseline"


def test_file_read_without_body_keeps_existing_stream_and_length(
    upload: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "upload.bin"
    path.write_bytes(b"baseline")
    monkeypatch.setattr(upload.payload.uri.web, "_file_path", lambda _url: str(path))
    upload.options.update(url="file:///C:/upload.bin", url_method="HEAD", body=None)
    result = upload.payload.uri.request(upload.options)
    assert result["failed"] and result["content_length"] == "8"
    assert result["content"] == "baseline" and path.read_bytes() == b"baseline"
