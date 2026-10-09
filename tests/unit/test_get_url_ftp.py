"""Exercise FTP reply fidelity, credentials, streaming and owned recovery."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Controller substitutions are not a Windows target compatibility proof.
# pylint: disable=protected-access

import ftplib
import hashlib
import io
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import load_payload


@pytest.fixture(name="ftp")
def ftp_boundary(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    """Keep real download decisions and files, replacing the FTP connection.

    :param monkeypatch: Scoped protocol and native-copy substitutions.
    :param tmp_path: Owned destination and temporary-file directory.
    :returns: Helper, options, observed control connection and data socket.
    """
    module = load_payload("win_get_url", monkeypatch)
    helper = module.get_url
    socket = SimpleNamespace(
        makefile=Mock(return_value=io.BytesIO(b"resource")),
        settimeout=Mock(),
        close=Mock(),
    )
    client = SimpleNamespace(
        cwd=Mock(return_value="250 Directory changed"),
        connect=Mock(),
        login=Mock(),
        close=Mock(),
        voidcmd=Mock(return_value="200 Binary mode"),
        sendcmd=Mock(return_value="213 20000101000000"),
        transfercmd=Mock(return_value=socket),
        voidresp=Mock(return_value="226 Transfer complete"),
        response="150 File status okay. About to open data connection.",
    )
    monkeypatch.setattr(helper.ftp, "_FtpClient", Mock(return_value=client))
    # Separate protocol fixtures keep their own file boundary; sharing these
    # substitutions would couple otherwise independent HTTP and FTP setups.
    # pylint: disable=duplicate-code
    monkeypatch.setattr(
        helper.copying,
        "copy_file",
        lambda source, dest, **_opts: shutil.copy2(source, dest),
    )
    create = helper.tempfile.mkstemp
    monkeypatch.setattr(
        helper.tempfile, "mkstemp", lambda **opts: create(dir=tmp_path, **opts)
    )
    # pylint: enable=duplicate-code
    options = module._parameters(
        {
            "url": "ftp://example.test/payload.bin",
            "dest": str(tmp_path / "dest"),
            "use_proxy": False,
            "url_timeout": 10,
        }
    )
    return helper, options, client, socket


@pytest.mark.parametrize("status", [125, 150])
def test_download_retains_complete_preliminary_reply_not_final_reply(
    ftp: Any, tmp_path: Path, status: int
) -> None:
    helper, options, client, socket = ftp
    client.response = str(status) + " First line\n" + str(status) + " Second line"
    result = helper.download(options)
    assert result["changed"] and not result.get("failed")
    assert result["status_code"] == status
    assert result["msg"] == (
        str(status) + " First line\r\n" + str(status) + " Second line\r\n"
    )
    assert (
        result["checksum_src"]
        == result["checksum_dest"]
        == hashlib.sha1(b"resource").hexdigest()
    )
    assert result["size"] == 8
    client.transfercmd.assert_called_once_with("RETR /payload.bin")
    socket.settimeout.assert_called_once_with(300)
    client.voidresp.assert_called_once_with()
    socket.close.assert_called_once_with()
    client.close.assert_called_once_with()
    assert {path.name for path in tmp_path.iterdir()} == {"dest"}


@pytest.mark.parametrize(
    "reply,expected",
    [
        ("150 Resource (26 bytes).", 26),
        ("125 Resource (  26\t bytes).", 26),
        ("150 Resource (00026 bytes).", 26),
        ("150 Resource (0 bytes).", 0),
        ("150 Resource (9223372036854775807 bytes).", 9223372036854775807),
        ("150 Resource (9223372036854775808 bytes).", -1),
        ("150 Resource (-26 bytes).", -1),
        ("150 Resource (+26 bytes).", -1),
        ("150 Resource (２６ bytes).", -1),
        ("150 Resource (26 Bytes).", -1),
        ("150 Resource (26 bytes)", -1),
        ("150 Resource (26 bytes). later (ignored)", -1),
        ("150 Resource (wrong bytes). later (26 bytes).", -1),
        ("150 Resource ( bytes).", -1),
        ("150 Resource", -1),
    ],
)
def test_preliminary_length_uses_exact_unsigned_int64_reply_grammar(
    ftp: Any,
    reply: str,
    expected: int,
) -> None:
    helper, _options, _client, _socket = ftp
    assert helper.ftp._preliminary_length(reply) == expected


@pytest.mark.parametrize("status", [125, 150])
def test_preliminary_length_survives_consumption_without_extra_commands(
    ftp: Any,
    status: int,
) -> None:
    helper, options, client, socket = ftp
    client.response = str(status) + " Resource (8 bytes)."
    response = helper.ftp.FtpResponse(options["url"], options)
    assert response.status == status and response.content_length == 8
    assert response.read() == b"resource" and response.read() == b""
    assert response.status == 226 and response.content_length == 8
    response.close()
    client.transfercmd.assert_called_once_with("RETR /payload.bin")
    client.voidcmd.assert_called_once_with("TYPE I")
    client.sendcmd.assert_not_called()
    client.voidresp.assert_called_once_with()
    socket.close.assert_called_once_with()
    client.close.assert_called_once_with()


@pytest.mark.parametrize("check", [False, True])
def test_check_and_idempotence_keep_existing_content(ftp: Any, check: bool) -> None:
    helper, options, client, _socket = ftp
    dest = Path(options["dest"])
    original = b"old" if check else b"resource"
    dest.write_bytes(original)
    result = helper.download(options, check)
    assert result["changed"] == check
    assert dest.read_bytes() == original
    assert result["checksum_dest"] == hashlib.sha1(original).hexdigest()
    assert result["checksum_src"] == hashlib.sha1(b"resource").hexdigest()
    client.close.assert_called_once_with()


def test_mdtm_returns_full_reply_and_utc_timestamp(ftp: Any) -> None:
    helper, options, client, socket = ftp
    response = helper.ftp.FtpResponse(options["url"], options, True)
    assert response.status == 213 and response.message == "213 20000101000000\r\n"
    assert response.modified() == 946684800
    assert response.read() == b""
    response.close()
    client.sendcmd.assert_called_once_with("MDTM /payload.bin")
    client.transfercmd.assert_not_called()
    socket.close.assert_not_called()
    client.close.assert_called_once_with()


@pytest.mark.parametrize("metadata", [False, True])
@pytest.mark.parametrize("status", [530, 550])
def test_protocol_failure_retains_partial_status_and_owned_files(
    ftp: Any, metadata: bool, status: int, tmp_path: Path
) -> None:
    helper, options, client, socket = ftp
    dest = Path(options["dest"])
    dest.write_bytes(b"old")
    options["force"] = not metadata
    failure = ftplib.error_perm(str(status) + " Server-specific description")
    if status == 530:
        client.login.side_effect = failure
    elif metadata:
        client.sendcmd.side_effect = failure
    else:
        client.transfercmd.side_effect = failure
    result = helper.download(options)
    expected = (
        "Not logged in"
        if status == 530
        else "File unavailable (e.g., file not found, no access)"
    )
    prefix = (
        "Error when requesting 'Last-Modified' date from '" + options["url"] + "'. "
        if metadata
        else "Error downloading '" + options["url"] + "' to '" + options["dest"] + "': "
    )
    assert (
        result["msg"]
        == prefix + f"The remote server returned an error: ({status}) {expected}."
    )
    assert (
        result["status_code"] == status and result["failed"] and not result["changed"]
    )
    assert result["elapsed"] >= 0
    assert "checksum_dest" not in result and "checksum_src" not in result
    assert dest.read_bytes() == b"old"
    assert {path.name for path in tmp_path.iterdir()} == {"dest"}
    client.close.assert_called_once_with()
    socket.close.assert_not_called()


@pytest.mark.parametrize("password", [None, "", "explicit"])
def test_explicit_credentials_never_inherit_uri_password(
    ftp: Any, password: Any
) -> None:
    helper, options, client, _socket = ftp
    options.update(
        url="ftp://uri:secret@example.test/payload.bin",
        url_username="explicit",
        url_password=password,
    )
    response = helper.ftp.FtpResponse(options["url"], options)
    client.login.assert_called_once_with("explicit", password or "")
    response.close()


def test_uri_credentials_are_unescaped_when_no_explicit_username(ftp: Any) -> None:
    helper, options, client, _socket = ftp
    options["url"] = "ftp://user%20name:p%40ss@example.test/payload.bin"
    response = helper.ftp.FtpResponse(options["url"], options)
    client.login.assert_called_once_with("user name", "p@ss")
    response.close()


def test_unsupported_method_has_minimal_failure_and_no_connection(
    ftp: Any, tmp_path: Path
) -> None:
    helper, options, client, _socket = ftp
    options["url_method"] = "GET"
    result = helper.download(options)
    assert result == {
        "changed": False,
        "failed": True,
        "msg": (
            'Unhandled exception while executing module: Exception setting "Method": '
            '"This method is not supported.\r\nParameter name: value"'
        ),
    }
    client.connect.assert_not_called()
    client.login.assert_not_called()
    helper.ftp._FtpClient.assert_not_called()
    assert not list(tmp_path.iterdir())


def test_stdlib_reply_parser_retains_failure_before_raising(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = load_payload("win_get_url", monkeypatch).get_url
    client = helper.ftp._FtpClient()
    client.file = io.StringIO("550 Server-specific reason\r\n")
    with pytest.raises(ftplib.error_perm, match="550 Server-specific reason"):
        client.getresp()
    assert client.response == "550 Server-specific reason"
    client.close()


@pytest.mark.parametrize("method", ["LIST", "NLST"])
def test_directory_listing_uses_requested_data_command(ftp: Any, method: str) -> None:
    helper, options, client, _socket = ftp
    options["url_method"] = method
    result = helper.download(options)
    assert result["changed"] and result["status_code"] == 150
    client.voidcmd.assert_called_once_with("TYPE I")
    client.transfercmd.assert_called_once_with(method + " /payload.bin")
    client.close.assert_called_once_with()


@pytest.mark.parametrize("method", ["SIZE", "MDTM", "PWD", "DELE", "MKD", "RMD"])
def test_non_data_method_preserves_reply_and_copies_empty_response(
    ftp: Any, method: str
) -> None:
    helper, options, client, socket = ftp
    options["url_method"] = method
    result = helper.download(options)
    assert result["changed"] and result["size"] == 0
    assert result["status_code"] == 213 and result["msg"] == "213 20000101000000\r\n"
    assert Path(options["dest"]).read_bytes() == b""
    client.sendcmd.assert_called_once_with(
        method if method == "PWD" else method + " /payload.bin"
    )
    client.voidcmd.assert_not_called()
    client.transfercmd.assert_not_called()
    socket.close.assert_not_called()
    client.close.assert_called_once_with()


@pytest.mark.parametrize("status", [530, 550])
def test_failed_control_reply_remains_available_after_connection_cleanup(
    ftp: Any,
    status: int,
) -> None:
    helper, options, client, socket = ftp
    client.connect.return_value = "220 Banner"
    client.login.return_value = "230 Welcome"
    failure = ftplib.error_perm(str(status) + " Original server reason")
    if status == 530:
        client.login.side_effect = failure
    else:
        client.transfercmd.side_effect = failure
    with pytest.raises(OSError) as raised:
        helper.ftp.FtpResponse(options["url"], options)
    preserved = getattr(raised.value, "response")
    assert preserved.status == status
    assert preserved.message == str(status) + " Original server reason\r\n"
    assert preserved.banner_message == "220 Banner"
    assert preserved.welcome_message == ("" if status == 530 else "230 Welcome")
    assert preserved.read() == b"" and preserved.modified() is None
    client.close.assert_called_once_with()
    socket.close.assert_not_called()
    preserved.close()


def test_nonnumeric_protocol_error_does_not_invent_a_response(ftp: Any) -> None:
    helper, options, client, _socket = ftp
    client.login.side_effect = ftplib.error_proto("Invalid control reply")
    with pytest.raises(OSError) as raised:
        helper.ftp.FtpResponse(options["url"], options)
    assert str(raised.value) == "Invalid control reply"
    assert getattr(raised.value, "status_code") is None
    assert not hasattr(raised.value, "response")
    client.close.assert_called_once_with()


@pytest.mark.parametrize("method", ["STOR", "STOU", "APPE"])
def test_bodyless_upload_closes_data_and_retains_final_reply(
    ftp: Any, method: str
) -> None:
    helper, options, client, socket = ftp
    options["url_method"] = method
    result = helper.download(options)
    assert result["changed"] and result["size"] == 0
    assert result["status_code"] == 226 and result["msg"] == "226 Transfer complete\r\n"
    client.transfercmd.assert_called_once_with(
        "STOU" if method == "STOU" else method + " /payload.bin"
    )
    if method == "STOU":
        client.cwd.assert_called_once_with("/payload.bin")
    socket.close.assert_called_once_with()
    socket.makefile.assert_not_called()
    client.voidresp.assert_called_once_with()
    client.close.assert_called_once_with()


def test_rename_source_denial_closes_without_rename_destination(ftp: Any) -> None:
    helper, options, client, socket = ftp
    options["url_method"] = "RENAME"
    client.sendcmd.side_effect = ftplib.error_perm("550 Not enough privileges")
    result = helper.download(options)
    assert result["failed"] and result["status_code"] == 550
    client.sendcmd.assert_called_once_with("RNFR /payload.bin")
    client.transfercmd.assert_not_called()
    socket.close.assert_not_called()
    client.close.assert_called_once_with()
