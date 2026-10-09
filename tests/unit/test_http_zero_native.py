"""Require positive HTTP timeouts before any network or native request opens."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutions and developer sockets are not target-runtime evidence.
# pylint: disable=protected-access

from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit import test_get_url_native as download_fixtures

native_download = download_fixtures.native_download
native_http = download_fixtures.native_http


@pytest.mark.parametrize(
    "protocol_timeout", [("http", 0), ("http", -1), ("https", 0), ("https", -1)]
)
@pytest.mark.parametrize("body", [None, b"", b"fixture"])
@pytest.mark.parametrize(
    "overrides",
    [
        {"use_proxy": False},
        {"use_proxy": True},
        {"url_username": "caller", "force_basic_auth": True},
        {"validate_certs": False},
        {"url_method": "POST"},
    ],
)
def test_nonpositive_timeout_is_rejected_before_any_request_or_upload(
    http: Any,
    monkeypatch: pytest.MonkeyPatch,
    protocol_timeout: tuple[str, int],
    body: bytes | None,
    overrides: dict[str, Any],
) -> None:
    helper, options, library = http
    scheme, timeout = protocol_timeout
    options = dict(options, url_timeout=timeout, **overrides)
    plain = Mock(side_effect=AssertionError("network request opened"))
    monkeypatch.setattr(helper.plain_http, "PlainHttpResponse", plain)
    with pytest.raises(ValueError, match="positive url_timeout"):
        helper.open_resource(scheme + "://owned/payload", options, [], body=body)
    plain.assert_not_called()
    library.WinHttpOpen.assert_not_called()


def test_zero_validation_precedes_header_preparation(
    http: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper, options = http[:2]
    prepare = Mock(side_effect=AssertionError("request headers prepared"))
    monkeypatch.setattr(helper, "_headers", prepare)
    with pytest.raises(ValueError, match="positive url_timeout"):
        helper.open_resource("https://owned/payload", dict(options, url_timeout=0), [])
    prepare.assert_not_called()


def test_file_zero_retains_existing_opener(
    http: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper, options = http[:2]
    opener = Mock()
    monkeypatch.setattr(helper, "_FileResponse", opener)
    assert (
        helper.open_resource(
            "file:///C:/owned/file.bin", dict(options, url_timeout=0), []
        )
        is opener.return_value
    )
    opener.assert_called_once_with("C:\\owned\\file.bin")


def test_ftp_zero_retains_existing_client_policy(
    http: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper, options = http[:2]
    opener = Mock()
    monkeypatch.setattr(helper.ftp, "FtpResponse", opener)
    options = dict(options, url_timeout=0)
    assert (
        helper.open_resource("ftp://owned/file.bin", options, []) is opener.return_value
    )
    opener.assert_called_once_with("ftp://owned/file.bin", options, False, body=None)
