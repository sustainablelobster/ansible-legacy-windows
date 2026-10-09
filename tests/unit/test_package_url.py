"""Exercise package response filenames, streaming and owned response lifetime."""

# SPDX-License-Identifier: GPL-3.0-or-later
# The boundary under test is the concrete private filename parser.
# pylint: disable=protected-access

from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import HELPER, load_module


@pytest.fixture(name="url_helper")
def package_url_helper(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load the Python3.4 helper and replace only the actual HTTP opener.

    :param monkeypatch: Scoped helper path and native substitutions.
    :returns: Concrete package acquisition module.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    return load_module(HELPER.parent / "legacy_windows_package_url.py", "package_url")


@pytest.mark.parametrize(
    "url,disposition,expected",
    [
        ("http://fixture/installer.msi?q=one", None, "installer.msi"),
        ("http://fixture/a%20b.msi", None, "a%20b.msi"),
        ("http://fixture/renamed.bin", 'attachment; filename=""', "renamed.bin"),
        ("http://fixture/renamed.bin", "attachment", "renamed.bin"),
    ],
)
def test_response_uri_segment_fallback_retains_percent_encoding(
    url_helper: Any, url: str, disposition: str | None, expected: str
) -> None:
    response = SimpleNamespace(url=url, header=Mock(return_value=disposition))
    assert url_helper._filename(response) == expected
    response.header.assert_called_once_with(65535, "Content-Disposition")


def test_content_disposition_filename_keeps_spaces_and_unique_prefix(
    url_helper: Any,
) -> None:
    response = SimpleNamespace(
        url="http://fixture/renamed.bin",
        header=Mock(return_value='attachment; filename="installer with spaces.msi"'),
    )
    first, second = url_helper._filename(response), url_helper._filename(response)
    assert first != second
    assert first.endswith(".tmp-installer with spaces.msi")
    assert second.endswith(".tmp-installer with spaces.msi")


def test_streaming_reports_web_metadata_and_closes_response(
    url_helper: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    response = SimpleNamespace(
        url="http://fixture/package.msi",
        status=200,
        message="OK",
        header=Mock(return_value=None),
        read=Mock(side_effect=[b"one", b"two", b""]),
        close=Mock(),
    )
    opener = Mock(return_value=response)
    monkeypatch.setattr(url_helper.web, "open_resource", opener)
    result: dict[str, Any] = {}
    path = url_helper.acquire("http://fixture/first", {}, result, str(tmp_path))
    assert Path(path).read_bytes() == b"onetwo"
    assert result["msg"] == "OK" and result["status_code"] == 200
    assert isinstance(result["elapsed"], float) and result["elapsed"] >= 0
    assert "warnings" not in result
    response.close.assert_called_once()
    response.read.assert_has_calls([call(65536), call(65536), call(65536)])


def test_http_error_does_not_create_package_and_closes_response(
    url_helper: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    response = SimpleNamespace(status=404, message="Not Found", close=Mock())
    monkeypatch.setattr(url_helper.web, "open_resource", Mock(return_value=response))
    result: dict[str, Any] = {}
    with pytest.raises(
        url_helper.PackageDownloadError,
        match=r"The remote server returned an error: \(404\) Not Found\.",
    ):
        url_helper.acquire("http://fixture/missing", {}, result, str(tmp_path))
    assert not list(tmp_path.iterdir())
    response.close.assert_called_once()
    assert isinstance(result["elapsed"], float)


def test_body_failure_closes_response_without_hiding_partial_owned_file(
    url_helper: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    response = SimpleNamespace(
        url="http://fixture/package.msi",
        status=200,
        message="OK",
        header=Mock(return_value=None),
        read=Mock(side_effect=[b"partial", OSError("wire body failure")]),
        close=Mock(),
    )
    monkeypatch.setattr(url_helper.web, "open_resource", Mock(return_value=response))
    with pytest.raises(url_helper.PackageDownloadError, match="wire body failure"):
        url_helper.acquire("http://fixture/package.msi", {}, {}, str(tmp_path))
    assert (tmp_path / "package.msi").read_bytes() == b"partial"
    response.close.assert_called_once()
