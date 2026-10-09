"""Retain real HTTPS trust failures and package preview cleanup."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Controller substitutions are not Windows execution evidence.
# pylint: disable=protected-access

import ctypes
from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock

import pytest

# Pytest discovers these fixture objects without a direct Python reference.
# Importing them reuses maintained native/public setup instead of duplicating it.
# pylint: disable=unused-import
from tests.unit.test_get_url_native import native_download, native_http
from tests.unit.test_win_package import package_remote_helper, package_runner

# pylint: enable=unused-import


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.mark.parametrize("asynchronous", [False, True])
def test_native_tls_trust_failure_retains_errno_and_closes_native_handles(
    http: Any, monkeypatch: pytest.MonkeyPatch, asynchronous: bool
) -> None:
    helper, options, library = http
    options.update(
        url="https://localhost:9443/payload.bin",
        url_timeout=1,
        use_proxy=False,
        proxy_url=None,
        validate_certs=True,
    )
    message = "Could not establish the SSL/TLS secure connection (WinHTTP 12175)"
    original = OSError(12175, message)
    failure = Mock(return_value=original)
    monkeypatch.setattr(helper, "_error", failure)
    monkeypatch.setattr(helper.ctypes, "get_last_error", lambda: 12175)

    def fail(*_arguments: Any) -> bool:
        """Report the measured trust code through either native failure boundary.

        :param _arguments: Native send arguments retained by the mock.
        :returns: Whether asynchronous initiation succeeded.
        """
        if asynchronous:
            error = helper._AsyncResult(1, 12175)
            library.callback(
                103, 1, 0x200000, ctypes.byref(error), ctypes.sizeof(error)
            )
        return asynchronous

    library.WinHttpSendRequest.side_effect = fail
    with pytest.raises(OSError) as caught:
        helper.open_resource(options["url"], options, [])
    error = caught.value
    assert error.errno == 12175 and error.strerror == message
    assert error is original
    assert error.args == original.args and helper._message(error) == message
    failure.assert_called_once_with(12175, 0)
    library.WinHttpSendRequest.assert_called_once()
    library.WinHttpReceiveResponse.assert_not_called()
    assert [call.args[0] for call in library.WinHttpCloseHandle.call_args_list] == [
        103,
        102,
        101,
    ]


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.mark.parametrize(
    "change,code,body",
    [
        ({"url_timeout": 1}, 12175, None),
        ({"url": "http://localhost/payload.bin"}, 12175, None),
        ({"validate_certs": False}, 12175, None),
        ({"use_proxy": True}, 12175, None),
        ({"url_method": "HEAD"}, 12175, None),
        ({}, 12029, None),
        ({}, 12175, b""),
    ],
)
def test_native_tls_trust_failure_does_not_change_other_failure_boundaries(
    http: Any,
    monkeypatch: pytest.MonkeyPatch,
    change: dict[str, Any],
    code: int,
    body: bytes | None,
) -> None:
    helper, options, _library = http
    options.update(
        url="https://localhost/payload.bin",
        url_timeout=1,
        use_proxy=False,
        proxy_url=None,
        validate_certs=True,
        url_method="GET",
    )
    options.update(change)
    original = OSError(code, "unchanged native failure")
    native_failure = Mock(side_effect=original)
    monkeypatch.setattr(helper, "_HttpResponse", native_failure)
    monkeypatch.setattr(helper.plain_http, "PlainHttpResponse", native_failure)
    with pytest.raises(OSError) as caught:
        helper._http_response(
            options["url"],
            options,
            {},
            True,
            deadline=None,
            body=body,
            redirected=False,
        )
    assert caught.value is original
    assert original.args == (code, "unchanged native failure")
    assert str(original) == f"[Errno {code}] unchanged native failure"
    native_failure.assert_called_once()


# pylint: enable=duplicate-code


@pytest.mark.parametrize("timeout,code", [(1, 12175), (1, 12029)])
def test_url_preview_trust_failure_retains_public_message_and_owned_temp_cleanup(
    runner: Any,
    package_remote: Any,
    monkeypatch: pytest.MonkeyPatch,
    timeout: int,
    code: int,
) -> None:
    web = package_remote.web
    error = web._error(code)
    request = Mock(side_effect=error)
    monkeypatch.setattr(web, "_HttpResponse", request)
    acquire = package_remote.acquire
    paths = []

    def observe_acquire(
        url: str, options: dict[str, Any], result: dict[str, Any], root: str
    ) -> str:
        """Observe the concrete acquisition's owned directory.

        :param url: The public HTTPS package URL.
        :param options: Bound request options.
        :param result: Public metadata updated by acquisition.
        :param root: Owned temporary directory.
        :returns: The maintained acquisition's local package path.
        """
        paths.append(Path(root))
        return cast(str, acquire(url, options, result, root))

    monkeypatch.setattr(package_remote, "acquire", observe_acquire)
    message = str(error)
    assert runner.run(
        {
            "path": "https://localhost:9443/payload.bin",
            "provider": "registry",
            "url_timeout": timeout,
            "use_proxy": False,
            "validate_certs": True,
            "_ansible_check_mode": True,
        }
    ) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "Unhandled exception while executing module: " + message,
        },
    )
    assert error.errno == code and error.args == (code, error.strerror)
    assert len(paths) == 1 and not paths[0].exists()
    request.assert_called_once()
    runner.installer.product_code.assert_not_called()
    runner.process.assert_not_called()
    runner.read.assert_not_called()
