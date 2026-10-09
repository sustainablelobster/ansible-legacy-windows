"""Test native credential selection without claiming Windows authentication."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes prove ownership and ordering; public Windows runs prove auth.
# pylint: disable=protected-access

import ctypes
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit import test_get_url_native as http_fixtures

native_download = http_fixtures.native_download
native_http = http_fixtures.native_http


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/resource",
        "https://LOCALHOST./resource",
        "http://127.0.0.1/resource",
        "http://192.0.2.5/resource",
        "http://2130706433/resource",
        "http://0x7f000001/resource",
        "http://0177.0.0.1/resource",
        "http://[::1]/resource",
        "http://[fe80::1%25scope]/resource",
    ],
)
@pytest.mark.parametrize("kind", ["explicit", "default"])
def test_proxy_only_unsafe_origin_fails_before_native_session(
    http: Any, monkeypatch: pytest.MonkeyPatch, url: str, kind: str
) -> None:
    helper, options, library = http
    options.update(
        proxy_username="supplied" if kind == "explicit" else None,
        proxy_use_default_credential=kind == "default",
    )
    native = Mock(return_value=library)
    monkeypatch.setattr(helper, "_winhttp", native)
    with pytest.raises(NotImplementedError, match="cannot safely isolate"):
        helper._HttpResponse(url, options, {})
    native.assert_not_called()


def test_redirect_cannot_reuse_original_origin_authorization(http: Any) -> None:
    helper, options, library = http
    options.update(url_username="supplied", proxy_use_default_credential=True)
    with pytest.raises(NotImplementedError, match="cannot safely isolate"):
        helper._HttpResponse("http://localhost/redirect", options, {}, False)
    library.WinHttpOpen.assert_not_called()


@pytest.mark.parametrize("target", [0, 1])
def test_explicit_identity_is_bound_before_initial_send(http: Any, target: int) -> None:
    helper, options, library = http
    prefix = "url" if target == 0 else "proxy"
    options.update({prefix + "_username": "supplied", prefix + "_password": "secret"})
    events = Mock()
    events.attach_mock(library.WinHttpSetCredentials, "credentials")
    events.attach_mock(library.WinHttpSendRequest, "send")
    response = helper._HttpResponse(options["url"], options, {})
    response.close()
    assert events.mock_calls[0] == call.credentials(
        103, target, 16, "supplied", "secret", None
    )
    assert events.mock_calls[1].args[0] == 103


def test_default_proxy_policy_is_low_only_during_authorized_send(
    http: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper, options, library = http
    options["proxy_use_default_credential"] = True
    policy: list[int | None] = [None]
    events: list[tuple[Any, int | None]] = []
    statuses = iter(["407", "200"])

    def set_option(_handle: int, number: int, value: Any, _size: int) -> bool:
        """Record autologon policy.

        :param number: Native option identifier.
        :param value: Native option value pointer.
        :returns: Native option-setting success.
        """
        if number == 77:
            policy[0] = ctypes.cast(value, ctypes.POINTER(ctypes.c_uint32))[0]
        return True

    def schemes(_handle: int, supported: Any, _first: Any, _target: Any) -> bool:
        """Advertise the native Negotiate challenge.

        :param supported: Caller-owned authentication scheme output.
        :returns: Native authentication-query success.
        """
        ctypes.cast(supported, ctypes.POINTER(ctypes.c_uint32))[0] = 16
        return True

    original = helper._HttpResponse._call

    def invoke(response: Any, operation: Any, timeout: Any, *arguments: Any) -> None:
        events.append((operation, policy[0]))
        original(response, operation, timeout, *arguments)

    library.WinHttpSetOption.side_effect = set_option
    library.WinHttpQueryAuthSchemes = Mock(side_effect=schemes)
    monkeypatch.setattr(helper._HttpResponse, "_call", invoke)
    monkeypatch.setattr(
        helper._HttpResponse,
        "header",
        lambda _self, number: next(statuses) if number == 19 else "response",
    )
    response = helper._HttpResponse(options["url"], options, {})
    response.close()
    assert events == [
        (library.WinHttpSendRequest, 2),
        (library.WinHttpReceiveResponse, 2),
        (library.WinHttpSendRequest, 1),
        (library.WinHttpReceiveResponse, 2),
    ]
    library.WinHttpSetCredentials.assert_called_once_with(103, 1, 16, None, None, None)


def test_requested_default_origin_keeps_its_authorization(http: Any) -> None:
    helper, options, _library = http
    options.update(use_default_credential=True, proxy_use_default_credential=True)
    response = helper._HttpResponse("http://localhost/resource", options, {})
    response.close()


def test_forced_basic_preserves_the_explicit_authorization_header(http: Any) -> None:
    helper, options, library = http
    options.update(
        url_username="supplied", url_password="secret", force_basic_auth=True
    )
    response = helper._HttpResponse(options["url"], options, {})
    response.close()
    library.WinHttpSetCredentials.assert_called_once_with(
        103, 0, 1, "supplied", "secret", None
    )
    assert "Authorization: Basic " in library.WinHttpSendRequest.call_args.args[1]


def test_disabled_proxy_ignores_its_credentials(http: Any) -> None:
    helper, options, library = http
    options.update(use_proxy=False, proxy_use_default_credential=True)
    response = helper._HttpResponse("http://localhost/resource", options, {})
    response.close()
    library.WinHttpSetCredentials.assert_not_called()
