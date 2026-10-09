"""Exercise public download binding without contacting Windows or the network."""

# SPDX-License-Identifier: GPL-3.0-or-later

from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload


@pytest.fixture(name="runner")
def download_runner(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> Any:
    """Replace the target-native download boundary and run the JSON entry point.

    :param monkeypatch: Scoped payload substitutions.
    :param capsys: JSON output capture.
    :returns: Request runner, payload and observed native call.
    """
    module = load_payload("win_get_url", monkeypatch)
    native = Mock(return_value={"changed": False, "elapsed": 0})
    monkeypatch.setattr(module.get_url, "download", native)

    def run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        """Run one public request with only the native boundary replaced.

        :param arguments: JSON-compatible public arguments.
        :returns: Module exit status and complete result.
        """
        monkeypatch.setattr(module, "read_arguments", lambda *_args: arguments)
        return invoke_payload(module, capsys)

    return SimpleNamespace(run=run, module=module, native=native)


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.mark.parametrize("check", [False, True])
def test_public_defaults_and_check_flag(runner: Any, check: bool) -> None:
    assert runner.run(
        {"url": "http://example.test/a", "dest": "C:\\a", "_ansible_check_mode": check}
    ) == (0, {"changed": False, "elapsed": 0})
    options, observed_check = runner.native.call_args.args
    assert observed_check == check
    assert options == {
        "url": "http://example.test/a",
        "dest": "C:\\a",
        "checksum": None,
        "checksum_url": None,
        "checksum_algorithm": "sha1",
        "url_method": None,
        "follow_redirects": "safe",
        "http_agent": "ansible-httpget",
        "client_cert": None,
        "client_cert_password": None,
        "url_username": None,
        "url_password": None,
        "proxy_url": None,
        "proxy_username": None,
        "proxy_password": None,
        "force": True,
        "validate_certs": True,
        "force_basic_auth": False,
        "use_default_credential": False,
        "use_proxy": True,
        "proxy_use_default_credential": False,
        "maximum_redirection": 50,
        "url_timeout": 30,
        "headers": None,
    }


# pylint: enable=duplicate-code


def test_aliases_bind_and_canonical_options_take_precedence(runner: Any) -> None:
    arguments: dict[str, Any] = {
        "url": "http://example.test/a",
        "dest": "C:\\a",
        "method": "POST",
        "timeout": "12",
    }
    assert runner.run(arguments)[0] == 0
    assert runner.native.call_args.args[0]["url_method"] == "POST"
    assert runner.native.call_args.args[0]["url_timeout"] == 12
    arguments.update(url_method="HEAD", url_timeout=7)
    assert runner.run(arguments)[0] == 0
    assert runner.native.call_args.args[0]["url_method"] == "HEAD"
    assert runner.native.call_args.args[0]["url_timeout"] == 7


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({}, "missing required arguments: dest, url"),
        ({"url": "http://example.test"}, "missing required arguments: dest"),
        (
            {"url": "http://example.test", "dest": None},
            "missing required arguments: dest",
        ),
        (
            {
                "url": "http://example.test",
                "dest": "C:\\a",
                "checksum": "",
                "checksum_url": "",
            },
            "parameters are mutually exclusive: checksum, checksum_url",
        ),
        (
            {"url": "http://example.test", "dest": "C:\\a", "url_timeout": "bad"},
            "Expected an integer for url_timeout.",
        ),
    ],
)
def test_binding_failure_prevents_download(
    runner: Any, arguments: dict[str, Any], message: str
) -> None:
    assert runner.run(arguments) == (
        1,
        {"changed": False, "failed": True, "msg": message},
    )
    runner.native.assert_not_called()


@pytest.mark.parametrize(
    "parameter,value", [("checksum_algorithm", "SHA256"), ("follow_redirects", "Safe")]
)
def test_choices_are_case_sensitive_before_execution(
    runner: Any, parameter: str, value: str
) -> None:
    status, result = runner.run(
        {"url": "http://example.test", "dest": "C:\\a", parameter: value}
    )
    assert status == 1 and result["failed"]
    assert result["msg"].startswith("value of " + parameter + " must be one of:")
    runner.native.assert_not_called()


def test_complete_partial_failure_is_not_discarded(runner: Any) -> None:
    failure = {
        "changed": False,
        "failed": True,
        "elapsed": 0.5,
        "url": "http://example.test/a",
        "dest": "C:\\a",
        "msg": "checksum failed",
        "status_code": 200,
        "checksum_src": "bad",
        "warnings": ["measured warning"],
    }
    runner.native.return_value = failure
    assert runner.run({"url": "http://example.test/a", "dest": "C:\\a"}) == (1, failure)


@pytest.mark.parametrize("method", ["GET", "HEAD", "POST", "PUT"])
@pytest.mark.parametrize("status", [300, 301, 302, 303, 307])
@pytest.mark.parametrize("explicit_length", [False, True])
def test_public_upload_headers_control_redirect_method(
    runner: Any,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    status: int,
    explicit_length: bool,
) -> None:
    helper = runner.module.get_url
    headers: dict[str, Any] = {"X-Fixture": "retained"}
    if explicit_length:
        headers["cOnTeNt-LeNgTh"] = 0
    assert (
        runner.run(
            {
                "url": "http://example.test/redirect",
                "dest": "C:\\a",
                "method": method,
                "follow_redirects": "all",
                "headers": headers,
            }
        )[0]
        == 0
    )
    options = runner.native.call_args.args[0]
    redirect = SimpleNamespace(
        status=status,
        message="redirect",
        header=Mock(return_value="/payload"),
        close=Mock(),
    )
    final = SimpleNamespace(status=200, header=Mock(return_value=None), close=Mock())
    factory = Mock(side_effect=[redirect, final])
    monkeypatch.setattr(helper, "_HttpResponse", factory)

    assert helper.open_resource(options["url"], options, []) is final
    rewrite = (
        explicit_length
        and method in ("POST", "PUT")
        and (status in (300, 303) or status in (301, 302) and method == "POST")
    )
    first, second = factory.call_args_list
    assert [first.args[1]["url_method"], second.args[1]["url_method"]] == [
        method,
        "GET" if rewrite else method,
    ]
    assert first.args[2] == (
        {"X-Fixture": "retained", "cOnTeNt-LeNgTh": "0"}
        if explicit_length and method in ("POST", "PUT")
        else {"X-Fixture": "retained"}
    )
    assert second.args[2] == ({"X-Fixture": "retained"} if rewrite else first.args[2])
    assert [first.args[3], second.args[3]] == [True, False]
    assert first.kwargs["deadline"] == second.kwargs["deadline"]
    redirect.close.assert_called_once_with()
    final.close.assert_not_called()
