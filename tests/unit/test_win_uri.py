"""Exercise URI argument binding through the public JSON entry point."""

# SPDX-License-Identifier: GPL-3.0-or-later

from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload


@pytest.fixture(name="runner")
def uri_runner(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> Any:
    """Replace only the request boundary and retain real public binding.

    :param monkeypatch: Scoped payload substitutions.
    :param capsys: JSON output capture.
    :returns: Entry-point runner and observed native request boundary.
    """
    module = load_payload("win_uri", monkeypatch)
    native = Mock(return_value={"changed": False, "elapsed": 0})
    monkeypatch.setattr(module.uri, "request", native)

    def run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        """Run the public entry point.

        :param arguments: Bound public argument fixture.
        :returns: Exit code and complete JSON result.
        """
        monkeypatch.setattr(module, "read_arguments", lambda *_args: arguments)
        return invoke_payload(module, capsys)

    return SimpleNamespace(run=run, module=module, native=native)


@pytest.mark.parametrize("check", [False, True])
def test_defaults_and_check_mode_reach_native_request(runner: Any, check: bool) -> None:
    assert runner.run({"url": "http://example.test", "_ansible_check_mode": check}) == (
        0,
        {"changed": False, "elapsed": 0},
    )
    options, observed_check = runner.native.call_args.args
    assert observed_check is check
    assert options == {
        "url": "http://example.test",
        "content_type": None,
        "url_method": "GET",
        "follow_redirects": "safe",
        "http_agent": "ansible-httpget",
        "client_cert": None,
        "client_cert_password": None,
        "url_username": None,
        "url_password": None,
        "proxy_url": None,
        "proxy_username": None,
        "proxy_password": None,
        "dest": None,
        "creates": None,
        "removes": None,
        "return_content": False,
        "validate_certs": True,
        "force_basic_auth": False,
        "use_default_credential": False,
        "use_proxy": True,
        "proxy_use_default_credential": False,
        "maximum_redirection": 50,
        "url_timeout": 30,
        "status_code": [200],
        "headers": None,
        "body": None,
    }


def test_aliases_and_canonical_precedence(runner: Any) -> None:
    arguments = {"url": "http://example.test", "method": "post", "timeout": "12"}
    assert runner.run(arguments)[0] == 0
    options = runner.native.call_args.args[0]
    assert (options["url_method"], options["url_timeout"]) == ("post", 12)
    arguments.update(url_method="HEAD", url_timeout="7")
    assert runner.run(arguments)[0] == 0
    options = runner.native.call_args.args[0]
    assert (options["url_method"], options["url_timeout"]) == ("HEAD", 7)


@pytest.mark.parametrize("codes", [202, ["202", "418"], "202, 418"])
def test_status_list_coercion(runner: Any, codes: Any) -> None:
    assert runner.run({"url": "http://example.test", "status_code": codes})[0] == 0
    assert runner.native.call_args.args[0]["status_code"] == (
        [202] if codes == 202 else [202, 418]
    )


@pytest.mark.parametrize(
    "body", [None, False, 0, "", [], {}, [7, False], {"key": "value"}]
)
def test_raw_body_is_not_bound_as_a_string(runner: Any, body: Any) -> None:
    assert runner.run({"url": "http://example.test", "body": body})[0] == 0
    assert runner.native.call_args.args[0]["body"] is body


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({}, "missing required arguments: url"),
        ({"url": None}, "missing required arguments: url"),
        (
            {"url": "http://example.test", "url_timeout": "bad"},
            "Expected an integer for url_timeout.",
        ),
        (
            {"url": "http://example.test", "status_code": ["bad"]},
            "Expected integer elements for status_code.",
        ),
        (
            {"url": "http://example.test", "follow_redirects": "Safe"},
            "value of follow_redirects must be one of: all, none, safe, got: Safe",
        ),
    ],
)
def test_binding_errors_prevent_native_operations(
    runner: Any, arguments: dict[str, Any], message: str
) -> None:
    assert runner.run(arguments) == (
        1,
        {"changed": False, "failed": True, "msg": message},
    )
    runner.native.assert_not_called()


def test_complete_public_failure_is_preserved(runner: Any) -> None:
    failure = {
        "changed": True,
        "failed": True,
        "elapsed": 0,
        "url": "http://example.test",
        "status_code": 404,
        "content": "fixture",
        "headers": ["X-Fixture"],
        "x_fixture": "value",
        "msg": "status rejected",
    }
    runner.native.return_value = failure
    assert runner.run({"url": "http://example.test"}) == (1, failure)
