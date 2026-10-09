"""Exercise WinHTTP proxy results, readback rollback, and recovery without Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Frontend calls cover binding and observable native-operation ordering.
# pylint: disable=protected-access

import json
import sys
from copy import deepcopy
from pathlib import Path
from types import ModuleType
from typing import Any, Callable
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

DIRECT = {"proxy": None, "bypass": None}
NAMED = {"proxy": "Gateway:8080", "bypass": "intranet;<local>"}
RequestRunner = Callable[[object], tuple[int, dict[str, Any]]]


@pytest.fixture(name="stored")
def stored_proxy() -> dict[str, str | None]:
    """Provide persistent system proxy configuration isolated to each test.

    :returns: Initially direct-access native proxy and bypass strings.
    """
    return dict(DIRECT)


@pytest.fixture(name="native")
def proxy_operations(stored: dict[str, str | None]) -> Mock:
    """Record native calls and retain successful proxy writes.

    :param stored: Persistent system configuration shared with the test.
    :returns: Recorder for native proxy reads, writes, and IE imports.
    """
    native = Mock()
    native.get_proxy.side_effect = lambda: dict(stored)
    native.get_ie_proxy.return_value = dict(NAMED)

    def _set_proxy(proxy: str | None, bypass: str | None) -> None:
        stored.update({"proxy": proxy or None, "bypass": bypass if proxy else None})

    native.set_proxy.side_effect = _set_proxy
    return native


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.fixture(name="payload")
def proxy_payload(monkeypatch: pytest.MonkeyPatch, native: Mock) -> ModuleType:
    """Import the frontend with its native operations substituted.

    :param monkeypatch: Scoped native-operation and comparison substitutions.
    :param native: Recorder for persistent proxy operations.
    :returns: Imported frontend without Windows operations.
    """
    module = load_payload("win_http_proxy", monkeypatch)
    for name in ("get_proxy", "set_proxy", "get_ie_proxy"):
        monkeypatch.setattr(module.http_proxy, name, getattr(native, name))
    # These public-binding fixtures use ASCII strings, not native collation tables.
    monkeypatch.setattr(module.environment, "name_key", lambda name: name.upper())
    monkeypatch.setattr(
        module.environment,
        "values_equal",
        lambda left, right: (
            left is right
            if left is None or right is None
            else left.lower() == right.lower()
        ),
    )
    return module


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.fixture(name="run_request")
def request_runner(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> RequestRunner:
    """Run argument files through the module's public JSON entry point.

    :param payload: Loaded module with isolated proxy operations.
    :param monkeypatch: Scoped command-line replacement.
    :param tmp_path: Directory for the JSON request file.
    :param capsys: Capture of the module's JSON output.
    :returns: Request runner sharing this test's persistent configuration.
    """
    argument_file = tmp_path / "arguments.json"
    monkeypatch.setattr(sys, "argv", ["win_http_proxy.py", str(argument_file)])

    def _run_request(arguments: object) -> tuple[int, dict[str, Any]]:
        argument_file.write_text(json.dumps(arguments), encoding="utf-8")
        return invoke_payload(payload, capsys)

    return _run_request


# pylint: enable=duplicate-code


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("diff", [False, True])
def test_direct_access_without_options_is_unchanged_and_diffs_are_conditional(
    native: Mock, run_request: RequestRunner, check: bool, diff: bool
) -> None:
    expected: dict[str, Any] = {"changed": False}
    if diff:
        expected["diff"] = {"before": DIRECT, "after": DIRECT}
    assert run_request({"_ansible_check_mode": check, "_ansible_diff": diff}) == (
        0,
        expected,
    )
    assert native.mock_calls == [call.get_proxy()]


def test_check_mode_predicts_then_actual_write_is_read_back_and_repeat_is_unchanged(
    native: Mock, stored: dict[str, str | None], run_request: RequestRunner
) -> None:
    arguments = {
        "proxy": NAMED["proxy"],
        "bypass": "intranet, <local>",
        "_ansible_diff": True,
    }
    expected = {"changed": True, "diff": {"before": DIRECT, "after": NAMED}}
    assert run_request({**arguments, "_ansible_check_mode": True}) == (0, expected)
    assert stored == DIRECT
    assert native.mock_calls == [call.get_proxy()]
    native.reset_mock()
    assert run_request(arguments) == (0, expected)
    assert stored == NAMED
    assert native.mock_calls == [
        call.get_proxy(),
        call.set_proxy(NAMED["proxy"], NAMED["bypass"]),
        call.get_proxy(),
    ]
    native.reset_mock()
    assert run_request(arguments) == (
        0,
        {"changed": False, "diff": {"before": NAMED, "after": NAMED}},
    )
    assert native.mock_calls == [call.get_proxy()]


def test_case_only_request_keeps_native_state_but_retains_requested_diff_spelling(
    native: Mock, stored: dict[str, str | None], run_request: RequestRunner
) -> None:
    stored.update(NAMED)
    requested = {"proxy": "GATEWAY:8080", "bypass": "INTRANET;<LOCAL>"}
    assert run_request({**requested, "_ansible_diff": True}) == (
        0,
        {"changed": False, "diff": {"before": NAMED, "after": requested}},
    )
    assert stored == NAMED
    assert native.mock_calls == [call.get_proxy()]


@pytest.mark.parametrize("uppercase", [False, True])
def test_protocol_dictionary_is_rendered_in_fixed_protocol_order_without_mutating_input(
    native: Mock,
    stored: dict[str, str | None],
    run_request: RequestRunner,
    uppercase: bool,
) -> None:
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    proxy = {"socks": "s:1080", "ftp": "f:21", "https": "s:443", "http": "h:80"}
    if uppercase:
        proxy = {key.upper(): value for key, value in proxy.items()}
    original = deepcopy(proxy)
    rendered = "http=h:80;https=s:443;ftp=f:21;socks=s:1080"
    # pylint: enable=duplicate-code
    expected = {"proxy": rendered, "bypass": None}
    assert run_request({"proxy": proxy, "_ansible_diff": True}) == (
        0,
        {"changed": True, "diff": {"before": DIRECT, "after": expected}},
    )
    assert proxy == original
    assert stored == expected
    native.reset_mock()
    assert run_request({"proxy": rendered}) == (0, {"changed": False})
    assert native.mock_calls == [call.get_proxy()]


@pytest.mark.parametrize("bypass", [None, "", [], [""]])
def test_empty_bypass_is_normalized_and_clears_the_stored_list(
    stored: dict[str, str | None], run_request: RequestRunner, bypass: object
) -> None:
    stored.update(NAMED)
    requested = {"proxy": NAMED["proxy"], "bypass": None}
    assert run_request(
        {"proxy": NAMED["proxy"], "bypass": bypass, "_ansible_diff": True}
    ) == (
        0,
        {"changed": True, "diff": {"before": NAMED, "after": requested}},
    )
    assert stored == requested


@pytest.mark.parametrize("arguments", [{}, {"proxy": None}, {"proxy": ""}])
def test_omitted_null_and_empty_proxy_clear_with_check_mode_nonmutation(
    native: Mock,
    stored: dict[str, str | None],
    run_request: RequestRunner,
    arguments: dict[str, object],
) -> None:
    stored.update(NAMED)
    assert run_request({**arguments, "_ansible_check_mode": True}) == (
        0,
        {"changed": True},
    )
    assert stored == NAMED
    native.set_proxy.assert_not_called()
    assert run_request(arguments) == (0, {"changed": True})
    assert stored == DIRECT
    native.set_proxy.assert_called_once_with(None, None)


def test_ie_import_reads_only_static_proxy_and_is_repeatable(
    native: Mock, stored: dict[str, str | None], run_request: RequestRunner
) -> None:
    expected = {"changed": True, "diff": {"before": DIRECT, "after": NAMED}}
    arguments = {"SOURCE": "IE", "_ANSIBLE_DIFF": True}
    assert run_request({**arguments, "_ANSIBLE_CHECK_MODE": "yes"}) == (0, expected)
    assert stored == DIRECT
    assert native.mock_calls == [call.get_proxy(), call.get_ie_proxy()]
    native.reset_mock()
    assert run_request(arguments) == (0, expected)
    assert stored == NAMED
    assert native.mock_calls == [
        call.get_proxy(),
        call.get_ie_proxy(),
        call.set_proxy(NAMED["proxy"], NAMED["bypass"]),
        call.get_proxy(),
    ]
    native.reset_mock()
    assert run_request(arguments) == (
        0,
        {"changed": False, "diff": {"before": NAMED, "after": NAMED}},
    )
    assert native.mock_calls == [call.get_proxy(), call.get_ie_proxy()]


def test_ie_import_without_static_proxy_clears_existing_configuration(
    native: Mock, stored: dict[str, str | None], run_request: RequestRunner
) -> None:
    stored.update(NAMED)
    native.get_ie_proxy.return_value = {"proxy": "", "bypass": ""}
    assert run_request({"source": "ie", "_ansible_diff": True}) == (
        0,
        {"changed": True, "diff": {"before": NAMED, "after": DIRECT}},
    )
    assert stored == DIRECT


@pytest.mark.parametrize("check", [False, True])
def test_invalid_protocol_keys_fail_before_any_native_read_or_diff(
    native: Mock, run_request: RequestRunner, check: bool
) -> None:
    assert run_request(
        {"proxy": {"fail2": "b", "fail1": "a"}, "_ansible_check_mode": check}
    ) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "Invalid keys found in proxy: fail1, fail2. "
            "Valid keys are http, https, ftp, socks.",
            "exception": "(traceback unavailable)",
        },
    )
    assert native.mock_calls == []


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.mark.parametrize(
    "arguments,message",
    [
        (
            {"source": "other"},
            "value of source must be one of: ie. Got no match for: other",
        ),
        (
            {"proxy": "gateway", "source": "ie"},
            "parameters are mutually exclusive: proxy, source",
        ),
        (
            {"bypass": ["local"], "source": "ie"},
            "parameters are mutually exclusive: bypass, source",
        ),
        ({"bypass": "local"}, "missing parameter(s) required by 'bypass': proxy"),
        (
            {"unexpected": True},
            "Unsupported parameters for (sustainablelobster.legacy_windows.win_http_proxy) "
            "module: unexpected. Supported parameters include: bypass, proxy, source",
        ),
    ],
)
def test_argument_failures_do_not_touch_native_configuration(
    native: Mock, run_request: RequestRunner, arguments: object, message: str
) -> None:
    assert run_request(arguments) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": message,
            "exception": "(traceback unavailable)",
        },
    )
    assert native.mock_calls == []


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.mark.parametrize(
    "arguments,message",
    [
        ({"bypass": None}, "missing parameter(s) required by 'bypass': proxy"),
        ({"bypass": []}, "missing parameter(s) required by 'bypass': proxy"),
        ({"bypass": ""}, "missing parameter(s) required by 'bypass': proxy"),
        (
            {"bypass": "abc", "proxy": None},
            "missing parameter(s) required by ''bypass'': proxy",
        ),
        (
            {"bypass": "abc", "proxy": ""},
            "missing parameter(s) required by ''bypass'': proxy",
        ),
        (
            {"bypass": "abc", "proxy": {}},
            "missing parameter(s) required by ''bypass'': proxy",
        ),
        (
            {"source": "ie", "proxy": None},
            "parameters are mutually exclusive: proxy, source",
        ),
        (
            {"source": "ie", "proxy": ""},
            "parameters are mutually exclusive: proxy, source",
        ),
        (
            {"source": "ie", "bypass": None},
            "parameters are mutually exclusive: bypass, source",
        ),
        (
            {"source": "ie", "bypass": []},
            "parameters are mutually exclusive: bypass, source",
        ),
        (
            {"proxy": {"HTTP": "one:80", "http": "two:80"}},
            "failure during exec_wrapper: Cannot convert the JSON string "
            "because a dictionary that was converted from the string "
            "contains the duplicated keys 'HTTP' and 'http'.",
        ),
        (
            {"proxy": "host", "bypass": True},
            "argument for bypass is of type System.Boolean and we were unable "
            "to convert to list: System.Boolean cannot be converted to a list",
        ),
        (
            {"proxy": "host", "bypass": ["abc", None]},
            'Unhandled exception while executing module: Exception calling "Create" '
            'with "2" argument(s): "Object reference not set to an instance of an object."',
        ),
    ],
)
def test_measured_presence_and_conversion_failures_preserve_exact_fields(
    native: Mock, run_request: RequestRunner, arguments: dict[str, object], message: str
) -> None:
    assert run_request({**arguments, "_ansible_diff": True}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": message,
            "exception": "(traceback unavailable)",
        },
    )
    assert native.mock_calls == []


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.mark.parametrize(
    "proxy,expected",
    [
        ({"http": None}, "http="),
        ({"http": ["one", "two"]}, "http=one two"),
        ({"http": {"nested": "value"}}, "http=System.Collections.Hashtable"),
        ({"http": True}, "http=True"),
        ({"http": 12.5}, "http=12.5"),
        (True, "True"),
        (12.5, "12.5"),
        (["one", "two"], "System.Object[]"),
    ],
)
def test_measured_raw_and_dictionary_coercions_predict_exact_requested_text(
    native: Mock,
    run_request: RequestRunner,
    proxy: object,
    expected: str,
) -> None:
    assert run_request(
        {"proxy": proxy, "_ansible_check_mode": True, "_ansible_diff": True}
    ) == (
        0,
        {
            "changed": True,
            "diff": {"before": DIRECT, "after": {"proxy": expected, "bypass": None}},
        },
    )
    assert native.mock_calls == [call.get_proxy()]


# pylint: enable=duplicate-code


def test_empty_comma_separated_bypass_entries_are_not_discarded(
    native: Mock, run_request: RequestRunner
) -> None:
    assert run_request(
        {
            "proxy": "host",
            "bypass": " , ",
            "_ansible_check_mode": True,
            "_ansible_diff": True,
        }
    ) == (
        0,
        {
            "changed": True,
            "diff": {"before": DIRECT, "after": {"proxy": "host", "bypass": ";"}},
        },
    )
    assert native.mock_calls == [call.get_proxy()]


def test_readback_mismatch_restores_previous_values_and_failure_has_only_before_diff(
    native: Mock, stored: dict[str, str | None], run_request: RequestRunner
) -> None:
    stored.update(NAMED)
    successful_write = native.set_proxy.side_effect

    def _normalizing_write(proxy: str | None, bypass: str | None) -> None:
        successful_write(None if proxy == "fake=proxy" else proxy, bypass)

    native.set_proxy.side_effect = _normalizing_write
    assert run_request({"proxy": "fake=proxy", "_ansible_diff": True}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "Unknown error when trying to set proxy 'fake=proxy' or bypass ''",
            "exception": "(traceback unavailable)",
            "diff": {"before": NAMED},
        },
    )
    assert stored == NAMED
    assert native.mock_calls == [
        call.get_proxy(),
        call.set_proxy("fake=proxy", None),
        call.get_proxy(),
        call.set_proxy(NAMED["proxy"], NAMED["bypass"]),
    ]
    native.reset_mock()
    assert run_request({"proxy": "fake=proxy", "_ansible_check_mode": True}) == (
        0,
        {"changed": True},
    )
    assert stored == NAMED
    native.set_proxy.assert_not_called()
    native.set_proxy.side_effect = successful_write
    assert run_request({"proxy": "Recovered"}) == (0, {"changed": True})
    assert stored == {"proxy": "Recovered", "bypass": None}


def test_case_only_native_readback_is_accepted_without_a_rollback(
    native: Mock, stored: dict[str, str | None], run_request: RequestRunner
) -> None:
    def _uppercase_write(proxy: str, bypass: str) -> None:
        stored.update({"proxy": proxy.upper(), "bypass": bypass.upper()})

    native.set_proxy.side_effect = _uppercase_write
    assert run_request(
        {"proxy": "gateway", "bypass": "local", "_ansible_diff": True}
    ) == (
        0,
        {
            "changed": True,
            "diff": {
                "before": DIRECT,
                "after": {"proxy": "gateway", "bypass": "local"},
            },
        },
    )
    assert stored == {"proxy": "GATEWAY", "bypass": "LOCAL"}
    native.set_proxy.assert_called_once_with("gateway", "local")
