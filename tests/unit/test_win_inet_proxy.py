"""Exercise WinINet results, independent connections, and recovery without Windows."""

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

Configuration = dict[str, str | bool | None]
StoredConnections = dict[str | None, Configuration]
RequestRunner = Callable[[object], tuple[int, dict[str, Any]]]
CONNECTION = "Owned Connection"
DEFAULT: Configuration = {
    "auto_config_url": None,
    "auto_detect": True,
    "proxy": None,
    "bypass": None,
}
DEFAULT_BEFORE = {
    "auto_config_url": None,
    "auto_detect": True,
    "server": None,
    "bypass": None,
}
NAMED: Configuration = {
    "auto_config_url": "http://PAC.invalid/Config.pac",
    "auto_detect": True,
    "proxy": "Gateway:8080",
    "bypass": "intranet;<local>",
}


@pytest.fixture(name="stored")
def stored_connections() -> StoredConnections:
    """Provide independent LAN and named connection settings for each test.

    :returns: Initially default configuration for both connections.
    """
    return {None: dict(DEFAULT), CONNECTION: dict(DEFAULT)}


@pytest.fixture(name="native")
def proxy_operations(stored: StoredConnections) -> Mock:
    """Record native operations while retaining successful connection writes.

    :param stored: Persistent connection configurations shared with the test.
    :returns: Recorder for validation, reads, and writes.
    """
    native = Mock()
    native.valid_connection.side_effect = lambda name: name in stored
    native.get_proxy.side_effect = lambda connection=None: dict(stored[connection])

    def _set_proxy(config: Configuration, connection: str | None = None) -> None:
        stored[connection] = {
            "auto_config_url": config["auto_config_url"] or None,
            "auto_detect": bool(config["auto_detect"]),
            "proxy": config["proxy"] or None,
            "bypass": config["bypass"] if config["proxy"] else None,
        }

    native.set_proxy.side_effect = _set_proxy
    return native


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.fixture(name="payload")
def proxy_payload(monkeypatch: pytest.MonkeyPatch, native: Mock) -> ModuleType:
    """Import the frontend with isolated native operations and ASCII comparison.

    :param monkeypatch: Scoped import and native-operation substitutions.
    :param native: Recorder for persistent proxy operations.
    :returns: Imported frontend without Windows operations.
    """
    helper = ModuleType("legacy_windows_inet_proxy")
    for name in ("get_proxy", "set_proxy", "valid_connection"):
        monkeypatch.setattr(helper, name, getattr(native, name), raising=False)
    monkeypatch.setitem(sys.modules, "legacy_windows_inet_proxy", helper)
    module = load_payload("win_inet_proxy", monkeypatch)
    # Public-binding fixtures use ASCII strings, not target collation tables.
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
    monkeypatch.setattr(sys, "argv", ["win_inet_proxy.py", str(argument_file)])

    def _run_request(arguments: object) -> tuple[int, dict[str, Any]]:
        argument_file.write_text(json.dumps(arguments), encoding="utf-8")
        return invoke_payload(payload, capsys)

    return _run_request


# pylint: enable=duplicate-code


@pytest.mark.parametrize(
    "value",
    ["not-a-boolean", "  NOT-A-BOOLEAN  ", "\u00a0NOT-A-BOOLEAN\u3000"],
)
def test_invalid_boolean_reports_measured_argument_failure(
    native: Mock, run_request: RequestRunner, value: str
) -> None:
    assert run_request({"auto_detect": value}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "exception": "(traceback unavailable)",
            "msg": (
                "argument for auto_detect is of type System.String and we were "
                "unable to convert to bool: The value 'not-a-boolean' is not a "
                "valid boolean. Valid booleans include: y, yes, on, 1, true, t, "
                "1.0, n, no, off, 0, false, f, 0.0"
            ),
        },
    )
    assert native.mock_calls == []


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("diff", [False, True])
def test_no_arguments_restore_defaults_and_unchanged_diff_preserves_server_quirk(
    native: Mock, run_request: RequestRunner, check: bool, diff: bool
) -> None:
    expected: dict[str, Any] = {"changed": False}
    if diff:
        expected["diff"] = {"before": DEFAULT_BEFORE, "after": DEFAULT}
    assert run_request({"_ansible_check_mode": check, "_ansible_diff": diff}) == (
        0,
        expected,
    )
    assert native.mock_calls == [call.get_proxy(None)]


def test_check_predicts_then_actual_writes_readback_and_repeat_does_not_write(
    native: Mock, stored: StoredConnections, run_request: RequestRunner
) -> None:
    disabled = {**DEFAULT, "auto_detect": False}
    expected = {"changed": True, "diff": {"before": DEFAULT_BEFORE, "after": disabled}}
    arguments = {"auto_detect": False, "_ansible_diff": True}
    assert run_request({**arguments, "_ansible_check_mode": True}) == (0, expected)
    assert stored[None] == DEFAULT
    assert native.mock_calls == [call.get_proxy(None)]
    native.reset_mock()
    assert run_request(arguments) == (0, expected)
    assert stored[None] == disabled
    assert native.mock_calls == [
        call.get_proxy(None),
        call.set_proxy(disabled, None),
        call.get_proxy(None),
    ]
    native.reset_mock()
    assert run_request(arguments) == (
        0,
        {
            "changed": False,
            "diff": {
                "before": {**DEFAULT_BEFORE, "auto_detect": False},
                "after": disabled,
            },
        },
    )
    assert native.mock_calls == [call.get_proxy(None)]


def test_omitted_url_proxy_and_bypass_clear_instead_of_preserving_individual_fields(
    stored: StoredConnections, run_request: RequestRunner
) -> None:
    stored[None] = dict(NAMED)
    before = {
        "auto_config_url": NAMED["auto_config_url"],
        "auto_detect": True,
        "server": NAMED["proxy"],
        "bypass": NAMED["bypass"],
    }
    assert run_request({"_ansible_diff": True}) == (
        0,
        {"changed": True, "diff": {"before": before, "after": DEFAULT}},
    )
    assert stored[None] == DEFAULT


def test_case_equal_fields_keep_native_spelling_when_another_field_changes(
    native: Mock, stored: StoredConnections, run_request: RequestRunner
) -> None:
    stored[None] = dict(NAMED)
    requested = {
        "auto_config_url": "HTTP://pac.INVALID/config.PAC",
        "auto_detect": False,
        "proxy": "GATEWAY:8080",
        "bypass": "INTRANET;<LOCAL>",
    }
    before = {
        "auto_config_url": NAMED["auto_config_url"],
        "auto_detect": True,
        "server": NAMED["proxy"],
        "bypass": NAMED["bypass"],
    }
    written = {**NAMED, "auto_detect": False}
    assert run_request({**requested, "_ansible_diff": True}) == (
        0,
        {"changed": True, "diff": {"before": before, "after": requested}},
    )
    assert stored[None] == written
    native.set_proxy.assert_called_once_with(written, None)
    native.reset_mock()
    assert run_request(requested) == (0, {"changed": False})
    assert native.mock_calls == [call.get_proxy(None)]


@pytest.mark.parametrize("connection", ["", "Missing Connection", "System.Object[]"])
@pytest.mark.parametrize("check", [False, True])
def test_invalid_connections_fail_before_reads_diff_or_writes(
    native: Mock, run_request: RequestRunner, connection: str, check: bool
) -> None:
    assert run_request(
        {"connection": connection, "_ansible_check_mode": check, "_ansible_diff": True}
    ) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "The connection '" + connection + "' does not exist.",
            "exception": "(traceback unavailable)",
        },
    )
    assert native.mock_calls == [call.valid_connection(connection)]


def test_named_connection_is_validated_and_changed_without_touching_lan(
    native: Mock, stored: StoredConnections, run_request: RequestRunner
) -> None:
    before = deepcopy(stored)
    arguments = {**NAMED, "connection": CONNECTION, "_ansible_diff": True}
    expected = {"changed": True, "diff": {"before": DEFAULT_BEFORE, "after": NAMED}}
    assert run_request({**arguments, "_ansible_check_mode": True}) == (0, expected)
    assert stored == before
    assert native.mock_calls == [
        call.valid_connection(CONNECTION),
        call.get_proxy(CONNECTION),
    ]
    native.reset_mock()
    assert run_request(arguments) == (0, expected)
    assert stored == {None: DEFAULT, CONNECTION: NAMED}
    assert native.mock_calls == [
        call.valid_connection(CONNECTION),
        call.get_proxy(CONNECTION),
        call.set_proxy(NAMED, CONNECTION),
        call.get_proxy(CONNECTION),
    ]
    native.reset_mock()
    assert run_request({"connection": None}) == (0, {"changed": False})
    assert native.mock_calls == [call.get_proxy(None)]


@pytest.mark.parametrize("uppercase", [False, True])
def test_dictionary_protocols_keep_fixed_order_and_input_mapping_is_not_mutated(
    stored: StoredConnections, run_request: RequestRunner, uppercase: bool
) -> None:
    proxy = {"socks": "s:1080", "ftp": "f:21", "https": "s:443", "http": "h:80"}
    if uppercase:
        proxy = {key.upper(): value for key, value in proxy.items()}
    original = deepcopy(proxy)
    rendered = "http=h:80;https=s:443;ftp=f:21;socks=s:1080"
    requested = {**DEFAULT, "proxy": rendered}
    assert run_request({"proxy": proxy, "_ansible_diff": True}) == (
        0,
        {"changed": True, "diff": {"before": DEFAULT_BEFORE, "after": requested}},
    )
    assert proxy == original
    assert stored[None] == requested
    assert run_request({"proxy": rendered}) == (0, {"changed": False})


@pytest.mark.parametrize("bypass", [None, "", [], [""]])
def test_null_or_empty_bypass_clears_the_list_while_retaining_explicit_proxy(
    stored: StoredConnections, run_request: RequestRunner, bypass: object
) -> None:
    stored[None] = {**DEFAULT, "proxy": "gateway", "bypass": "old"}
    assert run_request({"proxy": "gateway", "bypass": bypass}) == (0, {"changed": True})
    assert stored[None] == {**DEFAULT, "proxy": "gateway"}


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
            {"proxy": {"fail2": "b", "fail1": "a"}},
            "Invalid keys found in proxy: fail1, fail2. Valid keys are http, https, ftp, socks.",
        ),
        (
            {"proxy": {"HTTP": "one", "http": "two"}},
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
            {"proxy": "host", "bypass": [None]},
            'Unhandled exception while executing module: Exception calling "Create" '
            'with "2" argument(s): "Object reference not set to an instance of an object."',
        ),
        (
            {"unexpected": True},
            "Unsupported parameters for (sustainablelobster.legacy_windows.win_inet_proxy) "
            "module: unexpected. Supported parameters include: "
            "auto_config_url, auto_detect, bypass, connection, proxy",
        ),
    ],
)
def test_binding_failures_return_exact_fields_without_any_native_calls(
    native: Mock, run_request: RequestRunner, arguments: dict[str, object], message: str
) -> None:
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    assert run_request({**arguments, "_ansible_diff": True}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": message,
            "exception": "(traceback unavailable)",
        },
    )
    # pylint: enable=duplicate-code
    assert native.mock_calls == []


@pytest.mark.parametrize(
    "proxy,expected",
    [
        (["one", "two"], "System.Object[]"),
        ({"http": ["one", "two"]}, "http=one two"),
        ({"http": None}, "http="),
        ({"http": {"nested": "value"}}, "http=System.Collections.Hashtable"),
    ],
)
def test_raw_proxy_and_interpolated_dictionary_values_have_distinct_binding(
    native: Mock, run_request: RequestRunner, proxy: object, expected: str
) -> None:
    assert run_request(
        {"proxy": proxy, "_ansible_check_mode": True, "_ansible_diff": True}
    ) == (
        0,
        {
            "changed": True,
            "diff": {"before": DEFAULT_BEFORE, "after": {**DEFAULT, "proxy": expected}},
        },
    )
    assert native.mock_calls == [call.get_proxy(None)]


def test_case_insensitive_arguments_boolean_flags_and_null_url_are_bound(
    native: Mock, run_request: RequestRunner
) -> None:
    requested = {**DEFAULT, "auto_detect": False, "proxy": "gateway"}
    assert run_request(
        {
            "AUTO_DETECT": "no",
            "AUTO_CONFIG_URL": None,
            "PROXY": "gateway",
            "_ANSIBLE_CHECK_MODE": "yes",
            "_ANSIBLE_DIFF": True,
        }
    ) == (
        0,
        {"changed": True, "diff": {"before": DEFAULT_BEFORE, "after": requested}},
    )
    assert native.mock_calls == [call.get_proxy(None)]


@pytest.mark.parametrize("connection", [None, CONNECTION])
def test_nul_readback_mismatch_restores_all_previous_fields_and_recovery_succeeds(
    native: Mock,
    stored: StoredConnections,
    run_request: RequestRunner,
    connection: str | None,
) -> None:
    stored[connection] = dict(NAMED)
    successful_write = native.set_proxy.side_effect

    def _truncating_write(config: Configuration, selected: str | None = None) -> None:
        changed = dict(config)
        proxy = changed["proxy"]
        if isinstance(proxy, str):
            changed["proxy"] = proxy.split("\0", maxsplit=1)[0]
        successful_write(changed, selected)

    native.set_proxy.side_effect = _truncating_write
    proxy = "gateway\0truncated"
    arguments = {
        **NAMED,
        "proxy": proxy,
        "connection": connection,
        "_ansible_diff": True,
    }
    before = {
        "auto_config_url": NAMED["auto_config_url"],
        "auto_detect": True,
        "server": NAMED["proxy"],
        "bypass": NAMED["bypass"],
    }
    assert run_request(arguments) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "Unknown error when trying to set auto_config_url "
            "'http://PAC.invalid/Config.pac', proxy '"
            + proxy
            + "', or bypass 'intranet;<local>'",
            "exception": "(traceback unavailable)",
            "diff": {"before": before},
        },
    )
    assert stored[connection] == NAMED
    assert native.set_proxy.call_args_list == [
        call({**NAMED, "proxy": proxy}, connection),
        call(NAMED, connection),
    ]
    native.reset_mock()
    assert run_request({**arguments, "_ansible_check_mode": True})[0] == 0
    assert stored[connection] == NAMED
    native.set_proxy.assert_not_called()
    native.set_proxy.side_effect = successful_write
    assert run_request({"connection": connection}) == (0, {"changed": True})
    assert stored[connection] == DEFAULT
