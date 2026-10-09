"""Check polling results and failures without waiting or contacting Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Direct calls isolate the payload's polling logic from native Windows APIs.
# pylint: disable=protected-access

import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import invoke_payload, load_payload


@pytest.fixture(name="clock")
def polling_clock() -> dict[str, Any]:
    """Provide a deterministic wall clock shared with the payload fixture.

    :returns: Current time and recorded sleep durations.
    """
    return {"now": 100.0, "sleeps": []}


@pytest.fixture(name="payload")
def wait_payload(monkeypatch: pytest.MonkeyPatch, clock: dict[str, Any]) -> ModuleType:
    """Replace native operations and real waits with observable substitutes.

    :param monkeypatch: Scoped clock and native boundary replacements.
    :param clock: Mutable time and sleep observations.
    :returns: The imported payload.
    """
    module = load_payload("win_wait_for", monkeypatch)

    def sleep(seconds: float) -> None:
        if seconds < 0:
            raise ValueError("sleep length must be non-negative")
        clock["sleeps"].append(seconds)
        clock["now"] += seconds

    monkeypatch.setattr(
        module,
        "time",
        SimpleNamespace(time=lambda: clock["now"], sleep=Mock(side_effect=sleep)),
    )
    for name, result in (
        ("path_exists", False),
        ("read_text", ""),
        ("port_open", False),
        ("active_connections", []),
        ("resolve_addresses", []),
    ):
        monkeypatch.setattr(module.native, name, Mock(return_value=result))
    # Native helper tests cover numeric address aliases and IPv6 scope parsing.
    # Most polling fixtures use canonical strings to isolate connection filtering.
    monkeypatch.setattr(
        module.native,
        "address_matches",
        Mock(side_effect=lambda address, expected: address == expected),
    )
    return module


def _wait(payload: ModuleType, **arguments: object) -> dict[str, Any]:
    result: dict[str, Any] = payload._wait(payload._parameters(arguments))
    return result


def _run(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    arguments: object,
) -> tuple[int, dict[str, Any]]:
    argument_file = tmp_path / "arguments.json"
    argument_file.write_text(json.dumps(arguments), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["win_wait_for.py", str(argument_file)])
    return invoke_payload(payload, capsys)


def test_parameter_defaults(payload: ModuleType) -> None:
    assert payload._parameters({}) == {
        "connect_timeout": 5,
        "delay": None,
        "exclude_hosts": None,
        "host": "127.0.0.1",
        "path": None,
        "port": None,
        "regex": None,
        "sleep": 1,
        "state": "started",
        "timeout": 300,
    }


@pytest.mark.parametrize(
    "name", ["connect_timeout", "delay", "port", "sleep", "timeout"]
)
def test_explicit_null_integer_is_not_defaulted(payload: ModuleType, name: str) -> None:
    assert payload._parameters({name: None})[name] is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        (True, 1),
        (False, 0),
        (1.5, 2),
        (2.5, 2),
        (-1.5, -2),
        ("\t+12\n", 12),
        ("-2147483648", -(2**31)),
        ("2147483647", 2**31 - 1),
        ("2147483648", None),
        (2**31, None),
        (-(2**31) - 1, None),
        ("bad", None),
        ("", 0),
        (" ", None),
        ("1.5", 2),
        ("1e1", 10),
        ("0x10", 16),
        ("1,000", 1000),
        ("1,5", 15),
        ("0xffffffff", -1),
        ("-0x10", None),
        ("+0x10", None),
        (" 0x10 ", 16),
        ("0x100000000", None),
        ("1,,5", 15),
        ("1,", 1),
        ("0.5", 0),
        ("2147483647.4", 2**31 - 1),
        ("2147483647.5", None),
        ("\u0661", None),
        ("1\u00a0", 1),
        ("1kb", None),
        ([], None),
        ([1], None),
        ({}, None),
    ],
)
def test_nullable_legacy_integer_conversion(
    payload: ModuleType, value: object, expected: int | None
) -> None:
    assert payload._integer(value) == expected


@pytest.mark.parametrize(
    ("options", "expected"),
    [
        ({"regex": "first", "search_regex": "second", "regexp": "third"}, "first"),
        ({"regex": None, "search_regex": "second"}, None),
        ({"search_regex": "second", "regexp": "third"}, "second"),
        ({"regexp": "third"}, "third"),
    ],
)
def test_regex_alias_uses_first_present_name(
    payload: ModuleType, options: dict[str, object], expected: str | None
) -> None:
    assert payload._parameters(options)["regex"] == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        ([], []),
        ("one, two ,", ["one", "two", ""]),
        (42, [42]),
        (
            [None, True, ["nested"], {"key": "value"}],
            [None, True, ["nested"], {"key": "value"}],
        ),
    ],
)
def test_excludes_keep_raw_array_entries(
    payload: ModuleType, value: object, expected: object
) -> None:
    assert payload._parameters({"exclude_hosts": value})["exclude_hosts"] == expected


@pytest.mark.parametrize("value", [True, 1.5, {}, 2**31])
def test_invalid_excludes_fail_during_parameter_conversion(
    payload: ModuleType, value: object
) -> None:
    with pytest.raises(ValueError, match="is not a YAML list"):
        payload._parameters({"exclude_hosts": value})


@pytest.mark.parametrize("value", [None, "", "invalid", ["started", "absent"]])
def test_state_validates_before_conversion(payload: ModuleType, value: object) -> None:
    with pytest.raises(ValueError, match="Argument state needs to be one of"):
        payload._parameters({"state": value})


def test_singleton_state_array_validates_then_has_no_matching_branch(
    payload: ModuleType,
) -> None:
    assert payload._parameters({"state": ["started"]})["state"] == "System.Object[]"
    assert _wait(payload, state=["started"], path="C:\\fixture", timeout=9) == {
        "changed": False,
        "elapsed": 0.0,
        "wait_attempts": 0,
    }
    payload.native.path_exists.assert_not_called()


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (
            {"path": "C:\\fixture", "port": 1, "exclude_hosts": []},
            "port and path parameter can not both be passed to win_wait_for",
        ),
        (
            {"path": "C:\\fixture", "state": "stopped", "exclude_hosts": []},
            "exclude_hosts should only be with state=drained",
        ),
        (
            {"path": "C:\\fixture", "state": "stopped"},
            "state=stopped should only be used for checking a port in the win_wait_for module",
        ),
        (
            {"path": "C:\\fixture", "state": "STOPPED"},
            "state=STOPPED should only be used for checking a port in the win_wait_for module",
        ),
        (
            {"path": "C:\\fixture", "state": "drained", "exclude_hosts": []},
            "state=drained should only be used for checking a port in the win_wait_for module",
        ),
        (
            {"port": 1, "regex": ""},
            "regex should by used when checking a string in a file in the win_wait_for module",
        ),
    ],
)
def test_validation_precedes_delay_and_retains_only_initialized_fields(
    payload: ModuleType,
    clock: dict[str, Any],
    arguments: dict[str, object],
    message: str,
) -> None:
    assert _wait(payload, delay=10, **arguments) == {
        "changed": False,
        "elapsed": 0,
        "failed": True,
        "msg": message,
    }
    assert not clock["sleeps"]


@pytest.mark.parametrize("check", [False, True])
def test_unconditional_wait_includes_delay_and_ignores_unknown_options(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    check: bool,
) -> None:
    status, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {
            "DELAY": 2,
            "TIMEOUT": 3,
            "unknown": True,
            "_ansible_check_mode": check,
            "_ansible_inject_invocation": True,
        },
    )
    assert status == 0
    assert result == {"changed": False, "elapsed": 5.0, "wait_attempts": 0}
    assert payload.time.sleep.call_args_list == [call(2), call(3)]


def test_drained_without_port_only_applies_delay(
    payload: ModuleType, clock: dict[str, Any]
) -> None:
    assert _wait(
        payload, state="drained", delay=2, timeout=999, exclude_hosts=["bad"]
    ) == {
        "changed": False,
        "elapsed": 2.0,
        "wait_attempts": 0,
    }
    assert clock["sleeps"] == [2]
    payload.native.active_connections.assert_not_called()
    payload.native.resolve_addresses.assert_not_called()


@pytest.mark.parametrize("delay", [None, "bad", [], {}])
def test_unconvertible_delay_is_ignored_like_explicit_null(
    payload: ModuleType, clock: dict[str, Any], delay: object
) -> None:
    assert _wait(payload, delay=delay, timeout=0) == {
        "changed": False,
        "elapsed": 0.0,
        "wait_attempts": 0,
    }
    assert clock["sleeps"] == [0]


@pytest.mark.parametrize("state", ["present", "started", "absent"])
def test_file_condition_success_repeats_without_changes(
    payload: ModuleType, clock: dict[str, Any], state: str
) -> None:
    payload.native.path_exists.return_value = state != "absent"
    for _attempt in range(2):
        assert _wait(payload, path="C:\\fixture", state=state, timeout=1) == {
            "changed": False,
            "elapsed": 0.0,
            "wait_attempts": 1,
        }
    assert payload.native.path_exists.call_args_list == [call("C:\\fixture")] * 2
    assert not clock["sleeps"]
    payload.native.read_text.assert_not_called()


@pytest.mark.parametrize("check", [False, True])
def test_check_mode_really_polls_until_file_appears(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    check: bool,
) -> None:
    payload.native.path_exists.side_effect = [False, False, True]
    status, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"path": "C:\\fixture", "timeout": 3, "delay": 4, "_ansible_check_mode": check},
    )
    assert status == 0
    assert result == {"changed": False, "elapsed": 6.0, "wait_attempts": 3}
    assert payload.time.sleep.call_args_list == [call(4), call(1), call(1)]


@pytest.mark.parametrize("timeout", [0, -1, None, "bad"])
def test_nonpositive_timeout_does_not_attempt_condition(
    payload: ModuleType, timeout: object
) -> None:
    payload.native.path_exists.return_value = True
    assert _wait(payload, path="C:\\fixture", timeout=timeout) == {
        "changed": False,
        "elapsed": 0.0,
        "wait_attempts": 0,
        "failed": True,
        "msg": "timeout while waiting for file C:\\fixture to be present",
    }
    payload.native.path_exists.assert_not_called()


def test_timeout_allows_final_sleep_to_extend_deadline(
    payload: ModuleType, clock: dict[str, Any]
) -> None:
    result = _wait(payload, path="C:\\fixture", timeout=3, sleep=2, delay=4)
    assert result["elapsed"] == 8.0
    assert result["wait_attempts"] == 2
    assert result["failed"] is True
    assert clock["sleeps"] == [4, 2, 2]


def test_condition_that_finishes_after_deadline_can_succeed(
    payload: ModuleType, clock: dict[str, Any]
) -> None:
    def _slow_connect(_host: str, _port: int, _timeout: int) -> bool:
        clock["now"] += 5
        return True

    payload.native.port_open.side_effect = _slow_connect
    assert _wait(payload, port=1234, timeout=1, connect_timeout=5) == {
        "changed": False,
        "elapsed": 5.0,
        "wait_attempts": 1,
    }
    assert not clock["sleeps"]


@pytest.mark.parametrize(
    ("state", "contents", "pattern"),
    [
        ("present", "The READY marker", "ready"),
        ("started", "first\nsecond", "(?m)^second$"),
        ("absent", "first\nsecond", "^second$"),
        ("absent", "complete", "pending"),
    ],
)
def test_regex_search_is_case_insensitive_without_implicit_multiline(
    payload: ModuleType, state: str, contents: str, pattern: str
) -> None:
    payload.native.path_exists.return_value = True
    payload.native.read_text.return_value = contents
    result = _wait(payload, path="C:\\fixture", state=state, regex=pattern, timeout=1)
    assert result == {"changed": False, "elapsed": 0.0, "wait_attempts": 1}
    payload.native.read_text.assert_called_once_with("C:\\fixture")


def test_missing_file_does_not_compile_malformed_regex(payload: ModuleType) -> None:
    assert _wait(payload, path="C:\\missing", regex="[", state="absent", timeout=1) == {
        "changed": False,
        "elapsed": 0.0,
        "wait_attempts": 1,
    }
    result = _wait(payload, path="C:\\missing", regex="[", timeout=1)
    assert result["failed"] is True
    assert (
        result["msg"]
        == "timeout while waiting for string regex [ in file C:\\missing to match"
    )
    payload.native.read_text.assert_not_called()


@pytest.mark.parametrize("state", ["present", "absent"])
def test_empty_file_regex_has_no_match_or_nonmatch_condition(
    payload: ModuleType, state: str
) -> None:
    payload.native.path_exists.return_value = True
    payload.native.read_text.return_value = None
    result = _wait(payload, path="C:\\empty", regex="", state=state, timeout=1)
    assert result["failed"] is True and result["wait_attempts"] == 1
    assert result["elapsed"] == 1.0


def test_empty_file_still_validates_regex_and_discards_partial_result(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload.native.path_exists.return_value = True
    payload.native.read_text.return_value = None
    status, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"path": "C:\\empty", "regex": "[", "timeout": 1},
    )
    assert status == 1 and result["failed"] is True
    assert "elapsed" not in result and "wait_attempts" not in result
    assert "unterminated" in result["msg"]


@pytest.mark.parametrize("state", ["present", "started", "absent", "stopped"])
def test_port_state_selects_connect_result(payload: ModuleType, state: str) -> None:
    payload.native.port_open.return_value = state in ("present", "started")
    assert _wait(payload, port=1234, host="example.test", state=state, timeout=1) == {
        "changed": False,
        "elapsed": 0.0,
        "wait_attempts": 1,
    }
    payload.native.port_open.assert_called_once_with("example.test", 1234, 5)


@pytest.mark.parametrize("timeout", [None, "bad"])
def test_null_connect_timeout_reaches_connection_attempt_as_zero(
    payload: ModuleType, timeout: object
) -> None:
    result = _wait(
        payload, port=1234, state="absent", connect_timeout=timeout, timeout=1
    )
    assert result == {"changed": False, "elapsed": 0.0, "wait_attempts": 1}
    payload.native.port_open.assert_called_once_with("127.0.0.1", 1234, 0)


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ({"path": "C:\\fixture"}, "file C:\\fixture to be present"),
        ({"path": "C:\\fixture", "state": "absent"}, "file C:\\fixture to be absent"),
        (
            {"path": "C:\\fixture", "regex": "ready"},
            "string regex ready in file C:\\fixture to match",
        ),
        (
            {"path": "C:\\fixture", "regex": "ready", "state": "absent"},
            "string regex ready in file C:\\fixture to not match",
        ),
        ({"port": 1234}, "127.0.0.1:1234 to start listening"),
        ({"port": 1234, "state": "stopped"}, "127.0.0.1:1234 to stop listening"),
        ({"port": 1234, "state": "drained"}, "127.0.0.1:1234 to drain"),
    ],
)
def test_timeout_diagnostic_preserves_condition(
    payload: ModuleType, arguments: dict[str, object], message: str
) -> None:
    assert _wait(payload, timeout=0, **arguments) == {
        "changed": False,
        "elapsed": 0.0,
        "wait_attempts": 0,
        "failed": True,
        "msg": "timeout while waiting for " + message,
    }


def test_draining_ignores_other_ports_and_other_local_addresses(
    payload: ModuleType,
) -> None:
    payload.native.active_connections.return_value = [
        ("127.0.0.2", 1234, "192.0.2.1"),
        ("127.0.0.1", 4321, "192.0.2.2"),
    ]
    assert _wait(payload, port=1234, state="drained", timeout=1) == {
        "changed": False,
        "elapsed": 0.0,
        "wait_attempts": 1,
    }
    payload.native.port_open.assert_not_called()


def test_draining_all_addresses_waits_for_connections_to_close(
    payload: ModuleType,
) -> None:
    payload.native.active_connections.side_effect = [
        [("127.0.0.2", 1234, "192.0.2.1")],
        [("::1", 1234, "::1")],
        [],
    ]
    assert _wait(payload, host="0.0.0.0", port=1234, state="drained", timeout=3) == {
        "changed": False,
        "elapsed": 2.0,
        "wait_attempts": 3,
    }


def test_drain_host_uses_numeric_address_comparison_without_dns(
    payload: ModuleType,
) -> None:
    payload.native.active_connections.return_value = [("127.0.0.1", 1234, "192.0.2.1")]
    payload.native.address_matches.return_value = True
    payload.native.address_matches.side_effect = None
    result = _wait(payload, host="127.1", port=1234, state="drained", timeout=1)
    assert result["failed"] is True and result["wait_attempts"] == 1
    payload.native.address_matches.assert_called_once_with("127.0.0.1", "127.1")
    payload.native.resolve_addresses.assert_not_called()


def test_drain_excludes_resolve_each_attempt_and_keep_duplicate_warnings(
    payload: ModuleType,
) -> None:
    payload.native.active_connections.return_value = [("127.0.0.1", 1234, "192.0.2.1")]
    payload.native.resolve_addresses.side_effect = OSError("name not found")
    result = _wait(
        payload,
        port=1234,
        state="drained",
        exclude_hosts=["missing.invalid"],
        timeout=2,
    )
    assert result["failed"] is True and result["wait_attempts"] == 2
    assert result["warnings"] == ["Invalid hostname specified missing.invalid"] * 2
    assert (
        payload.native.resolve_addresses.call_args_list == [call("missing.invalid")] * 2
    )


def test_excludes_continue_resolving_after_all_connections_are_filtered(
    payload: ModuleType,
) -> None:
    payload.native.active_connections.return_value = [("127.0.0.1", 1234, "192.0.2.1")]
    payload.native.resolve_addresses.side_effect = [["192.0.2.1"], OSError("bad host")]
    assert _wait(
        payload,
        port=1234,
        state="drained",
        exclude_hosts=["allowed.example", "missing.invalid"],
        timeout=1,
    ) == {
        "changed": False,
        "elapsed": 0.0,
        "wait_attempts": 1,
        "warnings": ["Invalid hostname specified missing.invalid"],
    }


def test_empty_connections_do_not_resolve_excluded_hosts(payload: ModuleType) -> None:
    result = _wait(
        payload, port=1234, state="drained", exclude_hosts=["bad"], timeout=1
    )
    assert result["wait_attempts"] == 1 and "warnings" not in result
    payload.native.resolve_addresses.assert_not_called()


@pytest.mark.parametrize(
    ("excluded", "name"),
    [(None, ""), (1, "1"), (True, "True"), (["127.0.0.1"], "127.0.0.1")],
)
def test_excluded_hosts_use_powershell_string_parameter_binding(
    payload: ModuleType, excluded: object, name: str
) -> None:
    payload.native.active_connections.return_value = [("127.0.0.1", 1234, "192.0.2.1")]
    payload.native.resolve_addresses.return_value = ["192.0.2.1"]
    result = _wait(
        payload, port=1234, state="drained", exclude_hosts=[excluded], timeout=1
    )
    assert result["wait_attempts"] == 1 and "failed" not in result
    payload.native.resolve_addresses.assert_called_once_with(name)


def test_native_error_discards_partial_wait_result_and_next_call_recovers(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload.native.path_exists.side_effect = [False, OSError("access denied"), True]
    arguments = {"path": "C:\\fixture", "timeout": 3}
    status, failed = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 1
    assert failed == {"changed": False, "failed": True, "msg": "access denied"}
    status, recovered = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0
    assert recovered == {"changed": False, "elapsed": 0.0, "wait_attempts": 1}


def test_negative_sleep_only_fails_after_an_unsuccessful_condition(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload.native.path_exists.return_value = True
    assert _wait(payload, path="C:\\fixture", sleep=-1, timeout=1)["wait_attempts"] == 1
    payload.native.path_exists.return_value = False
    status, failed = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"path": "C:\\fixture", "sleep": -1, "timeout": 1},
    )
    assert status == 1
    assert failed["changed"] is False and failed["failed"] is True
    assert "Unhandled exception" in failed["msg"]
    assert "-1 argument is less than the minimum" in failed["msg"]
    assert "elapsed" not in failed and "wait_attempts" not in failed


@pytest.mark.parametrize("timeout", [None, "bad", -1])
def test_invalid_unconditional_sleep_fails_without_polling_fields(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    timeout: object,
) -> None:
    status, failed = _run(payload, monkeypatch, tmp_path, capsys, {"timeout": timeout})
    assert status == 1 and failed["failed"] is True
    assert "Cannot validate argument on parameter 'Seconds'" in failed["msg"]
    assert "elapsed" not in failed and "wait_attempts" not in failed
