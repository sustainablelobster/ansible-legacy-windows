"""Exercise endpoint-fact results, argument binding, and failure recovery."""

# SPDX-License-Identifier: GPL-3.0-or-later

import datetime
import json
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

_REFERENCE = (
    Path(__file__).parents[1] / "fixtures" / "listen_ports_state_reference.json"
)
_STATE_CASES = json.loads(_REFERENCE.read_text(encoding="utf-8"))["cases"]
_CREATED = datetime.datetime(2026, 9, 3, 4, 5, 6, 123456)
_TCP = {"address": "127.0.0.1", "port": 8080, "pid": 42, "state": 2}
_UDP = {"address": "::", "port": 5353, "pid": 42}
_PROCESS = {"name": "worker.exe", "creation_time": _CREATED, "user": "TEST\\reader"}


@pytest.fixture(name="payload")
def ports_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the payload with deterministic native reader boundaries.

    :param monkeypatch: Scoped imports and native substitutes.
    :returns: Payload module with independently controlled reader functions.
    """
    reader = Mock()
    reader.get.return_value = dict(_PROCESS)
    context = Mock()
    context.__enter__ = Mock(return_value=reader)
    context.__exit__ = Mock(return_value=False)
    replacements = {
        "legacy_windows_ports": {
            "tcp_endpoints": Mock(return_value=[dict(_TCP)]),
            "udp_endpoints": Mock(return_value=[dict(_UDP)]),
        },
        "legacy_windows_process_info": {"ProcessReader": Mock(return_value=context)},
        "legacy_windows_uformat": {"format_date": Mock(return_value="2026")},
    }
    for name, attributes in replacements.items():
        helper = ModuleType(name)
        for attribute, value in attributes.items():
            monkeypatch.setattr(helper, attribute, value, raising=False)
        monkeypatch.setitem(sys.modules, name, helper)
    return load_payload("win_listen_ports_facts", monkeypatch)


@pytest.fixture(name="invoke")
def ports_invocation(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> Callable[[object], tuple[int, dict[str, Any]]]:
    """Run the actual JSON entry point with selected public arguments.

    :param payload: Imported payload module.
    :param monkeypatch: Scoped command-line arguments.
    :param tmp_path: Isolated argument-file directory.
    :param capsys: Captured module output.
    :returns: Invocation callable accepting an argument mapping.
    """

    def _invoke(arguments: object) -> tuple[int, dict[str, Any]]:
        argument_file = tmp_path / "arguments.json"
        argument_file.write_text(json.dumps(arguments), encoding="utf-8")
        monkeypatch.setattr(
            sys, "argv", ["win_listen_ports_facts.py", str(argument_file)]
        )
        return invoke_payload(payload, capsys)

    return _invoke


@pytest.mark.parametrize("case", _STATE_CASES, ids=lambda case: repr(case["input"]))
def test_state_binding_matches_recorded_powershell(
    payload: ModuleType, case: dict[str, Any]
) -> None:
    if "error" in case:
        with pytest.raises(ValueError) as raised:
            payload._state_value(case["input"])  # pylint: disable=protected-access
        assert str(raised.value) == case["error"]
    else:
        # The captured enum converter is a boundary inside the payload.
        # pylint: disable-next=protected-access
        assert payload._state_value(case["input"]) == case["value"]


@pytest.mark.parametrize("check", [False, True])
def test_complete_facts_repeat_in_normal_and_check_mode(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    check: bool,
) -> None:
    common = {"name": "worker.exe", "pid": 42, "stime": "2026", "user": "TEST\\reader"}
    expected = {
        "changed": False,
        "ansible_facts": {
            "tcp_listen": [
                dict(common, address="127.0.0.1", port=8080, protocol="tcp")
            ],
            "udp_listen": [dict(common, address="::", port=5353, protocol="udp")],
        },
    }
    arguments = {"_ansible_check_mode": check, "_ansible_diff": True}
    assert invoke(arguments) == (0, expected)
    assert invoke(arguments) == (0, expected)
    assert payload.ports.tcp_endpoints.call_args_list == [call({2}, []), call({2}, [])]
    assert payload.uformat.format_date.call_args_list == [call(_CREATED, "%c")] * 4
    assert payload.process_info.ProcessReader.return_value.__exit__.call_count == 2


@pytest.mark.parametrize(
    ("supplied", "selected"),
    [
        ([], set()),
        (["Lis", "2", "listen"], {2}),
        ("Listen, Established", {2, 5}),
        (["Listen,Established"], {7}),
        (100, {100}),
        (["TimeWait", "CloseWait"], {11, 8}),
    ],
)
def test_filter_binding_passes_selected_states_without_filtering_udp(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    supplied: object,
    selected: set[int],
) -> None:
    assert invoke({"tcp_filter": supplied})[0] == 0
    payload.ports.tcp_endpoints.assert_called_once_with(selected, [])
    payload.ports.udp_endpoints.assert_called_once_with()


@pytest.mark.parametrize("format_value", [None, "", "%Y", 2026])
def test_format_is_coerced_once_and_passed_without_replacing_null_or_empty(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    format_value: object,
) -> None:
    assert invoke({"date_uformat": format_value})[0] == 0
    converted = str(format_value) if isinstance(format_value, int) else format_value
    assert payload.uformat.format_date.call_args_list == [call(_CREATED, converted)] * 2


def test_null_process_fields_remain_null(
    payload: ModuleType, invoke: Callable[[object], tuple[int, dict[str, Any]]]
) -> None:
    reader = payload.process_info.ProcessReader.return_value.__enter__.return_value
    reader.get.return_value = dict(_PROCESS, creation_time=None, user=None)
    payload.uformat.format_date.return_value = None
    code, result = invoke({})
    assert code == 0
    for records in result["ansible_facts"].values():
        assert records[0]["stime"] is None
        assert records[0]["user"] is None
    assert payload.uformat.format_date.call_args_list == [call(None, "%c")] * 2


@pytest.mark.parametrize("value", [None, ["not_a_state"], ["Fin"], ["13"]])
def test_invalid_states_close_process_reader_without_endpoint_queries(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    value: object,
) -> None:
    code, result = invoke({"tcp_filter": value})
    assert code == 1
    assert result["failed"] and not result["changed"]
    assert result["msg"].startswith("An error occurred while retrieving ports facts: ")
    assert "ansible_facts" not in result
    payload.ports.tcp_endpoints.assert_not_called()
    payload.ports.udp_endpoints.assert_not_called()
    payload.process_info.ProcessReader.return_value.__exit__.assert_called_once()


@pytest.mark.parametrize("phase", ["tcp", "udp", "process", "format"])
def test_retrieval_failure_discards_partial_facts_and_allows_recovery(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    phase: str,
) -> None:
    reader = payload.process_info.ProcessReader.return_value.__enter__.return_value
    boundary = {
        "tcp": payload.ports.tcp_endpoints,
        "udp": payload.ports.udp_endpoints,
        "process": reader.get,
        "format": payload.uformat.format_date,
    }[phase]
    boundary.side_effect = OSError("fixture failure")
    assert invoke({}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "An error occurred while retrieving ports facts: fixture failure",
        },
    )
    payload.process_info.ProcessReader.return_value.__exit__.assert_called_once()
    boundary.side_effect = None
    assert invoke({})[0] == 0


def test_process_snapshot_failure_precedes_retrieval_error_wrapper(
    payload: ModuleType, invoke: Callable[[object], tuple[int, dict[str, Any]]]
) -> None:
    payload.process_info.ProcessReader.return_value.__enter__.side_effect = OSError(
        "snapshot failed"
    )
    assert invoke({}) == (
        1,
        {"changed": False, "failed": True, "msg": "snapshot failed"},
    )
    payload.ports.tcp_endpoints.assert_not_called()


def test_legacy_warning_retains_other_available_facts(
    payload: ModuleType, invoke: Callable[[object], tuple[int, dict[str, Any]]]
) -> None:
    def _endpoints(states: set[int], warnings: list[str]) -> list[dict[str, Any]]:
        assert states == {2, 100}
        warnings.append("Bound endpoints are unavailable on this legacy API.")
        return [dict(_TCP)]

    payload.ports.tcp_endpoints.side_effect = _endpoints
    code, result = invoke({"tcp_filter": ["Listen", "Bound"]})
    assert code == 0
    assert result["warnings"] == ["Bound endpoints are unavailable on this legacy API."]
    assert result["ansible_facts"]["tcp_listen"][0]["pid"] == 42


@pytest.mark.parametrize("arguments", [{"unexpected": True}, {"tcp_filter": True}])
def test_argument_failure_happens_before_native_work(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    arguments: dict[str, Any],
) -> None:
    assert invoke(arguments)[0] == 1
    payload.process_info.ProcessReader.assert_not_called()
    payload.ports.tcp_endpoints.assert_not_called()


def test_invocation_reports_coerced_public_arguments(
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
) -> None:
    code, result = invoke(
        {
            "tcp_filter": "listen, established",
            "date_uformat": None,
            "_ansible_inject_invocation": True,
        }
    )
    assert code == 0
    assert result["invocation"] == {
        "module_args": {"tcp_filter": ["listen", "established"], "date_uformat": None}
    }
