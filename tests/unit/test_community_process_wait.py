"""Exercise process snapshot selection, bounded waits and handle cleanup."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

# Direct calls isolate selection and timing without contacting Windows.
# pylint: disable=protected-access

from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module

COLLECTION = ROOT / "legacy_community_windows/plugins"
PROCESS = {"name": "worker", "pid": 42, "owner": r"HOST\user"}


@pytest.fixture(name="payload")
def wait_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the payload and replace time and process observations.

    :param monkeypatch: Scoped import and native boundary replacements.
    :returns: Imported process wait payload.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(str(COLLECTION / "module_utils"))
    module = load_module(
        COLLECTION / "modules/win_wait_for_process.py", "tested_community_process_wait"
    )
    clock = {"now": 0.0}

    def sleep(seconds: float) -> None:
        clock["now"] += seconds

    monkeypatch.setattr(
        module, "time", SimpleNamespace(monotonic=lambda: clock["now"], sleep=sleep)
    )
    monkeypatch.setattr(module.native, "processes", Mock(return_value=[PROCESS]))
    monkeypatch.setattr(module.native, "wait_for_exit", Mock(return_value=True))
    return module


def test_present_waits_but_never_claims_change(payload: ModuleType) -> None:
    payload.native.processes.side_effect = [[], [PROCESS]]
    result = payload._wait(
        payload._parameters({"pid": 42})
    )  # pylint: disable=protected-access
    assert result == {
        "changed": False,
        "elapsed": 1.0,
        "matched_processes": [PROCESS],
    }
    payload.native.wait_for_exit.assert_not_called()


def test_absence_uses_initial_pid_snapshot_only(payload: ModuleType) -> None:
    parameters = payload._parameters(  # pylint: disable=protected-access
        {"process_name_exact": "worker", "state": "absent", "timeout": 12}
    )
    result = payload._wait(parameters)  # pylint: disable=protected-access
    assert result["changed"] is False
    assert result["matched_processes"] == [PROCESS]
    payload.native.processes.assert_called_once_with(parameters)
    payload.native.wait_for_exit.assert_called_once_with([42], 12)


def test_check_mode_still_waits_and_counts_pre_and_post_delays(
    payload: ModuleType,
) -> None:
    result = payload._wait(  # pylint: disable=protected-access
        payload._parameters(  # pylint: disable=protected-access
            {
                "pid": 42,
                "pre_wait_delay": 2,
                "post_wait_delay": 3,
                "_ansible_check_mode": True,
            }
        )
    )
    assert result["elapsed"] == 5.0
    assert result["changed"] is False
    payload.native.processes.assert_called_once()


def test_presence_timeout_keeps_elapsed_and_matches(payload: ModuleType) -> None:
    payload.native.processes.return_value = []
    result = payload._wait(
        payload._parameters({"pid": 42, "timeout": 0})
    )  # pylint: disable=protected-access
    assert result["failed"] is True
    assert result["changed"] is False
    assert result["elapsed"] == 1.0
    assert result["matched_processes"] == []


def test_exit_timeout_and_ignored_options_are_observable(payload: ModuleType) -> None:
    payload.native.wait_for_exit.return_value = False
    result = payload._wait(  # pylint: disable=protected-access
        payload._parameters(  # pylint: disable=protected-access
            {"pid": 42, "state": "absent", "sleep": 3, "process_min_count": 5}
        )
    )
    assert result["failed"] is True
    assert result["changed"] is False
    assert len(result["warnings"]) == 2
    assert result["matched_processes"] == [PROCESS]


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"pid": 42, "process_name_exact": "worker"},
        {"process_name_pattern": "worker", "process_name_exact": "worker"},
        {"pid": "bad"},
        {"pid": 42, "sleep": -1},
        {"pid": 42, "pre_wait_delay": -1},
        {"pid": 42, "post_wait_delay": -1},
        {"pid": 42, "state": "invalid"},
    ],
)
def test_invalid_arguments_fail_before_waiting(
    payload: ModuleType, arguments: dict[str, object]
) -> None:
    with pytest.raises(ValueError):
        payload._parameters(arguments)  # pylint: disable=protected-access
    payload.native.processes.assert_not_called()


def test_native_wait_holds_each_initial_handle_and_closes_on_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(HELPER.parent))
    native = load_module(
        COLLECTION / "module_utils/legacy_community_windows_process_wait.py",
        "tested_native_community_wait",
    )
    kernel = SimpleNamespace(
        OpenProcess=Mock(side_effect=[101, 102]),
        CloseHandle=Mock(),
        WaitForSingleObject=Mock(side_effect=[0, 258]),
    )
    monkeypatch.setattr(
        native.ctypes, "WinDLL", Mock(return_value=kernel), raising=False
    )
    assert native.wait_for_exit([41, 42], 0) is False
    assert kernel.OpenProcess.call_args_list == [
        call(0x00100000, False, 41),
        call(0x00100000, False, 42),
    ]
    assert kernel.CloseHandle.call_args_list == [call(102), call(101)]


def test_native_snapshot_filters_names_case_insensitively_and_resolves_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(HELPER.parent))
    native = load_module(
        COLLECTION / "module_utils/legacy_community_windows_process_wait.py",
        "tested_native_community_snapshot",
    )
    connection = SimpleNamespace(
        query=Mock(
            return_value=[
                {"ProcessId": 42, "Name": "Worker.EXE", "__PATH": "process42"},
                {"ProcessId": 43, "Name": "other.exe", "__PATH": "process43"},
            ]
        ),
        call_method=Mock(
            return_value={"ReturnValue": 0, "Domain": "HOST", "User": "user"}
        ),
    )
    manager = Mock(
        __enter__=Mock(return_value=connection), __exit__=Mock(return_value=False)
    )
    monkeypatch.setattr(native, "WmiConnection", Mock(return_value=manager))
    monkeypatch.setattr(native.account, "name_to_sid", Mock(return_value="S-1-5-21-42"))
    monkeypatch.setattr(
        native.account, "account_name_to_sid", Mock(return_value="S-1-5-21-42")
    )
    result = native.processes(
        {
            "pid": 0,
            "process_name_exact": ["worker"],
            "process_name_pattern": None,
            "owner": "user",
        }
    )
    assert result == [{"name": "Worker", "pid": 42, "owner": r"HOST\user"}]
    connection.call_method.assert_called_once()
