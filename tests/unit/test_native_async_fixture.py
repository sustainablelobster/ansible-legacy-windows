"""Require effective async fixture selection before acquiring a Windows lease."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

from tests.unit.integration_selection import assert_local_selection
from tests.unit.payload_support import ROOT, load_module


def _async_tasks(tasks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for task in tasks:
        if "async" in task:
            result.append(task)
        for keyword in ("block", "rescue", "always"):
            result.extend(_async_tasks(task.get(keyword, [])))
    return result


@pytest.mark.parametrize("compare", [False, True])
def test_automatic_poll_fixture_effective_selection_before_lab(
    tmp_path: Path, compare: bool
) -> None:
    integration = ROOT / "tests/integration"
    play = yaml.safe_load((integration / "native_async_poll.yml").read_text())[0]
    jobs = _async_tasks(play["tasks"])
    assert len(jobs) == 5
    assert all(task["poll"] == 1 for task in jobs)
    assert [task["async"] for task in jobs] == [30, 30, 30, 30, 12]
    assert jobs[1]["when"] == "native_async_poll_compare | bool"
    assert jobs[1]["vars"]["ansible_shell_type"] == "cmd"
    assert jobs[2]["sustainablelobster.legacy_windows.win_command"]["argv"][-1] == (
        "record_running"
    )
    assert jobs[2]["sustainablelobster.legacy_windows.win_command"]["stdin"] == (
        "{{ native_async_program }}"
    )
    assert jobs[2]["register"] == "native_async_poll_recorded"
    extra = tmp_path / "source.yml"
    extra.write_text(
        f"native_async_poll_compare: {str(compare).lower()}\n", encoding="utf-8"
    )
    assert_local_selection(
        tmp_path,
        {
            **play["vars"],
            "native_async_source_root": str(ROOT),
            "expected_compare": compare,
        },
        [
            "native_async_poll_compare == expected_compare",
            "'def _process(pid):' in native_async_program",
            "'def _record_running_job(workspace):' in native_async_program",
        ],
        [str(integration / path) for path in play["vars_files"]],
        extra,
    )


def test_failed_launch_fixture_has_one_explicit_zero_deadline_request(
    tmp_path: Path,
) -> None:
    play = yaml.safe_load(
        (ROOT / "tests/integration/native_async_launch_failure.yml").read_text()
    )[0]
    jobs = _async_tasks(play["tasks"])
    assert len(jobs) == 1
    assert (jobs[0]["async"], jobs[0]["poll"]) == (30, 0)
    assert jobs[0]["vars"]["ansible_win_async_startup_timeout"] == 0
    assert "ansible.builtin.config" in play["vars"]["native_async_failure_keepfiles"]

    def _check_raw(tasks: list[dict[str, Any]]) -> None:
        for task in tasks:
            if "ansible.builtin.raw" in task:
                program = re.search(r' -c\s+"([^\"]+)"', task["ansible.builtin.raw"])
                assert program is not None
                compile(program.group(1), "owned_launch_failure_observation", "exec")
            for keyword in ("block", "rescue", "always"):
                _check_raw(task.get(keyword, []))

    _check_raw(play["tasks"])
    assert_local_selection(
        tmp_path,
        play["vars"],
        ["native_async_failure_keepfiles is boolean"],
        [],
    )


def test_automatic_poll_error_timeout_and_birth_cleanup_gates_parse_locally(
    tmp_path: Path,
) -> None:
    play = yaml.safe_load(
        (ROOT / "tests/integration/native_async_poll.yml").read_text()
    )[0]
    block = next(task["block"] for task in play["tasks"] if "block" in task)
    names = {
        "Require the failed module result rather than a polling failure",
        "Require the watchdog timeout instead of a lost async job",
        "Require automatic core cleanup before fixture recovery",
        "Require all owned processes closed before fixture recovery",
    }
    conditions = [
        condition
        for task in block
        if task["name"] in names
        for condition in task["ansible.builtin.assert"]["that"]
    ]
    processes = [
        {"expected": {"pid": pid, "created": pid, "alive": True}, "actual": None}
        for pid in (71, 72, 73)
    ]
    assert_local_selection(
        tmp_path,
        {
            "native_async_poll_failure": {
                "failed": True,
                "finished": True,
                "msg": "boom",
            },
            "native_async_poll_timeout": {
                "failed": True,
                "finished": True,
                "msg": "failure during async watchdog: timed out waiting for module completion",
                "ansible_async_watchdog_pid": 72,
            },
            "native_async_poll_recorded": {"ansible_async_watchdog_pid": 71},
            "native_async_poll_observation": {
                "stdout": json.dumps(
                    {"cache": [], "staging": [], "processes": processes}
                )
            },
            "item": processes[0],
        },
        conditions,
        [],
    )


@pytest.mark.parametrize("compare", [False, True])
@pytest.mark.parametrize("timeout", [False, True])
def test_initial_async_fixture_selection_and_protocol(
    tmp_path: Path, compare: bool, timeout: bool
) -> None:
    integration = ROOT / "tests/integration"
    play = yaml.safe_load((integration / "native_async.yml").read_text())[0]
    extra = tmp_path / "source.yml"
    extra.write_text(
        f"native_async_compare: {str(compare).lower()}\n"
        f"native_async_exercise_timeout: {str(timeout).lower()}\n",
        encoding="utf-8",
    )
    assert_local_selection(
        tmp_path,
        {
            "native_async_source_root": str(ROOT),
            "expected_compare": compare,
            "expected_timeout": timeout,
            "native_async_timeout": {"ansible_job_id": "j1.2", "started": True},
        },
        [
            "native_async_compare == expected_compare",
            "native_async_exercise_timeout == expected_timeout",
            "'def _process(pid):' in native_async_program",
            "'WMI_SOURCE = ' in native_async_program",
        ],
        [str(integration / path) for path in play["vars_files"]],
        extra,
    )
    jobs = _async_tasks(play["tasks"])
    assert [task["async"] for task in jobs] == [30, 5, 30]
    assert all(task["poll"] == 0 for task in jobs)
    assert all(task["register"] != "native_async_exercise_timeout" for task in jobs)
    timeout_tasks = {
        "Launch an owned descendant tree that exceeds its deadline",
        "Pin the live watchdog identity before its deadline",
        "Retain the full expected timeout without changing its failed field",
        "Require the source watchdog timeout message",
    }
    for task in play["tasks"][3]["block"]:
        if task["name"] in timeout_tasks:
            assert task["when"] == "native_async_exercise_timeout | bool"
            timeout_tasks.remove(task["name"])
    assert not timeout_tasks


def test_public_fixture_assertions_parse_without_a_windows_connection(
    tmp_path: Path,
) -> None:
    play = yaml.safe_load((ROOT / "tests/integration/native_async.yml").read_text())[0]
    conditions = []
    for task in play["tasks"][3]["block"]:
        if task["name"] == "Require the source watchdog timeout message":
            conditions.extend(task["ansible.builtin.assert"]["that"])
        elif (
            task["name"]
            == "Compare the untouched released async wrapper on modern Windows"
        ):
            for source_task in task["block"]:
                if (
                    source_task["name"]
                    == "Require literal released module payload and metadata types"
                ):
                    conditions.extend(source_task["ansible.builtin.assert"]["that"])
    assert len(conditions) == 10
    metadata = {
        "ansible_job_id": "j1.2",
        "ansible_async_watchdog_pid": 1234,
        "ping": "async café λ",
        "started": True,
        "finished": True,
        "changed": False,
    }
    assert_local_selection(
        tmp_path,
        {
            "native_async_timeout_status": {
                "failed": True,
                "msg": "failure during async watchdog: timed out waiting for module completion",
                "stdout": None,
                "stderr": "",
            },
            "native_async_original_ping": metadata,
            "native_async_original_ping_status": metadata,
            "native_async_ping_status": metadata,
        },
        conditions,
        [],
    )


@pytest.mark.parametrize("configuration_changed", [False, True])
def test_owned_recovery_retains_runtime_churn_but_rejects_configuration_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    configuration_changed: bool,
) -> None:
    monkeypatch.setitem(sys.modules, "winreg", ModuleType("winreg"))
    fixture = load_module(
        ROOT / "tests/integration/fixtures/native_async.py", "tested_async_fixture"
    )
    original = {
        "registry": [["key", "value", "literal", 1]],
        "python_executable": "unchanged-bytes",
        "network": [{"Index": 1, "IPAddress": ["192.0.2.1"]}],
        "services": [{"Name": "background", "StartMode": "Manual", "State": "Running"}],
    }
    current = json.loads(json.dumps(original))
    current["services"][0]["State"] = "Stopped"
    if configuration_changed:
        current["services"][0]["StartMode"] = "Disabled"
    monkeypatch.setattr(fixture, "_protected", lambda: current)
    (tmp_path / "journal.json").write_text(
        json.dumps({"workspace": str(tmp_path), "protected": original}),
        encoding="utf-8",
    )
    (tmp_path / "sentinel.bin").write_bytes(b"protected async sentinel\x00\xff")
    (tmp_path / "cache").mkdir()
    (tmp_path / "staging").mkdir()
    # Exercise the private recovery boundary, not a public target module API.
    # pylint: disable=protected-access
    if configuration_changed:
        with pytest.raises(AssertionError):
            fixture._observe(str(tmp_path))
    else:
        result = fixture._observe(str(tmp_path))
        assert result["original_protected"] == original
        assert result["protected"] == current
        assert result["service_state_changes"] == [
            {"name": "background", "expected": "Running", "actual": "Stopped"}
        ]
        assert result["processes"] == [] and result["staging"] == []
    # pylint: enable=protected-access


@pytest.mark.parametrize("failure", [None, "parent", "dead", "multiple", "identifier"])
def test_automatic_payload_records_only_its_live_birth_identified_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str | None,
) -> None:
    monkeypatch.setitem(sys.modules, "winreg", ModuleType("winreg"))
    fixture = load_module(
        ROOT / "tests/integration/fixtures/native_async.py",
        "tested_async_worker_record",
    )
    cache = tmp_path / "cache"
    cache.mkdir()
    metadata = {
        "ansible_job_id": "j123.456",
        "ansible_async_watchdog_pid": 71,
        "started": True,
        "finished": False,
    }
    if failure == "identifier":
        metadata["ansible_job_id"] = "j999.456"
    (cache / "j123.456").write_text(json.dumps(metadata), encoding="utf-8-sig")
    if failure == "multiple":
        (cache / "unowned").write_text("{}", encoding="utf-8")
    parent = 72 if failure == "parent" else 71
    source = (
        "class WmiConnection:\n"
        "    def __enter__(self): return self\n"
        "    def __exit__(self, *args): pass\n"
        "    def query(self, query, fields):\n"
        "        assert query.endswith('ProcessId=81')\n"
        "        assert fields == ['ParentProcessId']\n"
        "        return [{'ParentProcessId': " + str(parent) + "}]\n"
    )
    monkeypatch.setattr(fixture, "WMI_SOURCE", source, raising=False)
    monkeypatch.setattr(fixture.os, "getppid", lambda: 81)
    monkeypatch.setattr(fixture.os, "getpid", lambda: 91)

    def _process(pid: int) -> dict[str, object]:
        return {"pid": pid, "created": pid * 100, "alive": failure != "dead"}

    monkeypatch.setattr(fixture, "_process", _process)
    # This is the fixture's private lifetime boundary, not a target module API.
    # pylint: disable=protected-access
    if failure:
        with pytest.raises(AssertionError):
            fixture._record_running_job(str(tmp_path))
    else:
        assert fixture._record_running_job(str(tmp_path)) == {
            "recorded_live_worker": True
        }
        journal = json.loads((tmp_path / "job-j123.456.json").read_text())
        assert journal["launch"] == metadata
        assert journal["worker"] == {"pid": 71, "created": 7100, "alive": True}
    # pylint: enable=protected-access
