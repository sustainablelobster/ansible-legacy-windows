"""Require literal input, live ownership and unassisted automatic-job closure."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These fixture substitutes do not establish Windows execution support.
# pylint: disable=protected-access

import base64
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="fixture")
def automatic_fixture(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load the fixture with exact accepted comparator sources, without Win32 I/O.

    :param monkeypatch: Temporary registry import substitute for source loading.
    :returns: Fixture module using its real typed public comparator.
    """
    monkeypatch.setitem(sys.modules, "winreg", ModuleType("winreg"))
    module = load_module(
        ROOT / "tests/integration/fixtures/native_async_runas_poll.py",
        "tested_automatic_runas_fixture",
    )
    monkeypatch.setattr(module, "WMI_SOURCE", "literal WMI source", raising=False)
    for name, filename in (
        ("ASYNC_SOURCE", "native_async.py"),
        ("RUNAS_ASYNC_SOURCE", "native_async_runas.py"),
    ):
        source = (
            (ROOT / "tests/integration/fixtures" / filename)
            .read_text(encoding="utf-8")
            .split('if __name__ == "__main__":')[0]
        )
        monkeypatch.setattr(module, name, source, raising=False)
    return module


def _pair(workspace: Path, phase: str, offset: int) -> tuple[dict[str, Any], list[Any]]:
    expected = {
        "sid": "S-1-5-18" if phase == "system" else "S-1-5-21-1-2-3-500",
        "python": [3, 4, 4],
        "body_base64": base64.b64encode(b"binary\x00\x01body \xce\xbb\r\n").decode(
            "ascii"
        ),
        "environment": "literal λ %PATH% !text! & | < > ^",
    }
    values, records = [], []
    for index in range(2):
        identifier = f"j{offset}.{index + 1}"
        worker = {"pid": offset + index, "created": 100, "alive": True}
        payload = {"pid": offset + index + 1000, "created": 200, "alive": True}
        result = {
            "ansible_job_id": identifier,
            "ansible_async_watchdog_pid": worker["pid"],
            "results_file": str(workspace / "cache" / identifier),
            "started": True,
            "finished": True,
            "changed": True,
            "start": "2026-10-03 01:02:03.123456",
            "end": "2026-10-03 01:02:06.123456",
            "delta": "0:00:03.000000",
            "rc": 0,
            "stdout": json.dumps(expected, sort_keys=True),
            "stderr": "",
            "stdout_lines": [json.dumps(expected, sort_keys=True)],
            "stderr_lines": [],
            "cmd": ["python.exe", "literal-owned.py", phase],
        }
        record = {
            "phase": phase,
            "launch": dict(result),
            "worker": worker,
            "payload": payload,
            "ancestors": [payload, worker],
        }
        records.append(record)
        values.append(result)
    values[1]["start"] = "2026-10-03 02:02:03.123456"
    values[1]["end"] = "2026-10-03 02:02:06.123456"
    return {
        "phase": phase,
        "native": values[0],
        "source": values[1],
        "expected": expected,
    }, records


def _write_records(workspace: Path, records: list[Any]) -> None:
    for record in records:
        identifier = record["launch"]["ansible_job_id"]
        (workspace / ("payload-" + identifier + ".json")).write_text(
            json.dumps(record), encoding="utf-8"
        )


@pytest.mark.parametrize(
    "difference",
    [
        None,
        "stdin",
        "sid",
        "environment",
        "python",
        "rc-type",
        "extra-field",
        "time",
        "watchdog",
        "live-birth",
        "phase",
        "missing",
    ],
)
def test_whole_results_reject_input_identity_type_ownership_and_missing_evidence(
    fixture: Any, tmp_path: Path, difference: str | None
) -> None:
    workspace = tmp_path / "legacy-windows-native-async-runas-poll-owned"
    workspace.mkdir()
    (workspace / "cache").mkdir()
    user, user_records = _pair(workspace, "user", 100)
    system, system_records = _pair(workspace, "system", 200)
    pairs, records = [user, system], user_records + system_records
    source = user["source"]
    if difference in ("stdin", "sid", "environment", "python"):
        body = json.loads(source["stdout"])
        key = {"stdin": "body_base64"}.get(difference, difference)
        body[key] = "not literal"
        source["stdout"] = json.dumps(body)
    elif difference == "rc-type":
        source["rc"] = False
    elif difference == "extra-field":
        source["extra_public_result"] = True
    elif difference == "time":
        source["delta"] = "0:00:09.000000"
    elif difference == "watchdog":
        source["ansible_async_watchdog_pid"] += 1
    elif difference == "live-birth":
        user_records[1]["worker"]["alive"] = False
    elif difference == "phase":
        user_records[1]["phase"] = "system"
    elif difference == "missing":
        records.pop()
    _write_records(workspace, records)
    before = json.dumps(pairs)
    if difference:
        with pytest.raises((AssertionError, KeyError, ValueError)):
            fixture._compare(str(workspace), pairs)
    else:
        assert fixture._compare(str(workspace), pairs) == {
            "complete_typed_public_equal": True,
            "pairs": 2,
        }
    assert json.dumps(pairs) == before


@pytest.mark.parametrize("residue", [None, "process", "cache", "staging"])
def test_natural_closure_does_not_terminate_or_delete_to_pass(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, residue: str | None
) -> None:
    observation = {
        "processes": [
            {
                "expected": {"created": 100},
                "actual": {"created": 100, "alive": residue == "process"},
            }
        ],
        "cache": ["j1.2"] if residue == "cache" else [],
        "staging": ["ansible-tmp-owned"] if residue == "staging" else [],
    }
    observer = {"_observe": Mock(return_value=observation), "_cleanup": Mock()}
    monkeypatch.setattr(fixture, "_async_observer", lambda: observer)
    monkeypatch.setattr(fixture, "_records", lambda _: {"owned": True})
    ticks = iter([0, 31])
    monkeypatch.setattr(fixture.time, "monotonic", lambda: next(ticks))
    if residue:
        with pytest.raises(RuntimeError, match="naturally close"):
            fixture._inspect("legacy-windows-native-async-runas-poll-owned")
    else:
        assert fixture._inspect("legacy-windows-native-async-runas-poll-owned") == {
            "natural_exit": True,
            "automatic_cache_absence": True,
            "observation": observation,
            "payloads": {"owned": True},
        }
    observer["_cleanup"].assert_not_called()


def test_public_tasks_are_identical_with_real_binary_stdin_and_core_polling() -> None:
    play = yaml.safe_load(
        (ROOT / "tests/integration/native_async_runas_poll.yml").read_text(
            encoding="utf-8"
        )
    )[0]
    block = play["tasks"][-1]
    jobs = [task for task in block["block"] if task.get("async")]
    assert len(jobs) == 4
    for offset, user in ((0, "{{ ansible_user }}"), (2, "NT AUTHORITY\\SYSTEM")):
        native, source = jobs[offset : offset + 2]
        assert (
            native["sustainablelobster.legacy_windows.win_command"]
            == source["ansible.windows.win_command"]
        )
        for task in (native, source):
            assert task["async"] == 60 and task["poll"] == 1
            assert task["become"] is True and task["become_user"] == user
            assert "until" not in task
            assert task["environment"]["LEGACY_WINDOWS_RUNAS_TEST"] == (
                "{{ native_async_runas_poll_environment }}"
            )
        assert source["vars"]["ansible_shell_type"] == "cmd"
        assert (
            "stdin_add_newline"
            not in native["sustainablelobster.legacy_windows.win_command"]
        )
    variables = yaml.safe_load(
        (ROOT / "tests/integration/vars/native_async_runas_poll.yml").read_text(
            encoding="utf-8"
        )
    )
    assert variables["native_async_runas_poll_stdin"].encode("utf-8") == (
        b"binary\x00\x01body \xce\xbb\r\n"
    )
    assert not any(
        "async_status" in key
        for task in block["block"] + block["always"]
        for key in task
    )
    cleanup = block["always"]
    recover = next(
        task
        for task in cleanup
        if task.get("register") == "native_async_runas_poll_recovery"
    )
    assert (
        recover["become_user"] == "NT AUTHORITY\\SYSTEM"
        and recover["failed_when"] is False
    )
    persist = next(
        index
        for index, task in enumerate(cleanup)
        if task["name"].startswith("Preserve all raw")
    )
    gate = next(
        index
        for index, task in enumerate(cleanup)
        if task["name"].startswith("Require protected")
    )
    delete = next(
        index
        for index, task in enumerate(cleanup)
        if task["name"].startswith("Delete only")
    )
    assert persist < gate < delete
