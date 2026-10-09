"""Reject incomplete async runas recovery before workspace deletion."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT, load_module


def test_system_observer_and_recovery_use_system_token() -> None:
    tasks = yaml.safe_load(
        (ROOT / "tests/integration/tasks/native_async_runas_case.yml").read_text(
            encoding="utf-8"
        )
    )
    pin = next(
        task for task in tasks if task.get("register") == "native_async_runas_pin"
    )
    assert pin["become"] is True
    assert pin["become_method"] == "ansible.builtin.runas"
    assert pin["become_user"] == "NT AUTHORITY\\SYSTEM"
    play = yaml.safe_load(
        (ROOT / "tests/integration/native_async_runas.yml").read_text(encoding="utf-8")
    )[0]
    recovery = play["tasks"][-1]["always"]
    cleanup = next(
        task
        for task in recovery
        if task.get("register") == "native_async_runas_recovery"
    )
    assert cleanup["become_user"] == "NT AUTHORITY\\SYSTEM"
    assert cleanup["failed_when"] is False
    assert cleanup["sustainablelobster.legacy_windows.win_command"]["stdin"] == (
        "{{ native_async_runas_recovery_program }}"
    )
    persist = next(
        index
        for index, task in enumerate(recovery)
        if task["name"] == "Preserve recovery diagnostics before enforcing its gate"
    )
    gate = next(
        index
        for index, task in enumerate(recovery)
        if task["name"] == "Require actual successful protected recovery"
    )
    delete = next(
        index
        for index, task in enumerate(recovery)
        if task["name"] == "Remove only the verified owned workspace"
    )
    assert persist < gate < delete
    assert recovery[delete]["become_user"] == "NT AUTHORITY\\SYSTEM"


@pytest.mark.parametrize("failure", ["live-staging", "live-child", "cache", "none"])
def test_recovery_requires_closed_staging_and_children_preserving_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    fixture = load_module(
        ROOT / "tests/integration/fixtures/native_async_runas.py",
        "tested_runas_recovery",
    )
    workspace = tmp_path / "legacy-windows-native-async-runas-owned"
    workspace.mkdir()
    staging = workspace / "staging"
    staging.mkdir()
    if failure == "live-staging":
        (staging / "unrecorded-worker").mkdir()
    (workspace / "system-live.json").write_text(
        json.dumps({"pid": 123, "created": 456}), encoding="utf-8"
    )
    final: dict[str, Any] = {"cache": [], "staging": []}
    if failure == "cache":
        final["cache"] = ["j1.2"]
    cleanup = Mock(return_value={"restored": True, "final": final})
    process = Mock(
        return_value={"pid": 123, "created": 456, "alive": failure == "live-child"}
    )
    monkeypatch.setattr(fixture, "ASYNC_SOURCE", "literal observer", raising=False)
    monkeypatch.setattr(
        fixture, "_namespace", lambda *_: {"_cleanup": cleanup, "_process": process}
    )
    ticks = iter([0, 121])
    monkeypatch.setattr(fixture.time, "monotonic", lambda: next(ticks))
    if failure == "live-staging":
        with pytest.raises(RuntimeError, match="staging did not close"):
            fixture._recover(str(workspace))  # pylint: disable=protected-access
        cleanup.assert_not_called()
    elif failure == "live-child":
        with pytest.raises(AssertionError):
            fixture._recover(str(workspace))  # pylint: disable=protected-access
    else:
        # Exercise the fixture's private recovery boundary without Windows I/O.
        result = fixture._recover(str(workspace))  # pylint: disable=protected-access
        assert result["restored"]
        assert result["final"]["cache"] == final["cache"]
        assert result["payloads"][0]["actual"]["alive"] is False


@pytest.mark.parametrize(
    "mismatch", [None, "stdout", "rc-type", "unknown", "timestamp", "duration"]
)
def test_comparison_preserves_raw_fields_and_rejects_literal_or_type_differences(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mismatch: str | None
) -> None:
    monkeypatch.setitem(sys.modules, "winreg", ModuleType("winreg"))
    fixture = load_module(
        ROOT / "tests/integration/fixtures/native_async_runas.py",
        "tested_runas_compare",
    )
    monkeypatch.setattr(
        fixture,
        "ASYNC_SOURCE",
        (ROOT / "tests/integration/fixtures/native_async.py")
        .read_text(encoding="utf-8")
        .split('if __name__ == "__main__":')[0],
        raising=False,
    )
    cache = tmp_path / "cache"
    cache.mkdir()
    native: dict[str, Any] = {
        "ansible_job_id": "j1.2",
        "ansible_async_watchdog_pid": 12,
        "results_file": str(cache / "j1.2"),
        "started": True,
        "finished": True,
        "start": "2026-10-03 01:02:03.123456",
        "end": "2026-10-03 01:02:04.123456",
        "delta": "0:00:01.000000",
        "stdout": "literal λ",
        "stderr": "",
        "rc": 0,
        "changed": True,
    }
    source = dict(
        native,
        ansible_job_id="j3.4",
        ansible_async_watchdog_pid=34,
        results_file=str(cache / "j3.4"),
        start="2026-10-03 02:02:03.123456",
        end="2026-10-03 02:02:04.123456",
    )
    if mismatch == "stdout":
        source["stdout"] = "different"
    elif mismatch == "rc-type":
        source["rc"] = False
    elif mismatch == "unknown":
        source["unexpected"] = True
    elif mismatch == "timestamp":
        source["start"] = "not a timestamp"
    elif mismatch == "duration":
        source["delta"] = "99:59:59.999999"
    before = json.dumps([native, source])
    pairs = [{"operation": "status", "native": native, "source": source}]
    # Exercise the fixture's private comparator with the real strict observer.
    compare = fixture._compare  # pylint: disable=protected-access
    if mismatch:
        with pytest.raises((AssertionError, ValueError)):
            compare(str(tmp_path), pairs)
    else:
        # Call the maintained comparator, including the real strict observer.
        actual = compare(str(tmp_path), pairs)
        assert actual == {
            "complete_typed_public_equal": True,
            "pairs": 1,
        }
    assert json.dumps([native, source]) == before
