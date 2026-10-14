"""Exercise DNS staging through the actual normal Python action lifecycle."""

# SPDX-License-Identifier: GPL-3.0-or-later
# pylint: disable=protected-access

from pathlib import Path

import pytest
from ansible_collections.sustainablelobster.legacy_windows.plugins.action.win_dns_zone import (
    ActionModule,
)

from tests.unit.test_python_action import _action


def test_dns_action_stages_exact_native_closure_and_cleans_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, shell, events = _action(ActionModule, monkeypatch)
    action._task.action = "sustainablelobster.legacy_windows.win_dns_zone"
    assert action.run(task_vars={}) == {"changed": False, "ping": "pong"}
    transfers = [Path(str(event[1])).name for event in events if event[0] == "transfer"]
    assert transfers == [
        "legacy_windows_module.py",
        "legacy_windows_wmi.py",
        "legacy_windows_dns_classic.py",
        "legacy_windows_dns_zone.py",
    ]
    modules = [event for event in events if event[0] == "module"]
    assert modules == [("module", {"task_vars": {}, "wrap_async": 0})]
    assert action._task.action == "sustainablelobster.legacy_windows.win_dns_zone"
    assert len([event for event in events if event[0] == "cleanup"]) == 1
    assert shell.tmpdir is None
