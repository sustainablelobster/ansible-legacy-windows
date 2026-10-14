"""Check record helper staging and cleanup through Ansible's action lifecycle."""

# SPDX-License-Identifier: GPL-3.0-or-later
# The lifecycle fixture supplies the real action's private Ansible task fields.
# pylint: disable=protected-access

from pathlib import Path

import pytest
from ansible_collections.sustainablelobster.legacy_windows.plugins.action.win_dns_record import (
    ActionModule,
)

from tests.unit.test_python_action import _action


def test_record_action_stages_native_closure_and_cleans_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, shell, events = _action(ActionModule, monkeypatch)
    action._task.action = "sustainablelobster.legacy_windows.win_dns_record"
    assert action.run(task_vars={}) == {"changed": False, "ping": "pong"}
    assert [Path(str(item[1])).name for item in events if item[0] == "transfer"] == [
        "legacy_windows_module.py",
        "legacy_windows_wmi.py",
        "legacy_windows_dns_classic.py",
        "legacy_windows_dns_record.py",
    ]
    assert [item for item in events if item[0] == "module"] == [
        ("module", {"task_vars": {}, "wrap_async": 0})
    ]
    assert action._task.action == "sustainablelobster.legacy_windows.win_dns_record"
    assert len([item for item in events if item[0] == "cleanup"]) == 1
    assert shell.tmpdir is None
