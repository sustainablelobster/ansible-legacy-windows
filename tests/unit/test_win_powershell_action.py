"""Verify controller-side UTF-8 loading and original task-argument recovery."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Ansible action objects expose their extension state through private attributes.
# pylint: disable=protected-access

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from ansible_collections.sustainablelobster.legacy_windows.plugins.action.win_powershell import (
    ActionModule,
)
from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


@pytest.mark.parametrize("async_val", [0, 120])
def test_controller_file_and_invocation_are_restored(
    monkeypatch: pytest.MonkeyPatch,
    async_val: int,
) -> None:
    action = object.__new__(ActionModule)
    original = {"path": "local.ps1", "remote_src": False, "parameters": {"Name": "λ"}}
    action._task = MagicMock(args=original, async_val=async_val, poll=0)
    action._loader = MagicMock()
    action._loader.get_text_file_contents.return_value = "'λ'"
    action._find_needle = MagicMock(return_value="/script/local.ps1")

    def execute(*_args: object) -> dict[str, object]:
        """Check the staged task and return its unchanged public invocation.

        :param _args: Unused action arguments.
        :returns: Simulated public result and invocation.
        """
        assert action._task.args == {
            "remote_src": False,
            "parameters": {"Name": "λ"},
            "script": "'λ'",
        }
        assert action._task.async_val == async_val and action._task.poll == 0
        return {"changed": False, "invocation": {"module_args": {"script": "'λ'"}}}

    monkeypatch.setattr(PythonModuleAction, "run", execute)
    assert action.run() == {
        "changed": False,
        "invocation": {"module_args": {"script": None, "path": "local.ps1"}},
    }
    assert action._task.args is original


@pytest.mark.parametrize("failure", [False, True])
def test_controller_async_launch_preserves_original_args_without_invocation(
    monkeypatch: pytest.MonkeyPatch,
    failure: bool,
) -> None:
    action = object.__new__(ActionModule)
    original = {"path": "local.ps1", "parameters": {"Text": "λ"}}
    action._task = MagicMock(args=original, async_val=120, poll=0)
    action._loader = MagicMock()
    action._loader.get_text_file_contents.return_value = "'λ'"
    action._find_needle = MagicMock(return_value="/script/local.ps1")
    launch = {
        "changed": False,
        "started": True,
        "finished": False,
        "ansible_job_id": "j1.2",
    }

    def execute(*_args: object) -> dict[str, object]:
        """Inspect the delegated async task before returning or raising.

        :param _args: Unused action arguments.
        :returns: The original simulated async launch result.
        :raises RuntimeError: For the simulated failed-launch branch.
        """
        assert action._task.args == {"script": "'λ'", "parameters": {"Text": "λ"}}
        assert action._task.async_val == 120 and action._task.poll == 0
        if failure:
            raise RuntimeError("launch failed")
        return launch

    monkeypatch.setattr(PythonModuleAction, "run", execute)
    if failure:
        with pytest.raises(RuntimeError, match="launch failed"):
            action.run()
    else:
        assert action.run() is launch
    assert action._task.args is original


def test_remote_file_does_not_read_controller(monkeypatch: pytest.MonkeyPatch) -> None:
    action = object.__new__(ActionModule)
    original = {"path": "remote.ps1", "remote_src": True}
    action._task = MagicMock(args=original)
    action._find_needle = MagicMock()
    monkeypatch.setattr(
        PythonModuleAction, "run", MagicMock(return_value={"changed": False})
    )
    assert action.run() == {"changed": False}
    action._find_needle.assert_not_called()
    assert action._task.args is original


def test_local_read_failure_and_execution_failure_keep_original_args(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    action = object.__new__(ActionModule)
    original = {"path": "local.ps1"}
    action._task = MagicMock(args=original)
    action._loader = SimpleNamespace()
    action._find_needle = MagicMock(return_value=str(tmp_path / "missing.ps1"))
    with pytest.raises(FileNotFoundError):
        action.run()
    assert action._task.args is original
    source = tmp_path / "local.ps1"
    source.write_text("'λ'", encoding="utf-8")
    action._find_needle.return_value = str(source)
    monkeypatch.setattr(
        PythonModuleAction,
        "run",
        MagicMock(side_effect=RuntimeError("execution failed")),
    )
    with pytest.raises(RuntimeError, match="execution failed"):
        action.run()
    assert action._task.args is original
