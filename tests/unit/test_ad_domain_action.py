"""Verify promotion recovery and legacy post-reboot functional-level completion."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Tests control the action's native module/reboot boundaries.
# pylint: disable=protected-access

from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
from ansible_collections.sustainablelobster.legacy_ad.plugins.action.domain import (
    ActionModule,
)

from tests.unit.test_python_action import _action


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("reboot", [False, True])
def test_pending_role_change_is_retried_once_only_after_requested_successful_reboot(
    monkeypatch: pytest.MonkeyPatch,
    check: bool,
    reboot: bool,
) -> None:
    action, shell, events = _action(ActionModule, monkeypatch)
    action._task.args = {"reboot": reboot, "reboot_timeout": 321}
    action._task.check_mode = check
    reboot_task = SimpleNamespace()
    action._task.copy = Mock(return_value=reboot_task)
    reboot_action = Mock()
    reboot_action.run.return_value = {"failed": False, "rebooted": True}
    loader = Mock()
    loader.get.return_value = reboot_action
    action._shared_loader_obj = SimpleNamespace(action_loader=loader)
    pending = {
        "changed": False,
        "failed": True,
        "msg": "Restart first",
        "reboot_required": True,
        "_do_action_reboot": True,
    }
    complete = {
        "changed": True,
        "reboot_required": True,
        "_do_action_reboot": False,
        "invocation": {"module_args": {"reboot": reboot}},
    }
    execute = Mock(side_effect=[pending.copy(), complete.copy()])
    monkeypatch.setattr(action, "_execute_module", execute)
    result = action.run(task_vars={"example": "value"})
    assert "_do_action_reboot" not in result
    assert execute.call_count == (2 if reboot and not check else 1)
    assert (
        shell.tmpdir is None
        and len([event for event in events if event[0] == "cleanup"])
        == execute.call_count
    )
    if reboot:
        assert result["changed"] is True and result["reboot_required"] is False
        if check:
            assert result["failed"] is False and "msg" not in result
            loader.get.assert_not_called()
        else:
            assert result["invocation"] == complete["invocation"]
            assert reboot_task.action == "sustainablelobster.legacy_windows.win_reboot"
            assert reboot_task.args == {"reboot_timeout": 321}
            assert reboot_action.run.call_count == 2
    else:
        assert result["failed"] is True and result["reboot_required"] is True
        loader.get.assert_not_called()


def test_reboot_failure_is_not_retried_and_keeps_module_failure_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, _shell, _events = _action(ActionModule, monkeypatch)
    action._task.args = {"reboot": True}
    action._task.copy = Mock(return_value=SimpleNamespace())
    reboot = Mock()
    reboot.run.return_value = {"failed": True, "msg": "connection did not recover"}
    loader = Mock()
    loader.get.return_value = reboot
    action._shared_loader_obj = SimpleNamespace(action_loader=loader)
    pending = {
        "changed": False,
        "failed": True,
        "msg": "Restart first",
        "reboot_required": True,
        "_do_action_reboot": True,
    }
    execute = Mock(return_value=pending.copy())
    monkeypatch.setattr(action, "_execute_module", execute)
    result = action.run()
    assert result["failed"] is True and result["module_result"] == {
        name: value for name, value in pending.items() if name != "_do_action_reboot"
    }
    reboot_result = result["reboot_result"]
    assert isinstance(reboot_result, dict)
    assert reboot_result["msg"] == "connection did not recover"
    execute.assert_called_once()


def test_repeated_pending_role_change_does_not_create_an_unbounded_retry_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, _shell, _events = _action(ActionModule, monkeypatch)
    action._task.args = {"reboot": True}
    action._task.copy = Mock(return_value=SimpleNamespace())
    reboot = Mock()
    reboot.run.return_value = {"failed": False}
    loader = Mock()
    loader.get.return_value = reboot
    action._shared_loader_obj = SimpleNamespace(action_loader=loader)
    pending = {
        "changed": False,
        "failed": True,
        "msg": "Restart first",
        "reboot_required": True,
        "_do_action_reboot": True,
    }
    execute = Mock(side_effect=[pending.copy(), pending.copy()])
    monkeypatch.setattr(action, "_execute_module", execute)
    result = action.run()
    assert result["failed"] is True and result["changed"] is True
    assert "_do_action_reboot" not in result
    assert execute.call_count == 2 and reboot.run.call_count == 2


@pytest.mark.parametrize("completion_failure", [False, True])
def test_successful_legacy_promotion_completes_levels_once_after_reboot(
    monkeypatch: pytest.MonkeyPatch,
    completion_failure: bool,
) -> None:
    action, _shell, _events = _action(ActionModule, monkeypatch)
    original = {"reboot": True, "dns_domain_name": "example.test"}
    action._task.args = original
    action._task.copy = Mock(return_value=SimpleNamespace())
    reboot_action = Mock()
    reboot_action.run.return_value = {"failed": False}
    action._shared_loader_obj = SimpleNamespace(
        action_loader=Mock(get=Mock(return_value=reboot_action))
    )
    seen: list[dict[str, Any]] = []

    def execute(**_kwargs: Any) -> dict[str, Any]:
        """Return the two owned native boundary results.

        :param _kwargs: Unchanged action execution arguments.
        :returns: Promotion followed by functional-level completion.
        :rtype: dict
        """
        seen.append(action._task.args.copy())
        if len(seen) == 1:
            return {
                "changed": True,
                "reboot_required": True,
                "_legacy_ad_complete_promotion": True,
            }
        return {
            "changed": False,
            "reboot_required": False,
            "failed": completion_failure,
        }

    monkeypatch.setattr(action, "_execute_module", execute)
    result = action.run()
    assert seen == [
        original,
        dict(original, _ansible_legacy_ad_complete_promotion=True),
    ]
    assert action._task.args is original
    assert result["changed"] is True and result["failed"] is completion_failure
    assert result["reboot_required"] is False
    assert reboot_action.run.call_count == 1
    assert "_legacy_ad_complete_promotion" not in result


@pytest.mark.parametrize("failure", ["failed", "unreachable"])
def test_legacy_completion_is_not_run_when_reboot_fails_or_cannot_reconnect(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    action, _shell, _events = _action(ActionModule, monkeypatch)
    action._task.args = {"reboot": True}
    action._task.copy = Mock(return_value=SimpleNamespace())
    reboot_action = Mock()
    reboot_action.run.return_value = {failure: True, "msg": "offline"}
    action._shared_loader_obj = SimpleNamespace(
        action_loader=Mock(get=Mock(return_value=reboot_action))
    )
    execute = Mock(
        return_value={
            "changed": True,
            "reboot_required": True,
            "_legacy_ad_complete_promotion": True,
        }
    )
    monkeypatch.setattr(action, "_execute_module", execute)
    result = action.run()
    assert result["failed"] is True and result["changed"] is True
    assert result["reboot_result"] == {failure: True, "msg": "offline"}
    module_result = result["module_result"]
    assert isinstance(module_result, dict)
    assert "_legacy_ad_complete_promotion" not in module_result
    assert module_result["changed"] is True
    assert module_result["reboot_required"] is True
    execute.assert_called_once()
    reboot_action.run.assert_called_once()


@pytest.mark.parametrize(
    "outcome", ["completed", "reboot_failed", "pending_again", "level_failed"]
)
def test_pending_retry_finishes_legacy_levels_only_after_successful_promotion(
    monkeypatch: pytest.MonkeyPatch,
    outcome: str,
) -> None:
    action, shell, events = _action(ActionModule, monkeypatch)
    original = {"reboot": True, "dns_domain_name": "example.test"}
    action._task.args = original
    action._task.copy = Mock(return_value=SimpleNamespace())
    reboot = Mock()
    reboot.run.side_effect = [
        {"failed": False},
        {"failed": outcome == "reboot_failed", "msg": "second reboot"},
    ]
    action._shared_loader_obj = SimpleNamespace(
        action_loader=Mock(get=Mock(return_value=reboot))
    )
    pending = {
        "changed": False,
        "failed": True,
        "reboot_required": True,
        "_do_action_reboot": True,
        "msg": "Restart first",
    }
    results = [
        pending.copy(),
        (
            pending.copy()
            if outcome == "pending_again"
            else {
                "changed": True,
                "reboot_required": True,
                "_legacy_ad_complete_promotion": True,
            }
        ),
        {
            "changed": False,
            "reboot_required": False,
            "failed": outcome == "level_failed",
        },
    ]
    seen: list[dict[str, Any]] = []

    def execute(**_kwargs: Any) -> dict[str, Any]:
        """Return pending, retried promotion and optional completion results.

        :param _kwargs: Standard native module execution arguments.
        :returns: The next owned native boundary result.
        :rtype: dict
        """
        seen.append(action._task.args.copy())
        return results.pop(0)

    monkeypatch.setattr(action, "_execute_module", execute)
    result = action.run()
    completes_levels = outcome in ("completed", "level_failed")
    assert seen == [original, original] + (
        [dict(original, _ansible_legacy_ad_complete_promotion=True)]
        if completes_levels
        else []
    )
    assert action._task.args is original
    assert result["changed"] is True
    assert bool(result.get("failed")) == (outcome != "completed")
    assert reboot.run.call_count == 2
    assert shell.tmpdir is None
    assert len([event for event in events if event[0] == "cleanup"]) == len(seen)
    assert "_do_action_reboot" not in result
    assert "_legacy_ad_complete_promotion" not in result
    module_result = result.get("module_result", {})
    assert isinstance(module_result, dict)
    assert "_do_action_reboot" not in module_result
    assert "_legacy_ad_complete_promotion" not in module_result
