"""Use the Windows collection's reboot action after a native AD operation."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Any

# Ansible's controller extension interfaces do not distribute typing metadata.
from ansible.module_utils.common.validation import (  # type: ignore[import-untyped]
    check_type_bool,
)
from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)

from ..module_utils.legacy_ad_arguments import as_int32


class RebootingAction(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Execute an AD payload and honor its upstream reboot_required contract."""

    def run(
        self, tmp: str | None = None, task_vars: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Run the module and optionally reboot using the established Windows action.

        :param tmp: Deprecated Ansible action argument.
        :param task_vars: Variables supplied to module and reboot execution.
        :returns: Module result, or a failure containing module and reboot results.
        :raises TypeError: Reboot arguments cannot be converted.
        :raises ValueError: Reboot timeout is not a signed decimal Int32.
        :raises Exception: Shared module execution or action loading fails.
        """
        reboot = check_type_bool(self._task.args.get("reboot", False))
        timeout = as_int32(self._task.args.get("reboot_timeout", 600), "reboot_timeout")
        if reboot and self._task.async_val:
            return {
                "failed": True,
                "changed": False,
                "msg": "async is not supported for this task when reboot=true",
            }
        result = super().run(tmp=tmp, task_vars=task_vars)
        if not reboot or not result.get("reboot_required", False):
            return result
        reboot_result: dict[str, Any] = {}
        if not self._task.check_mode:
            task = self._task.copy()
            task.action = "sustainablelobster.legacy_windows.win_reboot"
            task.args = {"reboot_timeout": timeout}
            # These arguments are Ansible's action constructor contract, not a
            # reusable operation shared with the unrelated template action.
            # pylint: disable=duplicate-code
            action = self._shared_loader_obj.action_loader.get(
                task.action,
                task=task,
                connection=self._connection,
                play_context=self._play_context,
                loader=self._loader,
                templar=self._templar,
                shared_loader_obj=self._shared_loader_obj,
            )
            # pylint: enable=duplicate-code
            reboot_result = action.run(task_vars=task_vars)
        if reboot_result.get("failed") or reboot_result.get("unreachable"):
            failure = {
                "changed": result.get("changed", False),
                "failed": True,
                "msg": "Failed to reboot after module returned reboot_required, "
                "see reboot_result and module_result for more details",
                "reboot_result": reboot_result,
                "module_result": result,
            }
            if "invocation" in result:
                failure["invocation"] = result["invocation"]
            return failure
        result.update(changed=True, reboot_required=False)
        return result
