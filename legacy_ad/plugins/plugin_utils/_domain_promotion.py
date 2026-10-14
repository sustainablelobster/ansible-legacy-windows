"""Coordinate pending role recovery and legacy post-reboot functional levels."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Any

# Ansible controller extensions do not publish typing metadata.
from ansible.module_utils.common.validation import (  # type: ignore[import-untyped]
    check_type_bool,
)

from ._reboot import RebootingAction


class DomainPromotionAction(RebootingAction):  # pylint: disable=too-many-ancestors
    """Complete native promotion and its bounded post-reboot work."""

    def run(
        self, tmp: str | None = None, task_vars: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Run promotion, finish legacy levels, and keep recovery flags private.

        :param tmp: Deprecated Ansible action argument.
        :param task_vars: Variables for module execution and rebooting.
        :returns: Final module result or the shared reboot failure envelope.
        :raises TypeError: The reboot option cannot be converted.
        :raises Exception: Shared execution or reboot action loading fails.
        """
        reboot = check_type_bool(self._task.args.get("reboot", False))
        result = super().run(tmp=tmp, task_vars=task_vars)
        if reboot and result.get("_do_action_reboot", False):
            if self._task.check_mode:
                result["failed"] = False
                result.pop("msg", None)
            else:
                result = super().run(tmp=tmp, task_vars=task_vars)
        complete = result.pop("_legacy_ad_complete_promotion", False)
        if (
            complete
            and reboot
            and not self._task.check_mode
            and not result.get("failed")
            and not result.get("unreachable")
        ):
            previous_arguments = self._task.args
            self._task.args = dict(
                previous_arguments, _ansible_legacy_ad_complete_promotion=True
            )
            try:
                completion = super().run(tmp=tmp, task_vars=task_vars)
            finally:
                self._task.args = previous_arguments
            completion["changed"] = result.get("changed", False) or completion.get(
                "changed", False
            )
            if result.get("warnings"):
                completion["warnings"] = result["warnings"] + completion.get(
                    "warnings", []
                )
            result = completion
        result.pop("_do_action_reboot", None)
        result.pop("_legacy_ad_complete_promotion", None)
        module_result = result.get("module_result")
        if isinstance(module_result, dict):
            module_result.pop("_do_action_reboot", None)
            module_result.pop("_legacy_ad_complete_promotion", None)
        return result
