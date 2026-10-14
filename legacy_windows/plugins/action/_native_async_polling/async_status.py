"""Opt in to native automatic status without changing non-native host behavior."""

# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Any, cast

from ansible.plugins.loader import (  # type: ignore[import-untyped]
    action_loader,
    shell_loader,
)

_CORE_STATUS_ACTION = action_loader.get("ansible.builtin.async_status", class_only=True)
_NATIVE_STATUS_ACTION = action_loader.get(
    "sustainablelobster.legacy_windows.async_status", class_only=True
)
_NATIVE_CMD_SHELL = shell_loader.get(
    "sustainablelobster.legacy_windows.cmd", class_only=True
)


# This legacy entry point is outside the collection's Python package. Standard
# loaders resolve its installed classes; their inherited public API is opaque
# to static analyzers, not missing from the action lifecycle.
class ActionModule(_NATIVE_STATUS_ACTION):  # type: ignore[misc, valid-type]  # pylint: disable=too-few-public-methods
    """Route legacy polling to native status only for the collection's cmd shell."""

    _supports_native_windows_polling = True

    def _native_shell(self) -> bool:
        # The action extension API exposes the selected connection's private shell.
        # pylint: disable=protected-access
        return isinstance(self._connection._shell, _NATIVE_CMD_SHELL)
        # pylint: enable=protected-access

    # The builtin and native status actions share this private keyword boundary.
    # pylint: disable=arguments-differ,protected-access
    def _execute_module(self, **kwargs: Any) -> dict[str, Any]:
        if self._native_shell():
            return cast(dict[str, Any], super()._execute_module(**kwargs))
        # Forward the same private execution boundary the builtin action invokes.
        return cast(dict[str, Any], _CORE_STATUS_ACTION._execute_module(self, **kwargs))

    # pylint: enable=arguments-differ,protected-access

    def run(
        self, tmp: str | None = None, task_vars: dict[str, object] | None = None
    ) -> dict[str, Any]:
        """Use the host's existing status lifecycle without changing task fields.

        :param tmp: Deprecated Ansible action argument; no longer used.
        :param task_vars: Variables supplied by normal automatic polling.
        :returns: The selected native or unchanged builtin status result.
        """
        if self._native_shell():
            return cast(dict[str, Any], super().run(tmp, task_vars))
        return cast(dict[str, Any], _CORE_STATUS_ACTION.run(self, tmp, task_vars))
