"""Transfer controller configurations before the native DSC v3 payload runs."""

# SPDX-License-Identifier: GPL-3.0-or-later

import os

# Ansible's action interfaces do not distribute Python typing metadata.
from ansible.errors import AnsibleActionFail  # type: ignore[import-untyped]
from ansible.module_utils.common.validation import (  # type: ignore[import-untyped]
    check_type_bool,
)

from ..plugin_utils._module import PythonModuleAction


# Reuse normal execution and helper ownership rather than a new transfer lifecycle.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Preserve the released local/remote configuration selection behavior."""

    EXTRA_MODULE_UTILS = ("legacy_windows_process.py", "legacy_windows_text.py")

    def _stage_module_utils(self, *, wrap_async: bool = False) -> None:
        super()._stage_module_utils(wrap_async=wrap_async)
        args = self._task.args
        config_file = args.get("config_file")
        if not config_file or check_type_bool(args.get("remote_config_file", False)):
            return
        full_path = self._find_needle("files", config_file)
        # Configuration and staged helpers share the normal action's task directory.
        shell = self._connection._shell  # pylint: disable=protected-access
        # A configuration may have a helper's basename; never overwrite staged code.
        remote_path = shell.join_path(
            shell.tmpdir, "dsc-config-" + os.path.basename(full_path)
        )
        self._transfer_file(full_path, remote_path)
        self._task.args = dict(args, config_file=remote_path, remote_config_file=True)

    def run(
        self, tmp: str | None = None, task_vars: dict[str, object] | None = None
    ) -> dict[str, object]:
        """Execute a configuration, transferring controller files when selected.

        :param tmp: Deprecated Ansible action argument.
        :param task_vars: Variables passed to normal module execution.
        :returns: Complete normal result, or the shared native async launch result.
        :raises AnsibleActionFail: For conflicting input or local-file async use.
        """
        original_args = self._task.args
        config_file = original_args.get("config_file")
        remote_config = check_type_bool(original_args.get("remote_config_file", False))
        if config_file and not remote_config:
            if original_args.get("config"):
                raise AnsibleActionFail(
                    "parameters are mutually exclusive: config, config_file"
                )
            if self._task.async_val:
                raise AnsibleActionFail(
                    "async operations are not supported with local config_file"
                )
        try:
            result = super().run(tmp, task_vars)
            if config_file and not remote_config:
                invocation = result.get("invocation")
                if isinstance(invocation, dict):
                    module_args = invocation.get("module_args")
                    if isinstance(module_args, dict):
                        module_args["config_file"] = config_file
                        module_args["remote_config_file"] = remote_config
            return result
        finally:
            self._task.args = original_args
