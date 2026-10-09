"""Read controller scripts before staging structured PowerShell Python helpers."""

# SPDX-License-Identifier: GPL-3.0-or-later

# Ansible exposes its extension API without distributed Python type metadata.
from ansible.errors import AnsibleActionFail  # type: ignore[import-untyped]
from ansible.module_utils.common.validation import (  # type: ignore[import-untyped]
    check_type_bool,
)

from ..plugin_utils._module import PythonModuleAction


# Keep normal Ansible staging/cleanup rather than adding a file-transfer lifecycle.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Supply local UTF-8 script content to the normal Python payload."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_powershell_engine.py",
        "legacy_windows_powershell.py",
    )

    def run(
        self, tmp: str | None = None, task_vars: dict[str, object] | None = None
    ) -> dict[str, object]:
        """Load a controller script, preserving the caller's invocation arguments.

        :param tmp: Deprecated Ansible action argument.
        :param task_vars: Variables supplied to normal module execution.
        :returns: Complete public module result.
        :raises AnsibleActionFail: If a local path conflicts with inline script.
        :raises Exception: If reading, staging, or execution fails.
        """
        original_args = self._task.args
        path = original_args.get("path")
        local_path = path and not check_type_bool(
            original_args.get("remote_src", False)
        )
        if local_path:
            if original_args.get("script"):
                raise AnsibleActionFail(
                    "parameters are mutually exclusive: path, script"
                )
            full_path = self._find_needle("files", path)
            if hasattr(self._loader, "get_text_file_contents"):
                content = self._loader.get_text_file_contents(full_path)
            else:
                with open(full_path, "rb") as script_file:
                    content = script_file.read().decode("utf-8")
            self._task.args = dict(original_args, script=content)
            del self._task.args["path"]
        try:
            result = super().run(tmp, task_vars)
            if local_path:
                invocation = result.get("invocation")
                if isinstance(invocation, dict):
                    module_args = invocation.get("module_args")
                    if isinstance(module_args, dict):
                        module_args["script"] = None
                        module_args["path"] = path
            return result
        finally:
            self._task.args = original_args
