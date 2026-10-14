"""Use Ansible's status action with the native Windows job-cache payload."""

# SPDX-License-Identifier: GPL-3.0-or-later

import importlib
from pathlib import Path
from typing import Any, cast

import ansible.utils.collection_loader as collection_config  # type: ignore[import-untyped]

# Ansible's controller action API does not distribute Python typing metadata.
from ansible.plugins.loader import action_loader  # type: ignore[import-untyped]

from ..plugin_utils._runas import NativeRunasExecution, check_runas, stage_runas

# An explicit legacy plugin path can shadow the Python module name. The standard
# loader's builtin FQCN still selects the installed core action without a cycle.
if collection_config.AnsibleCollectionConfig.collection_finder is None:
    # Do not ask the plugin loader to resolve a collection before core installs
    # its finder: a failed early lookup can poison later plugin resolution.
    # Direct builtin import leaves that startup state untouched.
    _CoreStatusAction = importlib.import_module(
        "ansible.plugins.action.async_status"
    ).ActionModule
else:
    _CoreStatusAction = action_loader.get(
        "ansible.builtin.async_status", class_only=True
    )

_HELPER = (
    Path(__file__).resolve().parents[1] / "module_utils" / "legacy_windows_module.py"
)


# The loader-resolved base supplies the other public action methods; adding
# placeholders would hide the inherited core lifecycle from readers.
class ActionModule(NativeRunasExecution, _CoreStatusAction):  # type: ignore[misc, valid-type]  # pylint: disable=too-few-public-methods
    """Read or erase standard job records, including native Python async jobs."""

    EXTRA_MODULE_UTILS: tuple[str, ...] = ()
    _native_job_async_dir: str | None = None

    def _get_async_dir(self) -> str:
        directory = self._native_job_async_dir
        if directory is not None:
            return directory
        return cast(str, super()._get_async_dir())

    # The standard status action passes options by keyword. Forward them intact
    # rather than duplicate Ansible's changing execution defaults/signature.
    # pylint: disable=arguments-differ
    def _execute_module(self, **kwargs: Any) -> dict[str, Any]:
        shell = self._connection._shell  # pylint: disable=protected-access
        if shell.tmpdir is None:
            self._make_tmp_path()
        self._transfer_file(str(_HELPER), shell.join_path(shell.tmpdir, _HELPER.name))
        stage_runas(self)
        kwargs["module_name"] = "sustainablelobster.legacy_windows.async_status"
        return cast(dict[str, Any], super()._execute_module(**kwargs))

    # pylint: enable=arguments-differ

    def run(
        self,
        tmp: str | None = None,
        task_vars: dict[str, object] | None = None,
        *,
        async_dir: str | None = None,
    ) -> dict[str, Any]:
        """Execute the standard status action and clean its owned staging directory.

        :param tmp: Deprecated Ansible action argument; no longer used.
        :param task_vars: Variables passed to module execution.
        :param async_dir: Exact cache directory supplied by native fact gathering;
            None retains the configured shell option for ordinary status tasks.
        :returns: Ansible's status result with the native payload's fields.
        :raises AnsibleActionFail: If an unsupported become method is requested.
        :raises Exception: If execution fails, after owned staging cleanup.
        """
        check_runas(self)
        shell = self._connection._shell  # pylint: disable=protected-access
        self._native_job_async_dir = async_dir
        try:
            return cast(dict[str, Any], super().run(tmp, task_vars))
        finally:
            self._native_job_async_dir = None
            self._remove_tmp_path(shell.tmpdir)
