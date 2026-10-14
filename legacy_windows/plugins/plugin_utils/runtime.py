"""Run native Windows Python payloads with explicitly owned helper sources."""

# SPDX-License-Identifier: GPL-3.0-or-later

from dataclasses import replace
from pathlib import Path
from typing import Any, cast

from ansible import constants as ansible_constants  # type: ignore[import-untyped]

# Ansible's action extension API does not distribute Python typing metadata.
from ansible.errors import AnsibleActionFail  # type: ignore[import-untyped]
from ansible.executor.module_common import modify_module  # type: ignore[import-untyped]
from ansible.plugins.action import ActionBase  # type: ignore[import-untyped]
from ansible.plugins.loader import action_loader  # type: ignore[import-untyped]
from ansible.utils.vars import merge_hash  # type: ignore[import-untyped]

from ._runas import NativeRunasAction, check_runas, runas_module_utils

_MODULE_UTILS = Path(__file__).resolve().parents[1] / "module_utils"


# Native runas and fixed helper staging both retain core's normal-action lifecycle.
class PythonModuleAction(NativeRunasAction):  # pylint: disable=too-many-ancestors
    """Supply target helpers, then use Ansible's normal module execution.

    ``EXTRA_MODULE_UTILS`` names helpers supplied by legacy_windows.
    ``COLLECTION_MODULE_UTILS`` supplies explicit helper paths from the consuming
    collection. Both are staged beside the payload under their original names.
    All staged helpers must remain compatible with target Python 3.4.4.
    """

    _supports_async = False
    _parallel_execution = False
    EXTRA_MODULE_UTILS: tuple[str, ...] = ()
    COLLECTION_MODULE_UTILS: tuple[Path, ...] = ()

    def _check_execution_support(self, *, allow_async: bool = False) -> None:
        if (self._task.async_val or self._parallel_execution) and not allow_async:
            raise AnsibleActionFail(
                f"This action ({self._task.action}) does not support async."
            )
        if self._task.async_val and getattr(self._task, "poll", 15) != 0:
            status_action = action_loader.get(
                "ansible.legacy.async_status", class_only=True
            )
            if (
                getattr(status_action, "_supports_native_windows_polling", False)
                is not True
            ):
                raise AnsibleActionFail(
                    "Automatic native Windows async polling requires "
                    "[defaults] action_plugins = "
                    f"{_MODULE_UTILS.parent / 'action' / '_native_async_polling'} "
                    "in your project's ansible.cfg; otherwise use poll: 0 and "
                    "sustainablelobster.legacy_windows.async_status"
                )
        check_runas(self)

    def _stage_module_utils(self, *, wrap_async: bool = False) -> None:
        # Custom actions such as win_copy execute several payloads before
        # cleaning their task directory; helper staging does not own that lifecycle.
        shell = self._connection._shell  # pylint: disable=protected-access
        if shell.tmpdir is None:
            self._make_tmp_path()
        helpers = ("legacy_windows_module.py",) + self.EXTRA_MODULE_UTILS
        if (self._task.async_val or wrap_async) and self._supports_async:
            helpers += (
                "legacy_windows_wmi.py",
                "legacy_windows_async_native.py",
                "legacy_windows_async_worker.py",
            )
        sources = [_MODULE_UTILS / name for name in helpers]
        sources.extend(self.COLLECTION_MODULE_UTILS)
        sources.extend(runas_module_utils(self))
        staged: dict[str, Path] = {}
        for source in sources:
            key = source.name.casefold()
            previous = staged.get(key)
            if previous is not None and previous.resolve() != source.resolve():
                raise AnsibleActionFail(
                    f"Distinct helper sources share the staged name '{source.name}'"
                )
            staged.setdefault(key, source)
        for source in staged.values():
            self._transfer_file(str(source), shell.join_path(shell.tmpdir, source.name))

    # Core calls this for the private async wrapper as well as public modules.
    # Forward other requests unchanged rather than copy its module-selection logic.
    # pylint: disable=arguments-differ
    def _configure_module(
        self, module_name: str, module_args: dict[str, Any], task_vars: dict[str, Any]
    ) -> tuple[Any, str]:
        if module_name != "ansible.legacy.async_wrapper" or not self._supports_async:
            return cast(
                tuple[Any, str],
                super()._configure_module(module_name, module_args, task_vars),
            )
        effective_vars = task_vars
        if self._task.delegate_to:
            effective_vars = task_vars["ansible_delegated_vars"][self._task.delegate_to]
        path = str(_MODULE_UTILS / "legacy_windows_async_wrapper.py")
        bits = modify_module(
            module_name=module_name,
            module_path=path,
            module_args=module_args,
            templar=self._templar,
            task_vars=effective_vars,
        )
        timeout = ansible_constants.config.get_config_value(
            "WIN_ASYNC_STARTUP_TIMEOUT", variables=effective_vars
        )
        marker = b"_STARTUP_TIMEOUT = 5  # Controller-configured startup deadline."
        if bits.b_module_data.count(marker) != 1:
            raise AnsibleActionFail(
                "The private native async wrapper has no unique startup deadline marker"
            )
        data = bits.b_module_data.replace(
            marker,
            f"_STARTUP_TIMEOUT = {int(timeout)}".encode("ascii"),
            1,
        )
        return replace(bits, b_module_data=data), path

    # pylint: enable=arguments-differ

    def run_parallel(
        self, task_vars: dict[str, object] | None = None
    ) -> dict[str, object]:
        """Run a core-selected parallel fact job through its normal action.

        :param task_vars: Variables supplied to the selected fact module.
        :returns: The native asynchronous launch result.
        :raises Exception: If validation, staging or execution fails.
        """
        previous = self._parallel_execution
        self._parallel_execution = True
        try:
            # Dispatch normally: custom actions still prepare their inputs and
            # reject unsupported async before the shared payload lifecycle.
            return self.run(task_vars=task_vars)
        finally:
            self._parallel_execution = previous

    def run(
        self, tmp: str | None = None, task_vars: dict[str, object] | None = None
    ) -> dict[str, object]:
        """Stage fixed helpers alongside the payload in Ansible's task directory.

        :param tmp: Deprecated Ansible action argument; no longer used.
        :param task_vars: Variables passed to normal module execution.
        :returns: The normal action's module result.
        :raises AnsibleActionFail: If unsupported async or escalation is requested.
        :raises Exception: If staging or module execution fails, after cleanup.
        """
        self._check_execution_support(allow_async=True)
        wrap_async = self._parallel_execution

        # Action plugins share the connection's shell and task directory by design.
        shell = self._connection._shell  # pylint: disable=protected-access
        supports_async = self._supports_async
        self._supports_async = bool(self._task.async_val) or wrap_async
        try:
            if wrap_async:
                self._stage_module_utils(wrap_async=True)
            else:
                self._stage_module_utils()
            staged_path = shell.tmpdir
            if wrap_async and not self._task.async_val:
                # Core's normal action couples detaching to a positive task
                # limit. Parallel facts need its same base initialization and
                # module executor without inventing a whole-gathering timeout.
                result = cast(
                    dict[str, object],
                    merge_hash(
                        ActionBase.run(self, tmp, task_vars),
                        self._execute_module(task_vars=task_vars, wrap_async=True),
                    ),
                )
            else:
                result = cast(dict[str, object], super().run(tmp, task_vars))
            if self._task.async_val or wrap_async:
                # Core's generic wrapper forces changed=True. The released
                # Windows wrapper reports no change until its module is polled.
                result["changed"] = False
                if result.get("failed"):
                    # Core forgets async staging even when no watchdog starts.
                    # Its explicit-path cleanup still honors ownership/keep-files.
                    self._remove_tmp_path(staged_path)
            return result
        except Exception:
            # Normal action cleans successful runs; errors must honor the same
            # ownership and ANSIBLE_KEEP_REMOTE_FILES checks before cleanup.
            self._remove_tmp_path(shell.tmpdir)
            raise
        finally:
            self._supports_async = supports_async
