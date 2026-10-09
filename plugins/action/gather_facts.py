"""Use native Setup's established action during Ansible fact gathering."""

# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Any, cast

# Ansible's action and module-default interfaces lack distributed typing metadata.
from ansible.errors import AnsibleActionFail  # type: ignore[import-untyped]
from ansible.executor.module_common import (  # type: ignore[import-untyped]
    _apply_action_arg_defaults,
)
from ansible.plugins.action import gather_facts  # type: ignore[import-untyped]

_SETUP = "sustainablelobster.legacy_windows.setup"
_STATUS = "sustainablelobster.legacy_windows.async_status"


# Core fact gathering owns selection, merging, failures and serial/parallel policy.
class ActionModule(gather_facts.ActionModule):  # type: ignore[misc]
    """Gather native Windows facts through the existing Setup action."""

    _native_jobs: set[str]

    def _native_fact_module(self, module_name: str | None) -> str | None:
        context = self._shared_loader_obj.module_loader.find_plugin_with_context(
            module_name or self._task.action, collection_list=self._task.collections
        )
        resolved = context.resolved_fqcn
        return (
            cast(str, resolved)
            if resolved and resolved.startswith("sustainablelobster.legacy_windows.")
            else None
        )

    def _is_native_setup(self, module_name: str | None) -> bool:
        return self._native_fact_module(module_name) == _SETUP

    def _native_action(self, module_name: str, arguments: dict[str, object]) -> Any:
        task = self._task.copy()
        task.action = module_name
        task.args = dict(arguments)
        # Ansible's loader needs these same caller-owned controller objects.
        # pylint: disable=duplicate-code
        action = self._shared_loader_obj.action_loader.get(
            module_name,
            task=task,
            connection=self._connection,
            play_context=self._play_context,
            loader=self._loader,
            templar=self._templar,
            shared_loader_obj=self._shared_loader_obj,
        )
        # pylint: enable=duplicate-code
        if action is None:
            raise AnsibleActionFail(
                "The native Windows fact action could not be loaded: " + module_name
            )
        return action

    # Child task fields are Ansible's private action boundary. Keep core's
    # parallel loop, but let each native action own staging and execution.
    # pylint: disable=protected-access
    def _parallel_fact(
        self, module_name: str, arguments: dict[str, object], task_vars: Any
    ) -> dict[str, object]:
        action = self._native_action(module_name, arguments)
        # Core already selects each job's execution limit. Setup's resolved
        # gather_timeout belongs to individual collectors, not the whole job.
        # An omitted job limit still needs detached execution for parallelism.
        action._task.poll = 0
        # Use the normal action lifecycle so runas validation and staging cleanup
        # follow the same path as a direct module task.
        result = cast(dict[str, object], action.run_parallel(task_vars=task_vars))
        result["changed"] = False
        if result.get("failed"):
            # Core's parallel loop assumes every launch has a job identifier.
            # Keep the native launch failure instead of leaking a KeyError.
            raise AnsibleActionFail(
                cast(str, result.get("msg", "Could not launch native parallel facts")),
                result=result,
            )
        # Core uses controller os.path.dirname to locate a job cache.
        # Keep this internal handoff readable on POSIX controllers;
        # Windows accepts the same path with forward separators.
        result["results_file"] = cast(str, result["results_file"]).replace("\\", "/")
        self._native_jobs.add(cast(str, result["ansible_job_id"]))
        return result

    def _native_status(
        self, arguments: dict[str, object], task_vars: Any
    ) -> dict[str, object]:
        # Core passes the cache directory to its module privately, not as a
        # public status-action argument. Keep its exact path outside validation.
        public_arguments = {
            name: value for name, value in arguments.items() if name != "_async_dir"
        }
        action = self._native_action(_STATUS, public_arguments)
        action._task.async_val = 0
        return cast(
            dict[str, object],
            action.run(task_vars=task_vars, async_dir=arguments.get("_async_dir")),
        )

    # pylint: enable=protected-access

    def _get_module_args(
        self, fact_module: str, task_vars: dict[str, object]
    ) -> dict[str, object]:
        if not self._is_native_setup(fact_module):
            return cast(
                dict[str, object], super()._get_module_args(fact_module, task_vars)
            )
        # Core recognizes only its own Setup names. Our Setup supports the same
        # gathering options; keep them and apply defaults for the resolved module.
        arguments = {
            name: value for name, value in self._task.args.items() if value is not None
        }
        return cast(
            dict[str, object],
            _apply_action_arg_defaults(_SETUP, self._task, arguments, self._templar),
        )

    # Ansible callers depend on the complete inherited execution signature.
    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def _execute_module(
        self,
        module_name: str | None = None,
        module_args: dict[str, object] | None = None,
        tmp: str | None = None,
        task_vars: dict[str, object] | None = None,
        persist_files: bool = False,
        delete_remote_tmp: bool | None = None,
        wrap_async: bool = False,
        ignore_unknown_opts: bool = False,
    ) -> dict[str, object]:
        arguments = module_args or {}
        if (
            module_name == "ansible.legacy.async_status"
            and arguments.get("jid") in self._native_jobs
        ):
            return self._native_status(arguments, task_vars)
        native = self._native_fact_module(module_name)
        if not native:
            # Preserve every ActionBase argument when this override delegates.
            # pylint: disable=duplicate-code
            return cast(
                dict[str, object],
                super()._execute_module(
                    module_name=module_name,
                    module_args=module_args,
                    tmp=tmp,
                    task_vars=task_vars,
                    persist_files=persist_files,
                    delete_remote_tmp=delete_remote_tmp,
                    wrap_async=wrap_async,
                    ignore_unknown_opts=ignore_unknown_opts,
                ),
            )
            # pylint: enable=duplicate-code
        if wrap_async:
            return self._parallel_fact(native, arguments, task_vars)
        action = self._native_action(native, arguments)
        return cast(dict[str, object], action.run(task_vars=task_vars))

    def run(
        self, tmp: str | None = None, task_vars: dict[str, object] | None = None
    ) -> dict[str, object]:
        """Use core fact selection, parallel polling and result merging.

        :param tmp: Deprecated Ansible action argument.
        :param task_vars: Variables supplied to configured fact modules.
        :returns: Core's complete merged fact result.
        """
        self._native_jobs = set()
        return cast(dict[str, object], super().run(tmp, task_vars))
