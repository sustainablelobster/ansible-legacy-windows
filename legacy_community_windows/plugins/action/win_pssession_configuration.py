"""Own session-configuration async polling across remoting service restarts."""

# Copyright: (c) 2020, Brian Scholer <@briantist>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import time
from pathlib import Path
from typing import Any, cast

from ansible.errors import (  # type: ignore[import-untyped]
    AnsibleActionFail,
    AnsibleConnectionFailure,
)
from ansible.utils.display import Display  # type: ignore[import-untyped]
from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)

_DISPLAY = Display()
_STATUS_KEYS = (
    "ansible_job_id",
    "ansible_async_watchdog_pid",
    "finished",
    "results_file",
    "started",
)


def _positive_integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise AnsibleActionFail(name + " must be a positive integer.")
    try:
        number = int(value)
    except ValueError as error:
        raise AnsibleActionFail(name + " must be a positive integer.") from error
    if number <= 0:
        raise AnsibleActionFail(name + " must be greater than 0.")
    return number


# Normal Ansible actions already have an established deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Apply endpoint changes asynchronously and return only their final result."""

    COLLECTION_MODULE_UTILS = (
        Path(__file__).resolve().parents[1]
        / "module_utils"
        / "legacy_community_windows_pssession_engine.py",
        Path(__file__).resolve().parents[1]
        / "module_utils"
        / "legacy_community_windows_clixml_dictionary.py",
    )
    _supports_check_mode = True

    def _load_action(self, name: str, arguments: dict[str, object]) -> Any:
        task = self._task.copy()
        task.action = name
        task.args = arguments
        task.async_val = 0
        task.poll = 0
        # Ansible needs this action's existing execution context unchanged.
        # pylint: disable=duplicate-code
        return self._shared_loader_obj.action_loader.get(
            name,
            task=task,
            connection=self._connection,
            play_context=self._play_context,
            loader=self._loader,
            templar=self._templar,
            shared_loader_obj=self._shared_loader_obj,
        )
        # pylint: enable=duplicate-code

    def _wait_ready(
        self, deadline: float, interval: int, task_vars: dict[str, object] | None
    ) -> None:
        # Use the collection's existing Python ping action, not core's modern
        # Python payload or a new connection/transport implementation.
        try:
            self._connection.reset()
        except NotImplementedError:
            pass
        ping = self._load_action("sustainablelobster.legacy_windows.win_ping", {})
        while time.monotonic() < deadline:
            try:
                result = ping.run(task_vars=task_vars)
                if not result.get("failed") and not result.get("unreachable"):
                    return
            except AnsibleConnectionFailure:
                pass
            time.sleep(interval)
        raise AnsibleConnectionFailure(
            "Timed out waiting for the session connection to return."
        )

    def _poll_job(
        self,
        status: Any,
        deadline: float,
        interval: int,
        task_vars: dict[str, object] | None,
    ) -> dict[str, Any]:
        failures = 0
        while time.monotonic() < deadline:
            try:
                result = cast(dict[str, Any], status.run(task_vars=task_vars))
                if result.get("unreachable"):
                    raise AnsibleConnectionFailure(str(result.get("msg", result)))
            except AnsibleConnectionFailure:
                failures += 1
                if failures >= 3:
                    raise
                self._wait_ready(deadline, interval, task_vars)
                continue
            if result.get("failed") or result.get("finished"):
                return result
            time.sleep(interval)
        return {
            "failed": True,
            "changed": False,
            "msg": "Session configuration exceeded async_timeout.",
        }

    def run(
        self, tmp: str | None = None, task_vars: dict[str, object] | None = None
    ) -> dict[str, object]:
        """Run one endpoint operation with implicit async and bounded reconnection.

        :param tmp: Deprecated core action argument forwarded unchanged.
        :param task_vars: Variables supplied to ordinary module execution.
        :returns: Final module result without private async status fields.
        :raises AnsibleActionFail: External async or invalid polling controls are
            supplied.
        :raises AnsibleConnectionFailure: The connection cannot be recovered in time.
        :raises Exception: Module launch or polling fails, after best-effort owned cleanup.
        """
        if self._task.async_val or self._parallel_execution:
            raise AnsibleActionFail(
                "win_pssession_configuration manages its own async operation; "
                "external async is not supported."
            )
        timeout = _positive_integer(
            self._task.args.get("async_timeout", 300), "async_timeout"
        )
        interval = _positive_integer(self._task.args.get("async_poll", 1), "async_poll")
        if self._task.check_mode:
            return super().run(tmp, task_vars)

        previous_async, previous_poll = self._task.async_val, self._task.poll
        cleanup = None
        try:
            # Detach through the existing native wrapper. This action, rather
            # than core's generic poller, owns reconnection and final cleanup.
            self._task.async_val, self._task.poll = timeout, 0
            launch = super().run(tmp, task_vars)
            self._task.async_val = 0
            if launch.get("failed") or not launch.get("ansible_job_id"):
                return launch
            arguments = {"jid": launch["ansible_job_id"]}
            status = self._load_action(
                "sustainablelobster.legacy_windows.async_status", arguments
            )
            cleanup = self._load_action(
                "sustainablelobster.legacy_windows.async_status",
                {**arguments, "mode": "cleanup"},
            )
            result = self._poll_job(
                status, time.monotonic() + timeout, interval, task_vars
            )
            for name in _STATUS_KEYS:
                result.pop(name, None)
            return cast(dict[str, object], result)
        finally:
            self._task.async_val, self._task.poll = previous_async, previous_poll
            if cleanup is not None:
                try:
                    result = cleanup.run(task_vars=task_vars)
                    if result.get("failed"):
                        _DISPLAY.vvvv(
                            "Session async cleanup failed: "
                            + str(result.get("msg", result))
                        )
                # Cleanup must not mask a completed module or an earlier failure.
                except Exception as error:  # pylint: disable=broad-exception-caught
                    _DISPLAY.vvvv("Session async cleanup failed: " + str(error))
