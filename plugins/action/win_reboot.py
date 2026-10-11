"""Coordinate native restart, reconnection, boot verification and readiness."""

# Copyright 2021 Ansible Project
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Derived from ansible.windows 3.8.0; modified by sustainablelobster on 2026-10-09.

import random
import time
import traceback
import uuid
from typing import Any, Callable, cast

# Ansible's controller extension interfaces do not distribute typing metadata.
from ansible.errors import (  # type: ignore[import-untyped]
    AnsibleConnectionFailure,
    AnsibleError,
)
from ansible.module_utils.common.validation import (  # type: ignore[import-untyped]
    check_type_float,
    check_type_str,
)
from ansible.plugins.action import ActionBase  # type: ignore[import-untyped]
from ansible.utils.display import Display  # type: ignore[import-untyped]

from ..plugin_utils._module import PythonModuleAction
from ..plugin_utils._runas import check_runas

_MODULE = "sustainablelobster.legacy_windows.win_reboot"
_DISPLAY = Display()
_IN_PROGRESS = (
    "The target has reported that a reboot or shutdown is already in progress. "
    "This has been triggered by something other than Ansible but Ansible will "
    "attempt to wait for the system to come back online. If the system is "
    "shutting down instead of rebooting then this will timeout waiting for "
    "the system to come back online and report a failure. If you see this "
    "message then you should investigate the target event logs to determine "
    "what is causing the reboot/shutdown outside of Ansible."
)


class _CommandFailure(Exception):
    def __init__(self, message: str, result: dict[str, Any]) -> None:
        super().__init__(message)
        self.result = {key: result[key] for key in ("rc", "stdout", "stderr")}


def _parameters(arguments: dict[str, Any]) -> dict[str, Any]:
    parameters = {
        "boot_time_command": None,
        "connect_timeout": 5,
        "msg": "Reboot initiated by Ansible",
        "post_reboot_delay": 0,
        "pre_reboot_delay": 2,
        "reboot_timeout": 600,
        "test_command": None,
    }
    for name in parameters:
        names = (
            (name, name + "_sec") if name.endswith(("timeout", "delay")) else (name,)
        )
        value = next((arguments.get(key) for key in names if arguments.get(key)), None)
        if value is None:
            continue
        try:
            if name in ("boot_time_command", "test_command", "msg"):
                value = check_type_str(value)
            else:
                value = check_type_float(value)
                value = 0 if value < 0 else value
        except TypeError as error:
            # Ansible renders an explicit cause again in the public message.
            raise AnsibleError(f"Invalid value given for '{name}': {error}.") from None
        if name != "pre_reboot_delay" or not value < 2:
            parameters[name] = value
    return parameters


# This action stages a fixed helper closure and owns its multi-call lifetime.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Restart through native target operations and Ansible's existing connection."""

    _close_on_reset: bool
    _reboot_variables: dict[str, object]
    _supports_check_mode = True
    _supports_async = True
    TRANSFERS_FILES = True
    # Keep the complete staging closure local instead of sharing unrelated lists.
    # pylint: disable=duplicate-code
    EXTRA_MODULE_UTILS = (
        "legacy_windows_wmi.py",
        "legacy_windows_boot.py",
        "legacy_windows_text.py",
        "legacy_windows_process.py",
        "legacy_windows_reboot_request.py",
    )
    # pylint: enable=duplicate-code
    _VALID_ARGS = frozenset(
        (
            "boot_time_command",
            "connect_timeout",
            "connect_timeout_sec",
            "msg",
            "post_reboot_delay",
            "post_reboot_delay_sec",
            "pre_reboot_delay",
            "pre_reboot_delay_sec",
            "reboot_timeout",
            "reboot_timeout_sec",
            "shutdown_timeout",
            "shutdown_timeout_sec",
            "test_command",
        )
    )

    def _early_needs_tmp_path(self) -> bool:
        # Initial staging creates its directory inside the initial boot retry.
        return False

    def cleanup(self, force: bool = False) -> None:
        """Leave normal cleanup to run and honor explicit forced cleanup.

        :param force: Whether to retry through Ansible's explicit cleanup hook.
        :raises AnsibleError: Explicit forced cleanup fails.
        """
        if force:
            super().cleanup(force=True)

    def _phase(self, operation: str, **parameters: Any) -> dict[str, Any]:
        result = self._execute_module(
            module_name=_MODULE,
            module_args=dict(parameters, _operation=operation),
            task_vars=self._reboot_variables,
            persist_files=True,
            wrap_async=False,
        )
        if result.get("failed"):
            result = {
                "rc": result.get("rc", 1),
                "stdout": result.get("stdout", result.get("module_stdout", "")),
                "stderr": result.get(
                    "stderr", result.get("module_stderr", result.get("msg", ""))
                ),
            }
        return cast(dict[str, Any], result)

    def _boot(self, command: str | None) -> str:
        result = self._phase("boot", command=command)
        if result["rc"]:
            raise _CommandFailure(
                self._task.action + ": failed to get host boot time info", result
            )
        return cast(str, result["stdout"])

    def _stage_and_read_boot(self, command: str | None) -> str:
        self._stage_module_utils()
        return self._boot(command)

    def _reset(self) -> None:
        if self._close_on_reset:
            try:
                self._connection.close()
            except Exception:  # pylint: disable=broad-exception-caught
                self._close_on_reset = False
                raise
        reset = getattr(self._connection, "reset", None)
        if reset is not None:
            reset()

    def _poll(
        self,
        operation: Callable[[], Any],
        *,
        tries: int | None = None,
        timeout: float | None = None,
        label: str = "",
    ) -> Any:
        deadline = time.monotonic() + timeout if timeout is not None else None
        failures = 0
        reset_needed = False
        error: Exception | None = None
        while failures == 0 or (
            (tries is None or failures < tries)
            and (deadline is None or time.monotonic() < deadline)
        ):
            try:
                if reset_needed:
                    self._reset()
                    reset_needed = False
                    continue
                return operation()
            except Exception as caught:  # pylint: disable=broad-exception-caught
                error = caught
                reset_needed = not isinstance(caught, ValueError)
                time.sleep(min(2**failures, 12) + random.randint(0, 1000) / 1000)
                failures += 1
        if timeout is not None and error is not None:
            raise TimeoutError(
                f"Timed out waiting for {label} (timeout={timeout})"
            ) from error
        if error is not None:
            raise error
        return None

    def _set_timeout(self, timeout: float) -> None:
        try:
            current = self._connection.get_option("connection_timeout")
        except KeyError:
            return
        if current != timeout:
            self._connection.set_option("connection_timeout", timeout)
            try:
                self._reset()
            except AnsibleError:
                pass

    def _request(self, parameters: dict[str, Any]) -> None:
        try:
            result = self._phase(
                "request",
                delay=parameters["pre_reboot_delay"],
                message=parameters["msg"],
                default_readiness=not parameters["test_command"],
            )
        except AnsibleConnectionFailure:
            return  # A connection can disappear before shutdown returns.
        if result["rc"] == 1190 or (result["rc"] and "(1190)" in result["stderr"]):
            # Preserve the original public warning's hyphenated spelling.
            _DISPLAY.warning(
                "A scheduled reboot was pre-empted by Ansible."  # codespell:ignore
            )
            self._phase("abort")
            try:
                result = self._phase(
                    "request",
                    delay=parameters["pre_reboot_delay"],
                    message=parameters["msg"],
                    default_readiness=not parameters["test_command"],
                )
            except AnsibleConnectionFailure:
                return
        if result["rc"] == 1115:
            _DISPLAY.warning(_IN_PROGRESS)
        elif result["rc"]:
            raise _CommandFailure(self._task.action + ": Reboot command failed", result)

    def _changed_boot(self, previous: str, parameters: dict[str, Any]) -> None:
        if parameters["connect_timeout"]:
            self._set_timeout(parameters["connect_timeout"])
        if self._boot(parameters["boot_time_command"]) == previous:
            raise ValueError("boot time has not changed")

    def _ready(self, command: str | None, expected: str) -> None:
        result = self._phase("ready", command=command, expected=expected)
        if result["rc"]:
            raise ValueError(
                f"{self._task.action}: Test command failed - rc: {result['rc']}, "
                f"stdout: {result['stdout']}, stderr: {result['stderr']}"
            )
        if not command and expected not in result["stdout"]:
            raise ValueError(
                f"{self._task.action}: Test command failed - '{expected}' "
                f"was not in stdout: {result['stdout']}"
            )

    def _cleanup_task_directory(self, result: dict[str, Any]) -> None:
        # Ansible actions own the connection shell's task directory.
        directory = self._connection._shell.tmpdir  # pylint: disable=protected-access
        try:
            self._remove_tmp_path(directory)
        except AnsibleError as error:
            message = f"Failed to remove reboot task directory {directory}: {error}"
            _DISPLAY.vvvv(message)
            if not result["failed"] and not result["unreachable"]:
                result.update(
                    failed=True, msg=message, exception=traceback.format_exc()
                )

    def run(
        self, tmp: str | None = None, task_vars: dict[str, object] | None = None
    ) -> dict[str, Any]:
        """Predict or perform a reboot and independently wait for boot/readiness.

        :param tmp: Deprecated Ansible action argument; no longer used.
        :param task_vars: Variables passed to native target phase execution.
        :returns: Original reboot flags, elapsed seconds and actionable failures.
        :raises AnsibleError: A controller argument cannot be converted.
        :raises AnsibleActionFail: A become method other than runas is requested.
        """
        if self._task.check_mode:
            return {"changed": True, "elapsed": 0, "rebooted": True}
        check_runas(self)
        self._reboot_variables = {} if task_vars is None else task_vars
        ActionBase.run(self, tmp, self._reboot_variables)
        parameters = _parameters(self._task.args)
        result: dict[str, Any] = {
            "changed": False,
            "elapsed": 0,
            "failed": False,
            "unreachable": False,
            "rebooted": False,
        }
        self._close_on_reset = True
        started = None
        try:
            try:
                previous = self._poll(
                    lambda: self._stage_and_read_boot(parameters["boot_time_command"]),
                    tries=3,
                )
            except Exception as error:  # pylint: disable=broad-exception-caught
                # Ansible distinguishes transport loss from an operation failure.
                # pylint: disable=duplicate-code
                result[
                    (
                        "unreachable"
                        if isinstance(error, AnsibleConnectionFailure)
                        else "failed"
                    )
                ] = True
                # pylint: enable=duplicate-code
                result.update(msg=str(error), exception=traceback.format_exc())
                if isinstance(error, _CommandFailure):
                    result.update(error.result)
                return result
            try:
                original_timeout = self._connection.get_option("connection_timeout")
            except KeyError:
                original_timeout = None
            self._request(parameters)
            started = time.monotonic()
            result.update(changed=True, rebooted=True)
            if parameters["post_reboot_delay"]:
                time.sleep(parameters["post_reboot_delay"])
            self._poll(
                lambda: self._changed_boot(previous, parameters),
                timeout=parameters["reboot_timeout"],
                label="last boot time check",
            )
            if original_timeout is not None:
                self._set_timeout(original_timeout)
            expected = "success-" + str(uuid.uuid4())
            self._poll(
                lambda: self._ready(parameters["test_command"], expected),
                timeout=parameters["reboot_timeout"],
                label="post-reboot test command",
            )
        except Exception as error:  # pylint: disable=broad-exception-caught
            result.update(failed=True, msg=str(error), exception=traceback.format_exc())
            if isinstance(error, _CommandFailure):
                result.update(error.result)
        finally:
            if started is not None:
                result["elapsed"] = int(time.monotonic() - started) % 86400
            self._cleanup_task_directory(result)
        return result
