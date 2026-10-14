"""Coordinate owned native update rounds, reconnects and required reboots."""

# Copyright 2021 Ansible Project
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Derived from ansible.windows 3.8.0; modified by sustainablelobster on 2026-10-09.

import traceback
from typing import Any, cast

from ansible.errors import (  # type: ignore[import-untyped]
    AnsibleActionFail,
    AnsibleConnectionFailure,
    AnsibleError,
)
from ansible.module_utils.common.validation import (  # type: ignore[import-untyped]
    check_type_bool,
    check_type_int,
)
from ansible.plugins.action import ActionBase  # type: ignore[import-untyped]
from ansible.utils.display import Display  # type: ignore[import-untyped]

from ..plugin_utils._updates_hresult import describe_hresult
from ..plugin_utils.runtime import PythonModuleAction
from .win_reboot import ActionModule as RebootAction

try:
    import requests.exceptions as _request_errors  # type: ignore[import-untyped]

    RequestTimeout = _request_errors.Timeout
except ImportError:
    RequestTimeout = AnsibleConnectionFailure

_MODULE = "sustainablelobster.legacy_windows.win_updates"
_DISPLAY = Display()
# Keep the complete staging closure local instead of sharing unrelated lists.
# pylint: disable=duplicate-code
_HELPERS = (
    "legacy_windows_wmi.py",
    "legacy_windows_boot.py",
    "legacy_windows_text.py",
    "legacy_windows_process.py",
    "legacy_windows_reboot_request.py",
    "legacy_windows_regex.py",
    "legacy_windows_regex_categories.py",
    "legacy_windows_updates_native.py",
    "legacy_windows_updates.py",
    "legacy_windows_updates_worker.py",
    "legacy_windows_account.py",
    "legacy_windows_s4u.py",
    "legacy_windows_system_token.py",
    "legacy_windows_runas_token.py",
)
# pylint: enable=duplicate-code
_CBS_PATH = r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Interface"


class _OperationFailure(Exception):
    def __init__(self, message: str, result: dict[str, Any]) -> None:
        super().__init__(message)
        self.result = {
            name: result[name]
            for name in ("rc", "stdout", "stderr", "exception")
            if name in result
        }


# Independent result flags and per-update maps must survive partial failures.
# Folding them into an opaque dictionary would obscure the released projection.
class _UpdateRound:  # pylint: disable=too-many-instance-attributes,too-few-public-methods
    def __init__(self) -> None:
        self.updates: dict[str, dict[str, Any]] = {}
        self.filtered: dict[str, list[str]] = {}
        self.selected: set[str] = set()
        self.download: dict[str, dict[str, Any]] = {}
        self.install: dict[str, dict[str, Any]] = {}
        self.changed = False
        self.reboot_required = False
        self.failed = False
        self.message = ""
        self.exception: str | None = None
        self.hresult: int | None = None
        self.hresult_description: str | None = None
        self.boot_time: str | None = None

    def receive(self, name: str, result: dict[str, Any]) -> None:
        """Accumulate one native progress packet for the public projection.

        :param name: Released progress packet name.
        :param result: Packet's result mapping.
        """
        if name == "search_result":
            self.updates = {value["id"]: value for value in result["updates"]}
            self.filtered = {
                value["id"]: value["reasons"] for value in result["filtered"]
            }
            self.selected.update(set(self.updates).difference(self.filtered))
        elif name in ("download_result", "install_result"):
            destination = self.download if name == "download_result" else self.install
            for value in result["info"]:
                current = {key: item for key, item in value.items() if key != "id"}
                current["hresult"] &= 0xFFFFFFFF
                destination[value["id"]] = current
        elif name in ("download", "install"):
            _DISPLAY.debug(f"Update {name} progress: {result}")
        elif name == "exit":
            self.changed = result["changed"]
            self.reboot_required = result["reboot_required"]
            self.failed = result["failed"]
            error = result.get("exception") or {}
            self.message = error.get("message", "")
            self.exception = error.get("exception")
            if "hresult" in error:
                self.hresult = error["hresult"] & 0xFFFFFFFF
                self.hresult_description = error.get("hresult_description")
                prefix, com_marker, native = self.message.rpartition("WUA.")
                suffix = f" failed (HRESULT 0x{self.hresult:08X})."
                if (
                    com_marker
                    and native.endswith(suffix)
                    and native[: -len(suffix)].isidentifier()
                ):
                    # Match the measured released COM fallback, as the accepted
                    # async projector does. Actual provider descriptions and
                    # numeric HRESULT fields remain untouched.
                    self.message = (
                        prefix + f"Exception from HRESULT: 0x{self.hresult:08X}"
                    )
            marker = error.get("_is_rebooting_last_boot_time")
            self.boot_time = str(marker) if marker is not None else None


# Reuse the accepted restart lifecycle; only update-specific readiness extends it.
class _UpdatesReboot(RebootAction):  # pylint: disable=too-many-ancestors
    # The base's inferred fixed-length tuple is deliberately extended by one
    # fixed native helper; the staging contract accepts either tuple length.
    EXTRA_MODULE_UTILS = RebootAction.EXTRA_MODULE_UTILS + (  # type: ignore[assignment]
        "legacy_windows_reg_stat.py",
    )
    previous_boot: str | None = None
    staged = False

    def _stage_and_read_boot(self, command: str | None) -> str:
        if self.previous_boot is not None:
            return self.previous_boot
        result = super()._stage_and_read_boot(command)
        self.staged = True
        return result

    def _request(self, parameters: dict[str, Any]) -> None:
        if self.previous_boot is None:
            super()._request(parameters)

    def _changed_boot(self, previous: str, parameters: dict[str, Any]) -> None:
        if not self.staged:
            self._stage_module_utils()
            self.staged = True
        super()._changed_boot(previous, parameters)

    def _ready(self, command: str | None, expected: str) -> None:
        super()._ready(command, expected)
        result = self._execute_module(
            module_name="sustainablelobster.legacy_windows.win_reg_stat",
            module_args={"path": _CBS_PATH, "name": "ServicingInProgress"},
            task_vars=self._reboot_variables,
            persist_files=True,
            wrap_async=False,
        )
        # The pinned CBS predicate treats a missing value or registry-query
        # exception as idle. Native module execution/transport errors still fail.
        if result.get("failed"):
            if result.get("msg", "").startswith("Unhandled exception"):
                raise ValueError(
                    "Cannot execute native CBS readiness: " + result["msg"]
                )
            return
        value = result.get("value", 0) if result.get("exists") else 0
        if value not in (0, 1):
            raise ValueError(
                f"CBS is still servicing updates (ServicingInProgress={value})."
            )


# The fixed helper closure and multi-call lifecycle belong to this public action.
# Per-update maps and scoped core contracts remain distinct task state.
class ActionModule(
    PythonModuleAction
):  # pylint: disable=too-many-ancestors,too-many-instance-attributes
    """Preserve released update selection, per-update results and reboot rounds."""

    _supports_check_mode = True
    _supports_async = True
    TRANSFERS_FILES = True
    EXTRA_MODULE_UTILS: tuple[str, ...] = _HELPERS
    _VALID_ARGS = frozenset(
        (
            "accept_list",
            "reject_list",
            "category_names",
            "skip_optional",
            "reboot",
            "reboot_timeout",
            "server_selection",
            "state",
            "log_path",
            "maximum_retries_on_failed_updates",
            "_operation",
        )
    )
    _invocation: dict[str, Any] | None
    _updates: dict[str, dict[str, Any]]
    _filtered: dict[str, list[str]]
    _selected: set[str]
    _download: dict[str, dict[str, Any]]
    _install: dict[str, dict[str, Any]]

    def _early_needs_tmp_path(self) -> bool:
        return False

    def cleanup(self, force: bool = False) -> None:
        """Leave ordinary cleanup to run and honor explicit forced cleanup.

        :param force: Whether the caller explicitly requests another cleanup attempt.
        :raises AnsibleError: Explicit forced cleanup fails.
        """
        if force:
            super().cleanup(force=True)

    def _execute(
        self,
        variables: dict[str, Any],
        operation: str,
        arguments: dict[str, Any] | None = None,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        parameters = dict(
            arguments or {}, _operation=operation, _operation_options=options or {}
        )
        for attempt in range(2):
            try:
                result = self._execute_module(
                    module_name=_MODULE,
                    module_args=parameters,
                    task_vars=variables,
                    persist_files=True,
                    wrap_async=False,
                )
                break
            except (AnsibleConnectionFailure, RequestTimeout) as error:
                if operation != "poll" or attempt == 1:
                    raise
                _DISPLAY.warning(
                    "Connection failure when polling update result - attempting to retry: "
                    + str(error)
                )
        if "invocation" in result and self._invocation is None:
            self._invocation = result["invocation"]
        if result.get("failed"):
            raise _OperationFailure(
                result.get("msg", "Failure while running win_updates " + operation),
                result,
            )
        for warning in result.get("warnings", []):
            if isinstance(warning, str):
                _DISPLAY.warning(warning)
        return cast(dict[str, Any], result)

    def _round(
        self, variables: dict[str, Any], arguments: dict[str, Any], test: bool
    ) -> _UpdateRound:
        self._stage_module_utils()
        start = self._execute(variables, "test" if test else "start", arguments)
        polling = dict(start.get("poll_options", {}))
        result = _UpdateRound()
        primary = False
        try:
            finished = False
            while not finished:
                response = self._execute(variables, "poll", options=polling)
                for packet in response["output"]:
                    result.receive(packet["task"], packet["result"])
                    finished = finished or packet["task"] == "exit"
                polling["offset"] = response["offset"]
        except Exception as error:
            primary = True
            _DISPLAY.warning(
                "Unknown failure when polling update result - attempting to cancel task: "
                + str(error)
            )
            raise
        finally:
            try:
                self._execute(
                    variables, "cancel", options=start.get("cancel_options", {})
                )
            # Cancellation runs after every poll outcome, including malformed
            # native packets; a secondary failure must retain the primary one.
            except Exception as error:  # pylint: disable=broad-exception-caught
                if not primary:
                    raise
                _DISPLAY.warning(
                    "Unknown failure when cancelling update task: " + str(error)
                )
        return result

    def _reboot(
        self, variables: dict[str, Any], timeout: int, boot_time: str | None
    ) -> dict[str, Any]:
        task = self._task.copy()
        task.args = {"reboot_timeout": timeout}
        action = _UpdatesReboot(
            task,
            self._connection,
            self._play_context,
            self._loader,
            self._templar,
            self._shared_loader_obj,
        )
        action.previous_boot = boot_time
        return action.run(task_vars=variables)

    # The explicit round inputs and local retry flags mirror one user-visible
    # reboot loop; splitting those decisions into stateful helpers hides order.
    # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals,too-many-branches
    def _sync(
        self,
        variables: dict[str, Any],
        arguments: dict[str, Any],
        reboot: bool,
        timeout: int,
        test: bool,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "changed": False,
            "reboot_required": False,
            "rebooted": False,
        }
        installed: set[str] = set()
        retried_failure, rollbacks = False, 0
        while True:
            current = self._round(variables, arguments, test)
            self._updates.update(current.updates)
            self._filtered.update(current.filtered)
            self._selected.update(current.selected)
            self._download.update(current.download)
            self._install.update(current.install)
            attempted = set(current.install)
            if attempted and not attempted.difference(installed):
                rollbacks += 1
            installed.update(attempted)
            # Preserve the released comparison with the raw controller value,
            # including its zero/negative and non-integer input behavior.
            if rollbacks >= arguments.get("maximum_retries_on_failed_updates", 1):
                for identifier in attempted:
                    self._install[identifier].update(result_code=4, hresult=-1)
                    # The loop sentinel replaces the provider's code, so its
                    # original Windows description no longer describes it.
                    self._install[identifier].pop("hresult_description", None)
                result.update(
                    failed=True,
                    msg=(
                        "An update loop was detected, this could be caused by an update "
                        "being rolled back during a reboot or the Windows Update API "
                        "incorrectly reporting a failed update as being successful."
                        "Check the Windows Updates logs on the host to gather more "
                        "information. Updates in the reboot "
                        f"loop are: {', '.join(attempted)}"
                    ),
                )
                break
            required = result["reboot_required"] = current.reboot_required
            result["changed"] = result["changed"] or current.changed
            if current.failed:
                message = current.message
                if current.hresult:
                    message += " - " + describe_hresult(
                        current.hresult, current.hresult_description
                    )
                if (
                    reboot
                    and not retried_failure
                    and arguments.get("state", "") != "searched"
                ):
                    required, retried_failure = True, True
                else:
                    result.update(failed=True, msg=message, exception=current.exception)
                    break
            elif reboot:
                retried_failure = False
            if required and reboot:
                if current.boot_time:
                    host = variables.get("inventory_hostname")
                    _DISPLAY.warning(
                        f"[{host}] Host indicated reboot is in progress, waiting for it "
                        "to come back online before trying again. This is a best effort "
                        "attempt to recover from a reboot that was triggered outside "
                        "of Ansible's control. "
                        "If the host is shutting down instead of rebooting the task will time out."
                    )
                restarted: dict[str, Any] = (
                    {"failed": False}
                    if self._task.check_mode
                    else self._reboot(variables, timeout, current.boot_time)
                )
                result["rebooted"] = True
                if restarted.get("failed"):
                    restarted["msg"] = "Failed to reboot host" + (
                        ": " + str(restarted["msg"]) if "msg" in restarted else ""
                    )
                    result.update(restarted)
                    break
                result.update(changed=True, reboot_required=False)
            if (
                not reboot
                or self._task.check_mode
                or arguments.get("state", "installed") != "installed"
                or not required
                and not current.selected
            ):
                break
        return result

    # pylint: enable=too-many-arguments,too-many-locals,too-many-branches

    def _info(self, identifier: str) -> dict[str, Any]:
        raw = self._updates[identifier]
        result = {
            "id": identifier,
            "title": raw["title"],
            "categories": raw["categories"],
            "kb": [
                value[2:] if value.startswith("KB") else value for value in raw["kb"]
            ],
            "downloaded": False,
            "installed": False,
        }
        for field, outcomes in (
            ("downloaded", self._download),
            ("installed", self._install),
        ):
            if identifier in outcomes:
                outcome = outcomes[identifier]
                if outcome["result_code"] == 2:
                    result[field] = True
                else:
                    result.update(
                        failure_hresult_code=outcome["hresult"],
                        failure_msg=describe_hresult(
                            outcome["hresult"], outcome.get("hresult_description")
                        ),
                    )
        return result

    def _options(self) -> tuple[dict[str, Any], bool, int, bool]:
        try:
            reboot = check_type_bool(self._task.args.get("reboot", False))
        except TypeError as error:
            raise AnsibleActionFail(
                f"Invalid value given for 'reboot': {error}."
            ) from None
        try:
            timeout = check_type_int(self._task.args.get("reboot_timeout", 1200))
        except TypeError as error:
            raise AnsibleActionFail(
                f"Invalid value given for 'reboot_timeout': {error}."
            ) from None
        arguments = self._task.args.copy()
        operation = arguments.pop("_operation", None)
        if operation is not None and operation != "test":
            raise AnsibleActionFail(
                "_operation is an internal option and cannot be set"
            )
        if self._task.async_val and reboot:
            raise AnsibleActionFail(
                "async is not supported for this task when reboot=yes"
            )
        self._check_execution_support(allow_async=bool(self._task.async_val))
        return arguments, reboot, timeout, operation == "test"

    def _async(
        self,
        tmp: str | None,
        variables: dict[str, Any],
        arguments: dict[str, Any],
        test: bool,
    ) -> dict[str, Any]:
        original_arguments = self._task.args
        original_helpers = self.EXTRA_MODULE_UTILS
        original_valid = self._VALID_ARGS
        self._task.args = dict(
            arguments,
            _operation="test" if test else "start",
            _operation_options={"wait": True},
        )
        # The established stager reads its uppercase helper contract from this
        # action instance; scope the extra projector to this async launch.
        # pylint: disable-next=invalid-name
        self.EXTRA_MODULE_UTILS = _HELPERS + ("legacy_windows_updates_async.py",)
        # Public arguments were already validated above. The normal action's
        # second validation must also accept our private wait flag, temporarily.
        # pylint: disable-next=invalid-name
        self._VALID_ARGS = original_valid.union(("_operation_options",))
        try:
            # The accepted normal-action lifecycle owns launch, startup failure,
            # core wrapper staging and transfer of cleanup to its watchdog.
            return PythonModuleAction.run(self, tmp, variables)
        finally:
            self._task.args = original_arguments
            self.EXTRA_MODULE_UTILS = original_helpers
            self._VALID_ARGS = original_valid

    def _project(self, result: dict[str, Any]) -> dict[str, Any]:
        result.update(
            found_update_count=0,
            failed_update_count=0,
            installed_update_count=0,
            updates={},
            filtered_updates={},
        )
        for identifier in self._selected:
            info = self._info(identifier)
            result["updates"][identifier] = info
            result["found_update_count"] += 1
            if "failure_hresult_code" in info:
                result["failed_update_count"] += 1
            elif info["installed"]:
                result["installed_update_count"] += 1
        for identifier, reasons in self._filtered.items():
            result["filtered_updates"][identifier] = dict(
                self._info(identifier), filtered_reasons=reasons
            )
        if self._invocation:
            result["invocation"] = self._invocation
            for name in ("_operation", "_operation_options"):
                result["invocation"].get("module_args", {}).pop(name, None)
        return result

    def run(
        self, tmp: str | None = None, task_vars: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Run update rounds and project complete released public result fields.

        :param tmp: Deprecated Ansible temporary-directory argument.
        :param task_vars: Variables supplied to ordinary native module execution.
        :returns: Selected/filtered updates, counters, reboot flags and failures.
        :raises AnsibleActionFail: Public controller options or execution mode are invalid.
        """
        variables = task_vars or {}
        ActionBase.run(self, tmp, variables)
        arguments, reboot, timeout, test = self._options()
        if self._task.async_val:
            return self._async(tmp, variables, arguments, test)
        self._invocation = None
        self._updates: dict[str, dict[str, Any]] = {}
        self._filtered: dict[str, list[str]] = {}
        self._selected: set[str] = set()
        self._download: dict[str, dict[str, Any]] = {}
        self._install: dict[str, dict[str, Any]] = {}
        try:
            result = self._sync(variables, arguments, reboot, timeout, test)
        # An unexpected controller/protocol failure still needs public counters
        # and primary failure facts after owned-directory cleanup.
        except Exception as error:  # pylint: disable=broad-exception-caught
            result = dict(error.result) if isinstance(error, _OperationFailure) else {}
            result[
                (
                    "unreachable"
                    if isinstance(error, AnsibleConnectionFailure)
                    else "failed"
                )
            ] = True
            result.update(msg=str(error))
            if not result.get("exception"):
                result["exception"] = traceback.format_exc()
        finally:
            try:
                # Ansible owns task staging through the connection shell.
                shell = self._connection._shell  # pylint: disable=protected-access
                self._remove_tmp_path(shell.tmpdir)
            except AnsibleError as error:
                message = "Failed to remove update task directory: " + str(error)
                _DISPLAY.vvvv(message)
                if not result.get("failed") and not result.get("unreachable"):
                    result.update(
                        failed=True, msg=message, exception=traceback.format_exc()
                    )
        return self._project(result)
