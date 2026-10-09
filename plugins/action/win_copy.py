"""Plan local copies, transfer changed content, and run the native copy payload."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import json
import os
import tempfile
import traceback
import zipfile
from contextlib import ExitStack
from pathlib import Path
from typing import Any, TypedDict, cast

# Ansible's controller extension interfaces do not distribute typing metadata.
from ansible import constants as C  # type: ignore[import-untyped]
from ansible.errors import (  # type: ignore[import-untyped]
    AnsibleError,
    AnsibleFileNotFound,
)
from ansible.module_utils.common.text.converters import (  # type: ignore[import-untyped]
    to_bytes,
    to_text,
)
from ansible.module_utils.parsing.convert_bool import (  # type: ignore[import-untyped]
    boolean,
)
from ansible.plugins.action import ActionBase  # type: ignore[import-untyped]
from ansible.utils.hashing import checksum  # type: ignore[import-untyped]

from ..plugin_utils._module import PythonModuleAction

_MODULE = "sustainablelobster.legacy_windows.win_copy"


class _Entry(TypedDict):
    src: str
    dest: str


class _File(_Entry):
    checksum: str | None


class _Sources(TypedDict):
    files: list[_File]
    directories: list[_Entry]
    symlinks: list[_Entry]


def _option(args: dict[str, Any], name: str, default: bool = False) -> bool:
    return cast(bool, boolean(args.get(name, default), strict=False))


def _local_file(
    loader: Any, path: str, destination: str, args: dict[str, Any]
) -> _File:
    resolved = loader.get_real_file(path, decrypt=_option(args, "decrypt", True))
    return {
        "src": resolved,
        "dest": destination,
        "checksum": checksum(resolved) if _option(args, "force", True) else None,
    }


def _directory_sources(loader: Any, source: str, args: dict[str, Any]) -> _Sources:
    sources: _Sources = {"files": [], "directories": [], "symlinks": []}
    follow = _option(args, "local_follow")
    if os.path.islink(source) and not follow:
        sources["symlinks"].append(
            {"src": os.readlink(source), "dest": os.path.basename(source)}
        )
        return sources

    root = os.path.normpath(source)
    prefix = "" if source.endswith(os.path.sep) else os.path.basename(root)

    def walk(directory: str, relative: str, ancestors: set[tuple[int, int]]) -> None:
        try:
            with os.scandir(directory) as entries:
                children = list(entries)
        except OSError:
            # The upstream os.walk skips a directory it cannot enumerate.
            return
        # Keep the file-before-directory ordering used by the upstream walker.
        for entry in children:
            if entry.is_dir():
                continue
            destination = os.path.join(relative, entry.name)
            if entry.is_symlink():
                resolved = os.path.realpath(entry.path)
                # The loader also diagnoses missing/decryption-failed link targets.
                real_file = loader.get_real_file(
                    resolved, decrypt=_option(args, "decrypt", True)
                )
                if not follow or not os.path.isfile(real_file):
                    sources["symlinks"].append(
                        {"src": os.readlink(entry.path), "dest": destination}
                    )
                    continue
                sources["files"].append(
                    {
                        "src": real_file,
                        "dest": destination,
                        "checksum": (
                            checksum(real_file)
                            if _option(args, "force", True)
                            else None
                        ),
                    }
                )
            else:
                sources["files"].append(
                    _local_file(loader, entry.path, destination, args)
                )

        descendants = []
        for entry in children:
            if not entry.is_dir():
                continue
            destination = os.path.join(relative, entry.name)
            info = entry.stat()
            identity = (info.st_dev, info.st_ino)
            if entry.is_symlink() and (not follow or identity in ancestors):
                sources["symlinks"].append(
                    {"src": os.readlink(entry.path), "dest": destination}
                )
                continue
            path = os.path.realpath(entry.path) if entry.is_symlink() else entry.path
            sources["directories"].append({"src": path, "dest": destination})
            if entry.is_symlink():
                walk(path, destination, ancestors | {identity})
            else:
                descendants.append((path, destination, identity))
        # os.walk lists this directory's children before descending into them.
        for path, destination, identity in descendants:
            walk(path, destination, ancestors | {identity})

    info = os.stat(root)
    walk(root, prefix, {(info.st_dev, info.st_ino)})
    return sources


def _write_archive(path: str, sources: _Sources) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for entry in [*sources["directories"], *sources["files"]]:
            encoded = base64.b64encode(to_bytes(entry["dest"])).decode("ascii")
            archive.write(entry["src"], encoded)


# This action reuses the normal action's helper staging, not its one-call run.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Copy controller or remote files through Python-only Windows payloads."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_copy.py",
        "legacy_windows_file.py",
        "legacy_windows_stat.py",
        "legacy_windows_time.py",
        "legacy_windows_calendar.py",
        "legacy_windows_datetime.py",
    )

    # Keep Ansible's extension signature, including its deprecated arguments.
    def _execute_module(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        module_name: str | None = None,
        module_args: dict[str, Any] | None = None,
        tmp: str | None = None,
        task_vars: dict[str, object] | None = None,
        persist_files: bool = False,
        delete_remote_tmp: bool | None = None,
        wrap_async: bool = False,
        ignore_unknown_opts: bool = False,
    ) -> dict[str, Any]:
        # ActionBase's maintained diff implementation calls these two modules.
        # Redirect only those calls to this collection's native file helpers.
        native_modules = {
            "ansible.legacy.file": "sustainablelobster.legacy_windows.win_file",
            "ansible.legacy.slurp": "sustainablelobster.legacy_windows.slurp",
        }
        return cast(
            dict[str, Any],
            super()._execute_module(
                module_name=(
                    native_modules.get(module_name, module_name)
                    if module_name is not None
                    else None
                ),
                module_args=module_args,
                tmp=tmp,
                task_vars=task_vars,
                persist_files=persist_files,
                delete_remote_tmp=delete_remote_tmp,
                wrap_async=wrap_async,
                ignore_unknown_opts=ignore_unknown_opts,
            ),
        )

    def _copy_call(
        self, mode: str, variables: dict[str, object], **parameters: Any
    ) -> dict[str, Any]:
        args = dict(self._task.args)
        args.pop("content", None)
        if mode == "query":
            args.pop("src", None)
        args.update(parameters, _copy_mode=mode)
        return self._execute_module(
            module_name=_MODULE, module_args=args, task_vars=variables
        )

    def _resolve_source(
        self, lifetime: ExitStack, result: dict[str, Any]
    ) -> str | None:
        content = self._task.args.get("content")
        if content is not None:
            try:
                descriptor, source = tempfile.mkstemp(
                    dir=getattr(C, "DEFAULT_LOCAL_TMP")
                )
                lifetime.callback(os.unlink, source)
                with os.fdopen(descriptor, "wb") as stream:
                    value = (
                        json.dumps(content)
                        if isinstance(content, (dict, list))
                        else content
                    )
                    stream.write(to_bytes(value))
                return cast(str, source)
            # Arbitrary content conversion failures share the reference's message.
            except Exception as error:  # pylint: disable=broad-exception-caught
                result.update(
                    failed=True, msg=f"could not write content tmp file: {error}"
                )
                return None
        source = self._task.args["src"]
        try:
            resolved = self._find_needle("files", source)
        except AnsibleError as error:
            result.update(
                failed=True, msg=to_text(error), exception=traceback.format_exc()
            )
            return None
        if source.endswith(os.path.sep) and not resolved.endswith(os.path.sep):
            resolved += os.path.sep
        elif not source.endswith(os.path.sep) and resolved.endswith(os.path.sep):
            resolved = resolved[:-1]
        return cast(str, resolved)

    def _plan_local(
        self, source: str, destination: str, result: dict[str, Any]
    ) -> tuple[_Sources, str, str] | None:
        shell = self._connection._shell  # pylint: disable=protected-access
        if os.path.isdir(source):
            result["operation"] = "folder_copy"
            sources = _directory_sources(self._loader, source, self._task.args)
            if not shell.path_has_trailing_slash(destination):
                destination += "\\"
            return sources, destination, destination
        result["operation"] = "file_copy"
        original = os.path.basename(source)
        try:
            entry = _local_file(self._loader, source, original, self._task.args)
        except AnsibleFileNotFound as error:
            result.update(failed=True, msg=f"could not find src={source}, {error}")
            return None
        result.update(
            original_basename=original,
            checksum=entry["checksum"],
            size=os.path.getsize(entry["src"]),
        )
        if shell.path_has_trailing_slash(destination):
            query_destination = destination
            result["dest"] = shell.join_path(destination, original)
        else:
            normalized = destination.replace("\\", os.path.sep)
            query_destination = os.path.dirname(normalized) or "."
            entry["dest"] = os.path.basename(normalized)
        return (
            {"files": [entry], "directories": [], "symlinks": []},
            destination,
            query_destination,
        )

    def _send_single(
        self,
        entry: _File,
        destination: str,
        result: dict[str, Any],
        variables: dict[str, object],
    ) -> dict[str, Any]:
        backup = _option(self._task.args, "backup")
        difference = None
        if self._task.diff:
            if result["operation"] == "folder_copy":
                # The 3.8.0 action fails before diff/transfer in this one-file
                # directory branch. Preserve that measured public failure.
                raise UnboundLocalError(
                    "cannot access local variable 'source_full' "
                    "where it is not associated with a value"
                )
            difference = self._get_diff_data(
                destination,
                entry["src"],
                variables,
                content=self._task.args.get("content") is not None,
            )
        if self._task.check_mode:
            copied: dict[str, Any] = {"changed": True}
            if backup:
                copied["backup_file"] = "check-mode-backup-file.bak"
        else:
            shell = self._connection._shell  # pylint: disable=protected-access
            staged = shell.join_path(shell.tmpdir, "source")
            self._transfer_file(entry["src"], staged)
            copied = self._copy_call(
                "single",
                variables,
                src=staged,
                dest=destination,
                _original_basename=result.get("original_basename") or entry["dest"],
                backup=backup,
            )
        if difference is not None:
            copied["diff"] = difference
        if copied.get("failed") is True:
            copied["msg"] = f"failed to copy file {entry['src']}: {copied['msg']}"
        return copied

    def _send_archive(
        self,
        lifetime: ExitStack,
        sources: _Sources,
        destination: str,
        variables: dict[str, object],
    ) -> dict[str, Any]:
        if self._task.check_mode:
            return {"changed": True}
        try:
            directory = lifetime.enter_context(
                # ExitStack owns this directory through transfer and execution.
                tempfile.TemporaryDirectory(  # pylint: disable=consider-using-with
                    dir=getattr(C, "DEFAULT_LOCAL_TMP")
                )
            )
            archive = str(Path(directory) / "win_copy.zip")
            _write_archive(archive, sources)
        # Preserve the action's structured failure for any ZIP construction error.
        except Exception as error:  # pylint: disable=broad-exception-caught
            return {
                "changed": False,
                "failed": True,
                "msg": f"failed to create tmp zip file: {error}",
                "exception": traceback.format_exc(),
            }
        shell = self._connection._shell  # pylint: disable=protected-access
        staged = shell.join_path(shell.tmpdir, "source.zip")
        self._transfer_file(archive, staged)
        return self._copy_call(
            "explode",
            variables,
            src=staged,
            dest=destination,
            backup=_option(self._task.args, "backup"),
        )

    def _local_copy(
        self, lifetime: ExitStack, result: dict[str, Any], variables: dict[str, object]
    ) -> dict[str, Any]:
        source = self._resolve_source(lifetime, result)
        if source is None:
            return result
        plan = self._plan_local(source, self._task.args["dest"], result)
        if plan is None:
            return result
        sources, destination, query_destination = plan
        self._stage_module_utils()
        needed = self._copy_call(
            "query",
            variables,
            dest=query_destination,
            force=_option(self._task.args, "force", True),
            **sources,
        )
        if needed.get("failed") is True:
            result.update(needed)
            return result
        if len(needed["files"]) == 1 and not needed["directories"]:
            result.update(
                self._send_single(needed["files"][0], destination, result, variables)
            )
        elif needed["files"] or needed["directories"]:
            # The reference sends the complete source tree after its delta query.
            result.update(self._send_archive(lifetime, sources, destination, variables))
        else:
            result.update(failed=False, changed=False)
            return result
        result["changed"] = True
        return result

    def run(
        self, tmp: str | None = None, task_vars: dict[str, object] | None = None
    ) -> dict[str, Any]:
        """Resolve and copy sources, cleaning task-owned staging on every exit.

        :param tmp: Deprecated Ansible action argument; no longer used.
        :param task_vars: Variables for each native module invocation.
        :returns: Upstream-compatible controller and payload result fields.
        :raises AnsibleActionFail: If async or a non-Runas become method is requested.
        :raises Exception: If loader, transport, or execution fails, after cleanup.
        """
        self._check_execution_support()
        variables = {} if task_vars is None else task_vars
        shell = self._connection._shell  # pylint: disable=protected-access
        with ExitStack() as lifetime:
            # Register before ActionBase.run because it can allocate task staging.
            # This override must own its staging even if ActionBase.run fails.
            # pylint: disable=duplicate-code
            lifetime.callback(lambda: self._remove_tmp_path(shell.tmpdir))
            result = cast(dict[str, Any], ActionBase.run(self, tmp, variables))
            # pylint: enable=duplicate-code
            source = self._task.args.get("src")
            content = self._task.args.get("content")
            destination = self._task.args.get("dest")
            result.update(src=source, dest=destination)
            if (source is None and content is None) or destination is None:
                result.update(failed=True, msg="src (or content) and dest are required")
            elif source is not None and content is not None:
                result.update(failed=True, msg="src and content are mutually exclusive")
            elif content is not None and destination.endswith(("/", "\\")):
                result.update(
                    failed=True, msg="dest must be a file if content is defined"
                )
            if result.get("failed"):
                return result
            if content is None and _option(self._task.args, "remote_src"):
                self._stage_module_utils()
                result.update(
                    self._copy_call(
                        "remote",
                        variables,
                        src=source,
                        dest=destination,
                        force=_option(self._task.args, "force", True),
                        backup=_option(self._task.args, "backup"),
                    )
                )
                return result
            return self._local_copy(lifetime, result, variables)
