"""Render controller templates and send their bytes through the native copy action."""

# SPDX-License-Identifier: GPL-3.0-or-later

import os
import tempfile
from contextlib import ExitStack
from pathlib import Path
from typing import Any, cast

# Ansible's controller extension APIs do not distribute typing metadata.
from ansible import constants as C  # type: ignore[import-untyped]
from ansible._internal._templating._template_vars import (  # type: ignore[import-untyped]
    generate_ansible_template_vars,
)
from ansible.config.manager import ensure_type  # type: ignore[import-untyped]
from ansible.errors import (  # type: ignore[import-untyped]
    AnsibleActionFail,
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
from ansible.template import trust_as_template  # type: ignore[import-untyped]
from jinja2 import defaults

from ..plugin_utils.runtime import PythonModuleAction

_DELIMITERS = {
    "block_start_string": defaults.BLOCK_START_STRING,
    "block_end_string": defaults.BLOCK_END_STRING,
    "variable_start_string": defaults.VARIABLE_START_STRING,
    "variable_end_string": defaults.VARIABLE_END_STRING,
    "comment_start_string": defaults.COMMENT_START_STRING,
    "comment_end_string": defaults.COMMENT_END_STRING,
}
_TEMPLATE_OPTIONS = frozenset(
    (
        *_DELIMITERS,
        "trim_blocks",
        "lstrip_blocks",
        "newline_sequence",
        "output_encoding",
    )
)


def _render_options(args: dict[str, Any]) -> dict[str, Any]:
    for name in ("src", "dest", "state", "newline_sequence", *_DELIMITERS):
        if name in args:
            value = ensure_type(args[name], "string")
            if value is not None and not isinstance(value, str):
                raise AnsibleActionFail(
                    f"{name} is expected to be a string, but got {type(value)} instead"
                )
            args[name] = value

    options = {name: args.get(name, default) for name, default in _DELIMITERS.items()}
    try:
        options.update(
            trim_blocks=boolean(args.get("trim_blocks", True), strict=False),
            lstrip_blocks=boolean(args.get("lstrip_blocks", False), strict=False),
        )
    except TypeError as error:
        raise AnsibleActionFail(str(error)) from error

    newline = args.get("newline_sequence", "\r\n")
    newline = {r"\n": "\n", r"\r": "\r", r"\r\n": "\r\n"}.get(newline, newline)
    if args.get("state") is not None:
        raise AnsibleActionFail("'state' cannot be specified on a template")
    if args.get("src") is None or args.get("dest") is None:
        raise AnsibleActionFail("src and dest are required")
    if newline not in ("\n", "\r", "\r\n"):
        raise AnsibleActionFail("newline_sequence needs to be one of: \n, \r or \r\n")
    options["newline_sequence"] = newline
    return options


# Reuse the collection's execution guards, not its one-payload staging lifecycle.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Render with Ansible's templater before invoking the Python-only copy action."""

    TRANSFERS_FILES = True

    def _render(
        self,
        source: str,
        args: dict[str, Any],
        variables: dict[str, object],
        options: dict[str, Any],
    ) -> bytes:
        try:
            readable_source = self._loader.get_real_file(source)
        except AnsibleFileNotFound as error:
            raise AnsibleActionFail(f"could not find src={source}, {error}") from error

        try:
            content = trust_as_template(self._loader.get_text_file_contents(source))
            # Include each role/playbook root and its templates directory without
            # mutating the caller's search list when this action is used in a loop.
            roots = [*cast(list[str], variables.get("ansible_search_path", []))]
            roots.extend((self._loader.get_basedir(), os.path.dirname(source)))
            searchpath = [
                path
                for root in roots
                for path in (os.path.join(root, "templates"), root)
            ]
            render_vars = dict(variables)
            render_vars.update(
                generate_ansible_template_vars(
                    args["src"],
                    fullpath=source,
                    dest_path=args["dest"],
                    include_ansible_managed="ansible_managed" not in render_vars,
                )
            )
            templar = self._templar.copy_with_new_env(
                searchpath=searchpath, available_variables=render_vars
            )
            rendered = templar.template(
                content,
                preserve_trailing_newlines=True,
                escape_backslashes=False,
                overrides=options,
            )
            return cast(
                bytes,
                to_bytes(
                    rendered,
                    encoding=args.get("output_encoding") or "utf-8",
                    errors="surrogate_or_strict",
                ),
            )
        finally:
            self._loader.cleanup_tmp_file(readable_source)

    def run(
        self, tmp: str | None = None, task_vars: dict[str, object] | None = None
    ) -> dict[str, Any]:
        """Render a template, delegate copying, and remove task-owned staging.

        :param tmp: Deprecated Ansible action argument; no longer used.
        :param task_vars: Variables available to the template and copy action.
        :returns: The delegated copy action's public result fields.
        :raises AnsibleActionFail: If arguments or execution options are invalid.
        :raises Exception: If loading, rendering, or copying fails, after cleanup.
        """
        self._check_execution_support()
        variables = {} if task_vars is None else task_vars
        shell = self._connection._shell  # pylint: disable=protected-access
        with ExitStack() as lifetime:
            lifetime.callback(lambda: self._remove_tmp_path(shell.tmpdir))
            result = cast(dict[str, Any], ActionBase.run(self, tmp, variables))
            args = dict(self._task.args)
            options = _render_options(args)
            try:
                source = self._find_needle("templates", args["src"])
            except AnsibleError as error:
                raise AnsibleActionFail(to_text(error)) from error
            directory = lifetime.enter_context(
                tempfile.TemporaryDirectory(dir=getattr(C, "DEFAULT_LOCAL_TMP"))
            )
            rendered_path = Path(directory) / os.path.basename(source)
            rendered_path.write_bytes(self._render(source, args, variables, options))
            copy_task = self._task.copy()
            copy_task.args = {
                name: value
                for name, value in args.items()
                if name not in _TEMPLATE_OPTIONS
            }
            copy_task.args["src"] = str(rendered_path)
            copy_action = self._shared_loader_obj.action_loader.get(
                "sustainablelobster.legacy_windows.win_copy",
                task=copy_task,
                connection=self._connection,
                play_context=self._play_context,
                loader=self._loader,
                templar=self._templar,
                shared_loader_obj=self._shared_loader_obj,
            )
            result.update(copy_action.run(task_vars=variables))
            return result
