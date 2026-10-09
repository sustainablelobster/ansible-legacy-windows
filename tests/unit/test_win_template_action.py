"""Exercise real controller templating with a captured native copy delegation."""

# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import datetime
import ntpath
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

# Ansible's controller interfaces do not distribute typing metadata.
from ansible import constants as C  # type: ignore[import-untyped]
from ansible.errors import (  # type: ignore[import-untyped]
    AnsibleActionFail,
    AnsibleError,
)
from ansible.parsing.dataloader import DataLoader  # type: ignore[import-untyped]
from ansible.parsing.vault import (  # type: ignore[import-untyped]
    VaultLib,
    VaultSecret,
)
from ansible.plugins.action import ActionBase  # type: ignore[import-untyped]
from ansible.template import Templar  # type: ignore[import-untyped]

from plugins.action import win_copy, win_template  # pylint: disable=import-error

_REMOTE = r"C:\Temp\ansible-tmp-template-test"
_DEST = r"C:\target\config.txt"


def _action(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    args: dict[str, Any],
    **task_options: Any,
) -> tuple[win_template.ActionModule, SimpleNamespace]:
    local_tmp = tmp_path / "controller-temp"
    local_tmp.mkdir(exist_ok=True)
    monkeypatch.setattr(C, "DEFAULT_LOCAL_TMP", str(local_tmp))
    monkeypatch.setattr(C, "DEFAULT_KEEP_REMOTE_FILES", False)
    state = SimpleNamespace(
        local_tmp=local_tmp,
        calls=[],
        cleanup=[],
        variables={"value": "Café 雪"},
        result={"changed": True, "checksum": "returned-checksum"},
        error=None,
    )
    state.shell = SimpleNamespace(
        tmpdir=None, remove=lambda path, recurse: (path, recurse)
    )
    state.task = SimpleNamespace(
        action="sustainablelobster.legacy_windows.win_template",
        args=args,
        async_val=0,
        check_mode=False,
        diff=False,
        no_log=False,
        get_search_path=lambda: [str(tmp_path)],
    )
    state.task.copy = lambda: copy.copy(state.task)
    for name, value in task_options.items():
        setattr(state.task, name, value)
    state.loader = DataLoader()
    state.loader.set_basedir(str(tmp_path))
    action = win_template.ActionModule(
        state.task,
        SimpleNamespace(_shell=state.shell, become=None),
        None,
        state.loader,
        Templar(loader=state.loader),
    )

    def _make_tmp() -> str:
        state.shell.tmpdir = _REMOTE
        action._cleanup_remote_tmp = True  # pylint: disable=protected-access
        return _REMOTE

    def _cleanup(command: object, **_kwargs: object) -> dict[str, int]:
        state.cleanup.append(command)
        return {"rc": 0}

    def _get_action(name: str, **kwargs: Any) -> SimpleNamespace:
        task = kwargs["task"]

        def _copy(*, task_vars: dict[str, object]) -> dict[str, Any]:
            state.calls.append(
                {
                    "action": name,
                    "task": task,
                    "variables": task_vars,
                    "content": Path(task.args["src"]).read_bytes(),
                    "connection": kwargs["connection"],
                    "loader": kwargs["loader"],
                }
            )
            if state.error is not None:
                raise state.error
            return cast(dict[str, Any], state.result)

        return SimpleNamespace(run=_copy)

    monkeypatch.setattr(action, "_make_tmp_path", _make_tmp)
    monkeypatch.setattr(action, "_low_level_execute_command", _cleanup)
    monkeypatch.setattr(
        action,
        "_shared_loader_obj",
        SimpleNamespace(action_loader=SimpleNamespace(get=_get_action)),
    )
    return action, state


def _source(tmp_path: Path, content: str = "value={{ value }}\n\n") -> Path:
    directory = tmp_path / "templates"
    directory.mkdir(exist_ok=True)
    source = directory / "config.j2"
    source.write_text(content, encoding="utf-8")
    return source


def _assert_clean(state: SimpleNamespace, *, runs: int = 1) -> None:
    assert not list(state.local_tmp.iterdir())
    assert state.shell.tmpdir is None
    assert state.cleanup == [(_REMOTE, True)] * runs
    assert not state.loader._tempfiles  # pylint: disable=protected-access
    for call in state.calls:
        assert not Path(call["task"].args["src"]).exists()


def test_relative_template_renders_crlf_and_delegates_without_mutating_task(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _source(tmp_path)
    args = {"src": "config.j2", "dest": _DEST}
    action, state = _action(monkeypatch, tmp_path, args)
    assert action.run(task_vars=state.variables) == state.result
    assert len(state.calls) == 1
    call = state.calls[0]
    assert call["content"] == "value=Café 雪\r\n\r\n".encode()
    assert call["action"] == "sustainablelobster.legacy_windows.win_copy"
    assert call["task"].args["dest"] == _DEST
    assert Path(call["task"].args["src"]).name == "config.j2"
    assert call["variables"] is state.variables
    assert call["loader"] is state.loader
    assert call["connection"] is action._connection  # pylint: disable=protected-access
    assert state.task.args == args == {"src": "config.j2", "dest": _DEST}
    _assert_clean(state)


@pytest.mark.parametrize("changed", [False, True])
def test_nested_copy_reuses_and_cleans_template_staging(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, changed: bool
) -> None:
    _source(tmp_path)
    action, state = _action(monkeypatch, tmp_path, {"src": "config.j2", "dest": _DEST})
    state.shell.join_path = ntpath.join
    state.shell.path_has_trailing_slash = lambda path: path.endswith(("/", "\\"))
    transfers = []

    def _new_directory(_self: object) -> str:
        pytest.fail("Nested copy must reuse the template's existing staging directory")

    def _transfer(_self: object, source: str, destination: str) -> str:
        transfers.append((destination, Path(source).read_bytes()))
        return destination

    def _execute(_self: object, **kwargs: Any) -> dict[str, Any]:
        parameters = kwargs["module_args"]
        if parameters["_copy_mode"] == "query":
            return {
                "changed": False,
                "files": parameters["files"] if changed else [],
                "directories": [],
                "symlinks": [],
            }
        assert parameters["_copy_mode"] == "single"
        return {"changed": True}

    def _get_action(name: str, **kwargs: Any) -> win_copy.ActionModule:
        assert name == "sustainablelobster.legacy_windows.win_copy"
        return win_copy.ActionModule(**kwargs)

    monkeypatch.setattr(win_copy.ActionModule, "_make_tmp_path", _new_directory)
    monkeypatch.setattr(win_copy.ActionModule, "_transfer_file", _transfer)
    monkeypatch.setattr(ActionBase, "_execute_module", _execute)
    state_loader = action._shared_loader_obj  # pylint: disable=protected-access
    state_loader.action_loader.get = _get_action
    result = action.run(task_vars=state.variables)
    assert result["changed"] is changed
    assert transfers and all(ntpath.dirname(path) == _REMOTE for path, _ in transfers)
    staged_content = [
        data for path, data in transfers if ntpath.basename(path) == "source"
    ]
    assert staged_content == (["value=Café 雪\r\n\r\n".encode()] if changed else [])
    _assert_clean(state)


@pytest.mark.parametrize("newline", ["\n", "\r", "\r\n", r"\n", r"\r", r"\r\n"])
def test_literal_and_escaped_newlines(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, newline: str
) -> None:
    _source(tmp_path, "{{ 'first' }}\r\nsecond\nthird\r\n\n")
    action, state = _action(
        monkeypatch,
        tmp_path,
        {"src": "config.j2", "dest": _DEST, "newline_sequence": newline},
    )
    action.run()
    expected = newline.replace(r"\r", "\r").replace(r"\n", "\n")
    # Core 2.21's trailing-newline preservation adds a third CR for this mixed
    # source. The untouched 3.8.0 reference action produces these same bytes.
    trailing = ["", "", ""] if expected == "\r" else ["", ""]
    assert (
        state.calls[0]["content"]
        == expected.join(["first", "second", "third", *trailing]).encode()
    )
    assert "newline_sequence" not in state.calls[0]["task"].args
    _assert_clean(state)


def test_literal_source_without_jinja_keeps_original_newlines(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _source(tmp_path, "first\r\nsecond\n")
    action, state = _action(
        monkeypatch,
        tmp_path,
        {"src": "config.j2", "dest": _DEST, "newline_sequence": "\r\n"},
    )
    action.run()
    assert state.calls[0]["content"] == b"first\r\nsecond\n"
    _assert_clean(state)


@pytest.mark.parametrize(
    ("trim", "lstrip", "expected"),
    [(True, False, b"  line  end\r\n"), (False, True, b"\r\nline\r\n\r\nend\r\n")],
)
def test_delimiters_and_whitespace_options(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    trim: bool,
    lstrip: bool,
    expected: bytes,
) -> None:
    _source(tmp_path, "  <% if true %>\n<< value >><# ignored #>\n  <% endif %>\nend\n")
    args = {
        "src": "config.j2",
        "dest": _DEST,
        "block_start_string": "<%",
        "block_end_string": "%>",
        "variable_start_string": "<<",
        "variable_end_string": ">>",
        "comment_start_string": "<#",
        "comment_end_string": "#>",
        "trim_blocks": trim,
        "lstrip_blocks": lstrip,
    }
    action, state = _action(monkeypatch, tmp_path, args)
    action.run(task_vars={"value": "line"})
    assert state.calls[0]["content"] == expected
    assert set(state.calls[0]["task"].args) == {"src", "dest"}
    _assert_clean(state)


def test_jinja_header_overrides_action_delimiters(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _source(
        tmp_path,
        "#jinja2:variable_start_string:'[%', variable_end_string:'%]', "
        "trim_blocks: False\n[% value %]\n{{ literal }}\n",
    )
    action, state = _action(monkeypatch, tmp_path, {"src": "config.j2", "dest": _DEST})
    action.run(task_vars=state.variables)
    assert state.calls[0]["content"] == "Café 雪\r\n{{ literal }}\r\n".encode()
    _assert_clean(state)


def test_includes_search_role_and_templates_roots_without_changing_search_list(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    role = tmp_path / "role"
    (role / "templates").mkdir(parents=True)
    (role / "templates" / "header.j2").write_text(
        "role {{ value }}\n", encoding="utf-8"
    )
    (role / "plain.j2").write_text("root\n", encoding="utf-8")
    _source(
        tmp_path,
        "{% include 'header.j2' %}{% include 'plain.j2' %}{% include 'tail.j2' %}",
    )
    (tmp_path / "templates" / "tail.j2").write_text("tail", encoding="utf-8")
    search = [str(role)]
    variables: dict[str, object] = {"ansible_search_path": search, "value": "one"}
    action, state = _action(monkeypatch, tmp_path, {"src": "config.j2", "dest": _DEST})
    action.run(task_vars=variables)
    assert state.calls[0]["content"] == b"role oneroottail"
    assert search == [str(role)]
    _assert_clean(state)


def test_template_metadata_and_user_ansible_managed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = _source(
        tmp_path,
        "{{ template_path }}|{{ template_fullpath }}|{{ template_destpath }}|"
        "{{ template_mtime.isoformat() }}|{{ template_host }}|{{ template_uid }}|"
        "{{ template_run_date.year }}|{{ ansible_managed }}\n",
    )
    os.utime(source, (946782245, 946782245))
    action, state = _action(monkeypatch, tmp_path, {"src": "config.j2", "dest": _DEST})
    variables: dict[str, object] = {
        "ansible_managed": "user-managed",
        "template_path": "wrong",
    }
    action.run(task_vars=variables)
    fields = state.calls[0]["content"].decode().rstrip().split("|")
    assert fields[:4] == [
        "config.j2",
        str(source),
        _DEST,
        datetime.datetime.fromtimestamp(946782245).isoformat(),
    ]
    assert fields[4] == os.uname().nodename
    assert fields[5]
    assert fields[6:] == [str(datetime.datetime.now().year), "user-managed"]
    assert variables == {"ansible_managed": "user-managed", "template_path": "wrong"}
    _assert_clean(state)


def test_default_ansible_managed_variable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _source(tmp_path, "{{ ansible_managed }}\n")
    action, state = _action(monkeypatch, tmp_path, {"src": "config.j2", "dest": _DEST})
    action.run()
    assert state.calls[0]["content"] == b"Ansible managed\r\n"
    _assert_clean(state)


@pytest.mark.parametrize(
    "encoding", [None, "", "utf-8", "utf-16-le", "utf-16", "cp1252"]
)
def test_output_encoding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, encoding: str | None
) -> None:
    _source(tmp_path, "{{ value }}\n")
    action, state = _action(
        monkeypatch,
        tmp_path,
        {"src": "config.j2", "dest": _DEST, "output_encoding": encoding},
    )
    action.run(task_vars={"value": "Café"})
    assert state.calls[0]["content"] == "Café\r\n".encode(encoding or "utf-8")
    assert "output_encoding" not in state.calls[0]["task"].args
    _assert_clean(state)


def test_vault_template_is_rendered_and_decrypted_file_is_removed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    secret = VaultSecret(b"test-only-secret")
    source = _source(tmp_path)
    source.write_bytes(VaultLib().encrypt(b"private={{ value }}\n", secret))
    encrypted = source.read_bytes()
    action, state = _action(monkeypatch, tmp_path, {"src": "config.j2", "dest": _DEST})
    state.loader.set_vault_secrets([("default", secret)])
    action.run(task_vars={"value": "rendered"})
    assert state.calls[0]["content"] == b"private=rendered\r\n"
    assert source.read_bytes() == encrypted
    _assert_clean(state)


@pytest.mark.parametrize("with_secret", [False, True])
def test_vault_failure_leaves_no_decrypted_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, with_secret: bool
) -> None:
    secret = VaultSecret(b"test-only-secret")
    source = _source(tmp_path)
    source.write_bytes(VaultLib().encrypt(b"{{ absent_variable }}", secret))
    action, state = _action(monkeypatch, tmp_path, {"src": "config.j2", "dest": _DEST})
    if with_secret:
        state.loader.set_vault_secrets([("default", secret)])
    with pytest.raises(AnsibleError):
        action.run()
    assert not state.calls
    _assert_clean(state)


def test_literal_backslashes_are_not_escaped_again(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _source(tmp_path, r"{{ 'C:\\path\\value' }}")
    action, state = _action(monkeypatch, tmp_path, {"src": "config.j2", "dest": _DEST})
    action.run()
    assert state.calls[0]["content"] == b"C:\\path\\value"
    _assert_clean(state)


def test_copy_options_check_diff_and_result_pass_through(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _source(tmp_path)
    action, state = _action(
        monkeypatch,
        tmp_path,
        {
            "src": "config.j2",
            "dest": _DEST,
            "backup": True,
            "force": False,
            "newline_sequence": r"\n",
        },
        check_mode=True,
        diff=True,
        no_log=True,
    )
    state.result = {
        "changed": True,
        "backup_file": "copy-backup",
        "diff": [{"before": "old", "after": "new"}],
        "size": 42,
    }
    assert action.run(task_vars=state.variables) == state.result
    task = state.calls[0]["task"]
    assert task.check_mode is True and task.diff is True and task.no_log is True
    assert task.args["backup"] is True and task.args["force"] is False
    assert set(task.args) == {"src", "dest", "backup", "force"}
    _assert_clean(state)


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ({}, "src and dest are required"),
        ({"src": "config.j2"}, "src and dest are required"),
        ({"dest": _DEST}, "src and dest are required"),
        (
            {"src": "config.j2", "dest": _DEST, "state": "file"},
            "'state' cannot be specified",
        ),
        (
            {"src": "config.j2", "dest": _DEST, "newline_sequence": "bad"},
            "newline_sequence needs",
        ),
        (
            {"src": "config.j2", "dest": _DEST, "newline_sequence": None},
            "newline_sequence needs",
        ),
        ({"src": "absent.j2", "dest": _DEST}, "Could not find or access"),
    ],
)
def test_invalid_arguments_fail_with_cleanup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, args: dict[str, Any], message: str
) -> None:
    _source(tmp_path)
    action, state = _action(monkeypatch, tmp_path, args)
    with pytest.raises(AnsibleActionFail, match=message):
        action.run()
    assert not state.calls
    _assert_clean(state)


@pytest.mark.parametrize(
    "name",
    [
        "src",
        "dest",
        "state",
        "newline_sequence",
        "variable_start_string",
        "variable_end_string",
        "block_start_string",
        "block_end_string",
        "comment_start_string",
        "comment_end_string",
    ],
)
def test_nonstring_arguments_use_ansible_validation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str
) -> None:
    action, state = _action(
        monkeypatch, tmp_path, {"src": "config.j2", "dest": _DEST, name: []}
    )
    with pytest.raises(ValueError, match="string"):
        action.run()
    assert not state.calls
    _assert_clean(state)


@pytest.mark.parametrize("name", ["trim_blocks", "lstrip_blocks"])
def test_nonboolean_option_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str
) -> None:
    action, state = _action(
        monkeypatch, tmp_path, {"src": "config.j2", "dest": _DEST, name: []}
    )
    with pytest.raises(AnsibleActionFail, match="bool"):
        action.run()
    _assert_clean(state)


@pytest.mark.parametrize(
    "content", ["{{ absent_variable }}", "{% if %}", "{% include 'missing.j2' %}"]
)
def test_render_failure_cleans_up_and_subsequent_run_recovers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, content: str
) -> None:
    source = _source(tmp_path, content)
    action, state = _action(monkeypatch, tmp_path, {"src": "config.j2", "dest": _DEST})
    with pytest.raises(AnsibleError):
        action.run()
    assert not state.calls
    _assert_clean(state)
    source.write_text("{{ 'recovered' }}\n", encoding="utf-8")
    action.run()
    assert state.calls[0]["content"] == b"recovered\r\n"
    _assert_clean(state, runs=2)


@pytest.mark.parametrize("encoding", ["absent-codec", "ascii"])
def test_encoding_failure_is_cleaned_up(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, encoding: str
) -> None:
    _source(tmp_path)
    action, state = _action(
        monkeypatch,
        tmp_path,
        {"src": "config.j2", "dest": _DEST, "output_encoding": encoding},
    )
    with pytest.raises((LookupError, UnicodeError)):
        action.run(task_vars=state.variables)
    assert not state.calls
    _assert_clean(state)


@pytest.mark.parametrize("raises", [False, True])
def test_copy_failure_preserves_result_or_exception_and_cleans_temporary_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, raises: bool
) -> None:
    _source(tmp_path)
    action, state = _action(monkeypatch, tmp_path, {"src": "config.j2", "dest": _DEST})
    state.result = {"failed": True, "changed": False, "msg": "copy failure"}
    if raises:
        state.error = AnsibleError("copy interrupted")
        with pytest.raises(AnsibleError, match="copy interrupted"):
            action.run(task_vars=state.variables)
    else:
        assert action.run(task_vars=state.variables) == state.result
    _assert_clean(state)


@pytest.mark.parametrize("guard", ["async", "become"])
def test_unsupported_execution_fails_before_allocating_staging(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, guard: str
) -> None:
    action, state = _action(monkeypatch, tmp_path, {"src": "config.j2", "dest": _DEST})
    if guard == "async":
        state.task.async_val = 1
        message = "does not support async"
    else:
        # Exercise a resolved unsupported method, not a boolean placeholder.
        action._connection.become = SimpleNamespace(  # pylint: disable=protected-access
            name="sudo"
        )
        message = "privilege escalation supports only runas"
    with pytest.raises(AnsibleActionFail, match=message):
        action.run()
    assert not state.calls and not state.cleanup and state.shell.tmpdir is None
    assert not list(state.local_tmp.iterdir())
