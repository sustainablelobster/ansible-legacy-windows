"""Exercise public copy planning and transfer lifetimes without a Windows host."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import hashlib
import json
import ntpath
import os
import zipfile
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

import pytest

# Ansible's controller interfaces do not distribute typing metadata.
from ansible import constants as C  # type: ignore[import-untyped]
from ansible._internal._templating._engine import (  # type: ignore[import-untyped]
    TemplateEngine,
)
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
from ansible_collections.sustainablelobster.legacy_windows.plugins.action import (
    win_copy,  # pylint: disable=import-error
)

_REMOTE = r"C:\Temp\ansible-tmp-copy-test"
_DEST = r"C:\target\file.txt"
_MODULE = "sustainablelobster.legacy_windows.win_copy"
_Response = Callable[[str, dict[str, Any]], dict[str, Any]]


def _action(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    args: dict[str, Any],
    *,
    response: _Response | None = None,
    **task_options: Any,
) -> tuple[win_copy.ActionModule, SimpleNamespace]:
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    local_tmp = tmp_path / "controller-temp"
    local_tmp.mkdir(exist_ok=True)
    monkeypatch.setattr(C, "DEFAULT_LOCAL_TMP", str(local_tmp))
    monkeypatch.setattr(C, "DEFAULT_KEEP_REMOTE_FILES", False)
    state = SimpleNamespace(
        local_tmp=local_tmp,
        calls=[],
        transfers=[],
        archives=[],
        cleanup=[],
        variables={"marker": "preserved"},
    )
    # pylint: enable=duplicate-code
    state.shell = SimpleNamespace(
        tmpdir=None,
        join_path=ntpath.join,
        path_has_trailing_slash=lambda path: path.endswith(("/", "\\")),
        remove=lambda path, recurse: (path, recurse),
    )
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    task = SimpleNamespace(
        action=_MODULE,
        args=args,
        async_val=0,
        check_mode=False,
        diff=False,
        no_log=False,
    )
    # pylint: enable=duplicate-code
    for name, value in task_options.items():
        setattr(task, name, value)
    state.loader = DataLoader()
    action = win_copy.ActionModule(
        task,
        SimpleNamespace(_shell=state.shell, become=None),
        None,
        state.loader,
        TemplateEngine(),
    )

    def _make_tmp() -> str:
        state.shell.tmpdir = _REMOTE
        action._cleanup_remote_tmp = True  # pylint: disable=protected-access
        return _REMOTE

    def _transfer(source: str, destination: str) -> str:
        state.transfers.append((source, destination, Path(source).read_bytes()))
        if destination.endswith("source.zip"):
            with zipfile.ZipFile(source) as archive:
                state.archives.append(
                    {
                        base64.b64decode(info.filename.rstrip("/")).decode("utf-8")
                        + ("/" if info.is_dir() else ""): archive.read(info)
                        for info in archive.infolist()
                    }
                )
        return destination

    def _execute(_self: object, **kwargs: Any) -> dict[str, Any]:
        state.calls.append(kwargs)
        parameters = kwargs["module_args"]
        if response is not None:
            return response(kwargs["module_name"], parameters)
        if parameters.get("_copy_mode") == "query":
            return {
                "changed": False,
                "files": parameters["files"],
                "directories": parameters["directories"],
                "symlinks": [],
            }
        return {"changed": True}

    def _cleanup(command: object, **_kwargs: object) -> dict[str, int]:
        state.cleanup.append(command)
        return {"rc": 0}

    monkeypatch.setattr(
        action, "_find_needle", lambda _directory, path: path.rstrip("/")
    )
    monkeypatch.setattr(action, "_make_tmp_path", _make_tmp)
    monkeypatch.setattr(action, "_transfer_file", _transfer)
    monkeypatch.setattr(action, "_low_level_execute_command", _cleanup)
    monkeypatch.setattr(ActionBase, "_execute_module", _execute)
    return action, state


def _source(tmp_path: Path, content: bytes = b"example\n") -> Path:
    source = tmp_path / "source.txt"
    source.write_bytes(content)
    return source


def _assert_clean(state: SimpleNamespace) -> None:
    assert not list(state.local_tmp.iterdir())
    assert state.shell.tmpdir is None
    assert state.cleanup == [(_REMOTE, True)]


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ({}, "src (or content) and dest are required"),
        ({"src": "file"}, "src (or content) and dest are required"),
        ({"dest": _DEST}, "src (or content) and dest are required"),
        (
            {"src": "file", "content": "text", "dest": _DEST},
            "src and content are mutually exclusive",
        ),
        (
            {"content": "text", "dest": "C:\\folder\\"},
            "dest must be a file if content is defined",
        ),
        (
            {"content": "text", "dest": "C:/folder/"},
            "dest must be a file if content is defined",
        ),
    ],
)
def test_invalid_inputs_fail_before_staging(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, args: dict[str, Any], message: str
) -> None:
    action, state = _action(monkeypatch, tmp_path, args)
    assert action.run() == {
        "src": args.get("src"),
        "dest": args.get("dest"),
        "failed": True,
        "msg": message,
    }
    assert not state.calls and not state.transfers and not state.cleanup


@pytest.mark.parametrize(
    "destination", [_DEST, "C:/target/", "C:\\target\\", "file.txt"]
)
def test_single_file_queries_then_transfers_with_public_results(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, destination: str
) -> None:
    source = _source(tmp_path)
    action, state = _action(
        monkeypatch, tmp_path, {"src": str(source), "dest": destination}
    )
    result = action.run(task_vars=state.variables)
    query, copy = [call["module_args"] for call in state.calls]
    assert query["_copy_mode"] == "query" and "src" not in query
    assert query["files"][0]["src"] == str(source)
    assert query["files"][0]["checksum"] == hashlib.sha1(b"example\n").hexdigest()
    assert copy["_copy_mode"] == "single"
    assert copy["src"] == ntpath.join(_REMOTE, "source")
    assert copy["dest"] == destination
    assert copy["_original_basename"] == source.name
    assert result["src"] == str(source)
    assert result["operation"] == "file_copy"
    assert result["size"] == 8 and result["changed"] is True
    assert result["checksum"] == query["files"][0]["checksum"]
    assert all(call["task_vars"] is state.variables for call in state.calls)
    assert all(call["module_name"] == _MODULE for call in state.calls)
    assert state.transfers[-1][2] == b"example\n"
    if destination.endswith(("/", "\\")):
        assert result["dest"] == ntpath.join(destination, source.name)
        assert query["dest"] == destination
    else:
        assert query["dest"] == ("C:/target" if ":" in destination else ".")
        assert query["files"][0]["dest"] == "file.txt"
    _assert_clean(state)


@pytest.mark.parametrize("content", ["", "snowman ☃\n", {"key": [1, True]}, [1, "two"]])
def test_content_is_encoded_and_removed_after_transfer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, content: object
) -> None:
    action, state = _action(
        monkeypatch,
        tmp_path,
        {"content": content, "dest": _DEST, "remote_src": True},
    )
    result = action.run()
    expected = json.dumps(content) if isinstance(content, (dict, list)) else content
    assert state.transfers[-1][2] == str(expected).encode("utf-8")
    assert result["src"] is None
    assert result["original_basename"].startswith("tmp")
    assert all("content" not in call["module_args"] for call in state.calls)
    _assert_clean(state)


@pytest.mark.parametrize("force", [False, "no", "unknown-value"])
def test_force_false_skips_controller_hashing_and_preserves_noop_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, force: object
) -> None:
    source = _source(tmp_path)
    action, state = _action(
        monkeypatch,
        tmp_path,
        {"src": str(source), "dest": _DEST, "force": force},
        response=lambda _name, _args: {"files": [], "directories": [], "symlinks": []},
    )
    monkeypatch.setattr(
        win_copy, "checksum", lambda _path: pytest.fail("checksum read")
    )
    result = action.run()
    assert result["changed"] is False and result["failed"] is False
    assert result["checksum"] is None
    assert len(state.calls) == 1
    assert state.calls[0]["module_args"]["force"] is False
    assert not any(
        destination.endswith("source") for _, destination, _ in state.transfers
    )
    _assert_clean(state)


@pytest.mark.parametrize("check_mode", [False, True])
def test_remote_source_uses_only_remote_payload(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, check_mode: bool
) -> None:
    args = {
        "src": r"C:\remote\file",
        "dest": _DEST,
        "remote_src": "yes",
        "backup": "yes",
    }
    action, state = _action(monkeypatch, tmp_path, args, check_mode=check_mode)
    result = action.run()
    assert result == {"src": args["src"], "dest": _DEST, "changed": True}
    assert len(state.calls) == 1
    assert state.calls[0]["module_args"] == dict(
        args, _copy_mode="remote", backup=True, force=True
    )
    assert not any(
        destination.endswith("source") for _, destination, _ in state.transfers
    )
    _assert_clean(state)


@pytest.mark.parametrize("backup", [False, True])
def test_single_check_mode_queries_but_never_transfers_content(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, backup: bool
) -> None:
    source = _source(tmp_path)
    action, state = _action(
        monkeypatch,
        tmp_path,
        {"src": str(source), "dest": _DEST, "backup": backup},
        check_mode=True,
    )
    result = action.run()
    assert result["changed"] is True
    assert result.get("backup_file") == (
        "check-mode-backup-file.bak" if backup else None
    )
    assert len(state.calls) == 1
    assert not any(
        destination.endswith("source") for _, destination, _ in state.transfers
    )
    _assert_clean(state)


@pytest.mark.parametrize("trailing_slash", [False, True])
def test_directory_transfer_preserves_relative_names_and_empty_directories(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, trailing_slash: bool
) -> None:
    source = tmp_path / "tree"
    source.mkdir()
    (source / "empty").mkdir()
    (source / "☃.txt").write_bytes(b"unicode filename")
    (source / "other.bin").write_bytes(b"\0binary")
    action, state = _action(
        monkeypatch,
        tmp_path,
        {"src": str(source) + ("/" if trailing_slash else ""), "dest": r"C:\target"},
    )
    result = action.run()
    prefix = "" if trailing_slash else "tree/"
    assert state.archives == [
        {
            prefix + "empty/": b"",
            prefix + "☃.txt": b"unicode filename",
            prefix + "other.bin": b"\0binary",
        }
    ]
    assert [call["module_args"]["_copy_mode"] for call in state.calls] == [
        "query",
        "explode",
    ]
    assert state.calls[1]["module_args"]["dest"] == "C:\\target\\"
    assert result["operation"] == "folder_copy" and result["dest"] == r"C:\target"
    assert "size" not in result and "checksum" not in result
    _assert_clean(state)


def test_directory_delta_triggers_complete_archive_like_reference(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "tree"
    source.mkdir()
    (source / "present.txt").write_bytes(b"present")
    (source / "missing").mkdir()

    def _response(_name: str, args: dict[str, Any]) -> dict[str, Any]:
        if args["_copy_mode"] == "query":
            return {"files": [], "directories": args["directories"]}
        return {"changed": True}

    action, state = _action(
        monkeypatch,
        tmp_path,
        {"src": str(source), "dest": _DEST, "force": False},
        response=_response,
    )
    assert action.run()["changed"] is True
    assert state.archives == [{"tree/missing/": b"", "tree/present.txt": b"present"}]
    _assert_clean(state)


@pytest.mark.parametrize("local_follow", [False, True])
def test_local_links_follow_only_when_requested_and_cycles_are_not_copied(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, local_follow: bool
) -> None:
    source = tmp_path / "tree"
    source.mkdir()
    external = tmp_path / "external"
    external.mkdir()
    (external / "file.txt").write_bytes(b"outside")
    (source / "linked-dir").symlink_to(external, target_is_directory=True)
    (source / "linked-file").symlink_to(external / "file.txt")
    (source / "loop").symlink_to(source, target_is_directory=True)
    action, state = _action(
        monkeypatch,
        tmp_path,
        {"src": str(source) + "/", "dest": r"C:\target", "local_follow": local_follow},
    )
    result = action.run()
    query = state.calls[0]["module_args"]
    if local_follow:
        assert {entry["dest"] for entry in query["files"]} == {
            "linked-file",
            "linked-dir/file.txt",
        }
        assert [entry["dest"] for entry in query["symlinks"]] == ["loop"]
        assert state.archives == [
            {
                "linked-dir/": b"",
                "linked-file": b"outside",
                "linked-dir/file.txt": b"outside",
            }
        ]
    else:
        assert not query["files"] and not query["directories"]
        assert {entry["dest"] for entry in query["symlinks"]} == {
            "linked-file",
            "linked-dir",
            "loop",
        }
        assert not state.archives and result["changed"] is False
    _assert_clean(state)


def test_loader_decrypts_vault_content_before_hash_and_transfer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    secret = VaultSecret(b"test-only-vault-secret")
    vault = VaultLib([("default", secret)])
    source = _source(tmp_path, vault.encrypt(b"decrypted value"))
    action, state = _action(monkeypatch, tmp_path, {"src": str(source), "dest": _DEST})
    state.loader.set_vault_secrets([("default", secret)])
    try:
        result = action.run()
        assert state.transfers[-1][2] == b"decrypted value"
        assert result["checksum"] == hashlib.sha1(b"decrypted value").hexdigest()
        assert result["original_basename"] == source.name
    finally:
        # DataLoader owns decrypted paths and removes them at its task boundary.
        state.loader.cleanup_all_tmp_files()
    _assert_clean(state)


def test_diff_uses_native_peek_and_slurp_and_ansible_text_format(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = _source(tmp_path, b"after\n")

    def _response(name: str, args: dict[str, Any]) -> dict[str, Any]:
        if name.endswith("win_file"):
            assert args == {"path": _DEST, "_diff_peek": True}
            return {"state": "file", "appears_binary": False}
        if name.endswith("slurp"):
            return {
                "content": base64.b64encode(b"before\n").decode("ascii"),
                "encoding": "base64",
            }
        if args["_copy_mode"] == "query":
            return {"files": args["files"], "directories": []}
        return {"changed": True, "diff": {}}

    action, state = _action(
        monkeypatch,
        tmp_path,
        {"src": str(source), "dest": _DEST},
        response=_response,
        diff=True,
    )
    result = action.run()
    assert result["diff"] == {
        "before": "before\n",
        "before_header": _DEST,
        "after": "after\n",
        "after_header": str(source),
    }
    assert [call["module_name"] for call in state.calls] == [
        _MODULE,
        "sustainablelobster.legacy_windows.win_file",
        "sustainablelobster.legacy_windows.slurp",
        _MODULE,
    ]
    _assert_clean(state)


@pytest.mark.parametrize("failure", ["query", "transfer", "single"])
def test_content_and_remote_staging_are_removed_after_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str
) -> None:
    def _response(_name: str, args: dict[str, Any]) -> dict[str, Any]:
        if args["_copy_mode"] == failure:
            return {"failed": True, "changed": False, "msg": "native failure"}
        return {"files": args["files"], "directories": []}

    action, state = _action(
        monkeypatch, tmp_path, {"content": "owned", "dest": _DEST}, response=_response
    )
    if failure == "transfer":

        def _broken_transfer(_source: str, _destination: str) -> str:
            raise AnsibleError("transport failed")

        monkeypatch.setattr(action, "_transfer_file", _broken_transfer)
        with pytest.raises(AnsibleError, match="transport failed"):
            action.run()
    else:
        result = action.run()
        assert result["failed"] is True
        assert "native failure" in result["msg"]
        assert result["changed"] is (failure == "single")
    _assert_clean(state)


@pytest.mark.parametrize("check_mode", [False, True])
def test_directory_staging_is_removed_without_writing_archive_in_check_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, check_mode: bool
) -> None:
    source = tmp_path / "tree"
    source.mkdir()
    (source / "empty").mkdir()
    action, state = _action(
        monkeypatch,
        tmp_path,
        {"src": str(source), "dest": _DEST},
        check_mode=check_mode,
    )
    assert action.run()["changed"] is True
    assert bool(state.archives) is not check_mode
    _assert_clean(state)


@pytest.mark.parametrize("restriction", ["async", "become"])
def test_unsupported_execution_modes_do_not_stage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, restriction: str
) -> None:
    action, state = _action(monkeypatch, tmp_path, {"content": "text", "dest": _DEST})
    if restriction == "async":
        action._task.async_val = 1  # pylint: disable=protected-access
    else:
        action._connection.become = object()  # pylint: disable=protected-access
    with pytest.raises(AnsibleActionFail):
        action.run()
    assert not state.calls and not state.transfers and not state.cleanup


def test_directory_single_file_diff_preserves_measured_reference_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "tree"
    source.mkdir()
    (source / "only.txt").write_bytes(b"one file")
    action, state = _action(
        monkeypatch, tmp_path, {"src": str(source), "dest": _DEST}, diff=True
    )
    with pytest.raises(UnboundLocalError, match="local variable 'source_full'"):
        action.run()
    assert len(state.calls) == 1
    assert state.calls[0]["module_args"]["_copy_mode"] == "query"
    assert not any(
        destination.endswith("source") for _, destination, _ in state.transfers
    )
    _assert_clean(state)


def test_directory_single_file_uses_relative_original_basename(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "tree"
    source.mkdir()
    (source / "only.txt").write_bytes(b"one file")
    action, state = _action(
        monkeypatch, tmp_path, {"src": str(source), "dest": r"C:\target"}
    )
    result = action.run()
    assert result["operation"] == "folder_copy"
    assert state.calls[1]["module_args"]["_original_basename"] == "tree/only.txt"
    assert state.calls[1]["module_args"]["dest"] == "C:\\target\\"
    assert not state.archives
    _assert_clean(state)


@pytest.mark.parametrize("failure", ["archive", "transfer", "execute"])
def test_archive_is_removed_on_construction_transfer_and_execution_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str
) -> None:
    source = tmp_path / "tree"
    source.mkdir()
    (source / "empty").mkdir()
    action, state = _action(monkeypatch, tmp_path, {"src": str(source), "dest": _DEST})
    if failure == "archive":

        def _broken_archive(_path: str, _sources: object) -> None:
            raise OSError("source unreadable")

        monkeypatch.setattr(win_copy, "_write_archive", _broken_archive)
        result = action.run()
        assert result["failed"] is True and result["changed"] is True
        assert result["msg"] == "failed to create tmp zip file: source unreadable"
    elif failure == "transfer":
        original = action._transfer_file  # pylint: disable=protected-access

        def _broken_transfer(local: str, remote: str) -> str:
            if remote.endswith("source.zip"):
                raise AnsibleError("archive transfer failed")
            return str(original(local, remote))

        monkeypatch.setattr(action, "_transfer_file", _broken_transfer)
        with pytest.raises(AnsibleError, match="archive transfer failed"):
            action.run()
    else:
        original_execute = (
            ActionBase._execute_module  # pylint: disable=protected-access
        )

        def _broken_execute(instance: object, **kwargs: Any) -> dict[str, Any]:
            if kwargs["module_args"]["_copy_mode"] == "explode":
                raise AnsibleError("archive execution failed")
            return dict(original_execute(instance, **kwargs))

        monkeypatch.setattr(ActionBase, "_execute_module", _broken_execute)
        with pytest.raises(AnsibleError, match="archive execution failed"):
            action.run()
    _assert_clean(state)


def test_decrypt_false_transfers_original_vault_bytes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    secret = VaultSecret(b"test-only-vault-secret")
    encrypted = VaultLib([("default", secret)]).encrypt(b"decrypted value")
    source = _source(tmp_path, encrypted)
    action, state = _action(
        monkeypatch, tmp_path, {"src": str(source), "dest": _DEST, "decrypt": False}
    )
    assert action.run()["checksum"] == hashlib.sha1(encrypted).hexdigest()
    assert state.transfers[-1][2] == encrypted
    _assert_clean(state)


@pytest.mark.parametrize("missing_at", ["search", "loader"])
def test_missing_source_returns_diagnostic_without_remote_staging(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, missing_at: str
) -> None:
    source = tmp_path / "missing.txt"
    action, state = _action(monkeypatch, tmp_path, {"src": str(source), "dest": _DEST})
    if missing_at == "search":

        def _missing(_directory: str, _path: str) -> str:
            raise AnsibleError("file search failed")

        monkeypatch.setattr(action, "_find_needle", _missing)
    result = action.run()
    assert result["failed"] is True
    assert (
        "file search failed" if missing_at == "search" else "could not find src="
    ) in result["msg"]
    assert not state.calls and not state.transfers and not state.cleanup
    assert not list(state.local_tmp.iterdir())


@pytest.mark.parametrize("keep", [False, True])
def test_preserves_borrowed_remote_staging_and_keep_remote_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, keep: bool
) -> None:
    action, state = _action(monkeypatch, tmp_path, {"content": "text", "dest": _DEST})
    if keep:
        monkeypatch.setattr(C, "DEFAULT_KEEP_REMOTE_FILES", True)
    else:
        state.shell.tmpdir = _REMOTE
    assert action.run()["changed"] is True
    assert not state.cleanup
    assert state.shell.tmpdir == _REMOTE
    assert not list(state.local_tmp.iterdir())


def test_diff_no_log_redacts_content_and_check_mode_does_not_transfer_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def _response(name: str, args: dict[str, Any]) -> dict[str, Any]:
        if name.endswith("win_file"):
            return {"state": "absent"}
        return {"files": args["files"], "directories": []}

    action, state = _action(
        monkeypatch,
        tmp_path,
        {"content": "private example", "dest": _DEST},
        response=_response,
        diff=True,
        no_log=True,
        check_mode=True,
    )
    result = action.run()
    assert result["diff"]["before"] == ""
    assert "private example" not in str(result["diff"])
    assert result["diff"]["after_header"] == _DEST
    assert not any(
        destination.endswith("source") for _, destination, _ in state.transfers
    )
    _assert_clean(state)


@pytest.mark.parametrize("reverse", [False, True])
def test_archive_lists_sibling_directories_before_their_descendants(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, reverse: bool
) -> None:
    source = tmp_path / "tree"
    (source / "first" / "nested").mkdir(parents=True)
    (source / "second").mkdir()
    original_scandir = os.scandir

    def _ordered_scandir(path: str) -> Any:
        if path != str(source):
            return original_scandir(path)
        with original_scandir(path) as entries:
            children = sorted(entries, key=lambda entry: entry.name, reverse=reverse)
        return nullcontext(children)

    monkeypatch.setattr(os, "scandir", _ordered_scandir)
    action, state = _action(
        monkeypatch, tmp_path, {"src": str(source) + "/", "dest": _DEST}
    )
    assert action.run()["changed"] is True
    archive_paths = list(state.archives[0])
    assert set(archive_paths[:2]) == {"first/", "second/"}
    assert archive_paths[2:] == ["first/nested/"]
    _assert_clean(state)


def test_unreadable_source_directory_is_skipped_like_reference_walk(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "tree"
    source.mkdir()
    action, state = _action(monkeypatch, tmp_path, {"src": str(source), "dest": _DEST})
    original = os.scandir

    def _unreadable(path: str) -> Any:
        if path == str(source):
            raise PermissionError("fixture read denied")
        return original(path)

    monkeypatch.setattr(os, "scandir", _unreadable)
    result = action.run()
    assert result["changed"] is False and result["failed"] is False
    assert state.calls[0]["module_args"]["files"] == []
    assert state.calls[0]["module_args"]["directories"] == []
    _assert_clean(state)
