"""Test gated legacy fact collectors, identity pinning and owned IPC cleanup."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Fault tests exercise the concrete private native ownership boundaries.
# pylint: disable=protected-access

import contextlib
import importlib
import json
import os
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock

import pytest


@pytest.fixture(name="helper")
def load_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the staged target helper and its maintained native dependencies.

    :param monkeypatch: Scoped import search and module isolation.
    :returns: Imported Setup helper.
    """
    monkeypatch.syspath_prepend(
        str(Path(__file__).resolve().parents[2] / "legacy_windows/plugins/module_utils")
    )
    for name in ("legacy_windows_setup", "legacy_windows_setup_native"):
        monkeypatch.delitem(sys.modules, name, raising=False)
    module = importlib.import_module("legacy_windows_setup")
    monkeypatch.setattr(
        module.native.ctypes, "get_last_error", lambda: 5, raising=False
    )
    monkeypatch.setattr(
        module.native.ctypes,
        "WinError",
        lambda code: OSError(code, "native failure"),
        raising=False,
    )
    return module


@pytest.fixture(name="runtime")
def detached_runtime(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Any:
    """Observe the concrete native gate using real, disposable IPC files.

    :param helper: Imported target Setup helper.
    :param monkeypatch: Scoped API and temporary-root substitutions.
    :param tmp_path: Owned local IPC root.
    :returns: Fake kernel, event order and captured launch state.
    """
    events: list[str] = []
    state: dict[str, Any] = {}
    kernel = SimpleNamespace(
        CreateEventW=Mock(return_value=100),
        CloseHandle=Mock(return_value=1),
        WaitForSingleObject=Mock(return_value=0),
        GetExitCodeProcess=Mock(return_value=1),
        TerminateProcess=Mock(return_value=1),
    )

    def _protect(directory: str, api: Any) -> None:
        assert api is kernel
        assert not list(Path(directory).iterdir())
        state["directory"] = Path(directory)
        events.append("private directory")

    def _launch(command: str, directory: str, environment: dict[str, str]) -> Any:
        events.append("waiting worker launched")
        assert events[0] == "private directory"
        assert directory == os.getcwd()
        assert (state["directory"] / "request.json").read_bytes() == b'"request"'
        assert "--collect-detached" in command
        state.update(cwd=Path(directory), command=command, environment=environment)
        return kernel, 201, 777

    @contextlib.contextmanager
    def _job(handle: int) -> Any:
        assert handle == 202
        events.append("assigned owned job")
        try:
            yield
        finally:
            events.append("descendants terminated")

    def _activate(event: int) -> int:
        assert event == 100 and events[-1] == "assigned owned job"
        events.append("activated")
        (state["directory"] / "output.json").write_bytes(
            b'{"facts":{"snow":"\\u96ea"}}'
        )
        (state["directory"] / "errors.txt").write_bytes(b"stderr")
        return 1

    kernel.SetEvent = Mock(side_effect=_activate)
    monkeypatch.setattr(helper.native, "_collector_kernel", lambda: kernel)
    monkeypatch.setattr(helper.native, "_private_collector_directory", _protect)
    monkeypatch.setattr(helper.native.async_native, "launch_watchdog", _launch)
    monkeypatch.setattr(helper.native, "_collector_handle", Mock(return_value=202))
    monkeypatch.setattr(helper.native, "owned_job", _job)
    monkeypatch.setattr(helper.native.tempfile, "tempdir", str(tmp_path))
    return SimpleNamespace(kernel=kernel, events=events, state=state)


def _run(helper: ModuleType, timeout: int = 10) -> tuple[bytes, bytes, int, bool]:
    return cast(
        tuple[bytes, bytes, int, bool],
        helper.native.collect_detached(
            ["python.exe", "helper.py", "--collect-detached"], b'"request"', timeout
        ),
    )


def test_activation_follows_ownership_and_descendants_close_before_ipc_removal(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, runtime: Any
) -> None:
    read_output = helper.native._collector_output

    def _read(paths: list[str]) -> Any:
        assert runtime.events[-1] == "descendants terminated"
        return read_output(paths)

    monkeypatch.setattr(helper.native, "_collector_output", _read)
    assert _run(helper) == (b'{"facts":{"snow":"\\u96ea"}}', b"stderr", 0, False)
    assert runtime.events == [
        "private directory",
        "waiting worker launched",
        "assigned owned job",
        "activated",
        "descendants terminated",
    ]
    assert not runtime.state["directory"].exists()
    assert [call.args for call in runtime.kernel.CloseHandle.call_args_list] == [
        (202,),
        (201,),
        (100,),
    ]
    runtime.kernel.TerminateProcess.assert_not_called()


def test_collector_inherits_caller_cwd_independently_of_private_ipc(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, runtime: Any, tmp_path: Path
) -> None:
    caller_directory = tmp_path / "caller-cwd"
    caller_directory.mkdir()
    monkeypatch.chdir(caller_directory)
    assert not _run(helper)[3]
    assert runtime.state["cwd"] == caller_directory
    assert runtime.state["directory"] != caller_directory
    assert not runtime.state["directory"].exists()
    assert not list(caller_directory.iterdir())


def test_timeout_closes_owned_job_then_reaps_collector(
    helper: ModuleType, runtime: Any
) -> None:
    runtime.kernel.WaitForSingleObject.side_effect = [258, 0, 0]
    assert _run(helper, 0)[3] is True
    assert runtime.kernel.WaitForSingleObject.call_args_list[0].args == (202, 0)
    assert runtime.events[-1] == "descendants terminated"
    assert not runtime.state["directory"].exists()
    runtime.kernel.TerminateProcess.assert_not_called()


def test_signed_native_exit_status_is_preserved(
    helper: ModuleType, runtime: Any
) -> None:
    def _exit(_handle: int, code: Any) -> int:
        code._obj.value = 0xFFFFFFFF
        return 1

    runtime.kernel.GetExitCodeProcess.side_effect = _exit
    assert _run(helper)[2] == -1


@pytest.mark.parametrize(
    "boundary", ["identity", "assignment", "activation", "wait", "exit"]
)
def test_failed_start_stops_only_pinned_process_and_closes_every_handle(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    runtime: Any,
    boundary: str,
) -> None:
    if boundary == "identity":
        monkeypatch.setattr(
            helper.native, "_collector_handle", Mock(side_effect=OSError("identity"))
        )
    elif boundary == "assignment":
        monkeypatch.setattr(
            helper.native, "owned_job", Mock(side_effect=OSError("assignment"))
        )
    elif boundary == "activation":
        runtime.kernel.SetEvent.side_effect = None
        runtime.kernel.SetEvent.return_value = 0
    elif boundary == "wait":
        runtime.kernel.WaitForSingleObject.side_effect = [0xFFFFFFFF, 258, 0]
    else:
        runtime.kernel.GetExitCodeProcess.return_value = 0
    if boundary != "wait":
        runtime.kernel.WaitForSingleObject.side_effect = (
            [0, 0, 258, 0] if boundary == "exit" else [258, 0]
        )
    with pytest.raises(OSError):
        _run(helper)
    runtime.kernel.TerminateProcess.assert_called_once_with(201, 1)
    assert not runtime.state["directory"].exists()
    closed = [call.args[0] for call in runtime.kernel.CloseHandle.call_args_list]
    assert closed == ([201, 100] if boundary == "identity" else [202, 201, 100])
    if boundary in ("identity", "assignment"):
        runtime.kernel.SetEvent.assert_not_called()


def test_even_failed_pinned_process_stop_closes_process_and_event_handles(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, runtime: Any
) -> None:
    monkeypatch.setattr(
        helper.native, "owned_job", Mock(side_effect=OSError("assignment"))
    )
    runtime.kernel.WaitForSingleObject.return_value = 258
    runtime.kernel.TerminateProcess.return_value = 0
    with pytest.raises(OSError) as caught:
        _run(helper)
    assert caught.value.errno == 5
    assert [call.args[0] for call in runtime.kernel.CloseHandle.call_args_list] == [
        202,
        201,
        100,
    ]
    assert not runtime.state["directory"].exists()


def test_launch_failure_closes_gate_and_removes_private_request(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, runtime: Any, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        helper.native.async_native,
        "launch_watchdog",
        Mock(side_effect=OSError("WMI launch failed")),
    )
    with pytest.raises(OSError, match="WMI launch failed"):
        _run(helper)
    runtime.kernel.CloseHandle.assert_called_once_with(100)
    runtime.kernel.SetEvent.assert_not_called()
    runtime.kernel.TerminateProcess.assert_not_called()
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("births", [(91, 91), (92, 91)])
def test_reopened_quota_handle_must_match_pinned_process_birth(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, births: tuple[int, int]
) -> None:
    kernel = SimpleNamespace(OpenProcess=Mock(return_value=202), CloseHandle=Mock())
    monkeypatch.setattr(helper.native, "_process_birth", Mock(side_effect=births))
    if births[0] == births[1]:
        assert helper.native._collector_handle(kernel, 201, 777) == 202
        kernel.CloseHandle.assert_not_called()
    else:
        with pytest.raises(OSError, match="identity changed"):
            helper.native._collector_handle(kernel, 201, 777)
        kernel.CloseHandle.assert_called_once_with(202)
    kernel.OpenProcess.assert_called_once_with(0x100501, False, 777)


def test_unavailable_birth_identity_releases_only_reopened_handle(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    kernel = SimpleNamespace(OpenProcess=Mock(return_value=202), CloseHandle=Mock())
    monkeypatch.setattr(
        helper.native, "_process_birth", Mock(side_effect=OSError(5, "birth query"))
    )
    with pytest.raises(OSError, match="birth query"):
        helper.native._collector_handle(kernel, 201, 777)
    kernel.CloseHandle.assert_called_once_with(202)


@pytest.mark.parametrize("set_result", [0, 1])
def test_ipc_acl_uses_actual_caller_and_system_with_protected_inheritance(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, set_result: int
) -> None:
    def _convert(_sddl: str, _revision: int, descriptor: Any, _size: Any) -> int:
        descriptor._obj.value = 99
        return 1

    security = SimpleNamespace(
        ConvertStringSecurityDescriptorToSecurityDescriptorW=Mock(side_effect=_convert),
        SetFileSecurityW=Mock(return_value=set_result),
    )
    kernel = SimpleNamespace(LocalFree=Mock())
    monkeypatch.setattr(
        helper.native.ctypes, "WinDLL", Mock(return_value=security), raising=False
    )
    monkeypatch.setattr(
        helper.native,
        "_user",
        lambda facts: facts.update(ansible_user_sid="S-1-5-21-123"),
    )
    if set_result:
        helper.native._private_collector_directory("owned", kernel)
    else:
        with pytest.raises(OSError):
            helper.native._private_collector_directory("owned", kernel)
    assert security.ConvertStringSecurityDescriptorToSecurityDescriptorW.call_args.args[
        0
    ] == ("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;S-1-5-21-123)")
    assert security.SetFileSecurityW.call_args.args[:2] == ("owned", 0x80000004)
    kernel.LocalFree.assert_called_once()
    assert kernel.LocalFree.call_args.args[0].value == 99


@pytest.mark.parametrize("wait", [0, 258, 0xFFFFFFFF])
def test_activation_wait_is_finite_and_event_always_closes(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, wait: int
) -> None:
    kernel = SimpleNamespace(
        OpenEventW=Mock(return_value=100),
        WaitForSingleObject=Mock(return_value=wait),
        CloseHandle=Mock(),
    )
    monkeypatch.setattr(helper.native, "_collector_kernel", lambda: kernel)
    if wait == 0:
        helper.native.await_collector_activation("owned-event")
    else:
        with pytest.raises(OSError):
            helper.native.await_collector_activation("owned-event")
    kernel.OpenEventW.assert_called_once_with(0x100000, False, "owned-event")
    kernel.WaitForSingleObject.assert_called_once_with(100, 5000)
    kernel.CloseHandle.assert_called_once_with(100)


@pytest.mark.parametrize("activated", [False, True])
def test_detached_worker_cannot_collect_or_write_before_activation(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, activated: bool
) -> None:
    directory = tmp_path / "legacy-windows-fact-collector-owned"
    directory.mkdir()
    paths = [directory / name for name in ("request.json", "output.json", "errors.txt")]
    paths[0].write_text('{"name":"user","parameters":{}}', encoding="utf-8")
    collect = Mock(
        side_effect=lambda _name, _params, facts, _warnings: facts.update(
            sid="expected"
        )
    )
    monkeypatch.setattr(helper.native, "collect", collect)

    def _activate(event: str) -> None:
        assert event == "owned-event"
        assert not paths[1].exists() and not paths[2].exists()
        collect.assert_not_called()
        if not activated:
            raise OSError("unarmed timeout")

    monkeypatch.setattr(helper.native, "await_collector_activation", _activate)
    monkeypatch.setattr(
        helper.sys,
        "argv",
        ["helper.py", "--collect-detached", "owned-event"]
        + [str(path) for path in paths],
    )
    if activated:
        assert helper._detached_worker() == 0
        assert json.loads(paths[1].read_bytes())["facts"] == {"sid": "expected"}
        assert paths[2].read_bytes() == b""
    else:
        with pytest.raises(OSError, match="unarmed timeout"):
            helper._detached_worker()
        assert not paths[1].exists() and not paths[2].exists()
        collect.assert_not_called()


def test_unexpected_worker_failure_preserves_traceback_without_result(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    directory = tmp_path / "legacy-windows-fact-collector-owned"
    directory.mkdir()
    paths = [directory / name for name in ("request.json", "output.json", "errors.txt")]
    paths[0].write_text('{"name":"user","parameters":{}}', encoding="utf-8")
    monkeypatch.setattr(
        helper.native, "collect", Mock(side_effect=RuntimeError("exact failure"))
    )
    monkeypatch.setattr(helper.native, "await_collector_activation", Mock())
    monkeypatch.setattr(
        helper.sys,
        "argv",
        ["helper.py", "--collect-detached", "owned-event"]
        + [str(path) for path in paths],
    )
    assert helper._detached_worker() == 1
    assert not paths[1].exists()
    assert "RuntimeError: exact failure" in paths[2].read_text(encoding="utf-8")


def test_foreign_ipc_path_rejected_before_activation(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    directory = tmp_path / "legacy-windows-fact-collector-owned"
    activation = Mock()
    monkeypatch.setattr(helper.native, "await_collector_activation", activation)
    monkeypatch.setattr(
        helper.sys,
        "argv",
        [
            "helper.py",
            "--collect-detached",
            "owned-event",
            str(directory / "request.json"),
            str(tmp_path / "output.json"),
            str(directory / "errors.txt"),
        ],
    )
    with pytest.raises(ValueError, match="one owned directory"):
        helper._detached_worker()
    activation.assert_not_called()


@pytest.mark.parametrize("breakaway", [False, True])
def test_capability_probe_reuses_native_job_policy_without_version_guesses(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, breakaway: bool
) -> None:
    kernel = object()
    policy = Mock(return_value=breakaway)
    monkeypatch.setattr(helper.native.async_native, "kernel_api", lambda: kernel)
    monkeypatch.setattr(helper.native.async_native, "_can_break_away", policy)
    assert helper.native.collector_needs_detached() is not breakaway
    policy.assert_called_once_with(kernel)


@pytest.mark.parametrize(
    "major, minor, detached",
    [(5, 1, True), (6, 1, True), (6, 2, False), (10, 0, False)],
)
def test_fallback_is_only_for_legacy_nonbreakaway_job(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    major: int,
    minor: int,
    detached: bool,
) -> None:
    policy = Mock(return_value=True)
    launch = Mock(
        return_value=(b'{"facts":{"sid":"expected"},"warnings":[]}', b"", 0, False)
    )
    monkeypatch.setattr(
        helper.native,
        "windows_version",
        lambda: SimpleNamespace(major=major, minor=minor),
    )
    monkeypatch.setattr(helper.native, "collector_needs_detached", policy)
    monkeypatch.setattr(helper.native, "collect_detached", launch)
    popen = Mock(side_effect=OSError("ordinary path"))
    monkeypatch.setattr(helper.subprocess, "Popen", popen)
    if detached:
        assert helper._collect_process("user", {"gather_timeout": 10})["facts"] == {
            "sid": "expected"
        }
        launch.assert_called_once()
        assert json.loads(launch.call_args.args[1]) == {
            "name": "user",
            "parameters": {"gather_timeout": 10},
        }
        popen.assert_not_called()
    else:
        with pytest.raises(OSError, match="ordinary path"):
            helper._collect_process("user", {"gather_timeout": 10})
        policy.assert_not_called()
        launch.assert_not_called()


@pytest.mark.parametrize("returncode, timeout", [(0, True), (1, False)])
def test_fallback_preserves_collector_timeout_and_failure_diagnostics(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, returncode: int, timeout: bool
) -> None:
    monkeypatch.setattr(
        helper.native, "windows_version", lambda: SimpleNamespace(major=6, minor=1)
    )
    monkeypatch.setattr(helper.native, "collector_needs_detached", lambda: True)
    monkeypatch.setattr(
        helper.native,
        "collect_detached",
        Mock(return_value=(b"", b"precise failure", returncode, timeout)),
    )
    if timeout:
        assert helper._collect_process("user", {"gather_timeout": 0}) == {
            "facts": {},
            "warnings": ["Failed to collect user due to timeout"],
        }
    else:
        with pytest.raises(
            OSError, match="Fact collector user failed: precise failure"
        ):
            helper._collect_process("user", {"gather_timeout": 10})
