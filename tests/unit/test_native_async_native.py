"""Check suspended-child/job ordering and exact native-handle cleanup."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native ABI fields and function names are the deliberate tested boundary.
# pylint: disable=protected-access

import ctypes
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import HELPER, load_module


@pytest.fixture(name="native")
def native_fixture(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load the native helper without opening a Windows DLL.

    :param monkeypatch: Scoped adjacent-helper search path.
    :returns: Imported native watchdog helper.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    return load_module(
        HELPER.parent / "legacy_windows_async_native.py", "tested_async_native"
    )


@pytest.mark.parametrize("assignment", [False, True])
def test_payload_is_suspended_then_assigned_before_resume_and_cleanup(
    native: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    assignment: bool,
) -> None:
    events: list[Any] = []
    terminated = False

    def _create(*args: Any) -> bool:
        assert args[4] is True and args[5] == 0x08000004
        assert args[7] == str(tmp_path)
        startup = ctypes.cast(args[8], ctypes.POINTER(native._StartupInfo)).contents
        assert startup.flags == 0x100 and startup.size == ctypes.sizeof(
            native._StartupInfo
        )
        assert (startup.stdin, startup.stdout, startup.stderr) == (101, 102, 103)
        info = ctypes.cast(args[9], ctypes.POINTER(native._ProcessInfo)).contents
        info.process, info.thread, info.pid = 21, 22, 23
        events.append(("create_suspended",))
        return True

    def _limits(job: int, kind: int, value: Any, size: int) -> bool:
        assert (
            job == 11 and kind == 9 and size == ctypes.sizeof(native._ExtendedJobLimits)
        )
        assert (
            ctypes.cast(
                value, ctypes.POINTER(native._ExtendedJobLimits)
            ).contents.basic.flags
            == 0x2000
        )
        events.append(("kill_on_close",))
        return True

    def _assign(job: int, process: int) -> bool:
        assert (job, process) == (11, 21)
        events.append(("assign",))
        return assignment

    def _resume(thread: int) -> int:
        assert thread == 22
        events.append(("resume",))
        return 1

    def _terminate(process: int, code: int) -> bool:
        nonlocal terminated
        assert (process, code) == (21, 1)
        terminated = True
        events.append(("terminate",))
        return True

    def _close(handle: int) -> bool:
        events.append(("close", handle))
        return True

    kernel = SimpleNamespace(
        CreateJobObjectW=lambda _security, _name: 11,
        SetInformationJobObject=_limits,
        SetHandleInformation=lambda _handle, _mask, _flags: True,
        CreateProcessW=_create,
        AssignProcessToJobObject=_assign,
        ResumeThread=_resume,
        TerminateProcess=_terminate,
        CloseHandle=_close,
        WaitForSingleObject=lambda _handle, _milliseconds: 0 if terminated else 258,
    )
    monkeypatch.setattr(native, "kernel_api", lambda: kernel)
    monkeypatch.setitem(
        sys.modules,
        "msvcrt",
        SimpleNamespace(get_osfhandle=lambda descriptor: descriptor + 100),
    )
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5, raising=False)
    monkeypatch.setattr(
        ctypes,
        "WinError",
        lambda code: OSError(code, "native assignment error"),
        raising=False,
    )
    streams = tuple(
        SimpleNamespace(fileno=lambda descriptor=descriptor: descriptor)
        for descriptor in (1, 2, 3)
    )
    if assignment:
        with native.payload_process(
            ["python", "payload", "args"], str(tmp_path), streams
        ) as process:
            assert process[1:] == (21, 11, 23)
            assert events == [
                ("kill_on_close",),
                ("create_suspended",),
                ("assign",),
                ("resume",),
            ]
    else:
        with pytest.raises(OSError, match="native assignment error"):
            with native.payload_process(
                ["python", "payload", "args"], str(tmp_path), streams
            ):
                pytest.fail("Unassigned process must never run")
        assert ("resume",) not in events
    assert events[-4:] == [("terminate",), ("close", 11), ("close", 21), ("close", 22)]


def test_native_abi_records_have_the_documented_windows_pointer_layout(
    native: Any,
) -> None:
    width = ctypes.sizeof(ctypes.c_void_p)
    assert ctypes.sizeof(native._StartupInfo) == (104 if width == 8 else 68)
    assert ctypes.sizeof(native._ProcessInfo) == (24 if width == 8 else 16)
    assert ctypes.sizeof(native._ExtendedJobLimits) == (144 if width == 8 else 112)


@pytest.fixture(name="launcher")
def launcher_fixture(native: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Supply job restrictions and exact process handles at the native boundary.

    :param native: Imported native async helper.
    :param monkeypatch: Scoped Windows API substitutes.
    :returns: Mutable launch state and its mocked kernel API.
    """
    state = SimpleNamespace(
        parent_job=False,
        job_flags=0,
        child_job=False,
        alive=True,
        create=True,
        resume=1,
        query=True,
        stop=True,
        events=[],
    )

    def _in_job(process: int, job: Any, member: Any) -> bool:
        assert job is None
        ctypes.cast(member, ctypes.POINTER(ctypes.c_int)).contents.value = (
            state.parent_job if process == 1 else state.child_job
        )
        return True

    def _query(job: Any, kind: int, limits: Any, size: int, returned: Any) -> bool:
        assert job is returned is None and kind == 2
        assert size == ctypes.sizeof(native._JobLimits)
        ctypes.cast(limits, ctypes.POINTER(native._JobLimits)).contents.flags = (
            state.job_flags
        )
        return bool(state.query)

    def _create(*arguments: Any) -> bool:
        state.events.append(("create", arguments))
        if state.create:
            info = ctypes.cast(
                arguments[9], ctypes.POINTER(native._ProcessInfo)
            ).contents
            info.process, info.thread, info.pid = 21, 22, 23
        return bool(state.create)

    def _resume(thread: int) -> int:
        state.events.append(("resume", thread))
        return int(state.resume)

    def _stop(handle: int, code: int) -> bool:
        state.events.append(("stop", handle, code))
        if state.stop:
            state.alive = False
        return bool(state.stop)

    kernel = SimpleNamespace(
        GetCurrentProcess=lambda: 1,
        IsProcessInJob=Mock(side_effect=_in_job),
        QueryInformationJobObject=Mock(side_effect=_query),
        CreateProcessW=Mock(side_effect=_create),
        ResumeThread=Mock(side_effect=_resume),
        OpenProcess=Mock(return_value=31),
        WaitForSingleObject=Mock(side_effect=lambda *_args: 258 if state.alive else 0),
        TerminateProcess=Mock(side_effect=_stop),
        CloseHandle=Mock(),
    )
    state.kernel = kernel
    monkeypatch.setattr(native, "kernel_api", lambda: kernel)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5, raising=False)
    monkeypatch.setattr(
        ctypes,
        "WinError",
        lambda code: OSError(code, "native launch error"),
        raising=False,
    )

    def _wmi(command: str, directory: str, environment: dict[str, str]) -> int:
        state.events.append(("wmi", command, directory, environment))
        return 33

    monkeypatch.setattr(native, "_launch_watchdog_wmi", Mock(side_effect=_wmi))
    return state


@pytest.mark.parametrize("parent_job,job_flags", [(False, 0), (True, 0x800)])
def test_direct_watchdog_escapes_job_without_wmi_or_connection_handles(
    native: Any, launcher: Any, parent_job: bool, job_flags: int
) -> None:
    launcher.parent_job, launcher.job_flags = parent_job, job_flags
    environment = {"SystemRoot": "C:\\Windows", "ASYNC_TEST": "café λ"}
    assert native.launch_watchdog(
        '"C:\\Python34\\python.exe" worker.py', "C:\\Task", environment
    ) == (
        launcher.kernel,
        21,
        23,
    )
    arguments = launcher.kernel.CreateProcessW.call_args.args
    assert arguments[1].value == '"C:\\Python34\\python.exe" worker.py'
    assert arguments[4] is False and arguments[5] == 0x0100040C
    assert arguments[7] == "C:\\Task"
    assert "".join(arguments[6]).startswith(
        "ASYNC_TEST=café λ\0SystemRoot=C:\\Windows\0\0"
    )
    startup = ctypes.cast(arguments[8], ctypes.POINTER(native._StartupInfo)).contents
    assert startup.flags == 0x101
    assert (startup.stdin, startup.stdout, startup.stderr) == (None, None, None)
    launcher.kernel.ResumeThread.assert_called_once_with(22)
    launcher.kernel.CloseHandle.assert_called_once_with(22)
    launcher.kernel.OpenProcess.assert_not_called()
    native._launch_watchdog_wmi.assert_not_called()


@pytest.mark.parametrize("job_flags", [0, 0x2000, 0x1000])
def test_restricted_job_uses_wmi_without_attempting_direct_launch(
    native: Any, launcher: Any, job_flags: int
) -> None:
    launcher.parent_job, launcher.job_flags = True, job_flags
    assert native.launch_watchdog("worker", "C:\\Task", {"TEMP": "C:\\Temp"}) == (
        launcher.kernel,
        31,
        33,
    )
    launcher.kernel.CreateProcessW.assert_not_called()
    launcher.kernel.ResumeThread.assert_not_called()
    native._launch_watchdog_wmi.assert_called_once_with(
        "worker", "C:\\Task", {"TEMP": "C:\\Temp"}
    )
    launcher.kernel.OpenProcess.assert_called_once_with(0x100401, False, 33)


def test_child_remaining_in_a_job_is_stopped_before_one_wmi_fallback(
    native: Any, launcher: Any
) -> None:
    launcher.parent_job, launcher.job_flags, launcher.child_job = True, 0x800, True
    assert native.launch_watchdog("worker", "C:\\Task", {})[1:] == (31, 33)
    assert [event[0] for event in launcher.events] == ["create", "stop", "wmi"]
    launcher.kernel.ResumeThread.assert_not_called()
    launcher.kernel.TerminateProcess.assert_called_once_with(21, 1)
    assert [call.args for call in launcher.kernel.CloseHandle.call_args_list] == [
        (21,),
        (22,),
    ]


@pytest.mark.parametrize("failure", ["create", "resume", "query", "inspect", "stop"])
def test_launch_failure_never_runs_a_second_watchdog(
    native: Any, launcher: Any, failure: str
) -> None:
    if failure == "create":
        launcher.create = False
    elif failure == "resume":
        launcher.resume = 0xFFFFFFFF
    elif failure == "query":
        launcher.parent_job, launcher.query = True, False
    elif failure == "inspect":
        launcher.kernel.IsProcessInJob.side_effect = [True, False]
    else:
        launcher.child_job, launcher.stop = True, False
    with pytest.raises(OSError, match="native launch error"):
        native.launch_watchdog("worker", "C:\\Task", {})
    native._launch_watchdog_wmi.assert_not_called()
    if failure in ("resume", "inspect", "stop"):
        assert [call.args for call in launcher.kernel.CloseHandle.call_args_list] == [
            (21,),
            (22,),
        ]
