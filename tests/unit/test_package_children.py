"""Exercise native tree-wait ordering, root results and exact resource cleanup."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Concrete ABI calls are inspected without contacting Windows.
# pylint: disable=protected-access

import io
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import HELPER, load_module


@pytest.fixture(name="children")
def children_helper(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load the concrete helper with only platform errors replaced on Linux.

    :param monkeypatch: Scoped native compatibility substitutions.
    :returns: Real Python3.4-compatible helper module.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    helper = load_module(
        HELPER.parent / "legacy_windows_package_children.py", "children"
    )
    monkeypatch.setattr(helper.ctypes, "get_last_error", lambda: 5, raising=False)
    monkeypatch.setattr(
        helper.ctypes,
        "WinError",
        lambda _code: OSError("native failure"),
        raising=False,
    )
    return helper


@pytest.fixture(name="native")
def native_boundary(children: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Provide concrete pipes and observable native job/process boundaries.

    :param children: Real helper.
    :param monkeypatch: Scoped Windows operations.
    :returns: Kernel boundary, call ordering and captured pipe descriptors.
    """
    calls: list[str] = []
    descriptors: list[int] = []
    messages = [6, 7, 4]

    def _assigned(*_args: Any) -> bool:
        calls.append("assign")
        return True

    def _resumed(*_args: Any) -> int:
        calls.append("resume")
        return 0

    def _waited(*_args: Any) -> int:
        calls.append("wait_root")
        return 0

    kernel = SimpleNamespace(
        CreateJobObjectW=Mock(return_value=100),
        CreateIoCompletionPort=Mock(return_value=101),
        SetInformationJobObject=Mock(return_value=True),
        AssignProcessToJobObject=Mock(side_effect=_assigned),
        ResumeThread=Mock(side_effect=_resumed),
        WaitForSingleObject=Mock(side_effect=_waited),
        TerminateProcess=Mock(),
        CloseHandle=Mock(),
    )

    def _exit(_process: int, pointer: Any) -> bool:
        pointer._obj.value = 0xFFFFFFFF
        calls.append("root_code")
        return True

    def _queued(
        _port: int, pointer: Any, _key: Any, _overlapped: Any, timeout: int
    ) -> bool:
        assert timeout == 0xFFFFFFFF
        pointer._obj.value = messages.pop(0)
        calls.append("notification")
        return True

    def _create(
        _kernel: Any,
        application: str,
        command: str,
        directory: str,
        streams: tuple[Any, ...],
    ) -> tuple[int, ...]:
        assert (
            application == "installer.exe"
            and command == "installer.exe arguments"
            and directory == "working"
        )
        descriptors.extend(stream.fileno() for stream in streams)
        assert all(os.get_inheritable(descriptor) for descriptor in descriptors)
        streams[1].write(b"root output")
        streams[1].flush()
        streams[2].write(b"root error")
        streams[2].flush()
        calls.append("create_suspended")
        return 200, 201, 202, 203

    kernel.GetExitCodeProcess = Mock(side_effect=_exit)
    kernel.GetQueuedCompletionStatus = Mock(side_effect=_queued)
    monkeypatch.setattr(children, "_kernel", lambda: kernel)
    monkeypatch.setattr(children, "_create_process", _create)
    return SimpleNamespace(kernel=kernel, calls=calls, descriptors=descriptors)


def test_job_assignment_precedes_resume_and_all_notifications_finish_before_return(
    children: Any, native: Any
) -> None:
    assert children._execute("installer.exe", "installer.exe arguments", "working") == (
        0xFFFFFFFF,
        b"root output",
        b"root error",
    )
    assert native.calls == [
        "create_suspended",
        "assign",
        "resume",
        "wait_root",
        "root_code",
        "notification",
        "notification",
        "notification",
    ]
    assert [call.args[0] for call in native.kernel.CloseHandle.call_args_list] == [
        201,
        200,
        101,
        100,
    ]
    native.kernel.TerminateProcess.assert_not_called()
    for descriptor in native.descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


@pytest.mark.parametrize(
    "operation,result",
    [
        ("CreateJobObjectW", 0),
        ("CreateIoCompletionPort", 0),
        ("SetInformationJobObject", False),
    ],
)
def test_job_setup_failure_closes_only_handles_already_owned(
    children: Any, native: Any, operation: str, result: Any
) -> None:
    getattr(native.kernel, operation).side_effect = None
    getattr(native.kernel, operation).return_value = result
    with pytest.raises(OSError, match="native failure"):
        children._execute("installer.exe", "installer.exe arguments", "working")
    assert native.calls == []
    expected = {
        "CreateJobObjectW": [],
        "CreateIoCompletionPort": [100],
        "SetInformationJobObject": [101, 100],
    }
    assert [
        call.args[0] for call in native.kernel.CloseHandle.call_args_list
    ] == expected[operation]


@pytest.mark.parametrize(
    "operation,result",
    [("AssignProcessToJobObject", False), ("ResumeThread", 0xFFFFFFFF)],
)
def test_failed_prestart_enrollment_does_not_abandon_the_suspended_root(
    children: Any, native: Any, operation: str, result: Any
) -> None:
    getattr(native.kernel, operation).side_effect = None
    getattr(native.kernel, operation).return_value = result
    with pytest.raises(OSError, match="native failure"):
        children._execute("installer.exe", "installer.exe arguments", "working")
    native.kernel.TerminateProcess.assert_called_once_with(200, 1)
    assert [call.args[0] for call in native.kernel.CloseHandle.call_args_list] == [
        201,
        200,
        101,
        100,
    ]
    for descriptor in native.descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_failed_notification_queue_has_released_return_behavior(
    children: Any, native: Any
) -> None:
    native.kernel.GetQueuedCompletionStatus.side_effect = None
    native.kernel.GetQueuedCompletionStatus.return_value = False
    assert (
        children._execute("installer.exe", "installer.exe arguments", "working")[0]
        == 0xFFFFFFFF
    )
    native.kernel.TerminateProcess.assert_not_called()


def test_stream_read_failures_are_not_silently_dropped(children: Any) -> None:
    stream, output = Mock(), [b"", b""]
    errors: list[OSError] = []
    stream.read.side_effect = OSError("broken stream")
    children._read_output(stream, output, errors, 0)
    assert output == [b"", b""] and str(errors[0]) == "broken stream"


def test_both_large_pipe_streams_are_collected(children: Any, native: Any) -> None:
    output = b"x" * 200000
    assert children._wait_process(
        native.kernel, 200, 101, (io.BytesIO(output), io.BytesIO(output))
    ) == (0xFFFFFFFF, output, output)


def test_cpython34_launch_preserves_primary_thread_and_console_cleanup(
    children: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    operation = Mock(return_value=(10, 11, 12, 13))
    monkeypatch.setitem(
        sys.modules, "_winapi", SimpleNamespace(CreateProcess=operation)
    )
    monkeypatch.setitem(
        sys.modules,
        "msvcrt",
        SimpleNamespace(get_osfhandle=lambda descriptor: descriptor),
    )
    monkeypatch.setattr(
        children.subprocess, "STARTUPINFO", SimpleNamespace, raising=False
    )
    kernel = SimpleNamespace(
        GetConsoleWindow=Mock(return_value=0),
        AllocConsole=Mock(return_value=1),
        FreeConsole=Mock(),
        SetConsoleCP=Mock(),
        SetConsoleOutputCP=Mock(),
    )
    with (tmp_path / "input").open("wb") as stream:
        assert children._create_process(
            kernel, "installer.exe", "quoted arguments", None, (stream, stream, stream)
        ) == (10, 11, 12, 13)
        assert operation.call_args.args[:8] == (
            "installer.exe",
            "quoted arguments",
            None,
            None,
            True,
            4,
            None,
            None,
        )
        startup = operation.call_args.args[8]
        assert startup.dwFlags == 0x100 and startup.hStdInput == stream.fileno()
    kernel.FreeConsole.assert_called_once_with()
    kernel.SetConsoleCP.assert_called_once_with(65001)


def test_public_runner_preserves_root_code_and_existing_output_decoding(
    children: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        children.processes, "_application_from_command", lambda _value: "installer.exe"
    )
    monkeypatch.setattr(
        children.processes, "resolve_executable", lambda value, _directory: value
    )
    monkeypatch.setattr(
        children, "_execute", lambda *_args: (3010, b"output\r\n", b"error\r\n")
    )
    assert children.run_command(
        None, "command", {"chdir": None, "output_encoding_override": "utf-8"}
    ) == {
        "changed": True,
        "cmd": "command",
        "rc": 3010,
        "stdout": "output\r\n",
        "stderr": "error\r\n",
    }


def test_invalid_encoding_cannot_create_a_job_or_process(
    children: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    execute = Mock()
    monkeypatch.setattr(children, "_execute", execute)
    result = children.run_command(
        None, "command", {"chdir": None, "output_encoding_override": "not-a-codec"}
    )
    assert (
        result["changed"] is False
        and result["failed"] is True
        and "Unsupported output_encoding_override" in result["msg"]
    )
    execute.assert_not_called()
