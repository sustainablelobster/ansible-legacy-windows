"""Check complete cache publication and watchdog failures without Windows claims."""

# SPDX-License-Identifier: GPL-3.0-or-later

import codecs
import ctypes
import os
from contextlib import contextmanager
from itertools import chain, repeat
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tests.unit.payload_support import HELPER, load_module


@pytest.fixture(name="worker")
def worker_fixture(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Import the staged watchdog with its ordinary adjacent helpers.

    :param monkeypatch: Scoped Python helper search path.
    :returns: The watchdog module without executing its entry point.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    return load_module(
        HELPER.parent / "legacy_windows_async_worker.py", "tested_async_worker"
    )


def test_atomic_cache_is_bom_marked_unicode_and_leaves_no_partial(
    worker: Any, tmp_path: Path
) -> None:
    path = tmp_path / "j1.2"
    value = {
        "stdout": "snowman \u2603",
        "started": True,
        "finished": False,
        "nested": [None, False, 0],
    }
    worker.atomic_json(str(path), value)
    assert path.read_bytes().startswith(codecs.BOM_UTF8)
    assert worker.read_json(str(path)) == value
    assert sorted(item.name for item in tmp_path.iterdir()) == ["j1.2"]
    worker.atomic_json(str(path), dict(value, finished=True))
    assert worker.read_json(str(path))["finished"] is True


@pytest.mark.parametrize(
    "output,expected",
    [
        (
            b'{"changed":false,"stdout":"done","nested":[null,0,false]}',
            {"changed": False, "stdout": "done", "nested": [None, 0, False]},
        ),
        (
            b'prefix\n{"warnings":["first"],"changed":true}\ntrailing',
            {
                "warnings": [
                    "first",
                    "Module invocation had junk after the JSON data: trailing",
                ],
                "changed": True,
            },
        ),
    ],
)
def test_complete_module_fields_and_trailing_warning(
    worker: Any, output: bytes, expected: dict[str, Any]
) -> None:
    assert worker.module_result(output, b"", 0) == expected


@pytest.mark.parametrize("output", [b"", b"not-json", b"{broken}"])
def test_invalid_module_output_fails_instead_of_inventing_result(
    worker: Any, output: bytes
) -> None:
    with pytest.raises(ValueError):
        worker.module_result(output, b"", 0)


def test_zero_job_limit_waits_for_completion_without_terminating_payload(
    worker: Any,
) -> None:
    waits: list[tuple[Any, int]] = []

    def _wait(handle: Any, milliseconds: int) -> int:
        waits.append((handle, milliseconds))
        return 0

    def _exit_code(_handle: Any, code: Any) -> bool:
        ctypes.cast(code, ctypes.POINTER(ctypes.c_uint32)).contents.value = 7
        return True

    kernel = SimpleNamespace(
        WaitForSingleObject=_wait,
        GetExitCodeProcess=_exit_code,
    )
    # The watchdog's private wait is the boundary that interprets core's limit.
    # pylint: disable-next=protected-access
    assert worker._wait_payload(kernel, "process", "job", 0) == 7
    assert waits == [("process", 0xFFFFFFFF)]


@pytest.mark.parametrize("timeout", [False, True])
@pytest.mark.parametrize("preserve", [False, True])
def test_watchdog_publishes_complete_success_or_timeout_and_honors_ownership(
    worker: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    timeout: bool,
    preserve: bool,
) -> None:
    request = tmp_path / "request.json"
    cache = tmp_path / "cache" / "j1.2"
    cache.parent.mkdir()
    metadata = {
        "started": True,
        "finished": False,
        "results_file": str(cache),
        "ansible_job_id": "j1.2",
        "ansible_async_watchdog_pid": os.getpid(),
    }
    worker.atomic_json(
        str(request),
        {
            "arguments": ["python", "payload", "args"],
            "cwd": str(tmp_path),
            "timeout": 1,
            "startup_timeout": 5,
            "preserve_tmp": preserve,
            "cache_path": str(cache),
        },
    )
    worker.atomic_json(str(request) + ".release", metadata)
    worker.atomic_json(str(request) + ".accepted", {"pid": os.getpid()})
    events: list[Any] = []
    monkeypatch.setattr(
        worker.os, "chdir", lambda directory: events.append(("cwd", directory))
    )

    def _exit_code(_handle: Any, code: Any) -> bool:
        ctypes.cast(code, ctypes.POINTER(ctypes.c_uint32)).contents.value = 0
        return True

    def _terminate(job: Any, code: int) -> bool:
        events.append(("terminate_job", job, code))
        return True

    kernel = SimpleNamespace(
        WaitForSingleObject=lambda _handle, _millis: 258 if timeout else 0,
        GetExitCodeProcess=_exit_code,
        TerminateJobObject=_terminate,
    )

    @contextmanager
    def _child(arguments: list[str], directory: str, streams: tuple[Any, ...]) -> Any:
        assert arguments == ["python", "payload", "args"] and directory == str(tmp_path)
        streams[1].write(b'{"changed":false,"ping":"pong","unicode":"\\u2603"}')
        yield kernel, "process", "job", 123
        events.append(("close_job",))

    monkeypatch.setattr(worker, "payload_process", _child)
    monkeypatch.setattr(
        worker,
        "remove_staging",
        lambda directory: events.append(("cleanup", directory)),
    )
    # Advance only the deadline wait on a timeout; do not introduce real sleeps.
    if timeout:
        clock = chain([0, 0, 0, 0, 2], repeat(2))
        monkeypatch.setattr(worker.time, "monotonic", lambda: next(clock))
    worker.supervise(str(request))
    result = worker.read_json(str(cache))
    assert result["finished"] is True and result["started"] is True
    assert {key: result[key] for key in metadata if key != "finished"} == {
        key: value for key, value in metadata.items() if key != "finished"
    }
    assert "_ansible_suppress_tmpdir_delete" not in result
    assert (
        ("cleanup", str(tmp_path)) in events
        if not preserve
        else not any(event[0] == "cleanup" for event in events)
    )
    if timeout:
        assert result["failed"] is True
        assert (
            result["msg"]
            == "failure during async watchdog: timed out waiting for module completion"
        )
        assert result["stdout"] is None and result["stderr"] == ""
        assert ("terminate_job", "job", 1) in events
    else:
        assert result["ping"] == "pong" and result["unicode"] == "\u2603"
        assert result["changed"] is False and "failed" not in result
