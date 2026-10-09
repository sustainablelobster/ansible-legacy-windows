"""Test file readiness, response ownership and maintained public selection."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Developer-runtime checks do not establish released file readiness on Windows.
# pylint: disable=protected-access

import json
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import load_payload

INTEGRATION = Path(__file__).resolve().parents[1] / "integration"


@pytest.fixture(name="file_open")
def controlled_file_open(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    """Control worker readiness while retaining the actual owned file stream.

    :param monkeypatch: Scoped opener and worker substitutions.
    :param tmp_path: Owned local source path.
    :returns: Yields the helper, stream, constructor and scheduled worker.
    """
    payload = load_payload("win_get_url", monkeypatch)
    path = tmp_path / "source.bin"
    path.write_bytes(b"owned file")
    helper = payload.get_url
    response = helper._FileResponse(str(path))
    response.close = Mock(wraps=response.close)
    constructor = Mock(return_value=response)
    monkeypatch.setattr(helper, "_FileResponse", constructor)
    worker = SimpleNamespace(start=Mock(), daemon=False)
    threads = Mock(return_value=worker)
    monkeypatch.setattr(helper.threading, "Thread", threads)
    yield SimpleNamespace(
        helper=helper,
        payload=payload,
        path=path,
        response=response,
        constructor=constructor,
        worker=worker,
        threads=threads,
    )
    if not response.stream.closed:
        response.close()


@pytest.mark.parametrize("timeout", [0, 2])
def test_file_open_returns_ready_stream_and_keeps_positive_opener_synchronous(
    file_open: Any, timeout: int
) -> None:
    boundary = file_open

    def start() -> None:
        """Complete the actual open before its zero-readiness observation."""
        boundary.threads.call_args.kwargs["target"]()

    boundary.worker.start.side_effect = start
    options = boundary.payload._parameters(
        {"url": "file://localhost/source.bin", "dest": "unused destination"}
    )
    options["url_timeout"] = timeout
    response = boundary.helper.open_resource(options["url"], options, [])
    assert response is boundary.response
    assert response.read() == b"owned file" and not response.stream.closed
    boundary.constructor.assert_called_once_with("\\source.bin")
    if timeout == 0:
        assert boundary.worker.daemon
        boundary.worker.start.assert_called_once_with()
    else:
        boundary.threads.assert_not_called()
    response.close()
    response.close.assert_called_once_with()


@pytest.mark.parametrize(
    "failure", [OSError(2, "ready open failure"), KeyboardInterrupt()]
)
def test_file_zero_preserves_already_ready_error(
    file_open: Any, failure: BaseException
) -> None:
    boundary = file_open
    boundary.response.close()
    boundary.constructor.side_effect = failure

    def start() -> None:
        """Complete the failing open before its zero-readiness observation."""
        boundary.threads.call_args.kwargs["target"]()

    boundary.worker.start.side_effect = start
    with pytest.raises(type(failure)) as caught:
        boundary.helper._file_zero_response("owned source")
    assert caught.value is failure
    boundary.response.close.assert_called_once_with()


def test_pending_file_zero_times_out_then_closes_late_response(file_open: Any) -> None:
    boundary = file_open
    with pytest.raises(OSError) as caught:
        boundary.helper._file_zero_response("owned source")
    assert caught.value.errno == 12002
    assert caught.value.strerror == "The operation has timed out"
    boundary.constructor.assert_not_called()
    assert boundary.worker.daemon
    boundary.threads.call_args.kwargs["target"]()
    assert boundary.response.stream.closed
    boundary.response.close.assert_called_once_with()


def test_pending_file_error_does_not_replace_already_returned_timeout(
    file_open: Any,
) -> None:
    boundary = file_open
    boundary.response.close()
    boundary.constructor.side_effect = OSError(2, "late file failure")
    with pytest.raises(OSError) as caught:
        boundary.helper._file_zero_response("owned source")
    boundary.threads.call_args.kwargs["target"]()
    assert caught.value.errno == 12002
    boundary.response.close.assert_called_once_with()


@pytest.mark.parametrize("phase", ["start", "wait"])
@pytest.mark.parametrize("completed", [False, True])
def test_file_worker_start_or_caller_interruption_releases_unclaimed_response(
    file_open: Any,
    monkeypatch: pytest.MonkeyPatch,
    phase: str,
    completed: bool,
) -> None:
    boundary = file_open
    failure = KeyboardInterrupt() if phase == "wait" else RuntimeError("start failed")

    def start() -> None:
        """Optionally complete the open before the caller is interrupted."""
        if completed:
            boundary.threads.call_args.kwargs["target"]()
        if phase == "start":
            raise failure

    boundary.worker.start.side_effect = start
    if phase == "wait":
        ready = Mock(wait=Mock(side_effect=failure))
        monkeypatch.setattr(
            boundary.helper.threading, "Event", Mock(return_value=ready)
        )
    with pytest.raises(type(failure)) as caught:
        boundary.helper._file_zero_response("owned source")
    assert caught.value is failure
    if not completed:
        boundary.threads.call_args.kwargs["target"]()
    boundary.response.close.assert_called_once_with()
    assert boundary.response.stream.closed


def test_actual_worker_does_not_wait_for_pending_open_and_closes_late_stream(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    helper = load_payload("win_get_url", monkeypatch).get_url
    path = tmp_path / "source.bin"
    path.write_bytes(b"owned")
    original_response, original_thread = helper._FileResponse, threading.Thread
    started, resume, closed = threading.Event(), threading.Event(), threading.Event()
    workers = []

    def open_file(source: str) -> Any:
        """Hold the real file open until after the zero-readiness observation.

        :param source: Owned local source path.
        :returns: Actual response with observed closure.
        """
        started.set()
        assert resume.wait(2)
        response = original_response(source)
        close = response.close

        def close_response() -> None:
            """Close the actual stream and signal the test's owned cleanup."""
            close()
            closed.set()

        response.close = close_response
        return response

    def thread(*, target: Any) -> threading.Thread:
        """Retain the actual worker so the test can finish its owned work.

        :param target: Unmodified Thread worker callback.
        :returns: Actual standard-library worker.
        """
        worker = original_thread(target=target)
        workers.append(worker)
        return worker

    monkeypatch.setattr(helper, "_FileResponse", open_file)
    monkeypatch.setattr(helper.threading, "Thread", thread)
    try:
        with pytest.raises(OSError) as caught:
            helper._file_zero_response(str(path))
        assert caught.value.errno == 12002
        assert started.wait(2) and not closed.is_set()
    finally:
        resume.set()
        for worker in workers:
            worker.join(2)
    assert closed.is_set() and len(workers) == 1
    assert workers[0].daemon and not workers[0].is_alive()


@pytest.mark.parametrize("existing", [False, True])
def test_public_get_url_pending_file_zero_preserves_destination_and_removes_temp(
    file_open: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    existing: bool,
) -> None:
    boundary = file_open
    dest = tmp_path / "dest.bin"
    if existing:
        dest.write_bytes(b"protected")
    options = boundary.payload._parameters(
        {"url": "file://localhost/source.bin", "dest": str(dest), "url_timeout": 0}
    )
    copy = Mock()
    monkeypatch.setattr(boundary.helper.copying, "copy_file", copy)
    create = boundary.helper.tempfile.mkstemp
    monkeypatch.setattr(
        boundary.helper.tempfile,
        "mkstemp",
        lambda **options: create(dir=tmp_path, **options),
    )
    monkeypatch.setattr(boundary.helper.time, "time", Mock(side_effect=[10.0, 10.125]))
    result = boundary.helper.download(options)
    assert result == {
        "changed": False,
        "failed": True,
        "elapsed": 0.125,
        "url": options["url"],
        "dest": str(dest),
        "status_code": None,
        "msg": f"Error downloading '{options['url']}' to '{dest}': The operation has timed out",
    }
    copy.assert_not_called()
    assert dest.read_bytes() == b"protected" if existing else not dest.exists()
    assert not list(tmp_path.glob("legacy-get-url-*"))
    boundary.threads.call_args.kwargs["target"]()
    assert boundary.response.stream.closed


def test_public_uri_pending_file_zero_keeps_timeout_result_typed_and_content_absent(
    file_open: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = file_open
    payload = load_payload("win_uri", monkeypatch)
    options = payload._parameters(
        {"url": "file://localhost/source.bin", "url_timeout": 0, "return_content": True}
    )
    monkeypatch.setattr(boundary.helper.time, "time", Mock(side_effect=[10.0, 10.125]))
    result = payload.uri.request(options)
    assert result == {
        "changed": False,
        "failed": True,
        "elapsed": 0.125,
        "url": options["url"],
        "status_code": None,
        "msg": "Unhandled exception occurred when sending web request. Exception: "
        "The operation has timed out",
    }
    boundary.threads.call_args.kwargs["target"]()
    assert boundary.response.stream.closed


@pytest.mark.parametrize("indices", [[0], [1, 2], [0, 1, 2]])
def test_file_selection_uses_owned_source_and_exact_zero_positive_inputs(
    tmp_path: Path,
    indices: list[int],
) -> None:
    maintained = yaml.safe_load((INTEGRATION / "http_zero_timeout.yml").read_text())[0]
    selection = next(
        task
        for task in maintained["tasks"]
        if task["name"]
        == "Require the exact selected matrix before starting owned work"
    )
    binding = yaml.safe_load((INTEGRATION / "tasks/http_zero_case.yml").read_text())[0]
    assertions = {
        "ansible.builtin.assert": {
            "that": [
                f"http_zero_selected_cases | length == {len(indices)}",
                "http_zero_case.file == true",
                "http_zero_params.url == get_url_setup_data.file",
                "http_zero_params.url_timeout == (2 if http_zero_case.name == "
                "'GetURL file positive retention' else 0)",
                "not http_zero_params.use_proxy",
                "http_zero_params.return_content == true if http_zero_case.module "
                "== 'uri' else http_zero_params.dest == get_url_workspace.path + "
                "'\\\\output\\\\result.bin'",
            ]
        }
    }
    (tmp_path / "file-case.yml").write_text(yaml.safe_dump([binding, assertions]))
    playbook = tmp_path / "file-selection.yml"
    playbook.write_text(
        yaml.safe_dump(
            [
                {
                    "hosts": "localhost",
                    "connection": "local",
                    "gather_facts": False,
                    "vars_files": [str(INTEGRATION / "vars/http_zero.yml")],
                    "vars": {
                        "get_url_setup_data": {
                            "file": "file:///C:/OwnedFixture/source.bin"
                        },
                        "get_url_workspace": {"path": "C:\\OwnedFixture"},
                    },
                    "tasks": [
                        selection,
                        {
                            "ansible.builtin.include_tasks": str(
                                tmp_path / "file-case.yml"
                            ),
                            "loop": "{{ http_zero_selected_cases }}",
                            "loop_control": {"loop_var": "http_zero_case"},
                        },
                    ],
                }
            ]
        )
    )
    arguments = [sys.executable, "-m", "ansible.cli.playbook"]
    arguments += ["-i", "localhost,", str(playbook), "-e"]
    arguments += ["@" + str(INTEGRATION / "vars/http_zero_file.yml")]
    arguments += ["-e", json.dumps({"http_zero_case_indices": indices})]
    run = subprocess.run(
        arguments,
        timeout=30,
        check=False,
        text=True,
        capture_output=True,
    )
    assert run.returncode == 0, run.stdout + run.stderr
