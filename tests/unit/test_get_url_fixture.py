"""Exercise download fixture ownership and recovery without Windows access."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import base64
import binascii
import ctypes
import hashlib
import json
import os
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock, call

import pytest

# The pinned Nix environment supplies PyYAML without optional typing stubs.
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


@pytest.fixture(name="fixture")
def get_url_fixture(tmp_path: Path) -> Any:
    """Execute the maintained fixture with scoped process and HTTP substitutes.

    :param tmp_path: Disposable controller-only parent directory.
    :returns: The workspace, native stand-ins, and actual fixture dispatcher.
    """
    document = yaml.safe_load(
        (ROOT / "tests/integration/vars/get_url_fixture.yml").read_text(
            encoding="utf-8"
        )
    )
    source = document["get_url_program"].replace(
        "{{ get_url_server | to_json }}", json.dumps(document["get_url_server"])
    )
    assigned = {"workspace", "journal_path", "output", "sentinel", "payload"}
    nodes: list[ast.stmt] = [
        node
        for node in ast.parse(source).body
        if isinstance(node, (ast.FunctionDef, ast.If))
        or (
            isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name)
                and target.id in assigned
                or isinstance(target, ast.Tuple)
                and any(
                    isinstance(item, ast.Name) and item.id in assigned
                    for item in target.elts
                )
                for target in node.targets
            )
        )
        or (
            isinstance(node, ast.Assert)
            and not any(
                isinstance(item, ast.Attribute) and item.attr == "version_info"
                for item in ast.walk(node)
            )
        )
    ]
    program = compile(
        ast.Module(body=nodes, type_ignores=[]), "<get_url fixture>", "exec"
    )
    workspace = tmp_path / "legacy-windows-get-url-owned"
    workspace.mkdir()
    state = SimpleNamespace(
        workspace=workspace,
        journal=workspace / "get-url-journal.json",
        output=workspace / "output",
        creation=0x123456789,
        pid=871,
        port=23456,
        tls_port=23457,
        last_error=87,
        reparse=set(),
        namespace={},
        clock=SimpleNamespace(time=time.time, sleep=Mock()),
    )

    def _attributes(path: str) -> int:
        if path in state.reparse:
            return 0x400
        if not os.path.exists(path):
            return 0xFFFFFFFF
        return 0x10 if os.path.isdir(path) else 0x20

    def _long_path(path: str, buffer: Any, _size: int) -> int:
        if buffer is None:
            return len(path) + 1
        buffer.value = path
        return len(path)

    def _times(_handle: int, creation: Any, *_other: Any) -> bool:
        array = ctypes.cast(creation, ctypes.POINTER(ctypes.c_uint32))
        array[0] = state.creation
        array[1] = state.creation >> 32
        return True

    state.api = SimpleNamespace(
        GetFileAttributesW=Mock(side_effect=_attributes),
        GetLongPathNameW=Mock(side_effect=_long_path),
        OpenProcess=Mock(return_value=31),
        GetProcessTimes=Mock(side_effect=_times),
        WaitForSingleObject=Mock(side_effect=[0x102, 0]),
        TerminateProcess=Mock(return_value=True),
        CloseHandle=Mock(return_value=True),
    )
    state.process = SimpleNamespace(
        poll=Mock(return_value=None), _handle=29, pid=state.pid
    )

    def _spawn(arguments: list[str], **_options: Any) -> Any:
        record = json.loads(state.journal.read_text(encoding="utf-8"))
        assert record["token"] == arguments[-1]
        assert not record["verified"]
        info = {
            "pid": state.pid,
            "creation": state.creation,
            "token": arguments[-1],
            "port": state.port,
        }
        if "tls_materials" in record:
            assert {"server-cert.pem", "server-key.pem"}.issubset(
                record["tls_materials"]
            )
            for name, original in record["tls_materials"].items():
                assert (workspace / name).read_bytes().hex() == original["hex"]
            info["tls_port"] = state.tls_port
        (workspace / "server.json").write_text(
            json.dumps(info),
            encoding="utf-8",
        )
        return state.process

    state.spawn = Mock(side_effect=_spawn)

    def _health(url: str, **_options: Any) -> Any:
        token = url.rsplit("/", 1)[-1]
        record = json.loads(state.journal.read_text(encoding="utf-8"))
        assert record["process"] == {"pid": state.pid, "creation": state.creation}
        with (workspace / "requests.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(
                json.dumps({"method": "GET", "path": "/health/" + token}) + "\n"
            )
        response = Mock()
        response.read.return_value = token.encode("ascii")
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        return response

    state.health = Mock(side_effect=_health)
    connection = Mock()
    connection.connect_ex.return_value = 1
    connection.__enter__ = Mock(return_value=connection)
    connection.__exit__ = Mock(return_value=False)
    state.connection = connection

    def _run(operation: str, case: Any = None, path: Path | None = None) -> Any:
        arguments = ["fixture", str(path or workspace), operation]
        if case is not None:
            arguments.append(base64.b64encode(json.dumps(case).encode()).decode())
        namespace: dict[str, Any] = {
            "base64": base64,
            "binascii": binascii,
            "ctypes": SimpleNamespace(
                byref=ctypes.byref,
                create_unicode_buffer=ctypes.create_unicode_buffer,
                get_last_error=lambda: state.last_error,
            ),
            "dword": ctypes.c_uint32,
            "hashlib": hashlib,
            "json": json,
            "os": os,
            "socket": SimpleNamespace(socket=Mock(return_value=connection)),
            "subprocess": SimpleNamespace(Popen=state.spawn),
            "sys": SimpleNamespace(argv=arguments, executable=sys.executable),
            "tempfile": SimpleNamespace(
                mkstemp=tempfile.mkstemp, gettempdir=lambda: str(tmp_path)
            ),
            "time": state.clock,
            "uuid": uuid,
            "api": state.api,
            "urlopen": state.health,
        }
        state.namespace = namespace
        # Run the real dispatcher; only target DLL loading and imports are omitted.
        # pylint: disable-next=exec-used
        exec(program, namespace)
        return namespace["result"]

    state.run = _run
    return state


@pytest.fixture(name="server")
def get_url_server(tmp_path: Path) -> Any:
    """Execute the real listener bootstrap without threads, sockets or TLS.

    :param tmp_path: Disposable controller-only metadata directory.
    :returns: Actual bootstrap with observable server and SSL substitutes.
    """
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/get_url_fixture.yml").read_text(
            encoding="utf-8"
        )
    )["get_url_server"]
    body = ast.parse(source).body
    start = next(
        index
        for index, node in enumerate(body)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "server"
            for target in node.targets
        )
    )
    program = compile(
        ast.Module(body=body[start:], type_ignores=[]), "<get_url listeners>", "exec"
    )
    state = SimpleNamespace(
        root=tmp_path,
        http=Mock(server_address=("127.0.0.1", 23456)),
        tls=Mock(server_address=("127.0.0.1", 23457)),
        context=Mock(),
        thread=Mock(),
        timer=Mock(),
    )
    state.factory = Mock(side_effect=[state.http, state.tls])
    state.ssl = SimpleNamespace(
        SSLContext=Mock(return_value=state.context),
        PROTOCOL_TLSv1_2=5,
        PROTOCOL_TLSv1=3,
        CERT_OPTIONAL=1,
    )
    state.threading = SimpleNamespace(
        Thread=Mock(return_value=state.thread), Timer=Mock(return_value=state.timer)
    )

    def _run() -> Any:
        namespace = {
            "Server": state.factory,
            "Handler": object(),
            "root": str(tmp_path),
            "token": "owned-token",
            "creation": 123,
            "os": os,
            "json": json,
            "ssl": state.ssl,
            "threading": state.threading,
        }
        # The real bootstrap runs; target API declarations and handlers do not.
        # pylint: disable-next=exec-used
        exec(program, namespace)
        return json.loads((tmp_path / "server.json").read_text(encoding="utf-8"))

    state.run = _run
    return state


def _record(fixture: Any) -> dict[str, Any]:
    record: dict[str, Any] = json.loads(fixture.journal.read_text(encoding="utf-8"))
    return record


def _append_requests(fixture: Any, records: list[dict[str, Any]]) -> None:
    with (fixture.workspace / "requests.jsonl").open("a", encoding="utf-8") as stream:
        for record in records:
            stream.write(json.dumps(record) + "\n")


def _tls_materials() -> dict[str, str]:
    return {
        "cert": base64.b64encode(b"substituted certificate PEM\n").decode("ascii"),
        "key": base64.b64encode(b"substituted private key PEM\n").decode("ascii"),
    }


@pytest.mark.parametrize(
    "path,status,location,delay",
    [
        ("/redirect-status/300", 300, "/payload.bin", None),
        ("/redirect-status/303", 303, "/payload.bin", None),
        ("/redirect-status/308", 308, "/payload.bin", None),
        ("/redirect-missing-location", 302, None, None),
        ("/redirect-delay", 302, "/delay/0.75", 0.75),
    ],
)
def test_redirect_fixture_keeps_exact_status_location_and_header_delay(
    tmp_path: Path, path: str, status: int, location: str | None, delay: float | None
) -> None:
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/get_url_fixture.yml").read_text()
    )["get_url_server"]
    handler = next(
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.ClassDef) and node.name == "Handler"
    )
    clock = SimpleNamespace(sleep=Mock())
    namespace: dict[str, Any] = {
        "http": SimpleNamespace(server=SimpleNamespace(BaseHTTPRequestHandler=object)),
        "root": str(tmp_path),
        "lock": threading.Lock(),
        "os": os,
        "json": json,
        "time": clock,
        "token": "owned-token",
    }
    # Execute the maintained request handler without creating a server/process.
    # pylint: disable-next=exec-used
    exec(
        compile(
            ast.Module(body=[handler], type_ignores=[]), "<fixture handler>", "exec"
        ),
        namespace,
    )
    request = namespace["Handler"]()
    request.path, request.command, request.headers = path, "HEAD", {}
    request.connection = object()
    request.send_response, request.send_header, request.end_headers = (
        Mock(),
        Mock(),
        Mock(),
    )
    request.handle_request()
    request.send_response.assert_called_once_with(status)
    expected = [call("Content-Length", "0")]
    if location:
        expected.insert(0, call("Location", location))
    assert request.send_header.call_args_list == expected
    assert clock.sleep.call_args_list == ([call(delay)] if delay is not None else [])
    assert json.loads((tmp_path / "requests.jsonl").read_text())["method"] == "HEAD"


def test_setup_journals_protected_files_before_launch_and_isolates_child(
    fixture: Any,
) -> None:
    setup = fixture.run("setup")
    record = _record(fixture)
    assert record == setup["before"]
    assert record["sentinel"]["hex"] == b"protected sibling\x00\xff".hex()
    assert record["source"]["hex"] == b"legacy download fixture\x00\xff\n".hex()
    assert record["sentinel"]["mtime"] == record["source"]["mtime"] == 946684800
    assert record["initial_output"]["children"] == {}
    assert not record["verified"]
    fixture.spawn.assert_called_once_with(
        [
            sys.executable,
            str(fixture.workspace / "server.py"),
            str(fixture.workspace),
            record["token"],
        ],
        creationflags=0x1000000 | 8 | 512,
        close_fds=True,
    )
    assert setup["server"]["pid"] == fixture.pid
    assert (
        setup["hashes"]["sha256"]
        == hashlib.sha256(b"legacy download fixture\x00\xff\n").hexdigest()
    )


def test_existing_workspace_is_never_claimed_or_overwritten(fixture: Any) -> None:
    protected = fixture.workspace / "previous-owner.bin"
    protected.write_bytes(b"previous owner")
    with pytest.raises(AssertionError):
        fixture.run("setup")
    assert protected.read_bytes() == b"previous owner"
    assert not fixture.journal.exists()
    fixture.spawn.assert_not_called()


@pytest.mark.parametrize("kind", ["name", "parent", "reparse"])
def test_unowned_workspace_is_rejected_before_process_access(
    fixture: Any, kind: str, tmp_path: Path
) -> None:
    path = fixture.workspace
    if kind == "name":
        path = tmp_path / "unowned"
        path.mkdir()
    elif kind == "parent":
        path = tmp_path / "other" / "legacy-windows-get-url-unowned"
        path.mkdir(parents=True)
    else:
        fixture.reparse.add(str(path))
    with pytest.raises(AssertionError):
        fixture.run("cleanup", path=path)
    fixture.api.OpenProcess.assert_not_called()
    fixture.spawn.assert_not_called()


def test_journal_from_another_workspace_cannot_authorize_cleanup(fixture: Any) -> None:
    fixture.run("setup")
    record = _record(fixture)
    record["workspace"] = "unowned"
    fixture.journal.write_text(json.dumps(record), encoding="utf-8")
    before = fixture.journal.read_bytes()
    with pytest.raises(AssertionError):
        fixture.run("cleanup")
    fixture.api.OpenProcess.assert_not_called()
    assert fixture.journal.read_bytes() == before


@pytest.mark.parametrize("name", ["preserved.bin", "source.bin"])
@pytest.mark.parametrize("change", ["content", "mtime", "reparse"])
def test_protected_file_change_prevents_process_or_output_mutation(
    fixture: Any, name: str, change: str
) -> None:
    fixture.run("setup")
    path = fixture.workspace / name
    if change == "content":
        path.write_bytes(b"unrelated change")
    elif change == "mtime":
        os.utime(path, (946684801,) * 2)
    else:
        fixture.reparse.add(str(path))
    with pytest.raises(AssertionError):
        fixture.run("cleanup")
    fixture.api.OpenProcess.assert_not_called()
    assert not _record(fixture)["verified"]


@pytest.mark.parametrize("operation", ["dump", "fsync", "replace"])
def test_atomic_journal_failure_retains_last_baseline_and_removes_temporary(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    fixture.run("setup")
    before = fixture.journal.read_bytes()
    record = _record(fixture)
    record["verified"] = True
    library = json if operation == "dump" else os
    monkeypatch.setattr(library, operation, Mock(side_effect=OSError("interrupted")))
    with pytest.raises(OSError, match="interrupted"):
        fixture.namespace["write"](record)
    assert fixture.journal.read_bytes() == before
    assert not list(fixture.workspace.glob(".get-url-journal-*"))


@pytest.mark.parametrize(
    ("case", "content", "mtime"),
    [
        ({}, None, None),
        ({"contents": "old bytes", "mtime": 100}, b"old bytes", 100),
        ({"fixture_payload": True}, b"legacy download fixture\x00\xff\n", 946684801),
    ],
)
def test_prepare_records_content_timestamp_and_request_history_boundary(
    fixture: Any, case: dict[str, Any], content: bytes | None, mtime: int | None
) -> None:
    fixture.run("setup")
    before = _record(fixture)
    _append_requests(fixture, [{"method": "GET", "path": "/previous-case"}])
    result = fixture.run("prepare", case)
    assert result["sentinel"] == before["sentinel"]
    assert result["source"] == before["source"]
    assert _record(fixture)["prepared_requests"] == 2
    children = result["output"]["children"]
    if content is None:
        assert children == {}
    else:
        assert set(children) == {"result.bin"}
        assert children["result.bin"]["hex"] == content.hex()
        assert children["result.bin"]["mtime"] == mtime


@pytest.mark.parametrize("kind", ["unknown", "directory", "reparse"])
def test_prepare_rejects_unowned_output_entries_without_removing_them(
    fixture: Any, kind: str
) -> None:
    fixture.run("setup")
    path = fixture.output / ("unknown.bin" if kind == "unknown" else "result.bin")
    if kind == "directory":
        path.mkdir()
    else:
        path.write_bytes(b"protected")
    if kind == "reparse":
        fixture.reparse.add(str(path))
    with pytest.raises(AssertionError):
        fixture.run("prepare", {})
    assert path.exists()
    assert not _record(fixture).get("prepared_requests")


def test_observe_retains_exact_output_and_only_current_case_requests(
    fixture: Any,
) -> None:
    fixture.run("setup")
    fixture.clock.time = Mock(return_value=1000)
    fixture.run("prepare", {})
    path = fixture.output / "result.bin"
    path.write_bytes(b"downloaded\x00\xff")
    os.utime(path, (1001,) * 2)
    records = [
        {"method": "HEAD", "path": "/payload.bin", "headers": {"X-Test": "a"}},
        {"method": "GET", "path": "/payload.bin", "headers": {"X-Test": "b"}},
    ]
    _append_requests(fixture, records)
    fixture.clock.time = Mock(return_value=1002)
    result = fixture.run("observe")
    assert result["requests"] == records
    assert result["output"]["children"]["result.bin"] == {
        "attributes": 0x20,
        "hex": b"downloaded\x00\xff".hex(),
        "mtime": 1001,
    }
    assert result["portable_output"]["children"]["result.bin"] == {
        "attributes": 0x20,
        "hex": b"downloaded\x00\xff".hex(),
    }
    assert result["modified_in_request"]


@pytest.mark.parametrize("mtime", [999, 1003])
def test_observe_detects_file_timestamp_outside_current_request(
    fixture: Any, mtime: int
) -> None:
    fixture.run("setup")
    fixture.clock.time = Mock(return_value=1000)
    fixture.run("prepare", {"contents": "same", "mtime": mtime})
    fixture.clock.time = Mock(return_value=1002)
    assert not fixture.run("observe")["modified_in_request"]


def test_cleanup_terminates_only_token_pid_and_creation_matched_process(
    fixture: Any,
) -> None:
    setup = fixture.run("setup")
    fixture.run("prepare", {"contents": "owned output"})
    result = fixture.run("cleanup")
    fixture.api.OpenProcess.assert_called_once_with(
        0x400 | 1 | 0x100000, False, fixture.pid
    )
    fixture.api.TerminateProcess.assert_called_once_with(31, 0)
    assert fixture.api.WaitForSingleObject.call_args_list == [
        call(31, 0),
        call(31, 5000),
    ]
    fixture.api.CloseHandle.assert_called_once_with(31)
    assert result["restored"] and result["server_stopped"]
    assert result["output"] == setup["before"]["initial_output"]
    assert result["sentinel"] == setup["before"]["sentinel"]
    assert result["source"] == setup["before"]["source"]
    assert result["requests"][0]["path"].startswith("/health/")
    assert _record(fixture)["verified"]
    assert fixture.run("finalize") == {"finalized": True}
    assert fixture.journal.exists()


@pytest.mark.parametrize(
    "identity", ["token", "metadata_pid", "metadata_creation", "creation"]
)
def test_process_identity_mismatch_never_terminates_or_marks_recovery(
    fixture: Any, identity: str
) -> None:
    fixture.run("setup")
    if identity != "creation":
        path = fixture.workspace / "server.json"
        info = json.loads(path.read_text(encoding="utf-8"))
        if identity == "token":
            info["token"] = "another owner"
        elif identity == "metadata_pid":
            info["pid"] += 1
        else:
            info["creation"] += 1
        path.write_text(json.dumps(info), encoding="utf-8")
    else:
        fixture.creation += 1
    with pytest.raises(AssertionError):
        fixture.run("cleanup")
    fixture.api.TerminateProcess.assert_not_called()
    assert not _record(fixture)["verified"]
    if identity == "creation":
        fixture.api.CloseHandle.assert_called_once_with(31)
    else:
        fixture.api.OpenProcess.assert_not_called()


@pytest.mark.parametrize(
    "failure", ["times", "terminate", "wait", "wait_failed", "port"]
)
def test_cleanup_failure_retains_original_journal_and_protected_output(
    fixture: Any, failure: str
) -> None:
    fixture.run("setup")
    fixture.run("prepare", {"contents": "owned output"})
    before = fixture.journal.read_bytes()
    if failure == "times":
        fixture.api.GetProcessTimes.side_effect = None
        fixture.api.GetProcessTimes.return_value = False
    elif failure == "terminate":
        fixture.api.TerminateProcess.return_value = False
    elif failure == "wait":
        fixture.api.WaitForSingleObject.side_effect = [0x102, 0x102]
    elif failure == "wait_failed":
        fixture.api.WaitForSingleObject.side_effect = [0xFFFFFFFF]
    else:
        fixture.connection.connect_ex.return_value = 0
    with pytest.raises(AssertionError):
        fixture.run("cleanup")
    assert fixture.journal.read_bytes() == before
    assert (fixture.output / "result.bin").read_bytes() == b"owned output"
    fixture.api.CloseHandle.assert_called_once_with(31)


def test_already_exited_process_is_not_terminated(fixture: Any) -> None:
    fixture.run("setup")
    fixture.api.WaitForSingleObject.side_effect = [0]
    assert fixture.run("cleanup")["server_stopped"]
    fixture.api.TerminateProcess.assert_not_called()


@pytest.mark.parametrize("error", [87, 5])
def test_absent_pid_is_safe_only_for_invalid_parameter_error(
    fixture: Any, error: int
) -> None:
    fixture.run("setup")
    fixture.api.OpenProcess.return_value = None
    fixture.last_error = error
    if error == 87:
        assert fixture.run("cleanup")["restored"]
    else:
        with pytest.raises(AssertionError):
            fixture.run("cleanup")
        assert not _record(fixture)["verified"]
    fixture.api.TerminateProcess.assert_not_called()
    fixture.api.CloseHandle.assert_not_called()


def test_failed_child_creation_has_journaled_no_process_recovery(fixture: Any) -> None:
    error = OSError("breakaway denied")
    vars(error)["winerror"] = 5
    fixture.spawn.side_effect = error
    with pytest.raises(OSError, match="breakaway denied"):
        fixture.run("setup")
    assert _record(fixture)["spawn_error"] == 5
    assert fixture.run("cleanup")["restored"]
    fixture.api.OpenProcess.assert_not_called()
    assert fixture.run("finalize")["finalized"]


def test_readiness_failure_with_published_identity_remains_recoverable(
    fixture: Any,
) -> None:
    fixture.health.side_effect = OSError("health failed")
    with pytest.raises(OSError, match="health failed"):
        fixture.run("setup")
    assert not _record(fixture)["verified"]
    assert fixture.run("cleanup")["restored"]
    assert fixture.run("finalize")["finalized"]


@pytest.mark.parametrize("failure", ["exit", "timeout"])
def test_child_without_published_metadata_uses_durable_exact_identity(
    fixture: Any, failure: str
) -> None:
    fixture.spawn.side_effect = None
    fixture.spawn.return_value = fixture.process
    if failure == "exit":
        fixture.process.poll.return_value = 1
    expected = (
        "exited before readiness" if failure == "exit" else "did not become ready"
    )
    with pytest.raises(ValueError, match=expected):
        fixture.run("setup")
    record = _record(fixture)
    assert record["process"] == {"pid": fixture.pid, "creation": fixture.creation}
    assert not (fixture.workspace / "server.json").exists()
    if failure == "exit":
        fixture.api.WaitForSingleObject.side_effect = [0]
    assert fixture.run("cleanup")["restored"]
    if failure == "exit":
        fixture.api.TerminateProcess.assert_not_called()
    else:
        fixture.api.TerminateProcess.assert_called_once_with(31, 0)
    assert fixture.run("finalize")["finalized"]


def test_unattributable_missing_process_metadata_does_not_authorize_cleanup(
    fixture: Any,
) -> None:
    fixture.run("setup")
    (fixture.workspace / "server.json").unlink()
    record = _record(fixture)
    del record["process"]
    fixture.journal.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(AssertionError):
        fixture.run("cleanup")
    fixture.api.OpenProcess.assert_not_called()
    fixture.api.TerminateProcess.assert_not_called()
    assert not _record(fixture)["verified"]


@pytest.mark.parametrize("failure", ["creation", "journal"])
def test_post_launch_failure_stops_exact_owned_handle_before_losing_authority(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    if failure == "creation":
        fixture.api.GetProcessTimes.side_effect = None
        fixture.api.GetProcessTimes.return_value = False
        expected: type[Exception] = AssertionError
    else:
        replace = os.replace
        attempts = 0

        def _replace(source: str, destination: str) -> None:
            nonlocal attempts
            attempts += 1
            if attempts == 2:
                raise OSError("process journal interrupted")
            replace(source, destination)

        monkeypatch.setattr(os, "replace", _replace)
        expected = OSError
    with pytest.raises(expected):
        fixture.run("setup")
    fixture.api.TerminateProcess.assert_called_once_with(29, 0)
    fixture.api.OpenProcess.assert_not_called()
    assert not _record(fixture)["verified"]
    fixture.api.OpenProcess.return_value = None
    assert fixture.run("cleanup")["restored"]
    assert fixture.run("finalize")["finalized"]


@pytest.mark.parametrize("change", ["unverified", "unknown", "missing", "output"])
def test_finalize_requires_complete_verified_owned_workspace(
    fixture: Any, change: str
) -> None:
    fixture.run("setup")
    if change != "unverified":
        fixture.run("cleanup")
    if change == "unknown":
        (fixture.workspace / "unowned.bin").write_bytes(b"do not remove")
    elif change == "missing":
        (fixture.workspace / "server.py").unlink()
    elif change == "output":
        (fixture.output / "result.bin").write_bytes(b"late change")
    before = fixture.journal.read_bytes()
    with pytest.raises(AssertionError):
        fixture.run("finalize")
    assert fixture.journal.read_bytes() == before


def test_tls_setup_journals_exact_materials_before_launch_and_protects_them(
    fixture: Any,
) -> None:
    setup = fixture.run("setup", _tls_materials())
    record = _record(fixture)
    assert setup["https"] == "https://127.0.0.1:23457"
    assert setup["server"]["tls_port"] == fixture.tls_port
    assert record["tls_materials"] == {
        "server-cert.pem": {
            "attributes": 0x20,
            "hex": b"substituted certificate PEM\n".hex(),
            "mtime": 946684800,
        },
        "server-key.pem": {
            "attributes": 0x20,
            "hex": b"substituted private key PEM\n".hex(),
            "mtime": 946684800,
        },
    }
    fixture.run("prepare", {"contents": "owned download"})
    fixture.run("cleanup")
    assert fixture.connection.connect_ex.call_args_list == [
        call(("127.0.0.1", fixture.port)),
        call(("127.0.0.1", fixture.tls_port)),
    ]
    assert _record(fixture)["tls_materials"] == record["tls_materials"]
    assert fixture.run("finalize")["finalized"]


@pytest.mark.parametrize("name", ["server-cert.pem", "server-key.pem"])
@pytest.mark.parametrize("change", ["content", "mtime", "reparse", "missing"])
def test_tls_material_change_blocks_cleanup_before_process_access(
    fixture: Any, name: str, change: str
) -> None:
    fixture.run("setup", _tls_materials())
    path = fixture.workspace / name
    if change == "content":
        path.write_bytes(b"changed material")
    elif change == "mtime":
        os.utime(path, (946684801,) * 2)
    elif change == "missing":
        path.unlink()
    else:
        fixture.reparse.add(str(path))
    with pytest.raises(AssertionError):
        fixture.run("cleanup")
    fixture.api.OpenProcess.assert_not_called()
    assert not _record(fixture)["verified"]
    with pytest.raises(AssertionError):
        fixture.run("finalize")


def test_tls_listener_still_open_prevents_verified_cleanup(fixture: Any) -> None:
    fixture.run("setup", _tls_materials())
    fixture.run("prepare", {"contents": "owned download"})
    before = fixture.journal.read_bytes()
    fixture.connection.connect_ex.side_effect = [1, 0]
    with pytest.raises(AssertionError):
        fixture.run("cleanup")
    assert fixture.journal.read_bytes() == before
    assert (fixture.output / "result.bin").read_bytes() == b"owned download"
    assert fixture.connection.connect_ex.call_count == 2


def test_tls_metadata_must_include_the_journaled_second_listener(fixture: Any) -> None:
    fixture.run("setup", _tls_materials())
    path = fixture.workspace / "server.json"
    info = json.loads(path.read_text(encoding="utf-8"))
    del info["tls_port"]
    path.write_text(json.dumps(info), encoding="utf-8")
    with pytest.raises(AssertionError):
        fixture.run("cleanup")
    fixture.api.OpenProcess.assert_not_called()


@pytest.mark.parametrize(
    "argument",
    [
        {},
        {"cert": "YQ=="},
        {"cert": "YQ==", "key": "Yg==", "extra": "Yw=="},
        {"cert": "invalid!", "key": "Yg=="},
        {"cert": 7, "key": "Yg=="},
        ["YQ==", "Yg=="],
    ],
)
def test_invalid_tls_material_argument_fails_before_workspace_changes(
    fixture: Any, argument: Any
) -> None:
    with pytest.raises((AssertionError, TypeError, ValueError)):
        fixture.run("setup", argument)
    assert not list(fixture.workspace.iterdir())
    fixture.spawn.assert_not_called()


def test_tls_failed_spawn_keeps_protected_materials_and_allows_recovery(
    fixture: Any,
) -> None:
    error = OSError("breakaway denied")
    vars(error)["winerror"] = 5
    fixture.spawn.side_effect = error
    with pytest.raises(OSError, match="breakaway denied"):
        fixture.run("setup", _tls_materials())
    materials = _record(fixture)["tls_materials"]
    assert fixture.run("cleanup")["restored"]
    assert _record(fixture)["tls_materials"] == materials
    fixture.api.OpenProcess.assert_not_called()
    assert fixture.run("finalize")["finalized"]


def test_finalize_cannot_claim_unjournaled_tls_materials(fixture: Any) -> None:
    fixture.run("setup")
    (fixture.workspace / "server-key.pem").write_bytes(b"another owner")
    fixture.run("cleanup")
    with pytest.raises(AssertionError):
        fixture.run("finalize")
    assert (fixture.workspace / "server-key.pem").read_bytes() == b"another owner"


@pytest.mark.parametrize("tls", [False, True])
def test_server_bootstrap_keeps_one_owned_process_and_optional_daemon_listener(
    server: Any, tls: bool
) -> None:
    if tls:
        (server.root / "server-cert.pem").write_bytes(b"substituted certificate")
        (server.root / "server-key.pem").write_bytes(b"substituted key")
    result = server.run()
    assert result["pid"] == os.getpid()
    assert result["creation"] == 123 and result["token"] == "owned-token"
    assert result["port"] == 23456
    assert server.factory.call_count == (2 if tls else 1)
    server.threading.Timer.assert_called_once_with(1200, server.http.shutdown)
    assert server.timer.daemon is True
    server.timer.start.assert_called_once_with()
    server.http.server_close.assert_called_once_with()
    if tls:
        assert result["tls_port"] == 23457
        server.ssl.SSLContext.assert_called_once_with(server.ssl.PROTOCOL_TLSv1_2)
        server.context.load_cert_chain.assert_called_once_with(
            str(server.root / "server-cert.pem"), str(server.root / "server-key.pem")
        )
        assert server.context.wrap_socket.call_args.kwargs == {"server_side": True}
        assert server.thread.daemon is True
        server.thread.start.assert_called_once_with()
        server.threading.Thread.assert_called_once_with(
            target=server.tls.serve_forever, kwargs={"poll_interval": 0.1}
        )
        server.tls.shutdown.assert_called_once_with()
        server.tls.server_close.assert_called_once_with()
    else:
        assert "tls_port" not in result
        server.ssl.SSLContext.assert_not_called()
        server.threading.Thread.assert_not_called()


@pytest.mark.parametrize("failure", ["certificate", "wrap", "thread", "http"])
def test_listener_startup_failure_closes_acquired_servers_without_false_shutdown(
    server: Any, failure: str
) -> None:
    (server.root / "server-cert.pem").write_bytes(b"substituted certificate")
    (server.root / "server-key.pem").write_bytes(b"substituted key")
    if failure == "certificate":
        server.context.load_cert_chain.side_effect = OSError("certificate failed")
    elif failure == "wrap":
        server.context.wrap_socket.side_effect = OSError("wrap failed")
    elif failure == "thread":
        server.thread.start.side_effect = OSError("thread failed")
    else:
        server.http.serve_forever.side_effect = OSError("http failed")
    with pytest.raises(OSError, match=failure + " failed"):
        server.run()
    server.http.server_close.assert_called_once_with()
    if failure == "certificate":
        server.tls.server_close.assert_not_called()
    else:
        server.tls.server_close.assert_called_once_with()
    if failure == "http":
        server.tls.shutdown.assert_called_once_with()
    else:
        server.tls.shutdown.assert_not_called()


@pytest.mark.parametrize("operation", ["cleanup", "finalize"])
def test_missing_journal_allows_only_exact_empty_owned_workspace(
    fixture: Any, operation: str
) -> None:
    assert fixture.run(operation) == {
        "restored": True,
        "server_stopped": True,
        "finalized": True,
        "empty_owned_workspace": True,
    }
    assert not list(fixture.workspace.iterdir())
    fixture.api.OpenProcess.assert_not_called()
    fixture.api.TerminateProcess.assert_not_called()
    fixture.spawn.assert_not_called()


@pytest.mark.parametrize("operation", ["cleanup", "finalize"])
@pytest.mark.parametrize("name", ["unknown.bin", "server-key.pem", "output"])
def test_nonempty_workspace_without_journal_is_never_adopted(
    fixture: Any, operation: str, name: str
) -> None:
    protected = fixture.workspace / name
    if name == "output":
        protected.mkdir()
    else:
        protected.write_bytes(b"unattributable material")
    with pytest.raises(AssertionError):
        fixture.run(operation)
    assert protected.exists()
    if name != "output":
        assert protected.read_bytes() == b"unattributable material"
    fixture.api.OpenProcess.assert_not_called()
    fixture.api.TerminateProcess.assert_not_called()
    fixture.spawn.assert_not_called()


def test_invalid_initial_argument_retains_empty_workspace_recovery(
    fixture: Any,
) -> None:
    with pytest.raises(AssertionError):
        fixture.run("setup", {})
    assert fixture.run("cleanup")["empty_owned_workspace"]
    assert fixture.run("finalize")["empty_owned_workspace"]
    assert not list(fixture.workspace.iterdir())


def test_first_journal_failure_does_not_authorize_nonempty_partial_setup(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "replace", Mock(side_effect=OSError("journal failed")))
    with pytest.raises(OSError, match="journal failed"):
        fixture.run("setup")
    assert not fixture.journal.exists()
    before = {path.name for path in fixture.workspace.iterdir()}
    assert before == {"output", "preserved.bin", "source.bin"}
    for operation in ("cleanup", "finalize"):
        with pytest.raises(AssertionError):
            fixture.run(operation)
        assert {path.name for path in fixture.workspace.iterdir()} == before
    fixture.spawn.assert_not_called()
