"""Exercise owned update-worker files, restart-safe polling and cancellation."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native ownership and launch substitutes are controller-only evidence.
# pylint: disable=protected-access

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="fixture")
def owned_fixture(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    """Supply an isolated workspace with explicit native-owner boundaries.

    :param monkeypatch: Scoped native/process/time substitutions.
    :param tmp_path: Private test parent directory.
    :returns: Helper, directory, ownership journal and native state.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    helper = load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_updates_worker.py",
        "tested_updates_worker",
    )
    root = tmp_path / (helper._PREFIX + "a" * 32)
    root.mkdir()
    journal = {
        "root": str(root),
        "nonce": "b" * 32,
        "sid": "S-1-5-21-owned",
        "worker": {"pid": 123, "created": 456, "alive": True},
    }
    helper._write(str(root), "journal.json", dict(journal, worker=None))
    helper._write(str(root), "launch.json", journal)
    state = SimpleNamespace(process=None, now=0.0)
    kernel = SimpleNamespace(
        GetFileAttributesW=lambda path: 16 if os.path.isdir(path) else 0
    )
    monkeypatch.setattr(helper, "_kernel", lambda: kernel)
    monkeypatch.setattr(helper, "_sid", lambda _pid: journal["sid"])
    monkeypatch.setattr(helper, "_process", lambda _pid: state.process)
    monkeypatch.setattr(helper.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(helper.time, "monotonic", lambda: state.now)
    monkeypatch.setattr(
        helper.time, "sleep", lambda seconds: setattr(state, "now", state.now + seconds)
    )
    return SimpleNamespace(
        helper=helper,
        root=root,
        journal=journal,
        state=state,
        kernel=kernel,
        options={"root": str(root), "nonce": journal["nonce"]},
    )


def test_native_helper_closure_and_workspace_names_are_explicit(fixture: Any) -> None:
    assert len(fixture.helper.HELPERS) == 15
    assert "legacy_windows_system_token.py" in fixture.helper.HELPERS
    assert "legacy_windows_regex_categories.py" in fixture.helper.HELPERS
    for name in fixture.helper.HELPERS:
        assert (ROOT / "legacy_windows/plugins/module_utils" / name).is_file()
    assert "launch.json" in fixture.helper._FILES


@pytest.mark.parametrize(
    "options",
    [
        {},
        {"root": "/", "nonce": "b" * 32},
        {"root": "relative", "nonce": "b" * 32},
        {"root": "/tmp/legacy-windows-updates-evil", "nonce": "b" * 32},
        {"root": "", "nonce": "not-owned"},
    ],
)
def test_invalid_ownership_never_reads_or_removes_workspace(
    fixture: Any, options: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    read = Mock()
    monkeypatch.setattr(fixture.helper, "_read", read)
    with pytest.raises(ValueError, match="Invalid internal"):
        fixture.helper.cancel(options)
    read.assert_not_called()
    assert fixture.root.exists()


@pytest.mark.parametrize("attributes", [0, 0x410])
def test_non_directory_and_reparse_root_are_rejected_before_journal(
    fixture: Any, attributes: int
) -> None:
    fixture.kernel.GetFileAttributesW = lambda _path: attributes
    with pytest.raises(OSError, match="reparse point or not a directory"):
        fixture.helper.poll(fixture.options)
    assert fixture.root.exists()


def test_wrong_nonce_or_sid_does_not_cancel_or_remove_files(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(OSError, match="does not belong"):
        fixture.helper.cancel(dict(fixture.options, nonce="c" * 32))
    monkeypatch.setattr(fixture.helper, "_sid", lambda _pid: "other-owner")
    with pytest.raises(OSError, match="does not belong"):
        fixture.helper.cancel(fixture.options)
    assert not (fixture.root / "cancel.request").exists()


def test_mismatched_launch_journal_never_targets_its_pid(fixture: Any) -> None:
    path = fixture.root / "launch.json"
    path.write_text(json.dumps(dict(fixture.journal, nonce="c" * 32)), encoding="utf-8")
    with pytest.raises(OSError, match="launch journal"):
        fixture.helper.cancel(fixture.options)
    assert not (fixture.root / "cancel.request").exists()


@pytest.mark.parametrize("offset", [True, -1, "0", 1.5])
def test_progress_offset_requires_nonnegative_integer(
    fixture: Any, offset: Any
) -> None:
    with pytest.raises(ValueError, match="progress offset"):
        fixture.helper.poll(dict(fixture.options, offset=offset))


def test_reconnect_replays_unacknowledged_packets_and_returns_next_offset(
    fixture: Any,
) -> None:
    output = [
        {"task": "started", "result": {}},
        {"task": "exit", "result": {"changed": False}},
    ]
    fixture.helper._atomic(
        str(fixture.root),
        {
            "nonce": fixture.journal["nonce"],
            "worker": fixture.journal["worker"],
            "finished": True,
            "output": output,
        },
    )
    expected = {"changed": False, "output": output, "offset": 2}
    assert fixture.helper.poll(fixture.options) == expected
    assert fixture.helper.poll(fixture.options) == expected
    assert fixture.helper.poll(dict(fixture.options, offset=1)) == dict(
        expected, output=output[1:]
    )


@pytest.mark.parametrize("nonce,offset", [("other", 0), ("b" * 32, 9)])
def test_progress_ownership_and_offset_cannot_be_silently_reset(
    fixture: Any, nonce: str, offset: int
) -> None:
    fixture.helper._atomic(
        str(fixture.root), {"nonce": nonce, "finished": True, "output": []}
    )
    with pytest.raises(OSError, match="ownership or offset"):
        fixture.helper.poll(dict(fixture.options, offset=offset))


def test_dead_worker_without_final_packet_is_actionable_and_retained(
    fixture: Any,
) -> None:
    fixture.helper._atomic(
        str(fixture.root),
        {"nonce": fixture.journal["nonce"], "finished": False, "output": []},
    )
    with pytest.raises(
        OSError, match="exited without an unread final result; recovery retained"
    ):
        fixture.helper.poll(fixture.options)
    assert fixture.root.exists()


def test_live_worker_waits_then_returns_bounded_progress_batch(fixture: Any) -> None:
    fixture.state.process = fixture.journal["worker"]
    output = [{"task": "download", "result": {"progress": 12}}]
    fixture.helper._atomic(
        str(fixture.root),
        {"nonce": fixture.journal["nonce"], "finished": False, "output": output},
    )
    result = fixture.helper.poll(fixture.options)
    assert result["output"] == output and result["offset"] == 1
    assert 1 <= fixture.state.now < 1.2


@pytest.mark.parametrize(
    "actual",
    [
        None,
        {"pid": 123, "created": 999, "alive": True},
        {"pid": 123, "created": 456, "alive": False},
    ],
)
def test_cancel_removes_only_confirmed_dead_owned_worker_not_recycled_pid(
    fixture: Any, actual: Any
) -> None:
    fixture.state.process = actual
    assert fixture.helper.cancel(fixture.options) == {"changed": False}
    assert not fixture.root.exists()


def test_uncancellable_live_worker_is_not_terminated_or_deleted(fixture: Any) -> None:
    fixture.state.process = fixture.journal["worker"]
    with pytest.raises(
        OSError,
        match="Retry cancellation after WUA finishes; the live worker was not terminated",
    ):
        fixture.helper.cancel(fixture.options)
    assert fixture.root.exists()
    assert (
        fixture.helper._read(str(fixture.root), "cancel.request")
        == fixture.journal["nonce"]
    )
    assert fixture.state.now >= 10


def test_repeat_cancel_requires_literal_nonce(fixture: Any) -> None:
    fixture.helper._write(str(fixture.root), "cancel.request", "wrong")
    with pytest.raises(OSError, match="cancellation request does not match"):
        fixture.helper.cancel(fixture.options)
    assert fixture.root.exists()


def test_cleanup_rejects_unowned_files_without_partial_deletion(fixture: Any) -> None:
    protected = fixture.root / "unowned.txt"
    protected.write_text("preserve", encoding="utf-8")
    with pytest.raises(OSError, match="unowned files: unowned.txt"):
        fixture.helper.cancel(fixture.options)
    assert protected.read_text(encoding="utf-8") == "preserve"
    assert (fixture.root / "journal.json").exists()


def test_cleanup_rejects_reparse_file_before_deleting_other_files(fixture: Any) -> None:
    fixture.kernel.GetFileAttributesW = lambda path: (
        16 if path == str(fixture.root) else 0x400
    )
    with pytest.raises(OSError, match="reparse point during update cleanup"):
        fixture.helper.cancel(fixture.options)
    assert (fixture.root / "journal.json").exists()


def test_ambiguous_create_failure_recovers_from_independent_worker_ack(
    fixture: Any,
) -> None:
    (fixture.root / "launch.json").unlink()
    fixture.helper._atomic(
        str(fixture.root),
        {
            "nonce": fixture.journal["nonce"],
            "worker": fixture.journal["worker"],
            "output": [],
            "finished": True,
        },
    )
    assert fixture.helper.cancel(fixture.options) == {"changed": False}
    assert not fixture.root.exists()


def test_worker_writes_atomic_complete_packets_with_literal_startup_environment(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture.state.process = fixture.journal["worker"]
    request = {
        "nonce": fixture.journal["nonce"],
        "sid": fixture.journal["sid"],
        "environment": dict(os.environ),
        "options": {},
    }
    fixture.helper._write(str(fixture.root), "request.json", request)
    monkeypatch.setattr(fixture.helper.sys, "argv", ["worker.py", str(fixture.root)])

    def run(_options: Any, emit: Any, cancelled: Any, log: Any) -> None:
        assert not cancelled()
        log("ignored without log_path")
        emit("started", {})
        emit("exit", {"changed": False, "failed": False})

    monkeypatch.setattr(fixture.helper.updates, "run", run)
    fixture.helper.main()
    result = fixture.helper._read(str(fixture.root), "state.json")
    assert result == {
        "nonce": fixture.journal["nonce"],
        "worker": fixture.journal["worker"],
        "finished": True,
        "output": [
            {"task": "started", "result": {}},
            {"task": "exit", "result": {"changed": False, "failed": False}},
        ],
    }
    assert not (fixture.root / ".state-next.json").exists()


def test_worker_refuses_changed_startup_environment_before_servicing(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture.helper._write(
        str(fixture.root),
        "request.json",
        {"sid": fixture.journal["sid"], "environment": {"ONLY": "different"}},
    )
    monkeypatch.setattr(fixture.helper.sys, "argv", ["worker.py", str(fixture.root)])
    run = Mock()
    monkeypatch.setattr(fixture.helper.updates, "run", run)
    with pytest.raises(OSError, match="caller identity and environment"):
        fixture.helper.main()
    run.assert_not_called()


@pytest.mark.parametrize("check_mode", [False, True])
def test_log_appends_utf8_diagnostics_but_check_mode_never_touches_log(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, check_mode: bool
) -> None:
    path = fixture.root / "public.log"
    path.write_text("existing\n", encoding="utf-8")
    request = {
        "nonce": fixture.journal["nonce"],
        "sid": fixture.journal["sid"],
        "environment": dict(os.environ),
        "options": {"log_path": str(path), "check_mode": check_mode},
    }
    fixture.helper._write(str(fixture.root), "request.json", request)
    monkeypatch.setattr(fixture.helper.sys, "argv", ["worker.py", str(fixture.root)])

    def run(_options: Any, emit: Any, _cancelled: Any, log: Any) -> None:
        log("Searching 雪")
        emit("exit", {"changed": False})

    monkeypatch.setattr(fixture.helper.updates, "run", run)
    fixture.helper.main()
    text = path.read_text(encoding="utf-8")
    assert text.startswith("existing\n")
    assert (" update_task Searching 雪\n" in text) is not check_mode
    assert (text == "existing\n") is check_mode


def test_invalid_log_directory_reports_final_failure_without_wua_access(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture.helper._write(
        str(fixture.root),
        "request.json",
        {
            "nonce": fixture.journal["nonce"],
            "sid": fixture.journal["sid"],
            "environment": dict(os.environ),
            "options": {"log_path": str(fixture.root / "missing" / "public.log")},
        },
    )
    monkeypatch.setattr(fixture.helper.sys, "argv", ["worker.py", str(fixture.root)])
    run = Mock()
    monkeypatch.setattr(fixture.helper.updates, "run", run)
    fixture.helper.main()
    run.assert_not_called()
    state = fixture.helper._read(str(fixture.root), "state.json")
    assert state["finished"] and state["output"][0]["result"]["failed"]
    assert "missing" in state["output"][0]["result"]["exception"]["message"]


def test_atomic_replace_retries_reader_sharing_violation_without_partial_final_json(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    replace = os.replace
    calls = []

    def transient(source: str, destination: str) -> None:
        calls.append(source)
        if len(calls) == 1:
            raise PermissionError("reader sharing violation")
        replace(source, destination)

    monkeypatch.setattr(fixture.helper.os, "replace", transient)
    fixture.helper._atomic(str(fixture.root), {"value": "雪"})
    assert fixture.helper._read(str(fixture.root), "state.json") == {"value": "雪"}
    assert len(calls) == 2 and fixture.state.now == 0.01


def test_supervised_worker_waits_for_cancellation_without_removing_callers_files(
    fixture: Any,
) -> None:
    fixture.state.process = dict(fixture.journal["worker"])
    fixture.helper._write(str(fixture.root), "cancel.request", fixture.journal["nonce"])
    fixture.helper._finish_supervised(
        str(fixture.root),
        {
            "supervisor": fixture.journal["worker"],
            "nonce": fixture.journal["nonce"],
            "sid": fixture.journal["sid"],
        },
        {"worker": fixture.journal["worker"]},
    )
    assert fixture.root.exists()


def test_dead_async_frontend_allows_only_exact_self_owned_cleanup(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = dict(fixture.journal["worker"])
    supervisor = {"pid": 999, "created": 789, "alive": True}
    monkeypatch.setattr(fixture.helper.os, "getpid", lambda: worker["pid"])
    monkeypatch.setattr(
        fixture.helper, "_process", lambda pid: worker if pid == worker["pid"] else None
    )
    changed = Mock()
    monkeypatch.setattr(fixture.helper.os, "chdir", changed)
    fixture.helper._finish_supervised(
        str(fixture.root),
        {
            "supervisor": supervisor,
            "nonce": fixture.journal["nonce"],
            "sid": fixture.journal["sid"],
        },
        {"worker": worker},
    )
    assert not fixture.root.exists()
    changed.assert_called_once_with(str(fixture.root.parent))


def test_self_cleanup_never_bypasses_a_different_live_worker_identity(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture.state.process = dict(fixture.journal["worker"])
    monkeypatch.setattr(
        fixture.helper,
        "_process",
        lambda pid: (
            fixture.state.process
            if pid == fixture.journal["worker"]["pid"]
            else {"pid": pid, "created": 999, "alive": True}
        ),
    )
    with pytest.raises(OSError, match="still running"):
        fixture.helper._cleanup(str(fixture.root), fixture.journal, own_worker=True)
    assert fixture.root.exists()


def test_default_synchronous_worker_does_not_wait_for_frontend_exit(
    fixture: Any,
) -> None:
    fixture.helper._finish_supervised(str(fixture.root), {}, {})
    assert fixture.root.exists()


def _startup(fixture: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    helper = fixture.helper
    source = fixture.root.parent / "staging"
    source.mkdir()
    for name in helper.HELPERS:
        (source / name).write_bytes(b"# frozen helper\n")
    nonce = "d" * 32
    root = fixture.root.parent / (helper._PREFIX + nonce)
    frontend = {"pid": 999, "created": 789, "alive": True}
    worker = dict(fixture.journal["worker"])
    state = SimpleNamespace(frontend=frontend, worker=worker)
    journal = {
        "root": str(root),
        "nonce": nonce,
        "sid": fixture.journal["sid"],
        "worker": None,
    }
    request = {
        "options": {},
        "nonce": nonce,
        "sid": journal["sid"],
        "environment": dict(os.environ),
        "supervisor": frontend,
    }
    path = source / (".updates-start-" + nonce + ".json")
    helper._write(str(source), path.name, {"journal": journal, "request": request})
    monkeypatch.setattr(
        helper, "__file__", str(source / "legacy_windows_updates_worker.py")
    )
    monkeypatch.setattr(helper.sys, "argv", ["-c", str(path)])
    monkeypatch.setattr(helper.os, "getpid", lambda: worker["pid"])
    monkeypatch.setattr(helper.os, "chdir", Mock())
    monkeypatch.setattr(
        helper,
        "_process",
        lambda pid: state.worker if pid == worker["pid"] else state.frontend,
    )
    create = Mock(side_effect=lambda value, _sid: Path(value).mkdir())
    monkeypatch.setattr(helper, "_directory", create)
    run = Mock()
    monkeypatch.setattr(helper, "main", run)
    return SimpleNamespace(
        helper=helper,
        source=source,
        root=root,
        path=path,
        journal=journal,
        request=request,
        state=state,
        create=create,
        run=run,
    )


def test_supervised_frontend_never_allocates_updates_root_before_native_launch(
    fixture: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    startup = _startup(fixture, monkeypatch)

    def launch(_command: str, source: str, environment: Any) -> int:
        requests = list(Path(source).glob(".updates-start-*.json"))
        # One request belongs to this fixture setup; the other is this start.
        value = json.loads(
            next(path for path in requests if path != startup.path).read_text()
        )
        assert not Path(value["journal"]["root"]).exists()
        assert environment == dict(os.environ)
        raise OSError("stop before Create")

    monkeypatch.setattr(startup.helper, "_launch", launch)
    with pytest.raises(OSError, match="stop before Create"):
        startup.helper.start({}, supervised=True)
    startup.create.assert_not_called()
    assert not startup.root.exists()
    assert list(startup.source.glob(".updates-start-*.json")) == [startup.path]


@pytest.mark.parametrize("outcome", ["denied", "uncertain", "started"])
def test_supervised_failure_only_advertises_recovery_after_uncertain_launch(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    helper = fixture.helper
    source = fixture.root.parent / "staging"
    source.mkdir()
    monkeypatch.setattr(helper, "__file__", str(source / "worker.py"))
    reason = "SYSTEM worker launch failed before dispatch: inaccessible token"
    error = None
    if outcome == "denied":
        error = helper._LaunchDenied(reason)
    elif outcome == "uncertain":
        error = OSError("uncertain dispatch")
    launch = Mock(side_effect=error, return_value=123)
    monkeypatch.setattr(helper, "_launch_owned", launch)
    create = Mock()
    monkeypatch.setattr(helper, "_directory", create)
    before = sorted(fixture.root.parent.glob("legacy-windows-updates-*"))
    with pytest.raises(OSError) as failure:
        helper.start({}, supervised=True)
    launch.assert_called_once()
    create.assert_not_called()
    assert sorted(fixture.root.parent.glob("legacy-windows-updates-*")) == before
    assert not list(source.iterdir())
    if outcome != "started":
        assert failure.value.__cause__ is error
    if outcome == "denied":
        assert str(failure.value) == (
            "Supervised update startup failed before launch: "
            + reason
            + "; no update workspace was created."
        )
        assert "recovery retained" not in str(failure.value)
        assert "nonce" not in str(failure.value)
    else:
        reason = (
            "uncertain dispatch"
            if outcome == "uncertain"
            else "The supervised update worker exited before startup."
        )
        assert "Supervised update startup failed: " + reason in str(failure.value)
        assert "recovery retained at" in str(failure.value)
        assert ", nonce " in str(failure.value)


def test_hard_frontend_death_before_create_leaves_only_watchdog_owned_staging(
    tmp_path: Path,
) -> None:
    source = tmp_path / "staging"
    source.mkdir()
    barrier = tmp_path / "before-create.json"
    program = """
import json,os,sys,time
sys.path.insert(0,sys.argv[1])
import legacy_windows_updates_worker as worker
worker.__file__=os.path.join(sys.argv[2],'worker.py')
worker.tempfile.gettempdir=lambda:sys.argv[3]
worker._sid=lambda pid:'S-1-5-owned'
worker._process=lambda pid:{'pid':pid,'created':1,'alive':True}
def before_create(command,source,environment):
    name=next(name for name in os.listdir(source) if name.startswith('.updates-start-'))
    with open(os.path.join(source,name)) as stream: value=json.load(stream)
    with open(sys.argv[4]+'.tmp','x') as stream: json.dump(value,stream)
    os.replace(sys.argv[4]+'.tmp',sys.argv[4])
    while True: time.sleep(.01)
worker._launch=before_create
worker.start({},supervised=True)
"""
    with subprocess.Popen(
        [
            sys.executable,
            "-c",
            program,
            str(ROOT / "legacy_windows/plugins/module_utils"),
            str(source),
            str(tmp_path),
            str(barrier),
        ]
    ) as process:
        deadline = time.monotonic() + 5
        while not barrier.is_file():
            assert process.poll() is None
            assert time.monotonic() < deadline
            time.sleep(0.01)
        process.kill()
        process.wait(timeout=5)
    value = json.loads(barrier.read_text())
    assert not Path(value["journal"]["root"]).exists()
    assert len(list(source.glob(".updates-start-*.json"))) == 1
    assert not list(tmp_path.glob("legacy-windows-updates-*"))


def test_dead_frontend_or_missing_staging_never_allocates_a_worker_root(
    fixture: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    startup = _startup(fixture, monkeypatch)
    startup.state.frontend = None
    startup.helper._supervised_main()
    startup.create.assert_not_called()
    startup.state.frontend = startup.request["supervisor"]
    (startup.source / startup.helper.HELPERS[-1]).unlink()
    with pytest.raises(FileNotFoundError):
        startup.helper._supervised_main()
    startup.create.assert_not_called()


def test_surviving_owner_recovers_frontend_death_immediately_after_journal(
    fixture: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    startup = _startup(fixture, monkeypatch)
    write = startup.helper._write

    def lose_frontend(root: str, name: str, value: Any) -> None:
        write(root, name, value)
        if name == "journal.json":
            startup.state.frontend = None

    monkeypatch.setattr(startup.helper, "_write", lose_frontend)
    startup.helper._supervised_main()
    startup.run.assert_not_called()
    assert not startup.root.exists()


def test_surviving_owner_cleans_partial_startup_copy_failure(
    fixture: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    startup = _startup(fixture, monkeypatch)
    write = startup.helper._write

    def fail_request(root: str, name: str, value: Any) -> None:
        if name == "request.json":
            raise OSError("partial startup")
        write(root, name, value)

    monkeypatch.setattr(startup.helper, "_write", fail_request)
    with pytest.raises(OSError, match="partial startup"):
        startup.helper._supervised_main()
    startup.run.assert_not_called()
    assert not startup.root.exists()


def test_normal_cancellation_leaves_cleanup_with_the_live_frontend(
    fixture: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    startup = _startup(fixture, monkeypatch)
    startup.helper._supervised_main()
    startup.run.assert_called_once_with(str(startup.root))
    assert startup.root.is_dir()
    assert (
        startup.helper._read(str(startup.root), "launch.json")["worker"]
        == startup.state.worker
    )


def test_owner_execution_error_recovers_root_even_with_live_frontend(
    fixture: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    startup = _startup(fixture, monkeypatch)
    startup.run.side_effect = OSError("before acknowledgment")
    with pytest.raises(OSError, match="before acknowledgment"):
        startup.helper._supervised_main()
    assert not startup.root.exists()
