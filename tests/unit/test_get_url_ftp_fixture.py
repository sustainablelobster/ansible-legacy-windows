# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise controller-only FTP fixture ownership and protocol boundaries."""

import ast
import hashlib
import json
import os
import pathlib
import signal
import subprocess
import sys
import time
import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

# PyYAML is already supplied by Ansible; no target or stub dependency is needed.
import yaml  # type: ignore[import-untyped]
from jinja2 import Environment

FIXTURE = pathlib.Path("tests/integration/vars/get_url_ftp_fixture.yml")


@pytest.mark.parametrize("directory", ["", "/owned/private-ssh"])
def test_forward_observes_existing_default_or_private_ssh_socket(
    directory: str,
) -> None:
    play = yaml.safe_load(
        pathlib.Path("tests/integration/win_get_url_ftp.yml").read_text(
            encoding="utf-8"
        )
    )[0]
    block = next(task["block"] for task in play["tasks"] if "block" in task)
    task = next(
        task
        for task in block
        if task["name"]
        == "Bind unchanged target fixture metadata and SSH multiplex socket"
    )
    template = task["ansible.builtin.set_fact"]["get_url_ftp_connection"]["socket"]
    environment = Environment()
    environment.filters["hash"] = lambda value, algorithm: hashlib.new(
        algorithm, value.encode()
    ).hexdigest()
    values = {"HOME": "/owned/home", "ANSIBLE_SSH_CONTROL_PATH_DIR": directory}
    actual = environment.from_string(template).render(
        lookup=lambda _plugin, key: values[key],
        ansible_host="192.0.2.110",
        ansible_user="fixture",
    )
    suffix = hashlib.sha1(b"192.0.2.110-None-fixture").hexdigest()[:10]
    assert actual == (directory or "/owned/home/.ansible/cp") + "/" + suffix


@pytest.fixture(name="fixture")
def _fixture(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> Any:
    document = yaml.safe_load(FIXTURE.read_text(encoding="utf-8"))
    source = (
        document["get_url_ftp_program"]
        .replace(
            "{{ get_url_ftp_server | to_json }}",
            json.dumps(document["get_url_ftp_server"]),
        )
        .replace(
            "{{ get_url_ftp_include_lengths | default(false) | to_json }}",
            json.dumps(getattr(request, "param", False)),
        )
    )
    nodes = ast.parse(source).body
    dispatch = next(
        index for index, node in enumerate(nodes) if isinstance(node, ast.If)
    )
    workspace = tmp_path / "get-url-ftp-owned"
    workspace.mkdir()
    monkeypatch.setattr(
        sys, "argv", ["fixture", str(workspace), "setup", str(tmp_path)]
    )
    namespace: dict[str, Any] = {}
    # Execute the maintained fixture itself rather than a copied test version.
    exec(  # pylint: disable=exec-used
        compile(ast.Module(nodes[:dispatch], []), str(FIXTURE), "exec"), namespace
    )
    process_identity = {"pid": 781, "creation": "1234", "command": ""}
    namespace["identity"] = Mock(return_value=process_identity)
    namespace["closed"] = Mock()
    namespace["socket"] = SimpleNamespace(socket=Mock(return_value=Mock()))
    namespace["socket"].socket.return_value.__enter__ = Mock(return_value=Mock())
    namespace["socket"].socket.return_value.__exit__ = Mock(return_value=False)
    process = Mock(pid=781)
    process.poll.return_value = None

    def _spawn(arguments: list[str], **_options: Any) -> Any:
        record = json.loads((workspace / "journal.json").read_text(encoding="utf-8"))
        assert arguments[-1] == record["token"]
        process_identity["command"] = (
            b"\x00".join(os.fsencode(argument) for argument in arguments) + b"\x00"
        ).hex()
        (workspace / "server.json").write_text(
            json.dumps(
                dict(
                    process_identity, token=record["token"], control=2121, passive=2122
                )
            ),
            encoding="utf-8",
        )
        return process

    spawn = Mock(side_effect=_spawn)
    monkeypatch.setattr(subprocess, "Popen", spawn)
    state = SimpleNamespace(
        workspace=workspace,
        namespace=namespace,
        spawn=spawn,
        process=process,
        process_identity=process_identity,
        program=compile(ast.Module(nodes[dispatch:], []), str(FIXTURE), "exec"),
    )

    def _run(operation: str, argument: Any = None) -> dict[str, Any]:
        namespace["operation"] = operation
        monkeypatch.setattr(
            sys,
            "argv",
            ["fixture", str(workspace), operation, str(tmp_path)]
            + ([] if argument is None else [json.dumps(argument)]),
        )
        # Exercise its actual operation dispatcher on controlled local resources.
        exec(state.program, namespace)  # pylint: disable=exec-used
        result: dict[str, Any] = namespace["result"]
        return result

    state.run = _run
    return state


def test_setup_journals_owned_materials_before_launch(fixture: Any) -> None:
    result = fixture.run("setup")
    record = fixture.namespace["journal"]()
    assert result["ftp"] == "ftp://127.0.0.1:2121"
    assert record["process"] == fixture.process_identity
    assert set(record["protected"]) == {"data", "server.py"}
    assert (fixture.workspace / "data/payload.bin").read_bytes().endswith(b"\x00\xff\n")
    assert (fixture.workspace / "data/payload.bin").stat().st_mtime == 946684800
    assert fixture.spawn.call_args.kwargs["close_fds"]
    assert fixture.spawn.call_args.kwargs["start_new_session"]
    assert fixture.spawn.call_args.kwargs["stdin"] == subprocess.DEVNULL


@pytest.mark.parametrize("fixture", [False, True], indirect=True)
def test_length_files_are_opt_in_and_journaled_without_changing_default_payloads(
    fixture: Any,
    request: pytest.FixtureRequest,
) -> None:
    fixture.run("setup")
    names = set(fixture.namespace["journal"]()["protected"]["data"]["children"])
    expected = {"payload.bin", "preliminary-125.bin", "checksum.sha256"}
    if request.node.callspec.params["fixture"]:
        expected |= {"length-125.bin", "length-150.bin"}
    assert names == expected
    for name in names - {"checksum.sha256"}:
        path = fixture.workspace / "data" / name
        assert path.read_bytes() == fixture.namespace["payload"]
        assert path.stat().st_mtime == 946684800


@pytest.mark.parametrize("name", ["data/payload.bin", "server.py"])
def test_protected_file_change_refuses_cleanup(fixture: Any, name: str) -> None:
    fixture.run("setup")
    (fixture.workspace / name).write_bytes(b"unowned replacement")
    fixture.namespace["stop"] = Mock()
    with pytest.raises(AssertionError):
        fixture.run("cleanup")
    fixture.namespace["stop"].assert_not_called()


def test_journal_workspace_mismatch_refuses_process_cleanup(fixture: Any) -> None:
    fixture.run("setup")
    record = fixture.namespace["journal"]()
    record["workspace"] = str(fixture.workspace.parent / "get-url-ftp-other")
    fixture.namespace["write"](record)
    fixture.namespace["stop"] = Mock()
    with pytest.raises(AssertionError):
        fixture.run("cleanup")
    fixture.namespace["stop"].assert_not_called()


def test_protected_symlink_refuses_cleanup(fixture: Any) -> None:
    fixture.run("setup")
    path = fixture.workspace / "data/payload.bin"
    path.unlink()
    path.symlink_to(fixture.workspace / "data/checksum.sha256")
    with pytest.raises(AssertionError):
        fixture.run("cleanup")


def test_process_command_must_include_owned_workspace_and_token(fixture: Any) -> None:
    fixture.run("setup")
    record = fixture.namespace["journal"]()
    record["process"]["command"] = b"python\x00unowned.py\x00".hex()
    fixture.namespace["write"](record)
    fixture.namespace["stop"] = Mock()
    with pytest.raises(AssertionError):
        fixture.run("cleanup")
    fixture.namespace["stop"].assert_not_called()


def test_journal_cannot_adopt_extra_protected_material(fixture: Any) -> None:
    fixture.run("setup")
    path = fixture.workspace / "unknown"
    path.write_bytes(b"not owned")
    record = fixture.namespace["journal"]()
    record["protected"]["unknown"] = fixture.namespace["tree"](path)
    fixture.namespace["write"](record)
    with pytest.raises(AssertionError):
        fixture.run("finalize")


def test_observe_retains_exact_wire_crlf_and_fixed_passive_port(fixture: Any) -> None:
    fixture.run("setup")
    fixture.run("mark")
    events = [
        {"kind": "passive", "port": 2122},
        {"kind": "reply", "response": "150 File status okay.\r\n"},
    ]
    (fixture.workspace / "wire.jsonl").write_text(
        "".join(json.dumps(event) + "\n" for event in events), encoding="utf-8"
    )
    assert fixture.run("observe")["wire"] == events


@pytest.mark.parametrize(
    "event",
    [
        {"kind": "passive", "port": 12345},
        {"kind": "refused_passive", "address": ["127.0.0.1", 0]},
    ],
)
def test_unowned_passive_port_invalidates_observation(fixture: Any, event: Any) -> None:
    fixture.run("setup")
    (fixture.workspace / "wire.jsonl").write_text(
        json.dumps(event) + "\n", encoding="utf-8"
    )
    with pytest.raises(AssertionError):
        fixture.run("observe")


def test_identity_capture_failure_stops_owned_child(fixture: Any) -> None:
    fixture.namespace["identity"].return_value = None
    with pytest.raises(AssertionError):
        fixture.run("setup")
    fixture.process.terminate.assert_called_once_with()
    fixture.process.wait.assert_called_once_with(timeout=5)
    assert fixture.namespace["journal"]()["child_stopped"]


def test_durable_postlaunch_failure_stops_owned_child(fixture: Any) -> None:
    write = fixture.namespace["write"]
    attempts = 0

    def _write(record: dict[str, Any]) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 3:
            raise OSError("journal unavailable")
        write(record)

    fixture.namespace["write"] = _write
    with pytest.raises(OSError, match="journal unavailable"):
        fixture.run("setup")
    fixture.process.terminate.assert_called_once_with()
    assert fixture.namespace["journal"]()["child_stopped"]
    assert not list(fixture.workspace.glob(".ftp-journal-*"))


def test_initial_atomic_write_failure_leaves_empty_recoverable_workspace(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "replace", Mock(side_effect=OSError("replace failed")))
    with pytest.raises(OSError, match="replace failed"):
        fixture.run("setup")
    assert not list(fixture.workspace.iterdir())
    fixture.spawn.assert_not_called()
    assert fixture.run("cleanup")["empty_owned_workspace"]


def test_wire_marker_excludes_prior_cases(fixture: Any) -> None:
    fixture.run("setup")
    path = fixture.workspace / "wire.jsonl"
    before = {"kind": "reply", "response": "213 Earlier metadata\r\n"}
    after = {"kind": "reply", "response": "150 Current transfer\r\n"}
    path.write_text(json.dumps(before) + "\n", encoding="utf-8")
    fixture.run("mark")
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(after) + "\n")
    assert fixture.run("observe")["wire"] == [after]


def test_missing_journal_allows_only_empty_owned_workspace(fixture: Any) -> None:
    assert fixture.run("cleanup")["empty_owned_workspace"]
    assert fixture.run("finalize")["finalized"]
    (fixture.workspace / "unknown").write_bytes(b"preserve me")
    with pytest.raises(AssertionError):
        fixture.run("cleanup")
    assert (fixture.workspace / "unknown").read_bytes() == b"preserve me"


def test_finalize_rejects_unknown_files_after_recovery(fixture: Any) -> None:
    fixture.run("setup")
    fixture.namespace["stop"] = Mock()
    fixture.run("cleanup")
    assert fixture.run("finalize")["finalized"]
    (fixture.workspace / "unknown").write_bytes(b"preserve me")
    with pytest.raises(AssertionError):
        fixture.run("finalize")


def test_termination_requires_creation_and_exact_command(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    namespace = fixture.namespace
    monkeypatch.setattr(os, "pidfd_open", Mock(return_value=91))
    monkeypatch.setattr(os, "close", Mock())
    send_signal = Mock()
    monkeypatch.setattr(signal, "pidfd_send_signal", send_signal)
    namespace["select"] = SimpleNamespace(select=Mock(return_value=([], [], [])))
    namespace["identity"].return_value = dict(
        fixture.process_identity, creation="other"
    )
    with pytest.raises(AssertionError):
        namespace["stop"](fixture.process_identity)
    send_signal.assert_not_called()
    namespace["identity"].return_value = dict(fixture.process_identity, command="other")
    with pytest.raises(AssertionError):
        namespace["stop"](fixture.process_identity)
    send_signal.assert_not_called()


def test_termination_waits_on_owned_pidfd(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(os, "pidfd_open", Mock(return_value=91))
    close = Mock()
    send_signal = Mock()
    monkeypatch.setattr(os, "close", close)
    monkeypatch.setattr(signal, "pidfd_send_signal", send_signal)
    fixture.namespace["select"] = SimpleNamespace(
        select=Mock(side_effect=[([], [], []), ([91], [], [])])
    )
    fixture.namespace["stop"](fixture.process_identity)
    send_signal.assert_called_once_with(91, signal.SIGTERM)
    close.assert_called_once_with(91)


def test_changed_ssh_master_is_not_adopted(fixture: Any) -> None:
    fixture.run("setup")
    record = fixture.namespace["journal"]()
    record.update(
        connection={"socket": "/owned/socket", "destination": "fixture"},
        master=fixture.process_identity,
        attempted_ports=[2121, 2122],
    )
    fixture.namespace["write"](record)
    fixture.namespace["master"] = Mock(
        return_value=dict(fixture.process_identity, creation="other")
    )
    fixture.namespace["forwarding"] = Mock()
    assert not fixture.run("unforward")["forwards_cancelled"]
    fixture.namespace["forwarding"].assert_not_called()


def test_partial_forward_failure_journals_exact_attempts(fixture: Any) -> None:
    fixture.run("setup")
    fixture.namespace["pathlib"] = SimpleNamespace(
        Path=Mock(
            return_value=SimpleNamespace(
                is_socket=Mock(return_value=True), is_symlink=Mock(return_value=False)
            )
        )
    )
    fixture.namespace["master"] = Mock(return_value=fixture.process_identity)
    fixture.namespace["forwarding"] = Mock(
        side_effect=[
            SimpleNamespace(returncode=0),
            SimpleNamespace(returncode=255, stderr="busy"),
        ]
    )
    with pytest.raises(AssertionError, match="busy"):
        fixture.run("forward", {"socket": "/owned/socket", "destination": "fixture"})
    assert fixture.namespace["journal"]()["attempted_ports"] == [2121, 2122]


@pytest.fixture(name="server")
def _server(fixture: Any) -> Any:
    document = yaml.safe_load(FIXTURE.read_text(encoding="utf-8"))
    nodes: list[ast.stmt] = [
        node
        for node in ast.parse(document["get_url_ftp_server"]).body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef))
    ]
    bind = Mock()
    passive = type("Passive", (), {"bind": bind})
    respond, command = Mock(), Mock()
    handler = type(
        "Handler",
        (),
        {"passive_dtp": passive, "respond": respond, "pre_process_command": command},
    )
    namespace: dict[str, Any] = {
        "os": os,
        "time": time,
        "json": json,
        "uuid": uuid,
        "root": str(fixture.workspace),
        "passive": 2122,
        "FTPHandler": handler,
    }
    # Isolate only socket/protocol side effects; execute the maintained overrides.
    exec(  # pylint: disable=exec-used
        compile(ast.Module(nodes, []), str(FIXTURE), "exec"), namespace
    )
    return SimpleNamespace(namespace=namespace, bind=bind, respond=respond)


def test_server_refuses_random_passive_fallback_before_bind(server: Any) -> None:
    passive = server.namespace["FixedPassive"]()
    with pytest.raises(ValueError, match="unowned passive port"):
        passive.bind(("127.0.0.1", 0))
    server.bind.assert_not_called()


def test_server_records_only_the_fixed_passive_port(server: Any) -> None:
    passive = server.namespace["FixedPassive"]()
    passive.socket = SimpleNamespace(getsockname=Mock(return_value=("127.0.0.1", 2122)))
    passive.bind(("127.0.0.1", 2122))
    server.bind.assert_called_once_with(("127.0.0.1", 2122))


@pytest.mark.parametrize(
    "preliminary", ["125 Original description", "150 Other description"]
)
@pytest.mark.parametrize("explicit_125", [False, True])
def test_server_sends_literal_selected_preliminary_reply(
    server: Any, preliminary: str, explicit_125: bool
) -> None:
    handler = server.namespace["Handler"]()
    handler.fixture_preliminary_125 = explicit_125
    handler.respond(preliminary)
    expected = (
        "125 Data connection already open. Transfer starting."
        if explicit_125
        else "150 File status okay. About to open data connection."
    )
    server.respond.assert_called_once_with(expected)


def test_server_never_logs_the_password_command_argument(server: Any) -> None:
    handler = server.namespace["Handler"]()
    handler.pre_process_command("PASS do-not-log", "PASS", "do-not-log")
    path = pathlib.Path(server.namespace["root"]) / "wire.jsonl"
    event = json.loads(path.read_text(encoding="utf-8"))
    assert event["argument"] == "<redacted>"
    assert "do-not-log" not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize("status", [125, 150])
def test_only_the_two_owned_length_resources_add_a_size_reply(
    server: Any,
    status: int,
) -> None:
    handler = server.namespace["Handler"]()
    filename = f"length-{status}.bin"
    handler.pre_process_command("RETR " + filename, "RETR", filename)
    handler.respond("150 Open data.")
    assert server.respond.call_args.args[0].startswith(str(status) + " ")
    assert server.respond.call_args.args[0].endswith(" (26 bytes).")
    server.respond.reset_mock()
    handler.pre_process_command("RETR payload.bin", "RETR", "payload.bin")
    handler.respond("150 Open data.")
    server.respond.assert_called_once_with(
        "150 File status okay. About to open data connection."
    )
