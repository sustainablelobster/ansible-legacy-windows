"""Exercise TLS fixture diagnostics without sockets or Windows access."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import base64
import hashlib
import json
import os
import ssl
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

# The pinned Nix environment supplies PyYAML without optional typing stubs.
import yaml  # type: ignore[import-untyped]

from tests.unit import test_get_url_fixture as ownership_fixtures
from tests.unit.payload_support import ROOT

# Reuse the owned dispatcher fixture; only listener diagnostics are new here.
get_url_fixture = ownership_fixtures.get_url_fixture


@pytest.mark.parametrize("failure", [None, "ssl", "socket"])
@pytest.mark.parametrize("peer", [None, b"public test certificate DER"])
def test_listener_records_tls_outcomes_without_certificate_material(
    tmp_path: Path, failure: str | None, peer: bytes | None
) -> None:
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/get_url_fixture.yml").read_text()
    )["get_url_server"]
    server_class = next(
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.ClassDef) and node.name == "Server"
    )
    connection = Mock(
        cipher=Mock(return_value=("AES128-SHA", "TLSv1", 128)),
        getpeercert=Mock(return_value=peer),
    )
    accept = Mock(return_value=(connection, ("127.0.0.1", 43123)))
    if failure:
        error = (
            ssl.SSLError(1, "unsupported protocol")
            if failure == "ssl"
            else OSError(10054, "connection reset")
        )
        if failure == "ssl":
            vars(error).update(library="SSL", reason="UNSUPPORTED_PROTOCOL")
        accept.side_effect = error
    namespace: dict[str, Any] = {
        "http": SimpleNamespace(
            server=SimpleNamespace(
                HTTPServer=type("HTTPServer", (), {"get_request": accept})
            )
        ),
        "socketserver": SimpleNamespace(ThreadingMixIn=type("ThreadingMixIn", (), {})),
        "ssl": SimpleNamespace(SSLError=ssl.SSLError, SSLSocket=type(connection)),
        "lock": threading.Lock(),
        "root": str(tmp_path),
        "os": os,
        "json": json,
        "hashlib": hashlib,
    }
    # Execute the maintained accept hook without creating sockets or threads.
    # pylint: disable-next=exec-used
    exec(
        compile(
            ast.Module(body=[server_class], type_ignores=[]), "<TLS accept>", "exec"
        ),
        namespace,
    )
    server = namespace["Server"]()
    server.socket = connection
    if failure:
        with pytest.raises(OSError):
            server.get_request()
        assert json.loads((tmp_path / "tls.jsonl").read_text()) == {
            "event": "failure",
            "errno": error.errno,
            "library": "SSL" if failure == "ssl" else None,
            "reason": "UNSUPPORTED_PROTOCOL" if failure == "ssl" else None,
            "message": str(error),
        }
    else:
        assert server.get_request() == (connection, ("127.0.0.1", 43123))
        assert json.loads((tmp_path / "tls.jsonl").read_text()) == {
            "event": "success",
            "version": "TLSv1.2",
            "cipher": ["AES128-SHA", "TLSv1", 128],
            "client_sha1": hashlib.sha1(peer).hexdigest() if peer else None,
        }
        if peer:
            assert peer.decode() not in (tmp_path / "tls.jsonl").read_text()


def test_tls_history_is_scoped_to_cases_and_retained_through_recovery(
    fixture: Any,
) -> None:
    fixture.run(
        "setup",
        {name: base64.b64encode(name.encode()).decode() for name in ("cert", "key")},
    )
    path = fixture.workspace / "tls.jsonl"
    previous = {"event": "failure", "reason": "UNSUPPORTED_PROTOCOL"}
    current = {"event": "success", "version": "TLSv1.2", "cipher": ["AES", 128]}
    path.write_text(json.dumps(previous) + "\n", encoding="utf-8")
    fixture.run("prepare", {})
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(current) + "\n")
    assert fixture.run("observe")["tls"] == [current]
    assert fixture.run("cleanup")["tls"] == [previous, current]
    assert fixture.run("finalize")["finalized"]


def test_unjournaled_tls_diagnostics_cannot_be_claimed_by_finalize(
    fixture: Any,
) -> None:
    fixture.run("setup")
    path = fixture.workspace / "tls.jsonl"
    path.write_text("{}\n", encoding="utf-8")
    fixture.run("cleanup")
    with pytest.raises(AssertionError):
        fixture.run("finalize")
    assert path.read_text(encoding="utf-8") == "{}\n"
