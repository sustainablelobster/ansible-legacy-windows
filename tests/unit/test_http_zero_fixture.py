"""Exercise the maintained bounded zero-timeout fixture without Windows access."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import base64
import http.client
import http.server
import json
import os
import socket
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
INTEGRATION = ROOT / "tests/integration"


@pytest.mark.parametrize("indices", [None, [0, 7, 8, 9, 10], [8, 9], list(range(20))])
def test_effective_source_matrix_and_body_server_are_exact_and_package_safe(
    tmp_path: Path,
    indices: list[int] | None,
) -> None:
    document = yaml.safe_load((INTEGRATION / "vars/http_zero.yml").read_text())
    cases = document["http_zero_cases"]
    assert len(cases) == len({case["name"] for case in cases}) == 29
    assert all(
        case.get("check") is True for case in cases if case["module"] == "package"
    )
    maintained = yaml.safe_load((INTEGRATION / "http_zero_timeout.yml").read_text())
    binding = next(
        task
        for task in maintained[0]["tasks"]
        if task["name"]
        == "Select the literal body-aware server over imported fixture defaults"
    )
    # Preserve the actual maintained fact-over-vars_files policy; map only its
    # fixture lookup path into this controller-only playbook's own namespace.
    binding["ansible.builtin.set_fact"]["get_url_server"] = binding[
        "ansible.builtin.set_fact"
    ]["get_url_server"].replace("playbook_dir +", "http_zero_integration_dir +")
    selected = cases if indices is None else [cases[index] for index in indices]
    if indices == list(range(20)):
        assert len(selected) == 20
        assert all(
            case.get("params", {}).get("url_timeout", 0) == 0 for case in selected
        )
        assert all(not case.get("file", False) for case in selected)
    probe = [
        {
            "hosts": "localhost",
            "connection": "local",
            "gather_facts": False,
            "vars_files": [
                str(INTEGRATION / "vars/get_url_fixture.yml"),
                str(INTEGRATION / "vars/http_zero.yml"),
            ],
            "vars": {
                "http_zero_expected_cases": selected,
                "http_zero_integration_dir": str(INTEGRATION),
                "http_zero_expected_server": (
                    INTEGRATION / "fixtures/http_zero_server.py"
                ).read_text(),
            },
            "tasks": [
                binding,
                {
                    "ansible.builtin.assert": {
                        "that": [
                            "http_zero_selected_cases == http_zero_expected_cases",
                            "http_zero_mode == 'source'",
                            "get_url_server == http_zero_expected_server",
                        ]
                    }
                },
            ],
        }
    ]
    playbook = tmp_path / "effective-matrix.yml"
    playbook.write_text(yaml.safe_dump(probe))
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    arguments = [
        sys.executable,
        "-m",
        "ansible.cli.playbook",
        "-i",
        "localhost,",
        str(playbook),
        "-e",
        "http_zero_mode=source",
    ]
    # pylint: enable=duplicate-code
    if indices is not None:
        arguments += ["-e", json.dumps({"http_zero_case_indices": indices})]
    run = subprocess.run(
        arguments,
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert run.returncode == 0, run.stdout + run.stderr


@pytest.fixture(name="server")
def owned_server(tmp_path: Path) -> Any:
    """Run the actual maintained handler, excluding Windows process setup.

    :param tmp_path: Owned request-journal directory.
    :returns: Independent client and the literal wire journal.
    """
    source = (INTEGRATION / "fixtures/http_zero_server.py").read_text()
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    nodes: list[ast.stmt] = [
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.ClassDef)
        or isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id in ("PAYLOAD", "LOCK")
            for target in node.targets
        )
    ]
    namespace: dict[str, Any] = {
        "base64": base64,
        "http": http,
        "json": json,
        "os": os,
        "socketserver": socketserver,
        "threading": threading,
        "time": time,
        "ROOT": str(tmp_path),
        "TOKEN": "owned",
        "urlsplit": __import__("urllib.parse", fromlist=["urlsplit"]).urlsplit,
    }
    # pylint: enable=duplicate-code
    # Execute only the maintained handler declarations; Windows process setup
    # stays excluded from this controller-local fixture.
    # pylint: disable-next=exec-used
    exec(
        compile(ast.Module(body=nodes, type_ignores=[]), "<zero HTTP fixture>", "exec"),
        namespace,
    )
    owned = namespace["Server"](("127.0.0.1", 0), namespace["Handler"])
    worker = threading.Thread(
        target=owned.serve_forever, kwargs={"poll_interval": 0.01}
    )
    worker.start()
    client = http.client.HTTPConnection("127.0.0.1", owned.server_port, timeout=3)
    try:
        yield client, tmp_path / "requests.jsonl"
    finally:
        client.close()
        owned.shutdown()
        worker.join(5)
        owned.server_close()
        assert not worker.is_alive()


def test_actual_fixture_journals_upload_before_delayed_response(server: Any) -> None:
    client, journal = server
    client.request("POST", "/delay/0.1", body=b"fixture\x00\xff")
    for _attempt in range(100):
        if journal.exists() and journal.stat().st_size:
            break
        time.sleep(0.001)
    row = json.loads(journal.read_text())
    assert row["method"] == "POST" and row["path"] == "/delay/0.1"
    assert row["body_base64"] == base64.b64encode(b"fixture\x00\xff").decode()
    assert dict(row["header_pairs"]) == row["headers"]
    response = client.getresponse()
    assert (
        response.status == 200
        and response.read() == b"legacy download fixture\x00\xff\n"
    )


def test_actual_fixture_preserves_redirect_and_proxy_absolute_target(
    server: Any,
) -> None:
    client, journal = server
    client.request("GET", "http://owned.invalid/redirect/0")
    response = client.getresponse()
    assert response.status == 302 and response.getheader("Location") == "/payload.bin"
    assert response.read() == b""
    assert json.loads(journal.read_text())["path"] == "http://owned.invalid/redirect/0"


def test_actual_fixture_retains_headers_and_empty_canceled_upload(server: Any) -> None:
    client, journal = server
    connection = socket.create_connection((client.host, client.port), timeout=3)
    connection.sendall(
        b"POST /delay/0 HTTP/1.1\r\nHost: owned\r\nContent-Length: 7\r\n"
        b"Expect: 100-continue\r\n\r\n"
    )
    assert connection.recv(1024) == b"HTTP/1.1 100 Continue\r\n\r\n"
    connection.shutdown(socket.SHUT_RDWR)
    connection.close()
    for _attempt in range(100):
        if journal.exists() and journal.stat().st_size:
            break
        time.sleep(0.001)
    row = json.loads(journal.read_text())
    assert row["headers"]["Content-Length"] == "7"
    assert row["body_base64"] == ""
    assert row["body_complete"] is False and row["peer_closed"] is True
