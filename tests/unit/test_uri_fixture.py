"""Exercise the URI fixture's real loopback HTTP/body observations locally."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import base64
import http.client
import http.server
import json
import os
import socketserver
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

import pytest

# PyYAML is provided by the pinned developer environment, not Windows payloads.
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.fixture(name="server")
def uri_fixture_server(tmp_path: Path) -> Any:
    """Run the maintained handler without executing Windows process setup.

    :param tmp_path: Owned request journal directory.
    :returns: Fixture server, raw request log path and independent HTTP client.
    """
    document = yaml.safe_load(
        (ROOT / "tests/integration/vars/uri_fixture.yml").read_text(encoding="utf-8")
    )
    nodes: list[ast.stmt] = [
        node
        for node in ast.parse(document["get_url_server"]).body
        if isinstance(node, ast.ClassDef)
        or isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name)
            and target.id in {"payloads", "payload", "lock"}
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
        "root": str(tmp_path),
        "token": "owned-fixture-token",
    }
    # Execute the maintained handler classes, not a separately reimplemented fake.
    exec(  # pylint: disable=exec-used
        compile(ast.Module(body=nodes, type_ignores=[]), "<uri fixture>", "exec"),
        namespace,
    )
    owned = namespace["Server"](("127.0.0.1", 0), namespace["Handler"])
    thread = threading.Thread(
        target=owned.serve_forever, kwargs={"poll_interval": 0.01}
    )
    thread.start()
    client = http.client.HTTPConnection("127.0.0.1", owned.server_port, timeout=5)
    try:
        yield client, tmp_path / "requests.jsonl"
    finally:
        client.close()
        owned.shutdown()
        thread.join(timeout=5)
        owned.server_close()
        assert not thread.is_alive()


# pylint: enable=duplicate-code


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH"])
def test_fixture_retains_exact_body_and_all_header_pairs(
    server: Any, method: str
) -> None:
    client, journal = server
    body = b"fixture\x00\xff"
    client.request(
        method, "/echo", body=body, headers={"Content-Type": "application/custom"}
    )
    response = client.getresponse()
    assert response.status == 200
    parsed = json.loads(response.read())
    assert parsed["body_base64"] == base64.b64encode(body).decode("ascii")
    assert parsed["method"] == method
    assert parsed["headers"]["Content-Type"] == "application/custom"
    record = json.loads(journal.read_text(encoding="utf-8"))
    assert dict(record["header_pairs"]) == record["headers"]
    assert record["body_base64"] == parsed["body_base64"]


def test_fixture_response_header_order_duplicates_and_fixed_dates(server: Any) -> None:
    client, _journal = server
    client.request("GET", "/custom")
    response = client.getresponse()
    assert response.read() == b"fixture"
    headers = response.getheaders()
    assert [value for key, value in headers if key == "X-Test-Value"] == [
        "first",
        "second",
    ]
    assert [value for key, value in headers if key == "Date"] == [
        "Sat, 01 Jan 2000 00:00:00 GMT"
    ]
    assert [key for key, _value in headers] == [
        "Server",
        "Date",
        "Content-Length",
        "Content-Type",
        "Last-Modified",
        "X-Test-Value",
        "X-Test-Value",
        "ETag",
        "Set-Cookie",
    ]


def test_fixture_head_and_redirect_preserve_body_metadata(server: Any) -> None:
    client, _journal = server
    client.request("HEAD", "/payload.bin")
    response = client.getresponse()
    assert response.read() == b"" and response.getheader("Content-Length") == "26"
    client.request("POST", "/redirect/307", body=b"fixture")
    response = client.getresponse()
    assert response.status == 307 and response.getheader("Location") == "/echo"
    assert response.read() == b"redirect"


@pytest.mark.parametrize(
    "matrix", ["echo", "slow_body", "default_host", "default_host_ipv6"]
)
def test_shared_download_wrapper_selects_only_its_effective_matrix(
    tmp_path: Path, matrix: str
) -> None:
    """Exercise Ansible's fact/vars_files precedence without executing Windows tasks."""
    integration = ROOT / "tests/integration"
    wrapper = yaml.safe_load(
        (integration / "win_uri_http_default_regression.yml").read_text()
    )
    assert wrapper[1]["ansible.builtin.import_playbook"] == "win_get_url.yml"
    binding, shared = (
        wrapper[0],
        yaml.safe_load((integration / "win_get_url.yml").read_text())[0],
    )
    facts = binding["tasks"][
        {"echo": 0, "slow_body": 1, "default_host": 2, "default_host_ipv6": 2}[matrix]
    ]["ansible.builtin.set_fact"]
    expected = list(facts["get_url_cases"])
    assert len(expected) == 3
    fixture = yaml.safe_load((integration / "vars/uri_fixture.yml").read_text())
    assert "Server(('127.0.0.1', 52771), Handler)" in fixture["get_url_server"]
    if matrix.startswith("default_host"):
        assert expected[0]["params"]["url"] == "http://127.0.0.1:80/echo"
        assert expected[1]["params"]["url"] == "http://127.0.0.1/echo"
        assert expected[2]["params"]["headers"] == {"Host": "caller.example:80"}
        expected_server = fixture["get_url_server"].replace(
            "Server(('127.0.0.1', 52771), Handler)",
            "Server(('127.0.0.1', 80), Handler)",
        )
        if matrix == "default_host_ipv6":
            expected += binding["tasks"][3]["vars"]["get_url_ipv6_cases"]
            expected_server = expected_server.replace(
                "enable_ipv6 = False", "enable_ipv6 = True"
            )
    else:
        assert all(
            case["params"]["url"].startswith("http://127.0.0.1:52771/")
            for case in expected
        )
        expected_server = fixture["get_url_server"]
    (tmp_path / "vars").symlink_to(integration / "vars", target_is_directory=True)
    binding["hosts"] = "localhost"
    binding["vars"] = {
        "uri_body_timeout_regression": matrix == "slow_body",
        "uri_default_host_regression": matrix.startswith("default_host"),
        "uri_ipv6_host_regression": matrix == "default_host_ipv6",
    }
    probe = [
        binding,
        {
            "hosts": "localhost",
            "gather_facts": False,
            "vars_files": [str(integration / path) for path in shared["vars_files"]],
            "vars": dict(
                shared["vars"],
                uri_http_expected_cases=expected,
                uri_http_expected_server=expected_server,
            ),
            "tasks": [
                {
                    "name": "Require the effective imported matrix and server",
                    "ansible.builtin.assert": {
                        "that": [
                            "get_url_selected_cases == uri_http_expected_cases",
                            "get_url_server == uri_http_expected_server",
                        ]
                    },
                }
            ],
        },
    ]
    if matrix != "echo":
        expected_uri = list(facts["uri_cases"])
        if matrix == "default_host_ipv6":
            expected_uri += binding["tasks"][3]["vars"]["uri_ipv6_cases"]
        uri_flow = yaml.safe_load((integration / "win_uri.yml").read_text())[0]
        probe.append(
            {
                "hosts": "localhost",
                "gather_facts": False,
                "vars_files": [
                    str(integration / path) for path in uri_flow["vars_files"]
                ],
                "vars": dict(uri_flow["vars"], uri_expected_cases=expected_uri),
                "tasks": [
                    {
                        "name": "Require the effective bounded URI matrix",
                        "ansible.builtin.assert": {
                            "that": ["uri_selected_cases == uri_expected_cases"]
                        },
                    }
                ],
            }
        )
    playbook = tmp_path / "selection-probe.yml"
    playbook.write_text(yaml.safe_dump(probe, sort_keys=False), encoding="utf-8")
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    result = subprocess.run(
        ["ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    # pylint: enable=duplicate-code
    assert "Require the effective imported matrix and server" in result.stdout
    assert "changed=0" in result.stdout and "failed=0" in result.stdout
