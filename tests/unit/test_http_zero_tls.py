"""Exercise the actual TLS fixture bootstrap with controller-only ABI substitutes."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Developer sockets/SSL and substituted process APIs do not prove Windows support.

import ast
import copy
import ctypes
import json
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock, patch
from urllib.error import URLError
from urllib.request import urlopen

import pytest
import yaml  # type: ignore[import-untyped]

from tests.unit import test_get_url_native as download_fixtures

native_download = download_fixtures.native_download
native_http = download_fixtures.native_http

ROOT = Path(__file__).resolve().parents[2]
SERVER_SOURCE = ROOT / "tests/integration/fixtures/http_zero_server.py"


@pytest.fixture(name="tls_server")
def tls_fixture_server(tmp_path: Path) -> Any:
    """Run the maintained server bootstrap and close both actual listener threads.

    :param tmp_path: Disposable controller PEM and request-journal workspace.
    :returns: Namespace and metadata from the actual maintained server.
    """
    generated = subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-keyout",
            str(tmp_path / "server-key.pem"),
            "-out",
            str(tmp_path / "server-cert.pem"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert generated.returncode == 0, generated.stderr
    tree = ast.parse(SERVER_SOURCE.read_text())
    main = next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "main"
        ),
        None,
    )
    assert main is not None
    # The actual Windows run proves the floor; remove only that runtime assertion
    # for this controller test while keeping all bootstrap/lifetime code intact.
    main.body = [
        node
        for node in main.body
        if not (
            isinstance(node, ast.Assert)
            and any(
                isinstance(item, ast.Attribute) and item.attr == "version_info"
                for item in ast.walk(node)
            )
        )
    ]
    tree.body = [node for node in tree.body if not isinstance(node, ast.If)]
    kernel = Mock()
    kernel.GetProcessTimes.return_value = True
    namespace: dict[str, Any] = {}
    # The standalone fixture reads its own arguments during import; the test
    # runner's arguments must not supply its workspace or ownership token.
    with patch.object(
        sys, "argv", [str(SERVER_SOURCE), str(tmp_path), "owned-tls-test"]
    ):
        # Load the real fixture definitions without invoking its main guard.
        # pylint: disable-next=exec-used
        exec(compile(tree, str(SERVER_SOURCE), "exec"), namespace)
    namespace["ctypes"] = SimpleNamespace(
        WinDLL=Mock(return_value=kernel),
        c_void_p=ctypes.c_void_p,
        c_int32=ctypes.c_int32,
        c_uint64=ctypes.c_uint64,
        byref=ctypes.byref,
    )
    namespace["threading"] = SimpleNamespace(
        Thread=threading.Thread, Timer=Mock(return_value=Mock())
    )
    original = namespace["Server"]
    listeners = []

    def _create_listener(*arguments: Any) -> Any:
        listener = original(*arguments)
        listeners.append(listener)
        return listener

    namespace["Server"] = _create_listener
    with ThreadPoolExecutor(max_workers=1) as executor:
        worker = executor.submit(namespace["main"])
        try:
            metadata = tmp_path / "server.json"
            for _attempt in range(200):
                if metadata.exists():
                    break
                if worker.done():
                    worker.result()
                time.sleep(0.005)
            assert metadata.exists()
            info = json.loads(metadata.read_text())
            assert info["tls_port"] != info["port"]
            yield namespace, info
        finally:
            if listeners and not worker.done():
                listeners[0].shutdown()
            worker.result(timeout=5)
            assert all(listener.socket.fileno() == -1 for listener in listeners)


def test_tls_ready_and_delayed_responses_use_the_same_owned_listener(
    tls_server: Any,
) -> None:
    namespace, info = tls_server
    context = namespace["ssl"].create_default_context()
    context.check_hostname = False
    context.verify_mode = namespace["ssl"].CERT_NONE
    for path, expected in (
        ("/health/owned-tls-test", b"owned-tls-test"),
        ("/payload.bin", namespace["PAYLOAD"]),
        ("/delay/0.01", namespace["PAYLOAD"]),
    ):
        with urlopen(
            f"https://127.0.0.1:{info['tls_port']}{path}", context=context, timeout=2
        ) as response:
            assert response.read() == expected


def test_normal_certificate_validation_rejects_disposable_self_signed_leaf(
    tls_server: Any,
) -> None:
    namespace, info = tls_server
    with pytest.raises(URLError) as raised:
        with urlopen(
            f"https://127.0.0.1:{info['tls_port']}/payload.bin",
            context=namespace["ssl"].create_default_context(),
            timeout=2,
        ) as response:
            response.read()
    assert isinstance(raised.value.reason, namespace["ssl"].SSLCertVerificationError)
    assert raised.value.reason.verify_code == 18


@pytest.mark.parametrize(
    "change,body",
    [
        ({}, None),
        ({"validate_certs": True}, None),
        ({"use_proxy": True}, None),
        ({"url_username": "caller"}, None),
        ({"client_cert": "caller.pem"}, None),
        ({"url_method": "HEAD"}, None),
        ({"url_method": "POST"}, None),
        ({}, b""),
        ({}, b"upload"),
    ],
)
def test_positive_tls_requests_keep_the_existing_native_response_route(
    http: Any,
    monkeypatch: pytest.MonkeyPatch,
    change: dict[str, Any],
    body: bytes | None,
) -> None:
    helper, options, _library = http
    options = dict(
        options, use_proxy=False, url_timeout=1, validate_certs=False, url_method="GET"
    )
    options.update(change)
    native = Mock(
        return_value=SimpleNamespace(header=Mock(return_value=None), status=200)
    )
    monkeypatch.setattr(helper, "_HttpResponse", native)
    assert (
        helper.open_resource("https://owned/", options, [], body=body)
        is native.return_value
    )
    native.assert_called_once()
    assert native.call_args.kwargs.get("body") == body


def test_tls_matrix_contains_only_bounded_three_module_readiness_and_validation() -> (
    None
):
    document = yaml.safe_load(
        (ROOT / "tests/integration/vars/http_zero_tls.yml").read_text()
    )
    cases = document["http_zero_cases"]
    assert document["get_url_tls"] is True
    assert len(cases) == 9
    assert {(case["module"], case["tls_boundary"]) for case in cases} == {
        (module, boundary)
        for module in ("uri", "get_url", "package")
        for boundary in ("ready", "response", "validation")
    }
    for case in cases:
        assert case.get("check", False) is (case["module"] == "package")
        params = case["params"]
        assert params["validate_certs"] is (case["tls_boundary"] == "validation")
        resource = params["path" if case["module"] == "package" else "url"]
        assert resource == "{{ get_url_setup_data.https }}" + case["path"]
        assert case["path"] == (
            "/delay/0.75" if case["tls_boundary"] == "response" else "/payload.bin"
        )


def _cleanup_failure_play(tmp_path: Path, failure: str) -> dict[str, Any]:
    maintained = yaml.safe_load(
        (ROOT / "tests/integration/http_zero_timeout.yml").read_text()
    )[0]
    observation = copy.deepcopy(
        next(task for task in maintained["tasks"] if "block" in task)
    )
    # Execute the actual controller allocation/generation tasks. Only their
    # checkout-local directory is rebound into this test's disposable directory.
    setup = observation["block"][:2]
    setup[0]["ansible.builtin.tempfile"]["path"] = str(tmp_path)
    setup.insert(
        1,
        {
            "when": "get_url_tls | bool",
            "ansible.builtin.copy": {
                "content": "owned controller setup witness",
                "dest": "{{ get_url_tls_workspace.path }}/setup-witness",
            },
        },
    )
    setup.append(
        {
            "when": "get_url_tls | bool",
            "ansible.builtin.assert": {
                "that": "lookup('ansible.builtin.fileglob', "
                "get_url_tls_workspace.path + '/server-*.pem', "
                "wantlist=true) | length == 2"
            },
        }
    )
    observation["block"] = setup
    recovery = observation["always"][0]
    # No Windows call is made. Supply explicit target-recovery outcomes, then
    # run the maintained raw capture, protected-state gate and TLS finally task
    # unchanged. Target-only recovery/deletion cannot run on this local host.
    recovery["block"] = [
        task
        for task in recovery["block"]
        if task["name"]
        in (
            "Retain raw recovery before asserting its outcome",
            "Require literal protected files and exact server exit",
        )
    ]
    assert len(recovery["block"]) == 2
    assert recovery["always"][0]["name"] == "Remove only owned controller TLS material"
    outcome = (
        {"skipped": True}
        if failure == "generation"
        else {
            "rc": 0 if failure == "protected" else 7,
            "stdout": json.dumps({"restored": False, "server_stopped": True}),
        }
    )
    return {
        "hosts": "localhost",
        "connection": "local",
        "gather_facts": False,
        "environment": (
            {"OPENSSL_CONF": str(tmp_path / "missing-openssl.cnf")}
            if failure == "generation"
            else {}
        ),
        "vars": {
            "get_url_tls": failure != "disabled",
            "get_url_workspace": {"path": str(tmp_path / "retained-target-journal")},
            "http_zero_recovery": outcome,
            "http_zero_results": [],
            "http_zero_staging_before": {"rc": 0, "stdout": "{}"},
            "http_zero_capture": {"path": str(tmp_path / "retained-failure.json")},
        },
        "tasks": [
            {
                "block": [observation],
                "rescue": [{"ansible.builtin.set_fact": {"failure_observed": True}}],
            },
            {"ansible.builtin.assert": {"that": "failure_observed | default(false)"}},
        ],
    }


@pytest.mark.parametrize("failure", ["generation", "recovery", "protected", "disabled"])
def test_tls_controller_cleanup_runs_after_setup_and_target_gate_failures(
    tmp_path: Path, failure: str
) -> None:
    journal = tmp_path / "retained-target-journal"
    journal.mkdir()
    (journal / "ownership.json").write_text("retain for bounded target recovery")
    playbook = tmp_path / "controller-cleanup.yml"
    playbook.write_text(yaml.safe_dump([_cleanup_failure_play(tmp_path, failure)]))
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "ansible.cli.playbook",
            "-i",
            "localhost,",
            str(playbook),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    # pylint: enable=duplicate-code
    capture = json.loads((tmp_path / "retained-failure.json").read_text())
    assert capture["workspace"]["path"] == str(journal)
    assert (
        journal / "ownership.json"
    ).read_text() == "retain for bounded target recovery"
    if failure == "disabled":
        assert "tls_workspace" not in capture
        assert not list(tmp_path.glob("http-zero-tls-*"))
    else:
        assert not Path(capture["tls_workspace"]["path"]).exists()
    if failure == "generation":
        assert capture["recovery"] == {"skipped": True}
        assert "missing-openssl.cnf" in run.stdout
    else:
        assert capture["recovery"]["rc"] == (0 if failure == "protected" else 7)
