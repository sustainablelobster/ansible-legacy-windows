"""Test native-authentication fixture boundaries without claiming Windows proof."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Controller native stand-ins test rejection, token ownership and redaction only.

import ast
import base64
import ctypes
import json
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


@pytest.fixture(name="listener")
def auth_listener(tmp_path: Path) -> Any:
    """Load the maintained handler with observable native substitutes.

    :param tmp_path: Controller-only journal directory.
    :returns: Native calls and a fresh handler constructor.
    """
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/http_auth_fixture.yml").read_text()
    )["http_auth_server"]
    tree = ast.parse(source)
    definitions: list[ast.stmt] = [
        node
        for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.ClassDef, ast.FunctionDef))
    ]
    native = SimpleNamespace(
        AcceptSecurityContext=Mock(return_value=0x90312),
        QueryContextAttributesW=Mock(return_value=0),
        CompleteAuthToken=Mock(return_value=0),
        FreeContextBuffer=Mock(return_value=0),
        DeleteSecurityContext=Mock(return_value=0),
    )
    namespace: dict[str, Any] = {
        "dword": ctypes.c_uint32,
        "pointer": ctypes.c_void_p,
        "native": native,
        "root": str(tmp_path),
        "token": "owned-token",
        "body": b"payload",
        "lock": threading.Lock(),
    }
    # Execute the maintained boundary; no listener or native resource is opened.
    # pylint: disable-next=exec-used
    exec(
        compile(ast.Module(definitions, type_ignores=[]), "<auth fixture>", "exec"),
        namespace,
    )
    namespace["credential"] = namespace["Handle"]()
    namespace["expiry"] = ctypes.c_int64()

    def handler(authorization: str = "", proxy: bool = False) -> Any:
        """Construct a disconnected handler.

        :param authorization: Header value supplied to the handler.
        :param proxy: Select proxy rather than origin authentication.
        :returns: Fresh handler without a socket or native context.
        """
        result = object.__new__(namespace["Handler"])
        result.context = namespace["Handle"]()
        result.identity = None
        result.rounds = 0
        result.headers = {
            "Proxy-Authorization" if proxy else "Authorization": authorization
        }
        result.command, result.path = "GET", "/owned"
        result.respond = Mock()
        return result

    return SimpleNamespace(
        handler=handler, native=native, namespace=namespace, root=tmp_path
    )


def test_absent_credentials_challenge_without_native_accept(listener: Any) -> None:
    handler = listener.handler()
    assert not handler.authenticate(False)
    handler.respond.assert_called_once_with(401, challenge="Negotiate", proxy=False)
    listener.native.AcceptSecurityContext.assert_not_called()


def test_native_continuation_preserves_connection_context(listener: Any) -> None:
    incoming = b"native token"
    handler = listener.handler("Negotiate " + base64.b64encode(incoming).decode())

    def accept(*arguments: Any) -> int:
        """Capture input and supply a continuation.

        :param arguments: Native SSPI arguments.
        :returns: Native continuation status.
        """
        inputs = ctypes.cast(
            arguments[2], ctypes.POINTER(listener.namespace["Buffers"])
        ).contents
        assert (
            ctypes.string_at(inputs.buffers[0].data, inputs.buffers[0].size) == incoming
        )
        context = ctypes.cast(
            arguments[5], ctypes.POINTER(listener.namespace["Handle"])
        ).contents
        context.lower = 123
        output = ctypes.cast(
            arguments[6], ctypes.POINTER(listener.namespace["Buffers"])
        ).contents.buffers[0]
        ctypes.memmove(output.data, b"challenge", 9)
        output.size = 9
        return 0x90312

    listener.native.AcceptSecurityContext.side_effect = accept
    assert not handler.authenticate(False)
    assert handler.context.lower == 123 and handler.identity is None
    handler.respond.assert_called_once_with(
        401, challenge="Negotiate Y2hhbGxlbmdl", proxy=False
    )


def test_denied_native_authentication_never_records_an_identity(listener: Any) -> None:
    handler = listener.handler("Negotiate bmF0aXZl", proxy=True)
    listener.native.AcceptSecurityContext.return_value = 0x8009030C
    assert not handler.authenticate(True)
    assert handler.identity is None and handler.close_connection
    handler.respond.assert_called_once_with(407, proxy=True)
    listener.native.QueryContextAttributesW.assert_not_called()


def test_only_native_completed_context_supplies_actual_identity(listener: Any) -> None:
    handler = listener.handler("Negotiate bmF0aXZl")
    name = ctypes.create_unicode_buffer("HOST\\owned")

    def accept(*arguments: Any) -> int:
        """Complete without an outgoing token.

        :param arguments: Native SSPI arguments.
        :returns: Native success status.
        """
        output = ctypes.cast(
            arguments[6], ctypes.POINTER(listener.namespace["Buffers"])
        ).contents.buffers[0]
        output.size = 0
        return 0

    def names(_context: Any, attribute: int, result: Any) -> int:
        """Supply the authenticated native context name.

        :param attribute: Requested context attribute.
        :param result: Address receiving the allocated name.
        :returns: Native success status.
        """
        assert attribute == 1
        ctypes.cast(result, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.cast(
            name, ctypes.c_void_p
        )
        return 0

    listener.native.AcceptSecurityContext.side_effect = accept
    listener.native.QueryContextAttributesW.side_effect = names
    assert handler.authenticate(False)
    assert handler.identity == "HOST\\owned"
    listener.native.FreeContextBuffer.assert_called_once()


def test_request_journal_excludes_credential_tokens(listener: Any) -> None:
    handler = listener.handler("Negotiate private-native-token")
    # record is intentionally called independently of respond's test substitute.
    handler.record(401)
    capture = json.loads((listener.root / "requests.jsonl").read_text())
    assert capture["headers"]["Authorization"] == "Negotiate [redacted]"
    assert capture["identity"] is None


def test_pac_points_only_to_the_owned_loopback_endpoint(listener: Any) -> None:
    handler = listener.handler()
    handler.path = "/pac/owned-token"
    handler.server = SimpleNamespace(server_address=("127.0.0.1", 12345))
    handler.handle_request()
    handler.respond.assert_called_once_with(
        200,
        b'function FindProxyForURL(url, host) { return "PROXY 127.0.0.1:12345"; }',
    )


def test_auth_listener_replaces_anonymous_server_at_vars_file_precedence() -> None:
    document = yaml.safe_load(
        (ROOT / "tests/integration/vars/http_auth_fixture.yml").read_text()
    )
    assert document["get_url_server"] == "{{ http_auth_server }}"
    play = yaml.safe_load((ROOT / "tests/integration/win_http_auth.yml").read_text())[0]
    assert play["vars_files"].index("vars/http_auth_fixture.yml") > play[
        "vars_files"
    ].index("vars/get_url_fixture.yml")
    assert "get_url_server" not in play["vars"]
    assert "{{" not in document["http_auth_server"]
