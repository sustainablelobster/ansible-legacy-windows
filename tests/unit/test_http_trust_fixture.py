"""Check the trust journal's ownership and failure recovery on the controller."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Substituted native APIs do not prove Windows TLS or certificate support.

import ast
import base64
import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest
import yaml  # type: ignore[import-untyped]

from tests.unit import test_get_url_fixture as download_fixtures

download_fixture = download_fixtures.get_url_fixture
listener_fixture = download_fixtures.get_url_server

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(name="trust")
def trust_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Execute the maintained journal with observable native substitutes.

    :param tmp_path: Disposable controller filesystem.
    :param monkeypatch: Scoped native/runtime substitutions.
    :returns: Fixture operations and independently mutable owned state.
    """
    workspace = tmp_path / "legacy-windows-http-trust-owned"
    workspace.mkdir()
    appdata = tmp_path / "profile"
    key_dir = appdata / "Microsoft/Crypto/RSA"
    key_dir.mkdir(parents=True)
    protected_key = key_dir / "existing-provider-key"
    protected_key.write_bytes(b"unrelated protected key")
    monkeypatch.setenv("APPDATA", str(appdata))
    registry = SimpleNamespace(HKEY_CURRENT_USER=1, HKEY_LOCAL_MACHINE=2, KEY_READ=1)

    def absent(*_arguments: Any) -> Any:
        error = OSError(2, "absent")
        error.winerror = 2  # type: ignore[attr-defined]
        raise error

    registry.OpenKey = absent
    monkeypatch.setitem(sys.modules, "winreg", registry)
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/http_trust_fixture.yml").read_text()
    )["http_trust_program"]
    tree = ast.parse(source)
    # Actual Windows execution, not this controller test, verifies the floor.
    tree.body = [
        node
        for node in tree.body
        if not isinstance(node, ast.Assert)
        or not any(
            isinstance(item, ast.Attribute) and item.attr == "version_info"
            for item in ast.walk(node)
        )
    ]
    state = SimpleNamespace(
        workspace=workspace,
        protected_key=protected_key,
        thumbprint=hashlib.sha1(b"owned certificate").hexdigest().upper(),
        certificates=[],
        crypt=Mock(),
    )
    state.crypt.CertOpenStore.return_value = 123
    state.crypt.CertEnumCertificatesInStore.return_value = None
    state.crypt.CertCloseStore.return_value = True
    kernel = Mock()

    def _long_path(path: str, buffer: Any, _size: int) -> int:
        if buffer is None:
            return len(path) + 1
        buffer.value = path
        return len(path)

    kernel.GetLongPathNameW.side_effect = _long_path
    monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(
        "ssl.enum_certificates", lambda _store: state.certificates, raising=False
    )
    monkeypatch.setattr(
        "ctypes.WinDLL",
        lambda name, *_args, **_kwargs: kernel if name == "kernel32" else state.crypt,
        raising=False,
    )
    monkeypatch.setattr("ctypes.get_last_error", lambda: 0, raising=False)

    def run(operation: str, thumbprint: str | None = None) -> dict[str, Any]:
        """Run the native journal dispatcher with retained controller state.

        :param operation: Setup, observation or cleanup operation.
        :param thumbprint: Optional substitute certificate identity.
        :returns: The fixture's independently produced result.
        """
        with monkeypatch.context() as scoped:
            scoped.setattr(
                sys,
                "argv",
                ["trust", str(workspace), operation, thumbprint or state.thumbprint],
            )
            namespace: dict[str, Any] = {}
            # This runs the maintained ownership and snapshot code, not a copy.
            # pylint: disable-next=exec-used
            exec(compile(tree, "<trust fixture>", "exec"), namespace)
            result = namespace["result"]
            assert isinstance(result, dict)
            return result

    state.run = run
    return state


def test_owned_trust_is_journaled_before_mutation_and_native_cleanup_is_verified(
    trust: Any,
) -> None:
    assert trust.run("setup") == {"journaled": True, "initially_absent": True}
    record = json.loads((trust.workspace / "trust.json").read_text())
    assert record["before"]["user_key_files"] == {
        str(trust.protected_key): hashlib.sha256(b"unrelated protected key").hexdigest()
    }
    assert trust.run("cleanup")["restored"]
    trust.crypt.CertOpenStore.assert_called_once_with(10, 0, None, 0x24000, "Root")
    trust.crypt.CertDeleteCertificateFromStore.assert_not_called()
    trust.crypt.CertCloseStore.assert_called_once_with(123, 0)


def test_initially_present_certificate_is_not_owned_or_changed(trust: Any) -> None:
    trust.certificates.append((b"owned certificate", "x509_asn", True))
    with pytest.raises(AssertionError):
        trust.run("setup")
    assert not list(trust.workspace.iterdir())
    trust.crypt.CertOpenStore.assert_not_called()


def test_existing_private_key_change_cannot_be_reported_as_restored(trust: Any) -> None:
    trust.run("setup")
    trust.protected_key.write_bytes(b"changed unrelated key")
    with pytest.raises(AssertionError, match="not restored"):
        trust.run("cleanup")
    assert trust.protected_key.read_bytes() == b"changed unrelated key"
    assert (trust.workspace / "trust.json").exists()


def test_personal_certificate_store_change_cannot_be_reported_as_restored(
    trust: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    trust.run("setup")
    registry = sys.modules["winreg"]
    original = registry.OpenKey
    created = MagicMock()
    monkeypatch.setattr(
        registry,
        "OpenKey",
        lambda hive, path, *args: (
            created if path.endswith("\\My") else original(hive, path, *args)
        ),
    )
    monkeypatch.setattr(registry, "QueryInfoKey", lambda _key: (0, 0, 0), raising=False)
    with pytest.raises(AssertionError, match="not restored"):
        trust.run("cleanup")
    assert (trust.workspace / "trust.json").exists()


def test_another_certificate_identity_cannot_use_the_recovery_journal(
    trust: Any,
) -> None:
    trust.run("setup")
    with pytest.raises(AssertionError):
        trust.run("cleanup", "1" * 40)
    trust.crypt.CertOpenStore.assert_not_called()


def test_client_credentials_and_legacy_protocol_are_protected_owned_inputs(
    fixture: Any,
) -> None:
    materials = {
        kind: base64.b64encode(content).decode("ascii")
        for kind, content in (
            ("cert", b"owned server certificate"),
            ("key", b"owned server key"),
            ("client_ca", b"owned CA PEM"),
            ("client_pfx", b"owned client PFX"),
            ("trust_ca", b"owned trust CA PEM"),
        )
    }
    fixture.run("setup", dict(materials, legacy_tls=True))
    record = json.loads(fixture.journal.read_text())
    assert set(record["tls_materials"]) == {
        "server-cert.pem",
        "server-key.pem",
        "client-ca.pem",
        "client.pfx",
        "trust-ca.pem",
        "legacy-tls.flag",
    }
    fixture.run("prepare", {})
    assert fixture.run("cleanup")["server_stopped"]
    assert fixture.run("finalize")["finalized"]


def test_legacy_client_listener_uses_owned_ca_without_changing_default_protocol(
    server: Any,
) -> None:
    for name in (
        "server-cert.pem",
        "server-key.pem",
        "client-ca.pem",
        "legacy-tls.flag",
    ):
        (server.root / name).write_bytes(b"owned fixture material")
    server.run()
    server.ssl.SSLContext.assert_called_once_with(server.ssl.PROTOCOL_TLSv1)
    server.context.load_verify_locations.assert_called_once_with(
        str(server.root / "client-ca.pem")
    )
    assert server.context.verify_mode == server.ssl.CERT_OPTIONAL
