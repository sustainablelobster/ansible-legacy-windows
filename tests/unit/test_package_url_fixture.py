"""Verify that the owned HTTP fixture stops only its exact process identity."""

# SPDX-License-Identifier: GPL-3.0-or-later
# The maintained fixture's private cleanup functions are the fault boundaries.
# pylint: disable=protected-access

import io
import json
from email.message import Message
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="fixture")
def package_url_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Replace actual Windows process and MSI observations without lab contact.

    :param tmp_path: Isolated owned journal and script paths.
    :param monkeypatch: Scoped fixture imports and process boundaries.
    :returns: Concrete maintained fixture, pristine record and native API spies.
    """
    record = {
        "url": {
            "pid": 17,
            "creation": 12345,
            "token": "owned",
            "temporary_directories": [],
            "script": {"bytes": b"server"},
        }
    }
    base = ModuleType("package_msp_fixture")
    journal = tmp_path / "journal.json"
    base.JOURNAL = str(journal)  # type: ignore[attr-defined]
    journal.write_text("{}", encoding="utf-8")
    base._read = Mock(return_value=record)  # type: ignore[attr-defined]
    base._cleanup = Mock(return_value={"restored": True})  # type: ignore[attr-defined]
    base._file_state = Mock(return_value={"bytes": b"server"})  # type: ignore[attr-defined]
    monkeypatch.setitem(__import__("sys").modules, "package_msp_fixture", base)
    monkeypatch.setattr(
        __import__("sys"), "argv", ["fixture", str(tmp_path), "cleanup"]
    )
    module = load_module(
        ROOT / "tests/integration/fixtures/package_url_fixture.py", "fixture"
    )
    api = SimpleNamespace(
        OpenProcess=Mock(return_value=42),
        WaitForSingleObject=Mock(side_effect=[0x102, 0]),
        TerminateProcess=Mock(return_value=True),
        CloseHandle=Mock(return_value=True),
    )
    monkeypatch.setattr(module, "_api", lambda: api)
    monkeypatch.setattr(module, "_creation", lambda _api, _handle: 12345)
    monkeypatch.setattr(module, "_temporary_directories", lambda: [])
    return SimpleNamespace(module=module, api=api, base=base, record=record)


def test_owned_live_process_is_stopped_and_closed_before_msi_recovery(
    fixture: Any,
) -> None:
    assert fixture.module._cleanup() == {
        "restored": True,
        "process_stopped": True,
        "temporary_directories_restored": True,
    }
    fixture.api.TerminateProcess.assert_called_once_with(42, 0)
    fixture.api.CloseHandle.assert_called_once_with(42)
    fixture.base._cleanup.assert_called_once()


def test_reused_pid_is_never_terminated_or_treated_as_recovered(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fixture.module, "_creation", lambda _api, _handle: 99999)
    with pytest.raises(AssertionError):
        fixture.module._cleanup()
    fixture.api.TerminateProcess.assert_not_called()
    fixture.api.CloseHandle.assert_called_once_with(42)
    fixture.base._cleanup.assert_not_called()


def test_unknown_download_directory_prevents_recovery_claim(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fixture.module, "_temporary_directories", lambda: ["foreign"])
    with pytest.raises(AssertionError):
        fixture.module._cleanup()
    fixture.base._cleanup.assert_not_called()


def test_fixture_script_mutation_prevents_recovery_claim(fixture: Any) -> None:
    fixture.base._file_state.return_value = {"bytes": b"modified server"}
    with pytest.raises(AssertionError):
        fixture.module._cleanup()
    fixture.base._cleanup.assert_not_called()


@pytest.mark.parametrize("source", ["native", "original"])
def test_install_source_qualification_requires_actual_owned_creation_record(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, source: str
) -> None:
    root = r"C:\Temp\legacy-windows-package-url-test-owned.abc"
    monkeypatch.setattr(fixture.module, "ROOT", root)
    monkeypatch.setattr(fixture.module.tempfile, "gettempdir", lambda: r"C:\Temp")
    monkeypatch.setattr(fixture.module.os.path, "exists", lambda _path: False)
    directory = (
        r"C:\Temp\legacy-windows-package-url-abcdef_1"
        if source == "native"
        else root + r"\ansible-moduletmp-12345-17-999"
    )
    value = ("InstallSource", directory + "\\", 1)
    snapshot: dict[str, Any] = {
        "uninstall_keys": {
            "owned": [value, ("DisplayName", "exact", 1)],
            "absent": None,
        }
    }
    proof = {"path": directory, "creation": 1.0, "observed": 2.0, "attributes": 0x10}
    qualified = fixture.module._portable_uninstall_keys(snapshot, [proof])
    assert qualified == {
        "owned": [
            ("InstallSource", "<owned-downloaded-package-directory>\\", 1),
            ("DisplayName", "exact", 1),
        ],
        "absent": None,
    }
    assert snapshot["uninstall_keys"]["owned"][0] == value
    with pytest.raises(AssertionError):
        fixture.module._portable_uninstall_keys(snapshot, [])


def test_install_source_of_regular_fixture_base_remains_literal(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fixture.module, "ROOT", r"C:\Temp\owned")
    snapshot = {
        "uninstall_keys": {"owned": [("InstallSource", "C:\\Temp\\owned\\", 1)]}
    }
    assert (
        fixture.module._portable_uninstall_keys(snapshot, [])
        == snapshot["uninstall_keys"]
    )


@pytest.mark.parametrize(
    "fault", ["foreign_parent", "reparse", "still_present", "wrong_type", "separator"]
)
def test_install_source_qualification_rejects_unowned_or_unverified_metadata(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    monkeypatch.setattr(fixture.module, "ROOT", r"C:\Temp\owned")
    monkeypatch.setattr(fixture.module.tempfile, "gettempdir", lambda: r"C:\Temp")
    directory = r"C:\Temp\legacy-windows-package-url-abcdef_1"
    if fault == "foreign_parent":
        directory = r"C:\Foreign\legacy-windows-package-url-abcdef_1"
    value = [
        "InstallSource",
        directory + ("\\" if fault != "separator" else ""),
        2 if fault == "wrong_type" else 1,
    ]
    monkeypatch.setattr(
        fixture.module.os.path, "exists", lambda _path: fault == "still_present"
    )
    proof = {
        "path": directory,
        "creation": 1.0,
        "observed": 2.0,
        "attributes": 0x410 if fault == "reparse" else 0x10,
    }
    with pytest.raises(AssertionError):
        fixture.module._portable_uninstall_keys(
            {"uninstall_keys": {"owned": [value]}}, [proof]
        )


@pytest.mark.parametrize(
    "scenario",
    [
        ("/patch.msi", None, 200, b"owned package", None),
        ("/redirect.msi", None, 302, b"", None),
        ("/missing.msi", None, 404, b"", None),
        ("/auth.msi", None, 401, b"", None),
        ("/auth.msi", "Basic Zml4dHVyZTpzZWNyZXQ=", 200, b"owned package", None),
        (
            "/disposition.bin",
            None,
            200,
            b"owned package",
            'attachment; filename="downloaded installer.msi"',
        ),
    ],
)
def test_server_records_wire_headers_and_serves_only_owned_package(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario: tuple[str, str | None, int, bytes, str | None],
) -> None:
    route, authorization, status, body, disposition = scenario
    (tmp_path / "patch.msi").write_bytes(b"owned package")
    monkeypatch.setattr(__import__("sys"), "argv", ["server", str(tmp_path), "owned"])
    server = load_module(
        ROOT / "tests/integration/fixtures/package_url_server.py", "server"
    )
    handler = object.__new__(server.Handler)
    handler.path, handler.command = route, "GET"
    handler.headers = Message()
    if authorization:
        handler.headers["Authorization"] = authorization
    handler.wfile = io.BytesIO()
    handler.send_response, handler.send_header, handler.end_headers = (
        Mock(),
        Mock(),
        Mock(),
    )
    handler.do_GET()
    handler.send_response.assert_called_once_with(status)
    assert handler.wfile.getvalue() == body
    if disposition:
        handler.send_header.assert_any_call("Content-Disposition", disposition)
    observed = json.loads((tmp_path / "requests.jsonl").read_text())
    assert observed == {
        "method": "GET",
        "path": route,
        "headers": dict(handler.headers),
    }
