"""Verify requested legacy DNS preparation and truthful partial-change results."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# These tests replace native service reads and installer process boundaries.
# pylint: disable=protected-access

import importlib
import subprocess
from contextlib import contextmanager
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT


@pytest.fixture(name="native")
def native_fixture(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the target helper without contacting Windows or changing services.

    :param monkeypatch: Scoped target helper import paths.
    :returns: The native promotion implementation.
    :rtype: ModuleType
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    return importlib.import_module("legacy_ad_domain_native")


@pytest.fixture(name="installer")
def installer_fixture(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> SimpleNamespace:
    """Replace only native installer inputs, process and service discovery.

    :param native: Real target-side promotion helper.
    :param monkeypatch: Scoped Windows boundary replacements.
    :returns: Mutable installer observations and failure-injection boundaries.
    :rtype: SimpleNamespace
    """
    engine = native.PromotionEngine.__new__(native.PromotionEngine)
    engine.path = "/native/System32/dcpromo.exe"
    installed = Mock(side_effect=[False, True])
    monkeypatch.setattr(native, "_dns_installed", installed)
    monkeypatch.setenv("SystemRoot", "/native")
    exists = Mock(return_value=True)
    monkeypatch.setattr(native.os.path, "isfile", exists)
    process = MagicMock()
    process.__enter__.return_value = process
    process.communicate.return_value = (b"Native DNS setup diagnostic", None)
    process.returncode = 0
    start = Mock(return_value=process)
    monkeypatch.setattr(native.subprocess, "Popen", start)
    contents_seen: list[bytes] = []
    cleanup = Mock()

    @contextmanager
    def _input(contents: bytes) -> Any:
        contents_seen.append(contents)
        try:
            yield "restricted-dns-input.ini"
        finally:
            cleanup()

    monkeypatch.setattr(native, "_private_input", _input)
    return SimpleNamespace(
        engine=engine,
        installed=installed,
        exists=exists,
        process=process,
        start=start,
        contents=contents_seen,
        cleanup=cleanup,
        result={"changed": False, "reboot_required": False},
    )


def test_existing_dns_service_is_not_reinstalled(installer: SimpleNamespace) -> None:
    installer.installed.side_effect = [True]
    installer.engine.ensure_dns_installed(installer.result)
    assert installer.result == {"changed": False, "reboot_required": False}
    installer.start.assert_not_called()
    installer.exists.assert_not_called()
    assert installer.contents == []
    installer.cleanup.assert_not_called()


def test_dns_installation_is_quiet_nonrebooting_and_does_not_reconfigure_ip(
    installer: SimpleNamespace,
) -> None:
    installer.engine.ensure_dns_installed(installer.result)
    assert installer.result == {"changed": True, "reboot_required": False}
    installer.start.assert_called_once_with(
        [
            "/native/System32/sysocmgr.exe",
            "/i:/native/inf/sysoc.inf",
            "/u:restricted-dns-input.ini",
            "/q",
            "/r",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert installer.contents == [
        b"[Components]\r\nNetOC=On\r\n[NetOptionalComponents]\r\nDNS=1\r\n"
    ]
    assert installer.installed.call_count == 2
    installer.cleanup.assert_called_once()


@pytest.mark.parametrize("code,installed", [(0, False), (5, False), (5, True)])
def test_failed_dns_setup_reports_any_verified_component_change(
    installer: SimpleNamespace, code: int, installed: bool
) -> None:
    installer.process.returncode = code
    installer.installed.side_effect = [False, installed]
    with pytest.raises(ValueError, match="Failed to install the requested DNS service"):
        installer.engine.ensure_dns_installed(installer.result)
    assert installer.result == {"changed": installed, "reboot_required": False}
    installer.cleanup.assert_called_once()


def test_installer_start_failure_cleans_input_and_does_not_claim_installation(
    installer: SimpleNamespace,
) -> None:
    installer.start.side_effect = OSError("Native installer could not start")
    with pytest.raises(OSError, match="could not start"):
        installer.engine.ensure_dns_installed(installer.result)
    assert installer.result == {"changed": False, "reboot_required": False}
    installer.installed.assert_called_once()
    installer.cleanup.assert_called_once()


def test_input_cleanup_failure_retains_completed_dns_installation(
    installer: SimpleNamespace,
) -> None:
    installer.cleanup.side_effect = OSError("Owned input cleanup failed")
    with pytest.raises(OSError, match="cleanup failed"):
        installer.engine.ensure_dns_installed(installer.result)
    assert installer.result == {"changed": True, "reboot_required": False}


@pytest.mark.parametrize("missing", ["sysocmgr.exe", "sysoc.inf"])
def test_missing_native_installer_fails_before_creating_input(
    installer: SimpleNamespace, missing: str
) -> None:
    installer.exists.side_effect = lambda path: not path.endswith(missing)
    with pytest.raises(OSError, match="does not provide"):
        installer.engine.ensure_dns_installed(installer.result)
    assert installer.result == {"changed": False, "reboot_required": False}
    installer.start.assert_not_called()
    assert installer.contents == []


@pytest.mark.parametrize(
    "rows,expected",
    [([], False), ([{"Name": "DNS"}], True), ([{}], None), ([{}, {}], None)],
)
def test_dns_presence_comes_from_one_native_service_record(
    native: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    rows: list[dict[str, str]],
    expected: bool | None,
) -> None:
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.query.return_value = rows
    monkeypatch.setattr(native, "WmiConnection", Mock(return_value=connection))
    if expected is None:
        with pytest.raises(OSError, match="no unique DNS service"):
            native._dns_installed()
    else:
        assert native._dns_installed() is expected
    connection.query.assert_called_once_with(
        "SELECT Name FROM Win32_Service WHERE Name='DNS'", ["Name"]
    )
    connection.__exit__.assert_called_once()


@pytest.mark.parametrize(
    "settings,check,prepare",
    [
        ({"AutoConfigDNS": "Yes"}, False, True),
        ({"AutoConfigDNS": "No"}, False, False),
        ({"InstallDNS": "Yes"}, False, False),
        ({}, False, False),
        ({"AutoConfigDNS": "Yes"}, True, False),
    ],
)
def test_dns_preparation_is_only_for_requested_legacy_apply(
    native: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    settings: dict[str, str],
    check: bool,
    prepare: bool,
) -> None:
    workflow = importlib.import_module("legacy_ad_domain")
    engine = Mock()
    engine.run.return_value = (2, "Native promotion completed")
    netlogon = Mock()
    monkeypatch.setattr(native, "start_netlogon", netlogon)
    result = {"changed": False, "reboot_required": False}
    workflow._run_operation(engine, settings, {"check_mode": check}, result)
    engine.validate.assert_called_once_with(settings)
    assert engine.ensure_dns_installed.call_count == int(prepare)
    assert engine.run.call_count == int(not check)
    assert netlogon.call_count == int(not check)
    assert result == {"changed": True, "reboot_required": True}


@pytest.mark.parametrize(
    "failure",
    ["validation", "installer", "installer_result", "promotion", "promotion_start"],
)
def test_preparation_and_promotion_failures_keep_truthful_partial_change(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    workflow = importlib.import_module("legacy_ad_domain")
    engine = Mock()
    engine.run.return_value = (65, "Native promotion failed")
    result = {"changed": False, "reboot_required": False}
    netlogon = Mock()
    monkeypatch.setattr(native, "start_netlogon", netlogon)

    def _prepare(current: dict[str, Any]) -> None:
        current["changed"] = True
        if failure == "installer":
            raise OSError("Native installer or cleanup failed after installation")
        if failure == "installer_result":
            raise ValueError("Native installer returned an error after installation")

    engine.ensure_dns_installed.side_effect = _prepare
    if failure == "validation":
        engine.validate.side_effect = ValueError("Invalid native answer")
    if failure == "promotion_start":
        engine.run.side_effect = OSError("Native promotion could not start")
    with pytest.raises((OSError, ValueError)):
        workflow._run_operation(
            engine, {"AutoConfigDNS": "Yes"}, {"check_mode": False}, result
        )
    assert result == {
        "changed": failure != "validation",
        "reboot_required": False,
    }
    assert engine.ensure_dns_installed.call_count == int(failure != "validation")
    assert engine.run.call_count == int(failure in ("promotion", "promotion_start"))
    netlogon.assert_not_called()
