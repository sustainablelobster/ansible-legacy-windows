"""Verify native package service guards without contacting Windows."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Tests exercise the private native boundary through public guard decisions.
# pylint: disable=protected-access

import ast
import ctypes
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import ROOT, load_payload, native_error

# Pytest discovers this imported fixture; reuse the complete public payload runner.
from tests.unit.test_win_package import package_runner  # pylint: disable=unused-import


@pytest.fixture(name="guard")
def service_guard(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Supply observable SCM access and real wildcard matching.

    :param monkeypatch: Scoped native and culture substitutions.
    :returns: Package helper and its SCM boundaries.
    """
    package = load_payload("win_package", monkeypatch).package
    library = Mock()
    library.OpenSCManagerW.return_value = 101
    library.OpenServiceW.return_value = 202
    last_error = Mock(return_value=1060)
    monkeypatch.setattr(ctypes, "WinDLL", Mock(return_value=library), raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", last_error, raising=False)
    monkeypatch.setattr(ctypes, "WinError", native_error, raising=False)
    names = Mock(return_value=["VendorAlpha", "VendorBeta", "Vendor[Literal]"])
    monkeypatch.setattr(package.services, "enumerate_names", names)
    lookup = Mock(return_value=None)
    monkeypatch.setattr(package.services, "_lookup_service_name", lookup)
    matcher = package.services.matches_service_name
    monkeypatch.setitem(matcher.__globals__, "_current_lower", lambda: str.lower)
    return SimpleNamespace(
        package=package,
        library=library,
        names=names,
        last_error=last_error,
        lookup=lookup,
    )


@pytest.mark.parametrize(
    "pattern,expected",
    [
        ("Vendor*", True),
        ("vendor?l*", True),
        ("Vendor[AB]*", True),
        ("Vendor[A-C]*", True),
        ("Vendor`[Literal`]*", True),
        ("Vendor`*?", False),
        ("Vendor[Z]*", False),
        ("Vendor?", False),
        ("VendorDisplay*", False),
        ("Tcp*", False),
    ],
)
def test_patterns_match_only_enumerated_service_keys(
    guard: Any, pattern: str, expected: bool
) -> None:
    assert guard.package._service_exists(pattern) is expected
    guard.names.assert_called_once_with()
    guard.library.OpenServiceW.assert_not_called()


@pytest.mark.parametrize("pattern", ["Vendor[", "[z-a]"])
@pytest.mark.parametrize("names", [[], ["VendorAlpha"]])
def test_invalid_patterns_fail_even_without_visible_services(
    guard: Any, pattern: str, names: list[str]
) -> None:
    guard.names.return_value = names
    with pytest.raises(ValueError):
        guard.package._service_exists(pattern)
    guard.library.OpenServiceW.assert_not_called()


def test_multiple_matches_require_only_one_existing_service(guard: Any) -> None:
    assert guard.package._service_exists("Vendor*") is True
    guard.names.assert_called_once_with()


@pytest.mark.parametrize(
    "name",
    [
        "VendorAlpha",
        "vendoralpha",
        "Tcpip",
        "Vendor`[Literal`]",
        "Vendor`*",
        "Vendor]",
        "Vendor``",
    ],
)
def test_literal_service_and_driver_names_keep_native_lookup(
    guard: Any, name: str
) -> None:
    assert guard.package._service_exists(name) is True
    guard.library.OpenSCManagerW.assert_called_once_with(None, None, 1)
    guard.library.OpenServiceW.assert_called_once_with(101, name, 4)
    assert guard.library.CloseServiceHandle.call_args_list == [call(202), call(101)]
    guard.names.assert_not_called()


def test_only_a_missing_literal_service_counts_as_absence(guard: Any) -> None:
    guard.library.OpenServiceW.return_value = 0
    assert guard.package._service_exists("AbsentVendor") is False
    guard.library.CloseServiceHandle.assert_called_once_with(101)


def test_escape_only_argument_does_not_match_unescaped_enumerated_name(
    guard: Any,
) -> None:
    guard.library.OpenServiceW.return_value = 0
    assert guard.package._service_exists("Vendor`[Literal`]") is False
    guard.library.OpenServiceW.assert_called_once_with(101, "Vendor`[Literal`]", 4)
    guard.lookup.assert_called_once_with(
        guard.library.GetServiceKeyNameW, 101, "Vendor`[Literal`]"
    )
    guard.names.assert_not_called()
    guard.library.CloseServiceHandle.assert_called_once_with(101)


def test_exact_display_name_resolves_its_canonical_key(guard: Any) -> None:
    guard.library.OpenServiceW.side_effect = [0, 202]
    guard.lookup.return_value = "VendorAlpha"
    assert guard.package._service_exists("Vendor Alpha Display") is True
    assert guard.library.OpenServiceW.call_args_list == [
        call(101, "Vendor Alpha Display", 4),
        call(101, "VendorAlpha", 4),
    ]
    guard.names.assert_not_called()
    assert guard.library.CloseServiceHandle.call_args_list == [call(202), call(101)]


def test_display_lookup_access_failure_remains_an_error(guard: Any) -> None:
    guard.library.OpenServiceW.return_value = 0
    guard.lookup.side_effect = native_error(5)
    with pytest.raises(OSError) as caught:
        guard.package._service_exists("Vendor Alpha Display")
    assert caught.value.errno == 5
    guard.library.CloseServiceHandle.assert_called_once_with(101)


@pytest.mark.parametrize("code", [5, 6, 123])
def test_literal_lookup_errors_are_not_mistaken_for_absence(
    guard: Any, code: int
) -> None:
    guard.library.OpenServiceW.return_value = 0
    guard.last_error.return_value = code
    with pytest.raises(OSError) as caught:
        guard.package._service_exists("VendorAlpha")
    assert caught.value.errno == code
    guard.library.CloseServiceHandle.assert_called_once_with(101)


def test_manager_access_failure_does_not_open_a_service(guard: Any) -> None:
    guard.library.OpenSCManagerW.return_value = 0
    guard.last_error.return_value = 5
    with pytest.raises(OSError) as caught:
        guard.package._service_exists("VendorAlpha")
    assert caught.value.errno == 5
    guard.library.OpenServiceW.assert_not_called()
    guard.library.CloseServiceHandle.assert_not_called()


def test_pattern_enumeration_failure_propagates(guard: Any) -> None:
    guard.names.side_effect = native_error(5)
    with pytest.raises(OSError) as caught:
        guard.package._service_exists("Vendor*")
    assert caught.value.errno == 5
    guard.library.OpenServiceW.assert_not_called()


def test_package_action_stages_service_guard_imports() -> None:
    action = ast.parse(
        (ROOT / "legacy_windows/plugins/action/win_package.py").read_text()
    )
    helpers = next(
        ast.literal_eval(node.value)
        for node in ast.walk(action)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "EXTRA_MODULE_UTILS"
            for target in node.targets
        )
    )
    for name in (
        "legacy_windows_service_info.py",
        "legacy_windows_service_config.py",
        "legacy_windows_account.py",
        "legacy_windows_find_match.py",
        "legacy_windows_regex.py",
    ):
        assert name in helpers
        assert (ROOT / "legacy_windows/plugins/module_utils" / name).is_file()


@pytest.mark.parametrize("initial", [(-1, False), (-1, True), (5, False), (5, True)])
@pytest.mark.parametrize("pattern", ["Vendor*", "vendor?l*", "Vendor[A-B]*"])
def test_matching_service_pattern_is_idempotent_without_installer_execution(
    runner: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    initial: tuple[int, bool],
    pattern: str,
) -> None:
    source = tmp_path / "package.msi"
    source.write_bytes(b"package")
    installed, check_mode = initial
    runner.installer.product_state.return_value = installed
    services = runner.module.package.services
    monkeypatch.setattr(
        services, "enumerate_names", lambda: ["VendorAlpha", "VendorBeta"]
    )
    monkeypatch.setitem(
        services.matches_service_name.__globals__, "_current_lower", lambda: str.lower
    )
    request = {
        "path": str(source),
        "creates_service": pattern,
        "creates_path": str(tmp_path / "missing"),
        "_ansible_check_mode": check_mode,
    }
    expected = (0, {"changed": False, "reboot_required": False, "rc": 0})
    assert runner.run(request) == expected
    assert runner.run(request) == expected
    runner.process.assert_not_called()
    runner.read.assert_not_called()


@pytest.mark.parametrize("check_mode", [False, True])
def test_nonmatching_service_guard_replaces_installed_product_status(
    runner: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, check_mode: bool
) -> None:
    source = tmp_path / "package.msi"
    source.write_bytes(b"package")
    runner.installer.product_state.return_value = 5
    services = runner.module.package.services
    monkeypatch.setattr(services, "enumerate_names", lambda: ["VendorAlpha"])
    monkeypatch.setitem(
        services.matches_service_name.__globals__, "_current_lower", lambda: str.lower
    )
    status, result = runner.run(
        {
            "path": str(source),
            "creates_service": "AbsentVendor*",
            "_ansible_check_mode": check_mode,
        }
    )
    assert status == 0 and result["changed"] is True
    assert runner.process.call_count == int(not check_mode)


@pytest.mark.parametrize("check_mode", [False, True])
def test_service_enumeration_error_fails_before_installation_including_preview(
    runner: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, check_mode: bool
) -> None:
    source = tmp_path / "package.msi"
    source.write_bytes(b"package")
    error = OSError(5, "SCM access denied")
    services = runner.module.package.services
    monkeypatch.setattr(services, "enumerate_names", Mock(side_effect=error))
    monkeypatch.setitem(
        services.matches_service_name.__globals__, "_current_lower", lambda: str.lower
    )
    assert runner.run(
        {
            "path": str(source),
            "creates_service": "Vendor*",
            "_ansible_check_mode": check_mode,
        }
    ) == (
        1,
        {
            "changed": False,
            "reboot_required": False,
            "failed": True,
            "msg": str(error),
        },
    )
    runner.process.assert_not_called()
    runner.read.assert_not_called()
