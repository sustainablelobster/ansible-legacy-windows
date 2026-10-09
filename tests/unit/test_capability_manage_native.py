"""Exercise native capability selection, servicing ownership and batch cleanup."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native ABI substitutes fill output records and inspect their ownership.
# pylint: disable=protected-access

import ctypes
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock
from xml.etree import ElementTree

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="provider")
def native_provider(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Retain native parsing while replacing only Windows library boundaries.

    :param monkeypatch: Scoped native imports and runtime values.
    :returns: Helper, library, backing array and observable native calls.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    module = load_module(
        ROOT / "plugins/module_utils/legacy_windows_capability_manage.py",
        "manage_tested",
    )
    rows = (module.metadata._Capability * 3)(
        ("B~~~~1", 4), ("A~~~~1", 0), ("C~~~~1", 4)
    )

    def _open(_image: str, _windows: Any, _system: Any, output: Any) -> int:
        output._obj.value = 13
        return 0

    def _catalogue(_session: Any, output: Any, count: Any) -> int:
        output._obj.contents = rows[0]
        count._obj.value = 3
        return 0

    library = SimpleNamespace(
        **{
            name: Mock(return_value=0)
            for name in (
                "DismInitialize",
                "DismOpenSession",
                "DismCloseSession",
                "DismShutdown",
                "DismGetCapabilities",
                "DismDelete",
                "DismAddCapability",
                "DismRemoveCapability",
            )
        }
    )
    library.DismGetLastErrorMessage = Mock(return_value=1)
    library.DismOpenSession.side_effect = _open
    library.DismGetCapabilities.side_effect = _catalogue
    monkeypatch.setattr(module.metadata, "_library", lambda: library)
    monkeypatch.setattr(module, "_windows_version", lambda: (10, 0, 19045))
    return SimpleNamespace(module=module, library=library, rows=rows)


@pytest.mark.parametrize("state", ["present", "absent"])
def test_multiple_matches_select_all_in_native_order_preserving_repetition(
    provider: Any, state: str
) -> None:
    assert provider.module.select(["*", "B~~~~1"], state) == (
        ["B~~~~1", "A~~~~1", "C~~~~1"] + (["B~~~~1"] if state == "absent" else [])
    )
    assert provider.library.DismDelete.call_count == 2
    provider.library.DismCloseSession.assert_called_once()
    provider.library.DismShutdown.assert_called_once()


@pytest.mark.parametrize(
    "state,expected", [("present", ["A~~~~1"]), ("absent", []), (None, [])]
)
def test_single_match_state_and_null_state(
    provider: Any, state: Any, expected: list[str]
) -> None:
    assert provider.module.select(["A~~~~1"], state) == expected


def test_old_provider_short_name_expands_only_without_wildcard_or_suffix(
    provider: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(provider.module, "_windows_version", lambda: (10, 0, 17763))
    assert provider.module.select(["A"], "present") == ["A~~~~1"]
    monkeypatch.setattr(provider.module, "_windows_version", lambda: (10, 0, 19045))
    with pytest.raises(LookupError, match="Failed to find capability 'A'"):
        provider.module.select(["A"], "present")


def test_native_version_ignores_manifest_limited_python_version(
    provider: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    native_version = provider.module._windows_version
    # Load an unpatched copy so the real native record binding is exercised.
    module = load_module(
        ROOT / "plugins/module_utils/legacy_windows_capability_manage.py",
        "version_tested",
    )

    def _version(output: Any) -> int:
        record = output._obj
        assert record.size == ctypes.sizeof(module._VersionInfo)
        record.major, record.minor, record.build = 10, 0, 19045
        return 0

    library = SimpleNamespace(RtlGetVersion=Mock(side_effect=_version))
    monkeypatch.setattr(
        module.ctypes, "WinDLL", Mock(return_value=library), raising=False
    )
    monkeypatch.setattr(
        module.sys,
        "getwindowsversion",
        lambda: SimpleNamespace(major=6, build=9200),
        raising=False,
    )
    assert module._windows_version() == (10, 0, 19045)
    assert native_version() == (10, 0, 19045)


def test_actual_version_failure_reports_ntstatus_without_silent_guess(
    provider: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module(
        ROOT / "plugins/module_utils/legacy_windows_capability_manage.py",
        "version_failed",
    )
    library = SimpleNamespace(RtlGetVersion=Mock(return_value=-1073741823))
    monkeypatch.setattr(
        module.ctypes, "WinDLL", Mock(return_value=library), raising=False
    )
    with pytest.raises(OSError, match="RtlGetVersion failed.*0xC0000001"):
        module._windows_version()
    assert provider.library.DismOpenSession.call_count == 0


@pytest.mark.parametrize(
    "version,expected",
    [
        ((10, 0, 19045), ("Errors", "Warnings", "WarningsInfo")),
        ((10, 0, 22000), ("Errors", "Warnings", "WarningsInfo", "Debug")),
        ((10, 0, 26200), ("Errors", "Warnings", "WarningsInfo", "Debug")),
    ],
)
def test_logging_enum_uses_explicit_windows11_boundary_inference(
    provider: Any,
    monkeypatch: pytest.MonkeyPatch,
    version: tuple[int, int, int],
    expected: tuple[str, ...],
) -> None:
    monkeypatch.setattr(provider.module, "_windows_version", lambda: version)
    assert provider.module.logging_levels() == expected


@pytest.mark.parametrize(
    "pattern,detail",
    [("[bad", "Unterminated [] set."), ("[z-a]", "[x-y] range in reverse order.")],
)
def test_measured_provider_diagnostics_release_session(
    provider: Any, pattern: str, detail: str
) -> None:
    with pytest.raises(ValueError) as failure:
        provider.module.select([pattern], "present")
    assert str(failure.value) == 'parsing "^' + pattern + '$" - ' + detail
    provider.library.DismGetCapabilities.assert_not_called()
    provider.library.DismCloseSession.assert_called_once()
    provider.library.DismShutdown.assert_called_once()


@pytest.mark.parametrize("pattern", [r"*[\W]*", r"*[\d]*"])
def test_provider_regex_character_classes_are_not_filename_wildcards(
    provider: Any, pattern: str
) -> None:
    assert provider.module.select([pattern], "absent") == [
        "B~~~~1",
        "A~~~~1",
        "C~~~~1",
    ]


def test_python34_unfinished_class_error_keeps_original_diagnostic(
    provider: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        provider.module.re,
        "compile",
        Mock(
            side_effect=provider.module.re.error("unexpected end of regular expression")
        ),
    )
    with pytest.raises(ValueError) as error:
        provider.module._validate_pattern("[bad")
    assert str(error.value) == 'parsing "^[bad$" - Unterminated [] set.'


@pytest.mark.parametrize("operation", ["DismGetCapabilities", "DismOpenSession"])
def test_native_failure_retains_hresult_and_shutdown(
    provider: Any, operation: str
) -> None:
    call = getattr(provider.library, operation)
    call.side_effect = None
    call.return_value = -2147024891
    with pytest.raises(OSError, match="0x80070005"):
        provider.module.select(["*"], "present")
    provider.library.DismShutdown.assert_called_once()


@pytest.mark.parametrize("status,reboot", [(0, False), (3010, True), (1, False)])
def test_add_binds_ordered_sources_limitaccess_and_native_success_statuses(
    provider: Any, status: int, reboot: bool
) -> None:
    provider.library.DismAddCapability.return_value = status
    with provider.module.CapabilitySession(0, "") as native:
        assert native.add("A~~~~1", ["first", "second"], True) is reboot
    call = provider.library.DismAddCapability.call_args.args
    assert call[0].value == 13 and call[1:3] == ("A~~~~1", True)
    assert list(call[3]) == ["first", "second"] and call[4:] == (2, None, None, None)
    provider.library.DismInitialize.assert_called_once_with(2, None, None)
    assert provider.library.DismOpenSession.call_count == (2 if status == 1 else 1)


def test_remove_has_no_add_source_or_update_parameters(provider: Any) -> None:
    with provider.module.CapabilitySession() as native:
        assert not native.remove("A~~~~1")
    call = provider.library.DismRemoveCapability.call_args.args
    assert call[0].value == 13 and call[1:] == ("A~~~~1", None, None, None)


@pytest.mark.parametrize("operation", ["add", "remove"])
def test_servicing_failure_keeps_original_provider_text_and_releases_buffer(
    provider: Any, operation: str
) -> None:
    detail = provider.module.metadata._DismString("Element not found.\r\n")

    def _message(output: Any) -> int:
        output._obj.contents = detail
        return 0

    provider.library.DismGetLastErrorMessage.side_effect = _message
    call = (
        provider.library.DismAddCapability
        if operation == "add"
        else provider.library.DismRemoveCapability
    )
    call.return_value = -2147023728
    with provider.module.CapabilitySession() as native:
        with pytest.raises(OSError) as error:
            if operation == "add":
                native.add("A~~~~1", None, False)
            else:
                native.remove("A~~~~1")
    assert str(error.value) == "Element not found.\r\n"
    provider.library.DismDelete.assert_called_once()
    provider.library.DismCloseSession.assert_called_once()
    provider.library.DismShutdown.assert_called_once()


def test_missing_servicing_detail_keeps_actionable_native_status(provider: Any) -> None:
    provider.library.DismAddCapability.return_value = -2147023728
    with provider.module.CapabilitySession() as native:
        with pytest.raises(OSError, match="DismAddCapability.*0x80070490"):
            native.add("A~~~~1", None, False)
    provider.library.DismDelete.assert_not_called()


def test_reload_open_failure_shuts_down_without_double_closing(provider: Any) -> None:
    with provider.module.CapabilitySession() as native:
        provider.library.DismAddCapability.return_value = 1
        provider.library.DismOpenSession.side_effect = None
        provider.library.DismOpenSession.return_value = -2147024891
        with pytest.raises(OSError, match="DismOpenSession.*0x80070005"):
            native.add("A~~~~1", None, False)
    provider.library.DismCloseSession.assert_called_once()
    provider.library.DismShutdown.assert_called_once()


def test_task_xml_uses_same_user_s4u_no_password_and_no_elevation(
    provider: Any,
) -> None:
    xml = provider.module._task_xml(
        "HOST\\User & Name", "request with spaces", "response", "ready"
    )
    root = ElementTree.fromstring(xml)
    namespace = {"s": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    assert (
        root.findtext("s:Principals/s:Principal/s:UserId", namespaces=namespace)
        == "HOST\\User & Name"
    )
    assert (
        root.findtext("s:Principals/s:Principal/s:LogonType", namespaces=namespace)
        == "S4U"
    )
    assert (
        root.findtext("s:Principals/s:Principal/s:RunLevel", namespaces=namespace)
        == "LeastPrivilege"
    )
    assert (
        root.findtext("s:Settings/s:ExecutionTimeLimit", namespaces=namespace) == "PT0S"
    )
    arguments = root.findtext("s:Actions/s:Exec/s:Arguments", namespaces=namespace)
    assert arguments is not None
    assert '--batch "request with spaces" response ready' in arguments


@pytest.mark.parametrize("failed", [False, True])
def test_batch_cleanup_ends_only_failed_owned_task_and_never_overwrites(
    provider: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failed: bool
) -> None:
    command = Mock()
    monkeypatch.setattr(provider.module, "_task_command", command)
    outcome = Mock(return_value={"reboot_required": False})
    if failed:
        outcome.side_effect = OSError("child failed")
    monkeypatch.setattr(provider.module, "_wait_for_response", outcome)
    directory = tmp_path / "owned"
    directory.mkdir()
    if failed:
        with pytest.raises(OSError, match="child failed"):
            provider.module._execute_batch("unique", str(directory))
    else:
        assert provider.module._execute_batch("unique", str(directory)) == {
            "reboot_required": False
        }
    assert command.call_args_list[0].args[0] == [
        "/Create",
        "/TN",
        "unique",
        "/XML",
        str(directory / "task.xml"),
    ]
    assert command.call_args_list[-1].args[0] == ["/Delete", "/TN", "unique", "/F"]
    assert any(call.args[0][0] == "/End" for call in command.call_args_list) is failed
    assert not directory.exists()


def test_failed_task_cleanup_keeps_precise_recovery_workspace(
    provider: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    command = Mock(side_effect=[None, None, OSError("delete denied")])
    monkeypatch.setattr(provider.module, "_task_command", command)
    monkeypatch.setattr(
        provider.module, "_wait_for_response", lambda *_args: {"reboot_required": False}
    )
    directory = tmp_path / "owned"
    directory.mkdir()
    with pytest.raises(OSError, match="unique.*owned.*delete denied"):
        provider.module._execute_batch("unique", str(directory))
    assert directory.exists()


def test_worker_check_mode_starts_without_native_servicing(
    provider: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    request = tmp_path / "request.json"
    request.write_text(json.dumps({"check_mode": True}), encoding="utf-8")
    session = Mock()
    monkeypatch.setattr(provider.module, "CapabilitySession", session)
    provider.module._batch_worker(
        str(request), str(tmp_path / "response.json"), str(tmp_path / "ready.json")
    )
    assert json.loads((tmp_path / "response.json").read_text()) == {
        "reboot_required": False
    }
    assert json.loads((tmp_path / "ready.json").read_text())["pid"] > 0
    session.assert_not_called()
