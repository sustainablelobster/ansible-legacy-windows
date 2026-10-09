"""Exercise native package ABI, ownership, servicing calls and MSU metadata."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native boundary substitutes inspect ABI records and by-reference output storage.
# pylint: disable=protected-access

import ctypes
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="provider")
def hotfix_provider(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load actual ABI parsing with an observable native resource boundary.

    :param monkeypatch: Scoped imports and library replacement.
    :returns: Helper, provider, buffers and resource events.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    module = load_module(
        ROOT / "plugins/module_utils/legacy_windows_hotfix.py", "tested_hotfix"
    )
    records = (module._Package * 2)()
    records[0].name, records[0].state = "Second", 4
    records[1].name, records[1].state = "First", 5
    buffers: list[Any] = [records]
    events: list[Any] = []

    def _open(_image: str, _windows: Any, _system: Any, output: Any) -> int:
        output._obj.value = 23
        return 0

    def _catalogue(_session: Any, output: Any, count: Any) -> int:
        output._obj.contents = records[0]
        count._obj.value = 2
        return 0

    def _information(_session: Any, name: str, kind: int, output: Any) -> int:
        value = module._PackageInfo()
        value.name, value.state, value.description, value.applicable = (
            name,
            4,
            "Update KB42",
            1,
        )
        buffers.append(value)
        output._obj.contents = value
        events.append(("info", name, kind))
        return 0

    def _delete(pointer: Any) -> int:
        events.append(("delete", ctypes.addressof(pointer.contents)))
        return 0

    library = SimpleNamespace(
        DismInitialize=Mock(return_value=0),
        DismOpenSession=Mock(side_effect=_open),
        DismGetPackages=Mock(side_effect=_catalogue),
        DismGetPackageInfo=Mock(side_effect=_information),
        DismAddPackage=Mock(return_value=0),
        DismRemovePackage=Mock(return_value=0),
        DismGetLastErrorMessage=Mock(return_value=1),
        DismDelete=Mock(side_effect=_delete),
        DismCloseSession=Mock(return_value=0),
        DismShutdown=Mock(return_value=0),
    )
    monkeypatch.setattr(module, "_library", lambda: library)
    return SimpleNamespace(
        module=module, library=library, buffers=buffers, events=events
    )


def test_complete_native_order_metadata_fields_and_allocation_release(
    provider: Any,
) -> None:
    with provider.module.HotfixSession() as session:
        assert session.native_catalogue() == [
            {"name": "Second", "state": "Installed"},
            {"name": "First", "state": "InstallPending"},
        ]
        assert session.information("Second") == {
            "name": "Second",
            "state": "Installed",
            "description": "Update KB42",
            "applicable": True,
        }
        session.information("fixture.cab", True)
    assert [event for event in provider.events if event[0] == "info"] == [
        ("info", "Second", 1),
        ("info", "fixture.cab", 2),
    ]
    assert len([event for event in provider.events if event[0] == "delete"]) == 3
    provider.library.DismCloseSession.assert_called_once()
    provider.library.DismShutdown.assert_called_once_with()


def test_missing_dll_selects_installed_tool_without_changing_public_session(
    provider: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    failure = OSError("native library absent")
    monkeypatch.setattr(provider.module, "_library", Mock(side_effect=failure))
    monkeypatch.setattr(
        provider.module.command, "executable", Mock(return_value="dism.exe")
    )
    backend = MagicMock()
    constructor = Mock(return_value=backend)
    monkeypatch.setattr(provider.module.command, "DismCommand", constructor)
    monkeypatch.setattr(provider.module, "_reference_file_use", nullcontext)
    with provider.module.HotfixSession() as session:
        session.catalogue()
        session.native_catalogue()
        session.information("package.cab", True)
        session.add("package.cab")
        session.remove("Package identity")
    constructor.assert_called_once_with("dism.exe")
    backend.__enter__.assert_called_once_with()
    backend.__exit__.assert_called_once_with(None, None, None)
    assert backend.catalogue.call_count == 2
    backend.information.assert_called_once_with("package.cab", True)
    backend.add.assert_called_once_with("package.cab")
    backend.remove.assert_called_once_with("Package identity")
    provider.library.DismInitialize.assert_not_called()


@pytest.mark.parametrize(
    "operation",
    ["DismInitialize", "DismOpenSession", "DismGetPackages", "DismGetPackageInfo"],
)
def test_failed_native_calls_close_only_acquired_resources(
    provider: Any, operation: str
) -> None:
    function = getattr(provider.library, operation)
    function.side_effect = None
    function.return_value = -2147024891
    with pytest.raises(OSError, match="0x80070005"):
        with provider.module.HotfixSession() as session:
            if operation == "DismGetPackageInfo":
                session.information("Package")
            else:
                session.native_catalogue()
    assert provider.library.DismCloseSession.call_count == (
        0 if operation in ("DismInitialize", "DismOpenSession") else 1
    )
    assert provider.library.DismShutdown.call_count == (
        0 if operation == "DismInitialize" else 1
    )


def test_error_message_buffer_is_copied_and_freed(provider: Any) -> None:
    value = provider.module._DismString("provider text\r\n")
    provider.buffers.append(value)

    def _error(output: Any) -> int:
        output._obj.contents = value
        return 0

    provider.library.DismGetLastErrorMessage.side_effect = _error
    with pytest.raises(OSError, match="^provider text\r\n$"):
        provider.module._check(provider.library, -1, "operation")
    assert provider.events == [("delete", ctypes.addressof(value))]


@pytest.mark.parametrize("state", [-1, 8, 123])
def test_unknown_package_states_preserve_their_native_value(
    provider: Any, state: int
) -> None:
    assert provider.module._state(state) == str(state)


@pytest.mark.parametrize("operation", ["add", "remove"])
@pytest.mark.parametrize(
    "status, reboot, reloads", [(0, False, 0), (3010, True, 0), (1, False, 1)]
)
def test_no_restart_servicing_and_successful_session_reload(
    provider: Any, operation: str, status: int, reboot: bool, reloads: int
) -> None:
    function = getattr(
        provider.library,
        "DismAddPackage" if operation == "add" else "DismRemovePackage",
    )
    function.return_value = status
    with provider.module.HotfixSession() as session:
        assert getattr(session, operation)("Package") is reboot
    assert provider.library.DismOpenSession.call_count == reloads + 1
    assert provider.library.DismCloseSession.call_count == reloads + 1
    assert function.call_args.args[1] == "Package"
    assert function.call_args.args[-3:] == (None, None, None)
    assert function.call_args.args[2:4] == (
        (False, False) if operation == "add" else (1, None)
    )


@pytest.mark.parametrize("operation", ["add", "remove"])
def test_successful_restart_is_not_replaced_by_session_close_restart_warning(
    provider: Any, operation: str
) -> None:
    function = getattr(
        provider.library,
        "DismAddPackage" if operation == "add" else "DismRemovePackage",
    )
    function.return_value = 3010
    provider.library.DismCloseSession.return_value = 3010
    with provider.module.HotfixSession() as session:
        assert getattr(session, operation)("Package") is True
    provider.library.DismCloseSession.assert_called_once()
    provider.library.DismShutdown.assert_called_once()
    assert session._opened is False  # pylint: disable=protected-access
    assert session._initialized is False  # pylint: disable=protected-access


def test_close_restart_warning_does_not_replace_an_operation_error(
    provider: Any,
) -> None:
    provider.library.DismAddPackage.return_value = -2147024891
    provider.library.DismCloseSession.return_value = 3010
    with pytest.raises(OSError, match="DismAddPackage failed.*0x80070005"):
        with provider.module.HotfixSession() as session:
            session.add("Package")
    provider.library.DismShutdown.assert_called_once()


@pytest.mark.parametrize("operation", ["DismCloseSession", "DismShutdown"])
def test_other_cleanup_hresult_failures_remain_failures(
    provider: Any, operation: str
) -> None:
    getattr(provider.library, operation).return_value = -2147024891
    with pytest.raises(OSError, match=operation + " failed.*0x80070005"):
        with provider.module.HotfixSession():
            pass
    provider.library.DismShutdown.assert_called_once()


@pytest.mark.parametrize("bits,folder", [(4, "Framework"), (8, "Framework64")])
def test_reference_image_matches_payload_architecture_and_is_optional(
    provider: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    bits: int,
    folder: str,
) -> None:
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    monkeypatch.setattr(provider.module.ctypes, "sizeof", lambda _kind: bits)
    assert provider.module._reference_clr_image() is None
    image = tmp_path / "Microsoft.NET" / folder / "v4.0.30319" / "clr.dll"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"existing runtime image")
    assert provider.module._reference_clr_image() == str(image)
    monkeypatch.delenv("SystemRoot")
    assert provider.module._reference_clr_image() is None


def test_missing_reference_image_does_not_require_a_runtime_or_native_loader(
    provider: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(provider.module, "_reference_clr_image", lambda: None)
    loader = Mock(side_effect=AssertionError("No runtime dependency allowed"))
    monkeypatch.setattr(provider.module.ctypes, "WinDLL", loader, raising=False)
    with provider.module.HotfixSession() as session:
        assert session.remove("Package") is False
    loader.assert_not_called()


@pytest.mark.parametrize(
    "status,reboot", [(0, False), (3010, True), (-2147024891, None)]
)
def test_native_resource_image_is_held_only_during_real_removal_and_freed(
    provider: Any,
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    reboot: Any,
) -> None:
    events: list[Any] = []

    def recorded(event: str, result: int) -> int:
        """Append one ownership event.

        :param event: Ownership event to append.
        :param result: Configured native return value.
        :returns: The native boundary's configured result.
        """
        events.append(event)
        return result

    api = SimpleNamespace(
        LoadLibraryExW=Mock(side_effect=lambda *_args: recorded("mapped", 0x10002)),
        FreeLibrary=Mock(side_effect=lambda _image: recorded("freed", 1)),
    )
    monkeypatch.setattr(
        provider.module, "_reference_clr_image", lambda: r"C:\Windows\clr.dll"
    )
    loader = Mock(return_value=api)
    monkeypatch.setattr(provider.module.ctypes, "WinDLL", loader, raising=False)
    provider.library.DismRemovePackage.side_effect = lambda *_args: recorded(
        "removed", status
    )
    expected = (
        pytest.raises(OSError, match="DismRemovePackage failed.*0x80070005")
        if reboot is None
        else nullcontext()
    )
    with expected:
        with provider.module.HotfixSession() as session:
            assert session.remove("Package") is reboot
    assert events == ["mapped", "removed", "freed"]
    loader.assert_called_once_with("kernel32", use_last_error=True)
    api.LoadLibraryExW.assert_called_once_with(r"C:\Windows\clr.dll", None, 0x20)
    api.FreeLibrary.assert_called_once_with(0x10002)
    assert api.LoadLibraryExW.restype is ctypes.c_void_p
    assert api.FreeLibrary.restype is ctypes.c_int


@pytest.mark.parametrize(
    "failure",
    [(0, 1, None, 32), (0x10002, 0, None, 6), (0x10002, 0, "servicing failed", 87)],
)
def test_reference_mapping_errors_preserve_native_codes_and_primary_failure(
    provider: Any,
    monkeypatch: pytest.MonkeyPatch,
    failure: tuple[int, int, str | None, int],
) -> None:
    load, free, primary, code = failure
    api = SimpleNamespace(
        LoadLibraryExW=Mock(return_value=load), FreeLibrary=Mock(return_value=free)
    )
    monkeypatch.setattr(
        provider.module, "_reference_clr_image", lambda: "existing-clr.dll"
    )
    monkeypatch.setattr(
        provider.module.ctypes, "WinDLL", Mock(return_value=api), raising=False
    )
    monkeypatch.setattr(
        provider.module.ctypes, "get_last_error", lambda: code, raising=False
    )
    monkeypatch.setattr(
        provider.module.ctypes,
        "WinError",
        lambda actual: OSError("native error " + str(actual)),
        raising=False,
    )
    with pytest.raises(OSError, match="native error " + str(code)) as caught:
        with provider.module._reference_file_use():
            if primary:
                raise OSError(primary)
    if primary:
        assert primary in str(caught.value)
        assert str(caught.value.__cause__) == primary
    assert api.FreeLibrary.call_count == (1 if load else 0)


def test_missing_native_array_fails_without_dereferencing_null(provider: Any) -> None:
    def _missing(_session: Any, _output: Any, count: Any) -> int:
        count._obj.value = 1
        return 0

    provider.library.DismGetPackages.side_effect = _missing
    with pytest.raises(OSError, match="count without a package array"):
        with provider.module.HotfixSession() as session:
            session.native_catalogue()
    provider.library.DismCloseSession.assert_called_once()
    provider.library.DismShutdown.assert_called_once()


def test_cli_enumeration_does_not_overlap_a_native_image_session(
    provider: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = provider.library

    def _cli() -> list[dict[str, str]]:
        library.DismCloseSession.assert_called_once()
        library.DismShutdown.assert_called_once()
        assert library.DismOpenSession.call_count == 1
        return [{"name": "Visible", "state": "Installed"}]

    monkeypatch.setattr(
        provider.module.HotfixSession, "_catalogue_command", staticmethod(_cli)
    )
    with provider.module.HotfixSession() as session:
        assert session.catalogue() == [{"name": "Visible", "state": "Installed"}]
        assert library.DismInitialize.call_count == 2
        assert library.DismOpenSession.call_count == 2
        session.information("Visible")
    assert library.DismCloseSession.call_count == 2
    assert library.DismShutdown.call_count == 2


def test_failed_cli_still_reopens_and_finally_releases_the_native_provider(
    provider: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        provider.module.HotfixSession,
        "_catalogue_command",
        staticmethod(Mock(side_effect=OSError("CLI failed"))),
    )
    with pytest.raises(OSError, match="CLI failed"):
        with provider.module.HotfixSession() as session:
            session.catalogue()
    assert provider.library.DismInitialize.call_count == 2
    assert provider.library.DismCloseSession.call_count == 2
    assert provider.library.DismShutdown.call_count == 2


def test_failed_restart_preserves_error_without_shutting_down_an_uninitialized_api(
    provider: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider.library.DismInitialize.side_effect = [0, -1]
    monkeypatch.setattr(
        provider.module.HotfixSession, "_catalogue_command", staticmethod(lambda: [])
    )
    with pytest.raises(OSError, match="DismInitialize failed"):
        with provider.module.HotfixSession() as session:
            session.catalogue()
    provider.library.DismCloseSession.assert_called_once()
    provider.library.DismShutdown.assert_called_once()


@pytest.mark.parametrize(
    "state", ["Installed", "Install Pending", "Uninstall Pending", "Not Present"]
)
def test_cli_visible_catalogue_preserves_order_and_maps_only_state_spaces(
    provider: Any, monkeypatch: pytest.MonkeyPatch, state: str
) -> None:
    class Output(bytes):
        """Return Windows command output without requiring the host mbcs codec."""

        def decode(self, encoding: str = "utf-8", errors: str = "strict") -> str:
            """Return one visible record.

            :param encoding: Required Windows ANSI codec.
            :param errors: Required replacement error handling.
            :returns: The simulated DISM command output.
            """
            assert encoding == "mbcs" and errors == "replace"
            return "Header\r\nPackage Identity : Visible\r\nState : " + state + "\r\n"

    process = SimpleNamespace(returncode=0, communicate=lambda: (Output(), None))
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    monkeypatch.setattr(
        provider.module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: nullcontext(process),
    )
    assert provider.module.HotfixSession._catalogue_command() == [
        {"name": "Visible", "state": state.replace(" ", "")}
    ]


def test_named_provider_failure_is_an_absent_stub(provider: Any) -> None:
    session = SimpleNamespace(information=Mock(side_effect=OSError("provider failure")))
    assert provider.module.metadata_from_name(session, "Missing") == {
        "name": "Missing",
        "state": "NotPresent",
        "kb": "UNKNOWN",
    }


@pytest.mark.parametrize(
    "description, kb",
    [
        ("before kB42 then KB99", "kB42"),
        ("KB without digits", "KB"),
        ("no identifier", "UNKNOWN"),
    ],
)
def test_named_metadata_returns_first_case_preserving_kb(
    provider: Any, description: str, kb: str
) -> None:
    session = SimpleNamespace(
        information=lambda _: {
            "name": "Package",
            "state": "Installed",
            "description": description,
        }
    )
    assert provider.module.metadata_from_name(session, "Package")["kb"] == kb


def test_extracted_metadata_namespace_order_kb_and_path_leaf(
    provider: Any, tmp_path: Path
) -> None:
    (tmp_path / "metadata.xml").write_text(
        '<unattend xmlns="urn:schemas-microsoft-com:unattend"><servicing><package>'
        '<source location="../first.cab"/><source location="folder\\second.cab"/>'
        "</package></servicing></unattend>",
        encoding="utf-8-sig",
    )
    (tmp_path / "properties.txt").write_text(
        'KB Article Number="42"\n', encoding="utf-8-sig"
    )
    session = SimpleNamespace(
        information=Mock(
            side_effect=lambda path, by_path: {
                "name": Path(path).name,
                "state": "Installed",
                "applicable": by_path,
            }
        )
    )
    assert provider.module.metadata_from_file(session, str(tmp_path)) == [
        {"path": str(tmp_path / name), "name": name, "state": "Installed", "kb": "KB42"}
        for name in ("first.cab", "second.cab")
    ]


def test_missing_xml_metadata_never_queries_a_package(
    provider: Any, tmp_path: Path
) -> None:
    session = SimpleNamespace(information=Mock())
    with pytest.raises(ValueError, match="failed to get metadata xml inside MSU"):
        provider.module.metadata_from_file(session, str(tmp_path))
    session.information.assert_not_called()


@pytest.mark.parametrize(
    "applicable,error", [(False, None), (True, OSError("provider text"))]
)
def test_inapplicable_and_invalid_cab_preserve_reached_source_errors(
    provider: Any, tmp_path: Path, applicable: bool, error: OSError | None
) -> None:
    (tmp_path / "metadata.xml").write_text(
        '<unattend><servicing><package><source location="package.cab"/>'
        "</package></servicing></unattend>",
        encoding="utf-8-sig",
    )
    session = SimpleNamespace(
        information=Mock(return_value={"applicable": applicable}, side_effect=error)
    )
    with pytest.raises((ValueError, OSError)) as failure:
        provider.module.metadata_from_file(session, str(tmp_path))
    assert str(failure.value) == (
        "hotfix package is not applicable for this server"
        if not applicable
        else "failed to get DISM package metadata from path "
        + str(tmp_path)
        + ": provider text"
    )


@pytest.mark.parametrize("failure", [OSError("launch failed"), 5])
def test_failed_expansion_removes_its_owned_directory(
    provider: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: Any
) -> None:
    folder = tmp_path / "owned-extract"
    folder.mkdir()
    monkeypatch.setenv("SystemRoot", "C:\\Windows")
    monkeypatch.setattr(provider.module.tempfile, "mkdtemp", lambda **_: str(folder))
    process = SimpleNamespace(communicate=lambda: (b"", b""), returncode=failure)
    monkeypatch.setattr(
        provider.module.subprocess,
        "Popen",
        Mock(
            side_effect=failure if isinstance(failure, OSError) else None,
            return_value=process,
        ),
    )
    with pytest.raises((OSError, ValueError), match="failed to run expand.exe"):
        with provider.module.ExpandedMsu("update.msu"):
            pytest.fail("Failed expansion cannot yield a directory")
    assert not folder.exists()
