"""Exercise registry command recovery through the public package payload."""

# SPDX-License-Identifier: GPL-3.0-or-later
# The tests inspect package-owned native parsing and lifecycle boundaries.
# pylint: disable=protected-access

import ctypes
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload


@pytest.fixture(name="uninstall")
def uninstall_runner(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> Any:
    """Run registry removal while recording parsed commands and child launches.

    :param monkeypatch: Scoped Windows library and registry substitutions.
    :param capsys: Complete public JSON output capture.
    :returns: Payload runner with controlled native argument tokens.
    """
    payload = load_payload("win_package", monkeypatch)
    state = SimpleNamespace(tokens=[], allocation=None)

    def _parse(_command: str, count: Any) -> Any:
        count._obj.value = len(state.tokens)
        state.allocation = (ctypes.c_wchar_p * len(state.tokens))(*state.tokens)
        return ctypes.cast(state.allocation, ctypes.POINTER(ctypes.c_wchar_p))

    parse = Mock(side_effect=_parse)
    free = Mock()
    monkeypatch.setattr(
        ctypes,
        "WinDLL",
        lambda name, **_kwargs: (
            SimpleNamespace(CommandLineToArgvW=parse)
            if name == "shell32"
            else SimpleNamespace(LocalFree=free)
        ),
        raising=False,
    )
    monkeypatch.setattr(payload.package, "WindowsInstaller", lambda: nullcontext(None))
    location = {
        "path": r"HKCU:\SOFTWARE\Uninstall\Owned",
        "values": {"UninstallString": "owned.exe"},
    }
    registry = Mock(return_value=location)
    monkeypatch.setattr(payload.package, "_registry_location", registry)
    process = Mock(return_value={"changed": True, "rc": 0, "stdout": "", "stderr": ""})
    monkeypatch.setattr(payload.package.processes, "run_command", process)
    monkeypatch.setenv("OwnedPackageRoot", r"C:\Program Files\Owned")

    def _run(**options: Any) -> tuple[int, dict[str, Any]]:
        arguments = {"provider": "registry", "state": "absent", "product_id": "Owned"}
        arguments.update(options)
        monkeypatch.setattr(payload, "read_arguments", lambda *_args: arguments)
        return invoke_payload(payload, capsys)

    return SimpleNamespace(
        run=_run,
        payload=payload,
        state=state,
        location=location,
        registry=registry,
        parse=parse,
        free=free,
        process=process,
    )


def test_unquoted_path_recovery_preserves_every_parsed_argument(
    uninstall: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = r"C:\Program Files\Owned App\uninstall.exe"
    arguments = [
        "",
        "two words",
        'quoted "value"',
        "trailing space\\",
        "^()%!<>&|",
        "雪",
    ]
    command = executable + ' /quiet "" "two words"'
    uninstall.location["values"]["UninstallString"] = command
    uninstall.state.tokens = [
        r"C:\Program",
        r"Files\Owned",
        r"App\uninstall.exe",
    ] + arguments
    inspected: list[str] = []

    def _is_file(path: str) -> bool:
        inspected.append(path)
        return path == executable

    monkeypatch.setattr(uninstall.payload.package.os.path, "isfile", _is_file)
    code, result = uninstall.run(arguments=["additional argument", ""])
    assert code == 0 and result["changed"] is True
    quote = uninstall.payload.package.quote_argument
    assert uninstall.process.call_args.args[1] == " ".join(
        quote(value) for value in [executable] + arguments + ["additional argument", ""]
    )
    assert inspected == [r"C:\Program", r"C:\Program Files\Owned", executable]
    assert uninstall.parse.call_args.args[0] == command
    uninstall.free.assert_called_once()


def test_recovery_selects_the_first_existing_literal_file_without_an_extension(
    uninstall: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    command = r"C:\Owned File\uninstall.exe /quiet"
    uninstall.location["values"]["UninstallString"] = command
    uninstall.state.tokens = [r"C:\Owned", r"File\uninstall.exe", "/quiet"]
    monkeypatch.setattr(
        uninstall.payload.package.os.path,
        "isfile",
        lambda path: path in (r"C:\Owned", r"C:\Owned File\uninstall.exe"),
    )
    uninstall.run()
    assert uninstall.process.call_args.args[1] == command
    uninstall.free.assert_called_once()


def test_no_existing_file_retains_the_literal_registry_command(
    uninstall: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    command = r'missing app.exe  /quiet "spaced argument"'
    uninstall.location["values"]["UninstallString"] = command
    uninstall.state.tokens = ["missing", "app.exe", "/quiet", "spaced argument"]
    monkeypatch.setattr(
        uninstall.payload.package.os.path, "isfile", lambda _path: False
    )
    uninstall.run()
    assert uninstall.process.call_args.args[1] == command
    uninstall.free.assert_called_once()


@pytest.mark.parametrize(
    "command",
    ['"C:\\Owned App\\uninstall.exe"  /quiet', "owned.exe", "owned.exe\t/quiet"],
)
def test_quoted_commands_and_commands_without_spaces_are_not_rewritten(
    uninstall: Any, command: str
) -> None:
    uninstall.location["values"]["UninstallString"] = command
    uninstall.run()
    assert uninstall.process.call_args.args[1] == command
    uninstall.parse.assert_not_called()
    uninstall.free.assert_not_called()


def test_quiet_variable_command_expands_before_recovery(
    uninstall: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    uninstall.location["values"][
        "QuietUninstallString"
    ] = r"%OwnedPackageRoot%\uninstall.exe /quiet"
    uninstall.location["values"]["UninstallString"] = "must-not-run"
    executable = r"C:\Program Files\Owned\uninstall.exe"
    uninstall.state.tokens = [r"C:\Program", r"Files\Owned\uninstall.exe", "/quiet"]
    monkeypatch.setattr(
        uninstall.payload.package.os.path, "isfile", lambda path: path == executable
    )
    uninstall.run()
    assert uninstall.parse.call_args.args[0] == executable + " /quiet"
    assert uninstall.process.call_args.args[1] == '"' + executable + '" /quiet'


def test_environment_variables_in_arguments_remain_literal(uninstall: Any) -> None:
    uninstall.location["values"]["UninstallString"] = '"owned.exe" %OwnedPackageRoot%'
    uninstall.run()
    assert uninstall.process.call_args.args[1] == '"owned.exe" %OwnedPackageRoot%'
    uninstall.parse.assert_not_called()


def test_explicit_removal_path_bypasses_registry_recovery(
    uninstall: Any, tmp_path: Path
) -> None:
    executable = tmp_path / "explicit uninstall.exe"
    executable.write_bytes(b"owned executable")
    uninstall.location["values"]["UninstallString"] = "missing app.exe /quiet"
    uninstall.run(path=str(executable), arguments="/explicit")
    assert uninstall.process.call_args.args[1] == '"' + str(executable) + '" /explicit'
    uninstall.parse.assert_not_called()


@pytest.mark.parametrize(
    "installed,check", [(True, True), (False, False), (False, True)]
)
def test_check_mode_and_absent_idempotence_do_not_parse_or_launch(
    uninstall: Any, installed: bool, check: bool
) -> None:
    uninstall.location["values"]["UninstallString"] = "missing app.exe /quiet"
    if not installed:
        uninstall.registry.return_value = None
    assert uninstall.run(_ansible_check_mode=check) == (
        0,
        {"changed": installed, "rc": 0, "reboot_required": False},
    )
    uninstall.parse.assert_not_called()
    uninstall.process.assert_not_called()


def test_recovered_uninstall_failure_retains_streams_and_exit_code(
    uninstall: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = r"C:\Owned App\uninstall.exe"
    uninstall.location["values"]["UninstallString"] = executable + " /quiet"
    uninstall.state.tokens = [r"C:\Owned", r"App\uninstall.exe", "/quiet"]
    monkeypatch.setattr(
        uninstall.payload.package.os.path, "isfile", lambda path: path == executable
    )
    uninstall.process.return_value.update(
        rc=23, stdout="owned stdout", stderr="owned stderr"
    )
    assert uninstall.run() == (
        1,
        {
            "changed": False,
            "failed": True,
            "reboot_required": False,
            "rc": 23,
            "stdout": "owned stdout",
            "stderr": "owned stderr",
            "msg": "unexpected rc from '\""
            + executable
            + "\" /quiet': see rc, stdout, and stderr for more details",
        },
    )
    uninstall.free.assert_called_once()


def test_native_parse_failure_stops_before_an_uninstaller_launch(
    uninstall: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    uninstall.location["values"]["UninstallString"] = "owned app.exe /quiet"
    uninstall.parse.side_effect = None
    uninstall.parse.return_value = None
    monkeypatch.setattr(
        ctypes, "WinError", lambda: OSError("native parse failed"), raising=False
    )
    code, result = uninstall.run()
    assert code == 1 and result["msg"] == "native parse failed"
    uninstall.process.assert_not_called()
    uninstall.free.assert_not_called()
