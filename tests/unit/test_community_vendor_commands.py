"""Exercise public JSON payloads against independent native process replies."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module


@pytest.fixture(name="native")
def native_fixture(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Record executable launches without depending on installed vendor tools.

    :param monkeypatch: Scoped target helper import path.
    :returns: Independently controlled native process state.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    return {
        "calls": [],
        "rc": 0,
        "stdout": "first line\r\nsecond line\r\n",
        "stderr": "",
        "launch_failure": False,
    }


# The JSON runner retains explicit arguments and pytest's three isolation fixtures.
def execute(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    name: str,
    arguments: dict[str, Any],
    native: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> tuple[int, dict[str, Any]]:
    """Run the actual payload entry point with only process execution replaced.

    :param name: Public module basename.
    :param arguments: Public JSON module arguments.
    :param native: Independent executable reply and observed calls.
    :param monkeypatch: Scoped command and argument substitutions.
    :param tmp_path: Owned argument file directory.
    :param capsys: Payload JSON output capture.
    :returns: Process status and decoded public response.
    """
    payload = load_module(
        ROOT / "legacy_community_windows/plugins/modules" / (name + ".py"),
        "community_" + name,
    )

    def launch(
        executable: str, command: str, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        """Return an independent vendor reply and retain the actual launch request.

        :param executable: Explicit process image.
        :param command: Complete native command line.
        :param parameters: Stdin, working directory and output encoding.
        :returns: Independent native process reply.
        """
        native["calls"].append((executable, command, parameters))
        if native["launch_failure"]:
            return {"failed": True, "rc": 2, "msg": "fixture launch failed"}
        return {
            "rc": native["rc"],
            "stdout": native["stdout"],
            "stderr": native["stderr"],
            "start": "2026-10-15 14:03:04.123456",
            "end": "2026-10-15 14:03:05.654321",
            "delta": "0:00:01.530865",
            "failed": native["rc"] != 0,
        }

    monkeypatch.setattr(payload, "run_command", launch)
    argument_file = tmp_path / (name + "-arguments.json")
    argument_file.write_text(json.dumps(arguments), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [str(payload.__file__), str(argument_file)])
    return invoke_payload(payload, capsys)


@pytest.mark.parametrize("architectures", [(), ("",), ("64",), ("", "64")])
@pytest.mark.parametrize("check_mode", [False, True])
# Both public behavior dimensions need the shared native and pytest fixtures.
def test_ngen_runs_only_installed_architectures(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    native: dict[str, Any],
    architectures: tuple[str, ...],
    check_mode: bool,
) -> None:
    monkeypatch.setenv("windir", str(tmp_path))
    for architecture in architectures:
        executable = (
            tmp_path
            / "Microsoft.NET"
            / ("Framework" + architecture)
            / "v4.0.30319/ngen.exe"
        )
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"independent NGen image")
    status, result = execute(
        "win_dotnet_ngen",
        {"_ansible_check_mode": check_mode},
        native,
        monkeypatch,
        tmp_path,
        capsys,
    )
    assert status == 0
    assert result["changed"] is bool(architectures)
    assert len(native["calls"]) == (0 if check_mode else len(architectures) * 2)
    for architecture in architectures:
        for operation in ("update", "eqi"):
            prefix = "dotnet_ngen" + architecture + "_" + operation
            assert result[prefix + "_exit_code"] == 0
            assert isinstance(result[prefix + "_output"], str)


def test_ngen_reports_native_nonzero_status_without_losing_both_operations(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    native: dict[str, Any],
) -> None:
    monkeypatch.setenv("windir", str(tmp_path))
    executable = tmp_path / "Microsoft.NET/Framework/v4.0.30319/ngen.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"independent NGen image")
    native["rc"] = 9
    status, result = execute(
        "win_dotnet_ngen", {}, native, monkeypatch, tmp_path, capsys
    )
    assert status == 0
    assert result["dotnet_ngen_update_exit_code"] == 9
    assert result["dotnet_ngen_eqi_exit_code"] == 9
    assert native["calls"][0][1].endswith("update /force")
    assert native["calls"][1][1].endswith("executeQueuedItems")


@pytest.mark.parametrize("code", range(17))
@pytest.mark.parametrize("purge", [False, True])
# Both status and deletion options need the independent process and pytest fixtures.
def test_robocopy_native_statuses(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    native: dict[str, Any],
    code: int,
    purge: bool,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    native["rc"] = code
    status, result = execute(
        "win_robocopy",
        {"src": str(source), "dest": str(tmp_path / "destination"), "purge": purge},
        native,
        monkeypatch,
        tmp_path,
        capsys,
    )
    assert status == (1 if code >= 8 else 0)
    assert result["rc"] == result["return_code"] == code
    assert result["changed"] is (code in (1, 3, 4, 5, 7) or (purge and code in (2, 6)))
    assert result["output"] == ["first line", "second line"]
    assert bool(result.get("warnings")) is (code in (2, 3, 4, 5, 7))


@pytest.mark.parametrize("code", [2, 6])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize(
    "options,deletes_extras",
    [
        ({"purge": True, "recurse": True}, True),
        ({"flags": "/PURGE"}, True),
        ({"flags": "/e /pUrGe /R:0 /W:0"}, True),
        ({"flags": "/miR"}, True),
        ({"purge": True, "flags": ""}, False),
        ({"purge": True, "recurse": True, "flags": "/E"}, False),
        ({"flags": "/E /PURGE /XX"}, False),
        ({"flags": "/MIR /xX"}, False),
        ({"flags": "/E /PURGE /XF extra.txt"}, False),
        ({"flags": "/MIR /XD extra-dir"}, False),
        ({"flags": "*.txt /E /PURGE"}, False),
        ({"flags": "/PURGE /JOB:owned-job"}, False),
        ({"flags": "/PURGE /MAX:1024"}, False),
        ({"flags": "/PURGE /MINAGE:1"}, False),
        ({"flags": "/PURGE /XA:H"}, False),
        ({"flags": "/PURGE /XJ"}, False),
        ({"flags": "/PURGE /LEV:1"}, False),
        ({"flags": "/E"}, False),
        ({"flags": "/PURGE-NOT-A-SWITCH /MIRROR"}, False),
        ({"flags": "/XF prefix-/PURGE suffix-/MIR"}, False),
    ],
)
# The effective option/status matrix uses the shared process and pytest fixtures.
def test_robocopy_deletion_only_reporting_uses_effective_switches(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    native: dict[str, Any],
    code: int,
    check_mode: bool,
    options: dict[str, Any],
    deletes_extras: bool,
) -> None:
    native["rc"] = code
    status, result = execute(
        "win_robocopy",
        {
            "src": str(tmp_path),
            "dest": str(tmp_path / "destination"),
            "_ansible_check_mode": check_mode,
            **options,
        },
        native,
        monkeypatch,
        tmp_path,
        capsys,
    )
    assert status == 0
    assert result["changed"] is deletes_extras
    assert result["rc"] == result["return_code"] == code
    assert result["failed"] is False
    assert bool(result.get("warnings")) is (code == 2)
    assert (" /l " in native["calls"][0][1]) is check_mode


@pytest.mark.parametrize(
    "flags,expected", [(None, "/purge /e"), ("/E /R:0", "/E /R:0")]
)
# Both option variants need the shared native and pytest isolation fixtures.
def test_robocopy_prediction_and_explicit_flags_precedence(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    native: dict[str, Any],
    flags: str | None,
    expected: str,
) -> None:
    source = tmp_path / "source with spaces"
    source.mkdir()
    status, result = execute(
        "win_robocopy",
        {
            "src": str(source),
            "dest": str(tmp_path / "dest"),
            "recurse": True,
            "purge": True,
            "flags": flags,
            "_ansible_check_mode": True,
        },
        native,
        monkeypatch,
        tmp_path,
        capsys,
    )
    assert status == 0
    assert native["calls"][0][1].endswith("/l " + expected)
    assert '"' + str(source) + '"' in native["calls"][0][1]
    assert result["flags"] == flags


def test_robocopy_returns_useful_vendor_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    native: dict[str, Any],
) -> None:
    native.update(
        rc=8,
        stdout="-----\r\nheader\r\n-----\r\nheader\r\n-----\r\nERROR 5 access denied\r\n",
    )
    status, result = execute(
        "win_robocopy",
        {"src": str(tmp_path), "dest": str(tmp_path / "dest")},
        native,
        monkeypatch,
        tmp_path,
        capsys,
    )
    assert status == 1
    assert result["msg"] == "ERROR 5 access denied"


def test_robocopy_missing_source_does_not_launch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    native: dict[str, Any],
) -> None:
    status, result = execute(
        "win_robocopy",
        {"src": str(tmp_path / "missing"), "dest": str(tmp_path / "dest")},
        native,
        monkeypatch,
        tmp_path,
        capsys,
    )
    assert status == 1
    assert "does not exist" in result["msg"]
    assert not native["calls"]


@pytest.mark.parametrize("wait", [False, True])
def test_installed_psexec_command_options_results_and_secret_masking(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    native: dict[str, Any],
    wait: bool,
) -> None:
    executable = tmp_path / "PsExec.exe"
    executable.write_bytes(b"independent vendor image")
    native["rc"] = 73
    status, result = execute(
        "win_psexec",
        {
            "executable": str(executable),
            "command": 'cmd /c "echo raw command"',
            "hostnames": ["other", "HOST", "host"],
            "username": "Operator",
            "password": "secret with spaces",
            "chdir": r"C:\Program Files\App",
            "interactive": True,
            "session": 2,
            "system": True,
            "nobanner": True,
            "noprofile": True,
            "elevated": True,
            "limited": True,
            "priority": "high",
            "timeout": 9,
            "wait": wait,
        },
        native,
        monkeypatch,
        tmp_path,
        capsys,
    )
    assert status == 0
    assert result["changed"] is True
    command = native["calls"][0][1]
    assert native["calls"][0][2]["keep_stdin_open"] is True
    assert r"\\HOST,other" in command
    assert command.endswith('-accepteula cmd /c "echo raw command"')
    assert '-p "secret with spaces"' in command
    assert '-w "C:\\Program Files\\App"' in command
    assert "-e -h -s -i 2 -l -high -n 9" in command
    assert (" -d " in command) is not wait
    assert "secret with spaces" not in json.dumps(result)
    assert "*PASSWORD_REPLACED*" in result["psexec_command"]
    assert result["rc"] == (73 if wait else 0)
    assert ("pid" not in result) if wait else result["pid"] == 73
    assert result["start"] == "2026-10-15 02:03:04.123456"


def test_installed_psexec_check_mode_skips_before_tool_lookup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    native: dict[str, Any],
) -> None:
    status, result = execute(
        "win_psexec",
        {"command": "cmd.exe", "_ansible_check_mode": True},
        native,
        monkeypatch,
        tmp_path,
        capsys,
    )
    assert status == 0
    assert result["skipped"] is True
    assert not native["calls"]


def test_installed_psexec_missing_binary_is_actionable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    native: dict[str, Any],
) -> None:
    status, result = execute(
        "win_psexec",
        {"command": "cmd.exe", "executable": str(tmp_path / "missing.exe")},
        native,
        monkeypatch,
        tmp_path,
        capsys,
    )
    assert status == 1
    assert "was not found" in result["msg"]
    assert not native["calls"]
