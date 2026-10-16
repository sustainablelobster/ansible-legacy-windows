"""Exercise Pester's public options, native data boundary and owned cleanup."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module

_RESULT_XML = """<Objs xmlns="http://schemas.microsoft.com/powershell/2004/04">
<Obj RefId="0"><DCT>
<En><S N="Key">changed</S><B N="Value">true</B></En>
<En><S N="Key">pester_version</S><S N="Value">3.4.0</S></En>
<En><S N="Key">output</S><Obj N="Value" RefId="1"><MS>
<I32 N="TotalCount">2</I32><I32 N="FailedCount">1</I32>
</MS></Obj></En>
</DCT></Obj></Objs>"""


@pytest.fixture(name="payload")
def payload_fixture(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load actual target-compatible payload and its concrete XML dictionary I/O.

    :param monkeypatch: Scoped target-helper import paths.
    :returns: Actual payload with no vendor process launched during import.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(
        str(ROOT / "legacy_community_windows/plugins/module_utils")
    )
    return load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_pester.py",
        "community_pester",
    )


class Process:
    """Write independently chosen JSON or native CLIXML vendor results."""

    def __init__(self) -> None:
        self.returncode = 0
        self.format = "json"
        self.command: list[str] = []
        self.request: dict[str, Any] = {}
        self.script = ""
        self.interrupt = False
        self.killed = False

    # This independent vendor fake uses the normal process protocol but writes
    # Pester-specific real result files rather than sharing a fake interpreter.
    # pylint: disable=duplicate-code
    def __enter__(self) -> "Process":
        return self

    def __exit__(self, *_arguments: object) -> None:
        return None

    def communicate(self) -> tuple[bytes, bytes]:
        """Write an independent vendor result in the observed owned directory.

        :returns: Native stdout/stderr independent of the result file.
        :raises KeyboardInterrupt: The requested cancellation interrupts this call.
        """
        if self.interrupt:
            self.interrupt = False
            raise KeyboardInterrupt()
        directory = Path(self.command[-1])
        if self.format == "json":
            (directory / "result.json").write_text(
                json.dumps(
                    {
                        "changed": True,
                        "pester_version": "3.4.0",
                        "output": {
                            "TotalCount": 2,
                            "FailedCount": 1,
                        },
                    }
                ),
                encoding="utf-8",
            )
        elif self.format == "xml":
            (directory / "result.xml").write_text(_RESULT_XML, encoding="utf-8-sig")
        return b"vendor host output", b"independent native failure"

    # pylint: enable=duplicate-code

    def kill(self) -> None:
        """Record terminating the single owned vendor process."""
        self.killed = True


@pytest.fixture(name="process")
def process_fixture(payload: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Process:
    """Replace only native process creation under real XML and file handling.

    :param payload: Actual Pester payload.
    :param monkeypatch: Scoped native process substitution.
    :returns: Controllable process with independently chosen results.
    """
    process = Process()
    monkeypatch.setattr(payload, "_engine", lambda: r"C:\Windows\powershell.exe")

    def launch(command: list[str], **streams: Any) -> Process:
        """Capture real operation files and arguments before returning the process.

        :param command: Static flags and owned file paths only.
        :param streams: Parent-owned output pipes.
        :returns: Independent fake vendor process.
        """
        process.command = command
        process.script = Path(command[-2]).read_text(encoding="utf-8-sig")
        process.request = payload.clixml.values(
            payload.clixml.read(str(Path(command[-1]) / "request.xml"))
        )
        assert set(streams) == {"stdin", "stdout", "stderr"}
        return process

    monkeypatch.setattr(payload.subprocess, "Popen", launch)
    return process


@pytest.mark.parametrize("result_format", ["json", "xml"])
def test_json_and_ps2_clixml_results_preserve_failing_test_counts_without_task_failure(
    payload: ModuleType,
    process: Process,
    result_format: str,
) -> None:
    process.format = result_format
    result = getattr(payload, "_invoke")({"path": r"C:\fixture.tests.ps1"})
    assert result["changed"] is True
    assert result["pester_version"] == "3.4.0"
    assert result["output"] == {"TotalCount": 2, "FailedCount": 1}
    assert "failed" not in result
    assert not Path(process.command[-1]).exists()


def test_public_alias_parameters_tags_and_check_mode_are_data_only(
    payload: ModuleType,
    process: Process,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    dangerous = "fixture';throw 'not code'"
    argument_file = tmp_path / "pester.json"
    argument_file.write_text(
        json.dumps(
            {
                "path": r"C:\fixture.tests.ps1",
                "minimum_version": "3.0.0",
                "tags": "CI,Unit",
                "test_parameters": {
                    "Name": dangerous,
                    "Enabled": True,
                    "Values": [1, None],
                },
                "_ansible_check_mode": True,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", [str(payload.__file__), str(argument_file)])
    status, result = invoke_payload(payload, capsys)
    assert status == 0 and result["changed"] is True
    assert process.request == {
        "path": r"C:\fixture.tests.ps1",
        "version": "3.0.0",
        "tags": ["CI", "Unit"],
        "test_parameters": {"Name": dangerous, "Enabled": True, "Values": [1, None]},
        "check_mode": True,
        "output_file": None,
        "output_format": "NunitXML",
    }
    assert dangerous not in process.script
    assert dangerous not in " ".join(process.command)


def test_clixml_request_escapes_controls_and_literal_escape_sequences(
    payload: ModuleType,
    process: Process,
) -> None:
    value = "line\r\n\x00 _x0041_ café"
    getattr(payload, "_invoke")({"path": value})
    assert process.request["path"] == value


def test_missing_vendor_result_is_actionable_and_cleans_owned_files(
    payload: ModuleType,
    process: Process,
) -> None:
    process.format = "none"
    with pytest.raises(OSError, match="independent native failure"):
        getattr(payload, "_invoke")({"path": "fixture"})
    assert not Path(process.command[-1]).exists()


def test_interruption_kills_the_owned_process_and_removes_owned_files(
    payload: ModuleType,
    process: Process,
) -> None:
    process.interrupt = True
    with pytest.raises(KeyboardInterrupt):
        getattr(payload, "_invoke")({"path": "fixture"})
    assert process.killed is True
    assert not Path(process.command[-1]).exists()


def test_nonzero_native_process_status_is_not_reported_as_success(
    payload: ModuleType,
    process: Process,
) -> None:
    process.returncode = 1
    result = getattr(payload, "_invoke")({"path": "fixture"})
    assert result["failed"] is True
    assert "process failed" in result["msg"]


def test_missing_public_path_fails_before_any_vendor_launch(
    payload: ModuleType,
) -> None:
    with pytest.raises(ValueError, match="path is required"):
        getattr(payload, "_execute")({})
