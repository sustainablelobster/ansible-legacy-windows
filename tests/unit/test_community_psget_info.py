"""Exercise fixed PowerShellGet queries and their data-only process boundary."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module

_HELPERS = ROOT / "legacy_community_windows/plugins/module_utils"


@pytest.fixture(name="engine")
def engine_fixture() -> ModuleType:
    """Load the native vendor process boundary without executing PowerShell.

    :returns: Actual Python3.4-compatible engine boundary.
    """
    return load_module(
        _HELPERS / "legacy_community_windows_psget_engine.py", "community_psget_engine"
    )


# Independent I/O, owned-file observations and cancellation controls stay explicit.
class Process:  # pylint: disable=too-many-instance-attributes
    """Return independently chosen engine results through an actual result file."""

    def __init__(self) -> None:
        self.returncode = 0
        self.response: object = {
            "success": True,
            "result": {"changed": False, "rows": []},
        }
        self.commands: list[list[str]] = []
        self.scripts: list[str] = []
        self.requests: list[dict[str, Any]] = []
        self.write_result = True
        self.interrupt = False
        self.killed = False

    def __enter__(self) -> "Process":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def communicate(self, data: bytes | None = None) -> tuple[bytes, bytes]:
        """Receive the real serialized request and write an independent response.

        :param data: JSON supplied through standard input, not command text.
        :returns: Deliberately unrelated vendor output and diagnostic streams.
        :raises KeyboardInterrupt: The test models an interrupted vendor process.
        """
        if self.interrupt:
            self.interrupt = False
            raise KeyboardInterrupt()
        if data is not None:
            request = json.loads(data)
            self.requests.append(request)
            if self.write_result:
                Path(request["result_path"]).write_text(
                    json.dumps(self.response), encoding="utf-8"
                )
        return b"unstructured vendor host output", b"independent engine failure"

    def kill(self) -> None:
        """Record terminating the owned vendor process after interruption."""
        self.killed = True


@pytest.fixture(name="process")
def process_fixture(engine: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Process:
    """Replace only native process creation beneath the actual data protocol.

    :param engine: Actual vendor engine helper.
    :param monkeypatch: Scoped executable and process substitutions.
    :returns: Independently controlled engine process.
    """
    process = Process()
    monkeypatch.setattr(engine, "_engine", lambda: r"C:\Windows\powershell.exe")

    def launch(command: list[str], **streams: Any) -> Process:
        """Capture the real process command without interpreting user data.

        :param command: Static engine launch flags and owned operation-file path.
        :param streams: Parent-owned input/output pipe configuration.
        :returns: Independently controlled vendor process.
        """
        process.commands.append(command)
        process.scripts.append(Path(command[-1]).read_text(encoding="utf-8-sig"))
        assert set(streams) == {"stdin", "stdout", "stderr"}
        return process

    monkeypatch.setattr(engine.subprocess, "Popen", launch)
    return process


def test_engine_passes_values_only_as_data_and_removes_owned_result_directory(
    engine: ModuleType,
    process: Process,
) -> None:
    dangerous = "name';throw 'injected'; # café"
    result = engine.invoke("@{ changed=$false; rows=@() }", {"name": dangerous})
    assert result == {"changed": False, "rows": []}
    command = process.commands[0]
    assert dangerous not in process.scripts[0]
    assert dangerous not in " ".join(command)
    assert process.requests[0]["parameters"] == {"name": dangerous}
    assert not Path(process.requests[0]["result_path"]).parent.exists()


def test_engine_preserves_vendor_warnings(engine: ModuleType, process: Process) -> None:
    process.response = {
        "success": True,
        "result": {"changed": False},
        "warnings": ["vendor warning"],
    }
    assert engine.invoke("@{}", {})["warnings"] == ["vendor warning"]


@pytest.mark.parametrize(
    "response", [None, [], {}, {"success": "yes"}, {"success": True, "result": []}]
)
def test_invalid_engine_responses_are_actionable(
    engine: ModuleType,
    process: Process,
    response: object,
) -> None:
    process.response = response
    with pytest.raises(ValueError, match="PowerShellGet"):
        engine.invoke("@{}", {})
    assert not Path(process.requests[0]["result_path"]).parent.exists()


def test_failed_vendor_operation_redacts_supplied_password(
    engine: ModuleType,
    process: Process,
) -> None:
    process.response = {"success": False, "message": "vendor rejected supplied-secret"}
    with pytest.raises(OSError, match="PASSWORD_REPLACED") as failure:
        engine.invoke("@{}", {"password": "supplied-secret"})
    assert "supplied-secret" not in str(failure.value)


def test_missing_engine_result_keeps_native_failure_actionable(
    engine: ModuleType,
    process: Process,
) -> None:
    process.write_result = False
    with pytest.raises(OSError, match="independent engine failure"):
        engine.invoke("@{}", {})
    assert not Path(process.requests[0]["result_path"]).parent.exists()


def test_interrupted_vendor_process_is_terminated(
    engine: ModuleType,
    process: Process,
) -> None:
    process.interrupt = True
    with pytest.raises(KeyboardInterrupt):
        engine.invoke("@{}", {})
    assert process.killed is True
    assert not Path(process.commands[0][-1]).parent.exists()


def test_largest_fixed_operation_uses_a_short_file_command_and_cleans_it(
    engine: ModuleType,
    process: Process,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(str(_HELPERS))
    payload = load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_psmodule_info.py",
        "community_large_module_query",
    )
    operation = getattr(payload, "_OPERATION")
    engine.invoke(operation, {"name": "*"})
    command = process.commands[0]
    assert "-File" in command and "-EncodedCommand" not in command
    assert len(" ".join(command)) < 2048
    assert len(process.scripts[0]) > 8192
    assert operation in process.scripts[0]
    assert not Path(command[-1]).parent.exists()


@pytest.mark.parametrize(
    "query",
    [
        ("win_psrepository_info", "repositories", {}, {"name": "*"}),
        (
            "win_psscript_info",
            "scripts",
            {"repository": "Local"},
            {"name": "*", "repository": "Local"},
        ),
        (
            "win_psmodule_info",
            "modules",
            {
                "name": "Fixture*",
                "include_properties": ["name", "version"],
                "skip_module_repository_info": "yes",
            },
            {
                "name": "Fixture*",
                "repository": None,
                "include_properties": ["name", "version"],
                "skip_module_repository_info": True,
            },
        ),
    ],
)
def test_public_info_payloads_preserve_queries_and_plain_results(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    query: tuple[str, str, dict[str, Any], dict[str, Any]],
) -> None:
    name, field, arguments, expected = query
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(str(_HELPERS))
    payload = load_module(
        ROOT / "legacy_community_windows/plugins/modules" / (name + ".py"),
        "community_" + name,
    )
    received: list[dict[str, Any]] = []
    data = {"changed": False, field: [{"name": "Fixture", "version": "1.2.3"}]}

    def invoke(_script: str, parameters: dict[str, Any]) -> dict[str, Any]:
        """Return independently selected vendor rows for the requested query.

        :param parameters: Converted public query options.
        :returns: Independent vendor rows, without rereading payload constants.
        """
        received.append(parameters)
        return data

    monkeypatch.setattr(payload, "invoke", invoke)
    argument_file = tmp_path / "info-arguments.json"
    argument_file.write_text(
        json.dumps({**arguments, "_ansible_check_mode": True}), encoding="utf-8"
    )
    monkeypatch.setattr(sys, "argv", [str(payload.__file__), str(argument_file)])
    status, result = invoke_payload(payload, capsys)
    assert status == 0
    assert result == data
    assert received == [expected]
