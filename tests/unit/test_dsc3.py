"""Exercise DSC's public JSON contract with only the child process replaced."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload


def _document(
    operation: str = "set", changed: list[str] | None = None
) -> dict[str, Any]:
    state_keys = (
        ("beforeState", "afterState", "changedProperties")
        if operation == "set"
        else ("actualState", "desiredState", "differingProperties")
    )
    return {
        "metadata": {"Microsoft.DSC": {"operation": operation}},
        "results": [
            {
                "name": "managed resource",
                "type": "Example/Resource",
                "result": {
                    state_keys[0]: {"message": "before", "untouched": "protected"},
                    state_keys[1]: {"message": "after", "untouched": "protected"},
                    state_keys[2]: changed or [],
                },
            }
        ],
    }


@pytest.fixture(name="run_request")
def request_runner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> Any:
    """Run the payload entry point with a recorded command boundary.

    :param monkeypatch: Scoped process and argument substitutions.
    :param tmp_path: Owned argument-file directory.
    :param capsys: Captured public JSON output.
    :returns: Request runner and the child-process recorder.
    """
    payload = load_payload("dsc3", monkeypatch)
    executor = MagicMock(
        return_value={"rc": 0, "stdout": json.dumps(_document()), "stderr": ""}
    )
    monkeypatch.setattr(payload, "run_command", executor)
    monkeypatch.setattr(
        payload, "resolve_executable", lambda *_: r"C:\Owned DSC\dsc.exe"
    )
    argument_file = tmp_path / "arguments.json"
    monkeypatch.setattr(sys, "argv", ["dsc3.py", str(argument_file)])

    def run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        """Emit the payload's public result.

        :param arguments: Request dictionary passed to the entry point.
        :returns: Exit status and decoded JSON result.
        """
        argument_file.write_text(json.dumps(arguments), encoding="utf-8")
        return invoke_payload(payload, capsys)

    return run, executor


@pytest.mark.parametrize("check", [False, True])
def test_external_command_and_default_schema(run_request: Any, check: bool) -> None:
    run, executor = run_request
    code, result = run({"config": {"resources": []}, "_ansible_check_mode": check})
    assert code == 0
    assert result == {"changed": False, "rc": 0, "stderr": "", "result": _document()}
    executable, command, parameters = executor.call_args.args
    assert executable == r"C:\Owned DSC\dsc.exe"
    assert command == subprocess.list2cmdline(
        [
            executable,
            "--trace-format=plaintext",
            "--progress-format=none",
            "--trace-level=warn",
            "config",
            "test" if check else "set",
            "--file=-",
            "--output-format=json",
        ]
    )
    assert json.loads(parameters["stdin"]) == {
        "resources": [],
        "$schema": "https://aka.ms/dsc/schemas/v3/bundled/config/document.json",
    }
    assert (
        parameters["chdir"] is None and parameters["output_encoding_override"] is None
    )


@pytest.mark.parametrize("level", ["WARN", "Info", "ErRoR", None])
def test_trace_choice_binding_preserves_original_case_and_explicit_null(
    run_request: Any, level: str | None
) -> None:
    run, executor = run_request
    assert run({"config": {"resources": []}, "trace_level": level})[0] == 0
    assert "--trace-level=" + (level or "") in executor.call_args.args[1]


@pytest.mark.parametrize("schema", [None, "https://example.invalid/schema"])
def test_schema_and_parameter_input(run_request: Any, schema: str | None) -> None:
    run, executor = run_request
    assert (
        run({"config": {"$schema": schema}, "parameters": {"text": '"\\<λ>'}})[0] == 0
    )
    _, command, parameters = executor.call_args.args
    assert "--parameters=" in command
    assert json.loads(parameters["stdin"])["$schema"] == (
        schema or "https://aka.ms/dsc/schemas/v3/bundled/config/document.json"
    )


def test_remote_file_has_no_standard_input(run_request: Any) -> None:
    run, executor = run_request
    assert (
        run({"config_file": r"C:\Owned Files\config.yml", "remote_config_file": True})[
            0
        ]
        == 0
    )
    assert executor.call_args.args[2]["stdin"] is None
    assert '"--file=C:\\Owned Files\\config.yml"' in executor.call_args.args[1]


@pytest.mark.parametrize("operation", ["set", "test"])
def test_complete_result_and_selective_diff(run_request: Any, operation: str) -> None:
    run, executor = run_request
    document = _document(operation, ["message", "missing"])
    executor.return_value["stdout"] = json.dumps(document)
    code, result = run({"config": {}, "_ansible_diff": True})
    assert code == 0 and result["changed"] is True
    assert result["result"] == document
    for side, message in (("before", "before"), ("after", "after")):
        assert result["diff"][side]["resources"] == [
            {
                "name": "managed resource",
                "type": "Example/Resource",
                "properties": {"message": message},
            }
        ]


def test_unchanged_diff_retains_identity_without_properties(run_request: Any) -> None:
    run, _ = run_request
    code, result = run({"config": {}, "_ansible_diff": True})
    assert code == 0 and result["changed"] is False
    assert (
        result["diff"]["before"]
        == result["diff"]["after"]
        == {"resources": [{"name": "managed resource", "type": "Example/Resource"}]}
    )


def test_not_in_desired_state_changes_without_a_property_diff(run_request: Any) -> None:
    run, executor = run_request
    document = _document("test")
    document["results"][0]["result"]["actualState"]["_inDesiredState"] = False
    executor.return_value["stdout"] = json.dumps(document)
    assert run({"config": {}, "_ansible_check_mode": True})[1]["changed"] is True


@pytest.mark.parametrize(
    "rc,message",
    [
        (1, "Invalid arguments (ExitCode=1)"),
        (2, "Resource error (ExitCode=2)"),
        (3, "JSON serizliation error (ExitCode=3)"),
        (4, "Input YAML or JSON is invalid (ExitCode=4)"),
        (5, "Data failed schema validation (ExitCode=5)"),
        (17, "Error: ExitCode=17"),
    ],
)
def test_child_failures_preserve_exit_and_diagnostics(
    run_request: Any, rc: int, message: str
) -> None:
    run, executor = run_request
    executor.return_value = {
        "rc": rc,
        "failed": True,
        "stdout": "not JSON",
        "stderr": "error\r\n",
    }
    assert run({"config": {}}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "rc": rc,
            "stderr": "error\r\n",
            "msg": message,
        },
    )


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({}, "one of the following is required: config, config_file"),
        (
            {"config": {}, "config_file": "file.yml"},
            "parameters are mutually exclusive: config, config_file",
        ),
        (
            {"config": {}, "trace_level": "invalid"},
            "value of trace_level must be one of: error, warn, info, debug, trace. "
            "Got no match for: invalid",
        ),
        (
            {"config": {}, "trace_level": ""},
            "value of trace_level must be one of: error, warn, info, debug, trace. "
            "Got no match for: ",
        ),
    ],
)
def test_validation_precedes_child_execution(
    run_request: Any, arguments: dict[str, Any], message: str
) -> None:
    run, executor = run_request
    assert run(arguments) == (1, {"changed": False, "failed": True, "msg": message})
    executor.assert_not_called()


def test_unexpected_operation_retains_result_and_empty_diff(run_request: Any) -> None:
    run, executor = run_request
    document = {"metadata": {"Microsoft.DSC": {"operation": "get"}}, "results": []}
    executor.return_value["stdout"] = json.dumps(document)
    code, result = run({"config": {}, "_ansible_diff": True})
    assert code == 1
    assert result["msg"] == "Unexpected operation result of type 'get'"
    assert result["result"] == document
    assert result["diff"] == {"before": {"resources": []}, "after": {"resources": []}}


def test_process_creation_failure_has_upstream_message_and_no_child_fields(
    run_request: Any,
) -> None:
    run, executor = run_request
    executor.return_value = {
        "rc": 2,
        "failed": True,
        "msg": "Failed to run: 'dsc.exe': [WinError 2] The system cannot find the file specified",
    }
    code, result = run({"config": {}})
    assert code == 1
    assert result == {
        "changed": False,
        "failed": True,
        "msg": (
            "Unhandled exception while executing module: Exception calling "
            '"CreateProcess" with "7" argument(s): "CreateProcessW() failed '
            "(The system cannot find the file specified, "
            'Win32ErrorCode 2 - 0x00000002)"'
        ),
    }
