"""Exercise the standalone payload under the developer's Python interpreter."""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

MODULE = (
    Path(__file__).resolve().parents[2]
    / "legacy_windows/plugins"
    / "modules"
    / "win_ping.py"
)
HELPER = MODULE.parent.parent / "module_utils" / "legacy_windows_module.py"


def _stage_payload(tmp_path: Path) -> Path:
    payload_directory = tmp_path / "payload"
    payload_directory.mkdir(exist_ok=True)
    staged_module = payload_directory / MODULE.name
    shutil.copyfile(MODULE, staged_module)
    shutil.copyfile(HELPER, payload_directory / HELPER.name)
    return staged_module


def _run_raw(
    tmp_path: Path, contents: bytes
) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
    argument_file = tmp_path / "arguments.json"
    argument_file.write_bytes(contents)
    process = subprocess.run(
        [sys.executable, str(_stage_payload(tmp_path)), str(argument_file)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    result: dict[str, object] = json.loads(process.stdout)
    assert not process.stderr
    return process, result


def _run(
    tmp_path: Path, arguments: object
) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
    return _run_raw(tmp_path, json.dumps(arguments).encode("utf-8"))


@pytest.mark.parametrize("check_mode", [False, True])
def test_default_response_is_unchanged(tmp_path: Path, check_mode: bool) -> None:
    arguments = {"_ansible_check_mode": check_mode}
    first_process, first = _run(tmp_path, arguments)
    second_process, second = _run(tmp_path, arguments)

    assert first_process.returncode == second_process.returncode == 0
    assert first == second == {"changed": False, "ping": "pong"}
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "arguments.json",
        "payload",
    ]


@pytest.mark.parametrize("flag", ["y", "t", "1.0", " Y ", 1.0])
def test_boolean_true_aliases_in_controller_flags(tmp_path: Path, flag: object) -> None:
    process, result = _run(tmp_path, {"_ansible_inject_invocation": flag})

    assert process.returncode == 0
    assert result["invocation"] == {"module_args": {"data": "pong"}}


@pytest.mark.parametrize("flag", ["n", "f", "0.0", " F ", 0.0])
def test_boolean_false_aliases_in_controller_flags(
    tmp_path: Path, flag: object
) -> None:
    process, result = _run(tmp_path, {"_ansible_inject_invocation": flag})

    assert process.returncode == 0
    assert result == {"changed": False, "ping": "pong"}


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        ("connected", "connected"),
        ("", ""),
        (
            '\u2603 \U0001f99e "quoted"\r\nsecond line',
            '\u2603 \U0001f99e "quoted"\r\nsecond line',
        ),
        (None, None),
        (True, "True"),
        (False, "False"),
        (27, "27"),
        ([], "System.Object[]"),
        (["a", "b"], "System.Object[]"),
        ({"a": "b"}, "System.Collections.Hashtable"),
    ],
)
def test_data_conversion(tmp_path: Path, data: object, expected: object) -> None:
    process, result = _run(tmp_path, {"data": data})

    assert process.returncode == 0
    assert result == {"changed": False, "ping": expected}


@pytest.mark.parametrize("name", ["data", "DATA", "dAtA"])
def test_data_parameter_name_is_case_insensitive(tmp_path: Path, name: str) -> None:
    process, result = _run(tmp_path, {name: "connected"})

    assert process.returncode == 0
    assert result == {"changed": False, "ping": "connected"}


@pytest.mark.parametrize("data", ["crash", "CRASH", "cRaSh"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_requested_exception_is_reported(
    tmp_path: Path, data: str, check_mode: bool
) -> None:
    process, result = _run(tmp_path, {"data": data, "_ansible_check_mode": check_mode})

    assert process.returncode == 1
    assert result["failed"] is True
    assert result["changed"] is False
    assert result["msg"] == "Unhandled exception while executing module: boom"
    assert "RuntimeError: boom" in str(result["exception"])


def test_crash_text_is_not_trimmed(tmp_path: Path) -> None:
    process, result = _run(tmp_path, {"data": " crash "})

    assert process.returncode == 0
    assert result["ping"] == " crash "


@pytest.mark.parametrize("name", ["unexpected", "Unexpected"])
def test_unknown_argument_fails_without_echoing_its_value(
    tmp_path: Path, name: str
) -> None:
    process, result = _run(tmp_path, {name: "private-value"})

    assert process.returncode == 1
    assert result["failed"] is True
    assert result["changed"] is False
    assert name in str(result["msg"])
    assert "Supported parameters include: data" in str(result["msg"])
    assert "private-value" not in process.stdout


def test_controller_metadata_does_not_become_a_module_argument(tmp_path: Path) -> None:
    process, result = _run(
        tmp_path,
        {
            "_ansible_check_mode": True,
            "_ansible_no_log": True,
            "_ansible_module_name": "sustainablelobster.legacy_windows.win_ping",
            "_ansible_verbosity": 0,
        },
    )

    assert process.returncode == 0
    assert result == {"changed": False, "ping": "pong"}


def test_invocation_is_supplied_only_when_requested(tmp_path: Path) -> None:
    process, result = _run(tmp_path, {"data": True, "_ansible_inject_invocation": True})

    assert process.returncode == 0
    assert result["invocation"] == {"module_args": {"data": "True"}}


def test_controller_can_ignore_unknown_arguments(tmp_path: Path) -> None:
    process, result = _run(
        tmp_path,
        {
            "unexpected": "retained",
            "_ansible_ignore_unknown_opts": True,
            "_ansible_inject_invocation": True,
        },
    )

    assert process.returncode == 0
    assert result["invocation"] == {
        "module_args": {"data": "pong", "unexpected": "retained"}
    }


@pytest.mark.parametrize("arguments", [[], None, "text", 17])
def test_argument_file_requires_an_object(tmp_path: Path, arguments: object) -> None:
    process, result = _run(tmp_path, arguments)

    assert process.returncode == 1
    assert result["failed"] is True
    assert "JSON object" in str(result["msg"])


@pytest.mark.parametrize(
    "contents",
    [b"{", b"\xff", b'{"data":NaN}', b'{"data":Infinity}', b'{"data":1e400}'],
)
def test_invalid_argument_encoding_or_numbers_fail(
    tmp_path: Path, contents: bytes
) -> None:
    process, result = _run_raw(tmp_path, contents)

    assert process.returncode == 1
    assert result["failed"] is True
    assert result["changed"] is False
    assert result["msg"]


@pytest.mark.parametrize("arguments", [[], ["missing.json"]])
def test_missing_argument_file_fails(tmp_path: Path, arguments: list[str]) -> None:
    process = subprocess.run(
        [sys.executable, str(_stage_payload(tmp_path)), *arguments],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    result = json.loads(process.stdout)

    assert process.returncode == 1
    assert not process.stderr
    assert result["failed"] is True
    assert result["changed"] is False
    assert result["msg"]
