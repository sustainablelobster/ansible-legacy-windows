"""Check payload behavior with developer Python, without contacting Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Pure helpers are tested directly where executing Windows APIs is not possible.
# pylint: disable=protected-access

import os
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

from tests.unit.payload_support import load_payload, run_payload


@pytest.fixture(name="payload")
def command_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the payload with the same adjacent helper import used on the target.

    :param monkeypatch: Scoped import-path changes.
    :returns: The loaded module without running its command entry point.
    """
    return load_payload("win_command", monkeypatch)


def _run(
    tmp_path: Path, arguments: object
) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
    return run_payload("win_command", tmp_path, arguments)


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"cmd": None},
        {"cmd": "test.exe", "argv": ["other.exe"]},
        {"argv": False, "chdir": "invalid\x00path"},
        {"cmd": "test.exe", "creates": "invalid\x00path"},
    ],
)
def test_check_mode_skips_before_command_validation(
    tmp_path: Path, arguments: dict[str, object]
) -> None:
    process, result = _run(tmp_path, {**arguments, "_ansible_check_mode": True})

    assert process.returncode == 0
    assert result == {
        "changed": False,
        "skipped": True,
        "msg": "remote module (sustainablelobster.legacy_windows.win_command) "
        "does not support check mode",
    }


def test_unknown_argument_fails_even_in_check_mode(tmp_path: Path) -> None:
    process, result = _run(
        tmp_path, {"unknown": "private-value", "_ansible_check_mode": True}
    )

    assert process.returncode == 1
    assert result["changed"] is False
    assert result["failed"] is True
    assert "Unsupported parameters" in str(result["msg"])
    assert "private-value" not in process.stdout


@pytest.mark.parametrize("command_keys", [("cmd", "argv"), ("cmd", "_raw_params")])
def test_mutual_exclusion_counts_explicit_null(
    tmp_path: Path, command_keys: tuple[str, str]
) -> None:
    process, result = _run(tmp_path, dict.fromkeys(command_keys))

    assert process.returncode == 1
    assert result["msg"] == "parameters are mutually exclusive: _raw_params, argv, cmd"


def test_a_command_parameter_is_required(tmp_path: Path) -> None:
    process, result = _run(tmp_path, {})

    assert process.returncode == 1
    assert result["msg"] == "one of the following is required: _raw_params, argv, cmd"


@pytest.mark.parametrize(
    "arguments",
    [
        {"cmd": ""},
        {"cmd": None},
        {"argv": None},
        {"_raw_params": ""},
        {"_raw_params": None},
    ],
)
def test_null_command_selection_preserves_released_failure(
    tmp_path: Path, arguments: dict[str, object]
) -> None:
    process, result = _run(tmp_path, arguments)

    assert process.returncode == 1
    assert result["changed"] is False
    assert result["failed"] is True
    assert result["msg"] == (
        "Unhandled exception while executing module: Cannot index into a null array."
    )
    assert "cmd" not in result
    assert "rc" not in result


def test_empty_argv_preserves_released_parameter_binding_failure(
    tmp_path: Path,
) -> None:
    process, result = _run(tmp_path, {"argv": []})

    assert process.returncode == 1
    assert result["changed"] is False and result["failed"] is True
    assert result["msg"] == (
        "Unhandled exception while executing module: Cannot bind argument "
        "to parameter 'FilePath' because it is null."
    )
    assert "cmd" not in result and "rc" not in result


@pytest.mark.parametrize("argv", [[None], ["program", None]])
def test_null_argv_elements_fail_before_guards(
    tmp_path: Path, argv: list[str | None]
) -> None:
    marker = tmp_path / "existing-marker"
    marker.touch()
    process, result = _run(tmp_path, {"argv": argv, "creates": str(marker)})

    assert process.returncode == 1
    assert result["changed"] is False
    assert result["failed"] is True
    assert result["msg"] == (
        'Unhandled exception while executing module: Exception calling "Create" '
        'with "2" argument(s): "Object reference not set to an instance of an object."'
    )
    assert "cmd" not in result
    assert "rc" not in result


def test_whitespace_free_form_reaches_the_filesystem_guard(tmp_path: Path) -> None:
    marker = tmp_path / "existing-marker"
    marker.touch()
    process, result = _run(tmp_path, {"_raw_params": "   ", "creates": str(marker)})

    assert process.returncode == 0
    assert result == {
        "changed": False,
        "skipped": True,
        "cmd": "",
        "rc": 0,
        "msg": "skipped, since " + str(marker) + " exists",
    }


@pytest.mark.parametrize("separator", ["\x1c", "\x1d", "\x1e", "\x1f"])
def test_control_separators_are_not_trimmed_from_arguments(
    payload: ModuleType, separator: str
) -> None:
    value = "argument" + separator
    parameters = payload._parameters({"_raw_params": " \ttool.exe " + value + "\xa0 "})
    assert payload._command(parameters) == (None, "tool.exe " + value)
    assert payload._argv(" tool.exe, \t" + value + "\xa0 ") == ["tool.exe", value]
    assert payload._argv(["tool.exe", value]) == ["tool.exe", value]


def test_whitespace_free_form_launch_failure_retains_command(tmp_path: Path) -> None:
    process, result = _run(tmp_path, {"_raw_params": "   "})

    assert process.returncode == 1
    assert result["changed"] is False
    assert result["failed"] is True
    assert result["cmd"] == ""
    assert result["rc"] == 2
    assert result["msg"] == (
        "Failed to run: '': Cannot bind argument to parameter "
        "'CommandLine' because it is an empty string."
    )


def test_empty_executable_resolves_before_the_filesystem_guard(tmp_path: Path) -> None:
    marker = tmp_path / "existing-marker"
    marker.touch()
    process, result = _run(tmp_path, {"argv": [""], "creates": str(marker)})

    assert process.returncode == 0
    assert result["changed"] is False
    assert result["skipped"] is True
    assert result["cmd"] == ".exe"
    assert result["rc"] == 0


@pytest.mark.parametrize("argv", [True, {}, 1.25])
def test_invalid_argv_type_fails(tmp_path: Path, argv: object) -> None:
    process, result = _run(tmp_path, {"argv": argv})

    assert process.returncode == 1
    assert result["msg"] == "argv must be a list of strings."


@pytest.mark.parametrize(
    "name", ["cmd", "stdin", "output_encoding_override", "chdir", "creates", "removes"]
)
def test_numeric_string_parameters_use_shared_conversion(
    payload: ModuleType, name: str
) -> None:
    arguments: dict[str, object] = {"cmd": "test.exe", name: 1.25}
    assert payload._parameters(arguments)[name] == "1.25"


def test_numeric_argv_entries_use_shared_conversion(payload: ModuleType) -> None:
    assert payload._parameters({"argv": ["tool.exe", 1.0, -0.0, 1e16]})["argv"] == [
        "tool.exe",
        "1.0",
        "0.0",
        "1E+16",
    ]


def test_creates_precedes_removes_and_preserves_cmd(tmp_path: Path) -> None:
    created = tmp_path / "exists"
    created.touch()
    arguments = {
        "CMD": "  missing.exe untouched  ",
        "creates": str(created),
        "removes": str(tmp_path / "missing"),
    }
    first_process, first = _run(tmp_path, arguments)
    second_process, second = _run(tmp_path, arguments)

    assert first_process.returncode == second_process.returncode == 0
    assert (
        first
        == second
        == {
            "changed": False,
            "skipped": True,
            "cmd": "  missing.exe untouched  ",
            "rc": 0,
            "msg": "skipped, since " + str(created) + " exists",
        }
    )


def test_removes_guard_skips_and_trims_free_form(tmp_path: Path) -> None:
    absent = tmp_path / "missing-parent" / "absent"
    process, result = _run(
        tmp_path, {"_raw_params": "  missing.exe argument  ", "removes": str(absent)}
    )

    assert process.returncode == 0
    assert result == {
        "changed": False,
        "skipped": True,
        "cmd": "missing.exe argument",
        "rc": 0,
        "msg": "skipped, since " + str(absent) + " does not exist",
    }


def test_argv_is_quoted_before_a_filesystem_skip(tmp_path: Path) -> None:
    process, result = _run(
        tmp_path,
        {
            "argv": ["no-such-program", "argument value", 'a"b', "", "value\\\n"],
            "removes": str(tmp_path / "absent"),
        },
    )

    assert process.returncode == 0
    assert result["cmd"] == (
        'no-such-program.exe "argument value" "a\\"b" "" "value\\\\\n"'
    )
    assert result["changed"] is False
    assert result["skipped"] is True


@pytest.mark.parametrize("separator", ["\x1c", "\x1d", "\x1e", "\x1f"])
def test_argv_control_separators_remain_unquoted_in_returned_command(
    tmp_path: Path, separator: str
) -> None:
    argument = "left" + separator + "right"
    process, result = _run(
        tmp_path,
        {
            "argv": ["no-such-program", argument],
            "removes": str(tmp_path / "absent"),
        },
    )

    assert process.returncode == 0
    assert result["cmd"] == "no-such-program.exe " + argument
    assert result["changed"] is False and result["skipped"] is True


@pytest.mark.parametrize(
    "separator",
    "\t\n\v\f\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005"
    "\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000",
)
def test_argv_dotnet_whitespace_and_quotes_remain_quoted_in_returned_command(
    tmp_path: Path, separator: str
) -> None:
    argument = "left" + separator + "right"
    process, result = _run(
        tmp_path,
        {
            "argv": ["no-such-program", argument, 'a"b'],
            "removes": str(tmp_path / "absent"),
        },
    )

    assert process.returncode == 0
    assert result["cmd"] == 'no-such-program.exe "' + argument + '" "a\\"b"'
    assert result["changed"] is False and result["skipped"] is True


@pytest.mark.parametrize("name", ["chdir", "creates", "removes"])
@pytest.mark.parametrize("wildcard", ["*", "?"])
def test_wildcards_fail_path_validation_before_guards(
    tmp_path: Path, name: str, wildcard: str
) -> None:
    marker = tmp_path / "existing-marker"
    marker.touch()
    arguments = {
        "cmd": "must-not-run.exe",
        "creates": str(marker),
        name: "C:\\example\\" + wildcard + ".txt",
    }
    process, result = _run(tmp_path, arguments)

    assert process.returncode == 1
    assert result["changed"] is False
    assert result["failed"] is True
    assert result["msg"] == "Invalid Windows path characters in " + name + "."
    assert "cmd" not in result
    assert "rc" not in result


def test_requested_invocation_contains_normalized_defaults(tmp_path: Path) -> None:
    process, result = _run(
        tmp_path,
        {
            "CMD": "tool.exe",
            "removes": str(tmp_path / "absent"),
            "_ansible_inject_invocation": True,
        },
    )
    assert process.returncode == 0
    assert result["invocation"] == {
        "module_args": {
            "cmd": "tool.exe",
            "argv": None,
            "_raw_params": None,
            "chdir": None,
            "creates": None,
            "removes": str(tmp_path / "absent"),
            "stdin": None,
            "output_encoding_override": None,
        }
    }


@pytest.mark.parametrize(
    ("argument", "expected"),
    [
        (None, '""'),
        ("", '""'),
        ("simple", "simple"),
        ("C:\\path\\", "C:\\path\\"),
        ("two words", '"two words"'),
        ("line\nbreak", '"line\nbreak"'),
        ("value\\\n", '"value\\\\\n"'),
        ("value\\\\\n", '"value\\\\\\\\\n"'),
        ("\\\n", '"\\\\\n"'),
        ("value\\\r\n", '"value\\\r\n"'),
        ("value\\\nnext", '"value\\\nnext"'),
        ("value\\\n\n", '"value\\\n\n"'),
        ('a"b', '"a\\"b"'),
        ('a\\"b', '"a\\\\\\"b"'),
        ("space at end\\", '"space at end\\\\"'),
        ("☃", "☃"),
    ],
)
def test_crt_argument_quoting(
    payload: ModuleType, argument: str | None, expected: str
) -> None:
    assert payload._quote_argument(argument) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [("one, two", ["one", "two"]), (42, ["42"]), ([True, 27], ["True", "27"])],
)
def test_known_list_and_string_conversions(
    payload: ModuleType, value: object, expected: list[str]
) -> None:
    assert payload._parameters({"argv": value})["argv"] == expected


def test_path_expansion_is_windows_percent_only(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LEGACY_COMMAND_TEST", r"C:\Example")
    assert payload.as_path(r"%legacy_command_test%\a", "chdir") == r"C:\Example\a"
    assert (
        payload.as_path(r"$LEGACY_COMMAND_TEST\a", "chdir") == r"$LEGACY_COMMAND_TEST\a"
    )
    assert payload.as_path(r"\\?\%LEGACY_COMMAND_TEST%", "chdir") == (
        r"\\?\%LEGACY_COMMAND_TEST%"
    )


@pytest.mark.skipif(os.name == "nt", reason="Only checks the non-Windows diagnostic")
def test_execution_on_non_windows_fails_cleanly(tmp_path: Path) -> None:
    process, result = _run(tmp_path, {"cmd": "tool.exe"})

    assert process.returncode == 1
    assert result["changed"] is False
    assert result["failed"] is True
    assert result["rc"] == 2
    assert "requires a Windows target" in str(result["msg"])
