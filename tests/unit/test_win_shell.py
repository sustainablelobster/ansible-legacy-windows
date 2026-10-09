"""Exercise shell payload contracts locally without starting a Windows process."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Pure helpers and a replaced child-process boundary isolate controller evidence.
# pylint: disable=protected-access

import base64
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import load_payload, run_payload


@pytest.fixture(name="payload")
def shell_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the shell payload with its adjacent target helpers.

    :param monkeypatch: Scoped import-path and locale substitutions.
    :returns: The imported module without invoking its entry point.
    """
    return load_payload("win_shell", monkeypatch)


def _execute(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    arguments: dict[str, object],
    child: dict[str, object] | None = None,
    use_real_probe: bool = False,
) -> tuple[dict[str, object], dict[str, object]]:
    captured: dict[str, object] = {}

    def _run_child(
        executable: str, command_line: str, parameters: dict[str, object]
    ) -> dict[str, object]:
        captured.update(
            executable=executable, command_line=command_line, parameters=parameters
        )
        return (
            {"changed": True, "cmd": command_line, "rc": 0, "stdout": "", "stderr": ""}
            if child is None
            else dict(child)
        )

    monkeypatch.setattr(payload, "read_arguments", lambda *unused: arguments)
    monkeypatch.setattr(payload, "run_command", _run_child)
    if not use_real_probe:
        monkeypatch.setattr(payload, "_powershell_input_encoding", lambda *_args: True)
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    return payload._execute(), captured


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"cmd": None},
        {"cmd": "echo unused", "_raw_params": None},
        {"cmd": "echo unused", "chdir": "invalid\0path"},
        {"cmd": "echo unused", "no_profile": "invalid"},
    ],
)
def test_check_mode_skips_before_argument_values_are_validated(
    tmp_path: Path, arguments: dict[str, object]
) -> None:
    process, result = run_payload(
        "win_shell", tmp_path, {**arguments, "_ansible_check_mode": True}
    )
    assert process.returncode == 0
    assert result == {
        "changed": False,
        "skipped": True,
        "msg": "remote module (sustainablelobster.legacy_windows.win_shell) "
        "does not support check mode",
    }


def test_unknown_options_fail_even_in_check_mode(tmp_path: Path) -> None:
    process, result = run_payload(
        "win_shell", tmp_path, {"unsupported": "private", "_ansible_check_mode": True}
    )
    assert process.returncode == 1
    assert result["changed"] is False
    assert result["failed"] is True
    assert "Unsupported parameters" in str(result["msg"])
    assert "private" not in process.stdout


@pytest.mark.parametrize("arguments", [{}, {"cmd": None}, {"_raw_params": None}])
def test_missing_or_null_command_fails_without_starting_a_shell(
    tmp_path: Path, arguments: dict[str, object]
) -> None:
    process, result = run_payload("win_shell", tmp_path, arguments)
    assert process.returncode == 1
    assert result["changed"] is False
    assert result["failed"] is True
    assert "cmd" in str(result["msg"])
    assert "rc" not in result


def test_free_form_alias_wins_over_named_command(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, captured = _execute(
        payload,
        monkeypatch,
        {"cmd": "named", "_raw_params": "  alias  ", "executable": "cmd"},
    )
    assert result["cmd"] == "alias"
    assert captured["command_line"] == '"cmd.exe" /c alias'


@pytest.mark.parametrize("command", ["", "   ", "\t\r\n", "\u2000\u2001\u202f"])
def test_empty_shell_text_is_not_rejected(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    result, captured = _execute(
        payload, monkeypatch, {"cmd": command, "executable": "cmd"}
    )
    assert result["cmd"] == ""
    assert captured["command_line"] == '"cmd.exe" /c '


def test_trimming_uses_dotnet_whitespace_not_python_extra_control_characters(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, captured = _execute(
        payload, monkeypatch, {"cmd": "\t\x1cecho text\x1f\n", "executable": "cmd"}
    )
    assert result["cmd"] == "\x1cecho text\x1f"
    assert captured["command_line"] == '"cmd.exe" /c \x1cecho text\x1f'


def test_creates_guard_precedes_removes_and_shell_selection(tmp_path: Path) -> None:
    marker = tmp_path / "existing-marker"
    marker.touch()
    process, result = run_payload(
        "win_shell",
        tmp_path,
        {"cmd": "  never executed  ", "creates": str(marker), "removes": "absent"},
    )
    assert process.returncode == 0
    assert result == {
        "changed": False,
        "skipped": True,
        "cmd": "never executed",
        "rc": 0,
        "msg": "skipped, since " + str(marker) + " exists",
    }


def test_removes_guard_skips_before_encoding_or_executable_lookup(
    tmp_path: Path,
) -> None:
    absent = tmp_path / "absent-marker"
    process, result = run_payload(
        "win_shell",
        tmp_path,
        {
            "cmd": "do not run",
            "removes": str(absent),
            "executable": "nonexistent-shell",
            "output_encoding_override": "nonexistent-encoding",
        },
    )
    assert process.returncode == 0
    assert result["cmd"] == "do not run"
    assert result["rc"] == 0
    assert result["skipped"] is True
    assert result["msg"] == "skipped, since " + str(absent) + " does not exist"


@pytest.mark.parametrize("name", ["chdir", "creates", "removes", "executable"])
@pytest.mark.parametrize(
    "value", ["", "   ", "invalid\0path", "wildcard*", "wildcard?"]
)
def test_invalid_paths_fail_before_a_guard_can_skip(
    tmp_path: Path, name: str, value: str
) -> None:
    marker = tmp_path / "existing-marker"
    marker.touch()
    arguments = {"cmd": "unused", "creates": str(marker), name: value}
    process, result = run_payload("win_shell", tmp_path, arguments)
    assert process.returncode == 1
    assert result["changed"] is False
    assert result["failed"] is True
    assert name in str(result["msg"])


@pytest.mark.parametrize(
    ("executable", "expected"),
    [
        ("cmd", "cmd.exe"),
        ("cmd.exe", "cmd.exe"),
        ("cmd.EXE", "cmd.EXE.exe"),
        ("other.com", "other.com.exe"),
        (r"C:\My Tools\shell.exe", r"C:\My Tools\shell.exe"),
        ("PowerShell.EXE", "PowerShell.EXE.exe"),
    ],
)
def test_non_powershell_executable_gets_the_raw_slash_c_command(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    executable: str,
    expected: str,
) -> None:
    text = 'echo "two words" & echo next>out.txt'
    result, captured = _execute(
        payload,
        monkeypatch,
        {"cmd": text, "executable": executable, "no_profile": True},
    )
    assert result["cmd"] == text
    assert captured["executable"] == expected
    assert captured["command_line"] == f'"{expected}" /c {text}'


@pytest.mark.parametrize("executable", [None, "powershell", "PoWeRsHeLl.exe", "pwsh"])
def test_powershell_receives_an_encoded_script(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, executable: str | None
) -> None:
    text = "Write-Output 'Café 雪'"
    result, captured = _execute(
        payload, monkeypatch, {"cmd": text, "executable": executable}
    )
    command_line = str(captured["command_line"])
    script = base64.b64decode(command_line.rsplit(" ", 1)[1]).decode("utf-16-le")
    assert result["cmd"] == text
    assert " -noninteractive -encodedcommand " in command_line
    assert "-noprofile" not in command_line
    assert script.endswith(text)
    if not executable:
        assert captured["executable"] == (
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        )


def test_powershell_encoding_replaces_unpaired_surrogates_without_losing_pairs(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    text = "Write-Output '\ud800\udfff\ud800X\udfff'"
    result, captured = _execute(payload, monkeypatch, {"cmd": text})
    command_line = str(captured["command_line"])
    script = base64.b64decode(command_line.rsplit(" ", 1)[1]).decode("utf-16-le")
    assert result["cmd"] == text
    assert script.endswith("Write-Output '\U000103ff\ufffdX\ufffd'")


def _diagnostic_process(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    stdout: bytes,
    stderr: bytes = b"",
    returncode: int = 0,
) -> MagicMock:
    process = MagicMock()
    process.__enter__.return_value = process
    process.communicate.return_value = stdout, stderr
    process.returncode = returncode
    monkeypatch.setattr(payload.subprocess, "Popen", Mock(return_value=process))
    return process


@pytest.mark.parametrize(
    ("marker", "expect_preamble"),
    [
        ("FullLanguage:None", True),
        ("FullLanguage:Audit", False),
        ("FullLanguage:Enforce", False),
        ("ConstrainedLanguage", False),
    ],
)
def test_measured_policy_results_control_only_the_input_encoding_preamble(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    marker: str,
    expect_preamble: bool,
) -> None:
    process = _diagnostic_process(
        payload,
        monkeypatch,
        ("LEGACY_WINDOWS_POLICY:" + marker + "\r\n").encode("ascii"),
    )
    result, captured = _execute(
        payload,
        monkeypatch,
        {
            "cmd": "Write-Output 'requested'",
            "stdin": "private-input",
            "no_profile": False,
        },
        use_real_probe=True,
    )
    user_line = str(captured["command_line"])
    user_script = base64.b64decode(user_line.rsplit(" ", 1)[1]).decode("utf-16-le")
    expected = "Write-Output 'requested'"
    if expect_preamble:
        expected = (
            "[Console]::InputEncoding = New-Object Text.UTF8Encoding $false; "
            + expected
        )
    assert user_script == expected
    assert "-noprofile" not in user_line
    assert "-noninteractive" not in user_line
    assert result["cmd"] == "Write-Output 'requested'"
    assert process.communicate.call_args.kwargs == {"timeout": 30}
    process.__exit__.assert_called_once()
    process._handle.Close.assert_called_once()


def test_policy_probe_resolves_the_same_executable_and_receives_no_user_input(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    process = _diagnostic_process(
        payload, monkeypatch, b"LEGACY_WINDOWS_POLICY:FullLanguage:None\r\n"
    )
    resolver = Mock(return_value=r"C:\Tools\powershell.exe")
    monkeypatch.setattr(payload, "resolve_executable", resolver)
    assert payload._powershell_input_encoding("powershell.exe", r"C:\Work") is True
    resolver.assert_called_once_with("powershell.exe", r"C:\Work")
    command_line = payload.subprocess.Popen.call_args.args[0]
    assert command_line.startswith(
        '"C:\\Tools\\powershell.exe" -NoProfile -NonInteractive -EncodedCommand '
    )
    script = base64.b64decode(command_line.rsplit(" ", 1)[1]).decode("utf-16-le")
    assert "GetSystemLockdownPolicy()" in script
    assert "ConstrainedLanguage" in script
    assert payload.subprocess.Popen.call_args.kwargs == {
        "executable": r"C:\Tools\powershell.exe",
        "cwd": r"C:\Work",
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
    }
    assert process.communicate.call_args.args == ()


@pytest.mark.parametrize(
    ("stdout", "stderr", "returncode"),
    [
        (b"", b"", 0),
        (b"LEGACY_WINDOWS_POLICY:FullLanguage:Unknown\r\n", b"", 0),
        (b"LEGACY_WINDOWS_POLICY:RestrictedLanguage\r\n", b"", 0),
        (b"LEGACY_WINDOWS_POLICY:ConstrainedLanguage:Enforce\r\n", b"", 0),
        (b"LEGACY_WINDOWS_POLICY:FullLanguage:None\n", b"", 0),
        (b"LEGACY_WINDOWS_POLICY:FullLanguage:None\r\nextra", b"", 0),
        (b"LEGACY_WINDOWS_POLICY:FullLanguage:None\r\n", b"API call failed", 0),
        (b"LEGACY_WINDOWS_POLICY:FullLanguage:None\r\n", b"", 1),
        (b"\xff", b"", 0),
    ],
)
def test_unusable_policy_probe_never_starts_the_requested_command(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    stdout: bytes,
    stderr: bytes,
    returncode: int,
) -> None:
    process = _diagnostic_process(payload, monkeypatch, stdout, stderr, returncode)
    result, captured = _execute(
        payload, monkeypatch, {"cmd": "requested-command"}, use_real_probe=True
    )
    assert not captured
    assert result["cmd"] == "requested-command"
    assert result["changed"] is False
    assert result["failed"] is True
    assert result["rc"] == 2
    assert "PowerShell policy probe" in str(result["msg"])
    process.__exit__.assert_called_once()
    process._handle.Close.assert_called_once()


def test_probe_progress_is_discarded_without_changing_requested_output(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    progress = (
        b'#< CLIXML\r\n<Objs><Obj S="progress"><S>Preparing modules</S></Obj></Objs>'
    )
    _diagnostic_process(
        payload, monkeypatch, b"LEGACY_WINDOWS_POLICY:FullLanguage:Audit\r\n", progress
    )
    result, _ = _execute(
        payload, monkeypatch, {"cmd": "requested-command"}, use_real_probe=True
    )
    assert result["changed"] is True
    assert result["stdout"] == ""
    assert result["stderr"] == ""


@pytest.mark.parametrize("native_code", [2, 5, 193])
def test_probe_launch_failure_preserves_the_native_error_code(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, native_code: int
) -> None:
    error = OSError("Native launch failure")
    setattr(error, "winerror", native_code)
    monkeypatch.setattr(payload.subprocess, "Popen", Mock(side_effect=error))
    result, captured = _execute(
        payload, monkeypatch, {"cmd": "requested-command"}, use_real_probe=True
    )
    assert not captured
    assert result == {
        "changed": False,
        "failed": True,
        "cmd": "requested-command",
        "rc": native_code,
        "msg": "Failed to run: '': Native launch failure",
    }


@pytest.mark.parametrize(
    ("failure", "diagnostic"),
    [
        (
            subprocess.TimeoutExpired("owned diagnostic child", 30),
            "timed out after 30 seconds",
        ),
        (OSError("controlled read failure"), "controlled read failure"),
        (UnicodeError("controlled decode failure"), "controlled decode failure"),
    ],
)
def test_probe_read_failure_stops_the_owned_process_and_closes_resources(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
    diagnostic: str,
) -> None:
    # The payload owns this process's context; the finally block is test-failure cleanup.
    process = subprocess.Popen(  # pylint: disable=consider-using-with
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    handle = Mock()
    setattr(process, "_handle", handle)
    communicate = process.communicate
    calls: list[float | None] = []

    def _communicate(timeout: float | None = None) -> tuple[bytes, bytes]:
        calls.append(timeout)
        if timeout is not None:
            raise failure
        return communicate()

    monkeypatch.setattr(process, "communicate", _communicate)
    monkeypatch.setattr(payload.subprocess, "Popen", Mock(return_value=process))
    try:
        result, captured = _execute(
            payload, monkeypatch, {"cmd": "requested-command"}, use_real_probe=True
        )
        assert not captured
        assert result["changed"] is False
        assert result["failed"] is True
        assert result["cmd"] == "requested-command"
        assert diagnostic in str(result["msg"])
        assert calls == [30, None]
        assert process.poll() is not None
        assert process.stdout is not None and process.stdout.closed
        assert process.stderr is not None and process.stderr.closed
        handle.Close.assert_called_once()
    finally:
        if process.poll() is None:
            process.kill()
            communicate()


@pytest.mark.parametrize("stdin", [None, "", "\n", "input"])
@pytest.mark.parametrize(
    ("no_profile", "expected_profile_flag"),
    [
        (None, False),
        (False, False),
        (True, True),
        ("yes", True),
        ("no", False),
        (" y ", True),
        ("T", True),
        ("1.0", True),
        ("n", False),
        ("F", False),
        ("0.0", False),
    ],
)
def test_powershell_flags_depend_on_stdin_and_profile_option(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    stdin: str | None,
    no_profile: bool | str | None,
    expected_profile_flag: bool,
) -> None:
    _, captured = _execute(
        payload,
        monkeypatch,
        {"cmd": "script", "stdin": stdin, "no_profile": no_profile},
    )
    command_line = str(captured["command_line"])
    assert ("-noninteractive" in command_line) is (not stdin)
    assert ("-noprofile" in command_line) is expected_profile_flag


def test_process_results_are_preserved_but_cmd_is_original_shell_text(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    child = {
        "cmd": '"cmd.exe" /c exit 17',
        "rc": 17,
        "changed": True,
        "failed": True,
        "msg": "non-zero return code",
        "stdout": "literal\r\n",
        "stderr": "failure\r\n",
        "start": "2026-09-28 00:00:00.000001",
        "end": "2026-09-28 00:00:00.000002",
        "delta": "0:00:00.000001",
    }
    result, _ = _execute(
        payload, monkeypatch, {"cmd": "  exit 17  ", "executable": "cmd"}, child
    )
    assert result == {**child, "cmd": "exit 17"}


def test_launch_failure_retains_shell_text_and_native_error_code(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    child = {
        "cmd": '"missing.exe" /c echo test',
        "rc": 2,
        "changed": False,
        "failed": True,
        "msg": "Failed to run: '\"missing.exe\" /c echo test': file not found",
    }
    result, _ = _execute(
        payload, monkeypatch, {"cmd": "echo test", "executable": "missing"}, child
    )
    assert result == {
        **child,
        "cmd": "echo test",
        "msg": "Failed to run: '': file not found",
    }


def test_invocation_keeps_untrimmed_command_and_converted_defaults(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, _ = _execute(
        payload,
        monkeypatch,
        {
            "cmd": "  echo test  ",
            "executable": "cmd",
            "_ansible_inject_invocation": True,
        },
    )
    assert result["cmd"] == "echo test"
    assert result["invocation"] == {
        "module_args": {
            "cmd": "  echo test  ",
            "executable": "cmd",
            "chdir": None,
            "creates": None,
            "removes": None,
            "stdin": None,
            "no_profile": False,
            "output_encoding_override": None,
        }
    }


@pytest.mark.parametrize("stderr", ["", "literal\r\n", "#< CLIXML\r\nnot XML"])
def test_stderr_without_a_matching_xml_document_is_unchanged(
    payload: ModuleType, stderr: str
) -> None:
    assert payload._format_stderr(stderr) == stderr


def test_clixml_extracts_error_strings_and_discards_other_streams(
    payload: ModuleType,
) -> None:
    stderr = (
        'before\r\n#< CLIXML\r\n<Objs Version="1.1.0.1" '
        'xmlns="http://schemas.microsoft.com/powershell/2004/04">'
        '<S S="Error">first_x000D__x000A_&lt;message&gt;</S>'
        '<S S="Warning">unused warning</S><Obj S="Error"><S>unused object</S></Obj>'
        '<S S="Error">second</S></Objs>\r\nafter\r\n'
    )
    assert payload._format_stderr(stderr) == (
        "before\r\n\r\nfirst<message>\r\nsecond\r\n\r\nafter"
    )


def test_clixml_keeps_non_crlf_escape_sequences(payload: ModuleType) -> None:
    stderr = '#< CLIXML<Objs><S S="Error">_x0041__x000D__x000A__x000A_</S></Objs>'
    assert payload._format_stderr(stderr) == "_x0041__x000A_"


@pytest.mark.parametrize(
    ("xml", "expected"),
    [
        ('<Objs><S Name="Other" S="Error">ignored</S></Objs>', ""),
        ('<Objs><Other Name="S" S="Error">selected</Other></Objs>', "selected"),
        ('<Objs><S S="Error"><Name>Other</Name>ignored</S></Objs>', ""),
        (
            '<Objs><S Name="Other" S="Error"><Name>S</Name>selected</S></Objs>',
            "selected",
        ),
        (
            '<Objs><S Name="S" S="Error"><Name>Other</Name>selected</S></Objs>',
            "selected",
        ),
        ('<Objs><S S="Warning"><S>Error</S>selected</S></Objs>', "selected"),
        ('<Objs><S S="Error"><S>Warning</S>selected</S></Objs>', "selected"),
        ("<Objs><S><S>Warning</S><S>Error</S>selected</S></Objs>", "selected"),
        ("<Objs><Other><Name>S</Name><S>Error</S>selected</Other></Objs>", "selected"),
        ("<Objs><S><S>Error</S>selected</S></Objs>", "selected"),
        ('<objs><s s="error">selected</s></objs>', "selected"),
        ("<Objs><S>ignored</S></Objs>", ""),
        (
            '<Objs><S S="Error">first<Other>ignored</Other>last</S></Objs>',
            "first\r\nlast",
        ),
    ],
)
def test_clixml_selects_adapted_name_and_stream_properties_and_direct_text(
    payload: ModuleType, xml: str, expected: str
) -> None:
    assert payload._format_stderr("#< CLIXML" + xml) == expected


@pytest.mark.parametrize(
    "body",
    [
        "<S S='Error'/>",
        "<S S='Error'></S>",
        "<S S='Error'><![CDATA[not direct text]]></S>",
    ],
)
def test_clixml_selected_element_without_direct_text_preserves_the_null_error(
    payload: ModuleType, body: str
) -> None:
    stderr = "#< CLIXML<Objs>" + body + "</Objs>"
    assert payload._format_stderr(stderr) == (
        "***EXCEPTION PARSING CLIXML: You cannot call a method on a "
        "null-valued expression.***" + stderr
    )


def test_clixml_greedy_matching_preserves_earlier_documents_and_markers(
    payload: ModuleType,
) -> None:
    first = '<Objs><S S="Error">first</S></Objs>'
    last = '<Objs><S S="Error">last</S></Objs>'
    assert payload._format_stderr("#< CLIXML" + first + last) == first + "last"
    assert payload._format_stderr(
        "before#< CLIXML" + first + "middle#< CLIXML" + last + "after"
    ) == ("before#< CLIXML" + first + "middlelast\r\nafter")
    assert payload._format_stderr("#< CLIXML<Objs />") == "#< CLIXML<Objs />"


def test_malformed_clixml_retains_original_stderr_with_parse_diagnostic(
    payload: ModuleType,
) -> None:
    stderr = '#< CLIXML<Objs><S S="Error">unterminated</Objs>'
    result = payload._format_stderr(stderr)
    assert result.startswith("***EXCEPTION PARSING CLIXML: ")
    assert result.endswith("***" + stderr)


def test_real_entrypoint_stages_helpers_and_reports_a_non_windows_failure(
    tmp_path: Path,
) -> None:
    process, result = run_payload(
        "win_shell", tmp_path, {"cmd": "  echo test  ", "executable": "cmd"}
    )
    assert process.returncode == 1
    assert result["changed"] is False
    assert result["failed"] is True
    assert result["cmd"] == "echo test"
    assert result["rc"] == 2
    assert (
        result["msg"]
        == "Failed to run: '': Process execution requires a Windows target."
    )
    assert json.loads(process.stdout) == result
