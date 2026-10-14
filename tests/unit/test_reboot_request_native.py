"""Exercise reboot commands and readiness observations without Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import datetime
import ntpath
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock, Mock, call

import pytest

from tests.unit.payload_support import ROOT, load_module, native_error

LOGON_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoLogonChecked"
AUTO_START_EVENT = r"Global\SC_AutoStartComplete"
SHUTDOWN = r"C:\Windows\System32\shutdown.exe"
PROCESS_OPTIONS = {
    "chdir": None,
    "stdin": None,
    "output_encoding_override": None,
}


@pytest.fixture(name="helper")
def reboot_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the target helper without executing any native operation.

    :param monkeypatch: Scoped adjacent-helper import path.
    :returns: Fresh reboot helper loaded by the developer interpreter.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    return load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_reboot_request.py",
        "tested_reboot_request",
    )


@pytest.fixture(name="native")
def reboot_boundaries(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Mock:
    """Record Windows process, boot-reader, and registry operations locally.

    :param helper: Imported target helper.
    :param monkeypatch: Scoped native-operation and Windows-path substitutions.
    :returns: Recorders with configurable native results and errors.
    """
    native = Mock()
    native.boot.return_value = datetime.datetime(1970, 1, 1)
    native.process.return_value = {"rc": 0, "stdout": "", "stderr": ""}
    native.registry.HKEY_LOCAL_MACHINE = 0x80000002
    native.registry.OpenKey.return_value = MagicMock()
    native.kernel.OpenEventW.return_value = 0x123456
    native.kernel.WaitForSingleObject.return_value = 0
    native.kernel.CloseHandle.return_value = 1
    native.last_error = 5
    monkeypatch.setattr(helper.boot, "last_boot_time", native.boot)
    monkeypatch.setattr(helper, "run_command", native.process)
    monkeypatch.setattr(helper, "winreg", native.registry)
    monkeypatch.setattr(
        helper,
        "sys",
        SimpleNamespace(getwindowsversion=lambda: SimpleNamespace(major=10, minor=0)),
    )
    monkeypatch.setattr(
        helper.ctypes, "WinDLL", lambda *_args, **_kwargs: native.kernel, raising=False
    )
    monkeypatch.setattr(
        helper.ctypes, "get_last_error", lambda: native.last_error, raising=False
    )
    monkeypatch.setattr(helper.ctypes, "WinError", native_error, raising=False)
    monkeypatch.setattr(
        helper,
        "os",
        SimpleNamespace(path=ntpath, environ={"SystemRoot": r"C:\Windows"}),
    )
    return native


@pytest.mark.parametrize("command", [None, "", "default"])
@pytest.mark.parametrize(
    ("timestamp", "filetime"),
    [
        (datetime.datetime(1601, 1, 1), "0"),
        (datetime.datetime(1601, 1, 1, microsecond=1), "10"),
        (datetime.datetime(1970, 1, 1), "116444736000000000"),
        (
            datetime.datetime(2026, 9, 28, 8, 11, 41, 679063),
            "134350567016790630",
        ),
    ],
)
def test_default_boot_returns_decimal_filetime_without_losing_microseconds(
    helper: ModuleType,
    native: Mock,
    command: str | None,
    timestamp: datetime.datetime,
    filetime: str,
) -> None:
    native.boot.return_value = timestamp
    if command == "default":
        command = helper.DEFAULT_BOOT_COMMAND
    assert helper.observe_boot(command) == {"rc": 0, "stdout": filetime, "stderr": ""}
    native.boot.assert_called_once_with()
    native.process.assert_not_called()
    native.registry.DeleteKey.assert_not_called()
    native.registry.OpenKey.assert_not_called()


@pytest.mark.parametrize(
    "error", [OSError("WMI unavailable"), ValueError("Invalid LastBootUpTime")]
)
def test_native_boot_failure_propagates_and_a_later_read_recovers(
    helper: ModuleType, native: Mock, error: Exception
) -> None:
    native.boot.side_effect = error
    with pytest.raises(type(error)) as raised:
        helper.observe_boot()
    assert raised.value is error
    native.process.assert_not_called()
    native.boot.side_effect = None
    assert helper.observe_boot() == {
        "rc": 0,
        "stdout": "116444736000000000",
        "stderr": "",
    }


@pytest.mark.parametrize("phase", ["boot", "ready"])
def test_explicit_powershell_commands_preserve_unicode_and_failure_exit_semantics(
    helper: ModuleType, native: Mock, phase: str
) -> None:
    command = "$value = 'snow 雪'; Write-Output $value; exit 19"
    native.process.return_value = {
        "rc": 19,
        "stdout": "\r\n snow 雪\r\nsecond line \r\n",
        "stderr": "\tcommand failed\r\n detail \r\n",
    }
    expected_script = command + (
        "; If (-not $?) { If (Get-Variable LASTEXITCODE -ErrorAction SilentlyContinue)"
        " { exit $LASTEXITCODE } Else { exit 1 } }"
    )
    encoded = base64.b64encode(expected_script.encode("utf-16-le")).decode("ascii")
    observe = helper.observe_boot if phase == "boot" else helper.observe_readiness
    assert observe(command) == {
        "rc": 19,
        "stdout": "snow 雪\r\nsecond line",
        "stderr": "command failed\r\n detail",
    }
    native.process.assert_called_once_with(
        "powershell.exe",
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Unrestricted "
        "-EncodedCommand " + encoded,
        PROCESS_OPTIONS,
    )
    native.boot.assert_not_called()
    native.registry.DeleteKey.assert_not_called()
    native.registry.OpenKey.assert_not_called()


@pytest.mark.parametrize("default_readiness", [False, True])
def test_request_passes_native_restart_arguments_and_removes_marker_first(
    helper: ModuleType, native: Mock, default_readiness: bool
) -> None:
    native.process.return_value = {
        "rc": 1190,
        "stdout": " first\r\n second \r\n",
        "stderr": "\r\nAlready scheduled.\r\n",
    }
    message = 'Restart "quoted" 雪'
    assert helper.request_reboot(7.9, message, default_readiness) == {
        "rc": 1190,
        "stdout": "first\r\n second",
        "stderr": "Already scheduled.",
    }
    expected_calls = []
    if default_readiness:
        expected_calls.append(call.registry.DeleteKey(0x80000002, LOGON_KEY))
    expected_calls.append(
        call.process(
            SHUTDOWN,
            SHUTDOWN + r' /r /t 7 /c "Restart \"quoted\" 雪"',
            PROCESS_OPTIONS,
        )
    )
    assert native.mock_calls == expected_calls


@pytest.mark.parametrize("code", [2, 3, 5, 1018])
def test_marker_deletion_errors_do_not_prevent_native_restart(
    helper: ModuleType, native: Mock, code: int
) -> None:
    native.registry.DeleteKey.side_effect = native_error(code)
    assert helper.request_reboot(2, "Reboot initiated by Ansible", True) == {
        "rc": 0,
        "stdout": "",
        "stderr": "",
    }
    assert native.mock_calls == [
        call.registry.DeleteKey(0x80000002, LOGON_KEY),
        call.process(
            SHUTDOWN,
            SHUTDOWN + ' /r /t 2 /c "Reboot initiated by Ansible"',
            PROCESS_OPTIONS,
        ),
    ]


@pytest.mark.parametrize(
    ("delay", "exception"),
    [
        (float("nan"), ValueError),
        (float("inf"), OverflowError),
        ("not a number", ValueError),
        (None, TypeError),
        ([], TypeError),
    ],
)
def test_invalid_native_delay_cannot_remove_marker_or_launch_shutdown(
    helper: ModuleType, native: Mock, delay: object, exception: type[Exception]
) -> None:
    with pytest.raises(exception):
        helper.request_reboot(delay, "Restart", True)
    assert native.mock_calls == []


def test_abort_uses_native_abort_command_without_touching_logon_marker(
    helper: ModuleType, native: Mock
) -> None:
    native.process.return_value = {"rc": 1116, "stdout": "", "stderr": " No shutdown. "}
    assert helper.abort_reboot() == {"rc": 1116, "stdout": "", "stderr": "No shutdown."}
    assert native.mock_calls == [
        call.process(SHUTDOWN, SHUTDOWN + " /a", PROCESS_OPTIONS)
    ]


def test_reboot_and_abort_use_system_root_and_quote_a_directory_with_spaces(
    helper: ModuleType, native: Mock
) -> None:
    helper.os.environ["SystemRoot"] = r"D:\Windows directory"
    shutdown = r"D:\Windows directory\System32\shutdown.exe"
    assert helper.request_reboot(2, "Restart", False)["rc"] == 0
    assert helper.abort_reboot()["rc"] == 0
    assert native.mock_calls == [
        call.process(
            shutdown,
            '"' + shutdown + '" /r /t 2 /c Restart',
            PROCESS_OPTIONS,
        ),
        call.process(shutdown, '"' + shutdown + '" /a', PROCESS_OPTIONS),
    ]


@pytest.mark.parametrize("operation", ["abort", "request"])
@pytest.mark.parametrize(
    ("process_result", "expected_stderr"),
    [
        (
            {"rc": 2, "msg": " Failed to run shutdown.exe. \r\n"},
            "Failed to run shutdown.exe.",
        ),
        ({"rc": 2, "stderr": "", "msg": "must not replace stderr"}, ""),
    ],
)
def test_process_start_errors_retain_exit_code_and_available_diagnostics(
    helper: ModuleType,
    native: Mock,
    operation: str,
    process_result: dict[str, object],
    expected_stderr: str,
) -> None:
    native.process.return_value = process_result
    result = (
        helper.abort_reboot()
        if operation == "abort"
        else helper.request_reboot(2, "Restart", False)
    )
    assert result == {"rc": 2, "stdout": "", "stderr": expected_stderr}


@pytest.mark.parametrize("operation", ["abort", "request", "boot", "ready"])
def test_process_boundary_exception_is_not_replaced_with_success(
    helper: ModuleType, native: Mock, operation: str
) -> None:
    error = OSError("Could not capture the child process")
    native.process.side_effect = error
    actions = {
        "abort": helper.abort_reboot,
        "request": lambda: helper.request_reboot(2, "Restart", False),
        "boot": lambda: helper.observe_boot("Write-Output custom-boot"),
        "ready": lambda: helper.observe_readiness("exit 0"),
    }
    with pytest.raises(OSError) as raised:
        actions[operation]()
    assert raised.value is error


@pytest.mark.parametrize("command", [None, ""])
def test_default_readiness_emits_expected_token_only_after_marker_open_and_close(
    helper: ModuleType, native: Mock, command: str | None
) -> None:
    key = native.registry.OpenKey.return_value
    expected = "success-controller-generated-token"
    assert helper.observe_readiness(command, expected) == {
        "rc": 0,
        "stdout": expected,
        "stderr": "",
    }
    native.registry.OpenKey.assert_called_once_with(0x80000002, LOGON_KEY)
    key.__enter__.assert_called_once_with()
    key.__exit__.assert_called_once_with(None, None, None)
    native.registry.DeleteKey.assert_not_called()
    native.registry.QueryValueEx.assert_not_called()
    native.boot.assert_not_called()
    native.process.assert_not_called()


@pytest.mark.parametrize("code", [2, 3, 5, 1018])
def test_unavailable_logon_marker_returns_failure_and_later_readiness_recovers(
    helper: ModuleType, native: Mock, code: int
) -> None:
    error = native_error(code)
    native.registry.OpenKey.side_effect = error
    assert helper.observe_readiness(expected="success-token") == {
        "rc": 1,
        "stdout": "",
        "stderr": str(error),
    }
    native.process.assert_not_called()
    native.registry.OpenKey.return_value.__enter__.assert_not_called()
    native.registry.OpenKey.side_effect = None
    assert helper.observe_readiness(expected="success-token") == {
        "rc": 0,
        "stdout": "success-token",
        "stderr": "",
    }


def test_custom_readiness_uses_only_command_output_not_expected_token(
    helper: ModuleType, native: Mock
) -> None:
    native.registry.OpenKey.side_effect = native_error(5)
    native.process.return_value = {"rc": 0, "stdout": "custom result", "stderr": ""}
    assert helper.observe_readiness(
        "Write-Output 'custom result'", "success-token"
    ) == {
        "rc": 0,
        "stdout": "custom result",
        "stderr": "",
    }
    native.registry.OpenKey.assert_not_called()
    native.registry.DeleteKey.assert_not_called()


@pytest.mark.parametrize("minor", [1, 2])
def test_legacy_reboot_keeps_windows_startup_signals_untouched(
    helper: ModuleType, native: Mock, minor: int
) -> None:
    helper.sys.getwindowsversion = lambda: SimpleNamespace(major=5, minor=minor)
    assert helper.request_reboot(2, "Restart", True)["rc"] == 0
    assert native.mock_calls == [
        call.process(SHUTDOWN, SHUTDOWN + " /r /t 2 /c Restart", PROCESS_OPTIONS)
    ]


@pytest.mark.parametrize("minor", [1, 2])
@pytest.mark.parametrize("command", [None, ""])
def test_legacy_readiness_requires_signaled_global_scm_event_and_closes_handle(
    helper: ModuleType, native: Mock, minor: int, command: str | None
) -> None:
    helper.sys.getwindowsversion = lambda: SimpleNamespace(major=5, minor=minor)
    assert helper.observe_readiness(command, "success-token") == {
        "rc": 0,
        "stdout": "success-token",
        "stderr": "",
    }
    assert native.mock_calls == [
        call.kernel.OpenEventW(0x00100000, False, AUTO_START_EVENT),
        call.kernel.WaitForSingleObject(0x123456, 0),
        call.kernel.CloseHandle(0x123456),
    ]


def test_unsignaled_legacy_startup_event_returns_failure_and_later_recovers(
    helper: ModuleType, native: Mock
) -> None:
    helper.sys.getwindowsversion = lambda: SimpleNamespace(major=5, minor=1)
    native.kernel.WaitForSingleObject.return_value = 258
    result = helper.observe_readiness(expected="success-token")
    assert result["rc"] == 1 and result["stdout"] == ""
    assert result["stderr"] == (
        "SCM has not completed automatic service/driver startup "
        "(Global\\SC_AutoStartComplete)."
    )
    native.kernel.CloseHandle.assert_called_once_with(0x123456)
    native.kernel.WaitForSingleObject.return_value = 0
    assert helper.observe_readiness(expected="success-token") == {
        "rc": 0,
        "stdout": "success-token",
        "stderr": "",
    }


@pytest.mark.parametrize(
    ("failure", "diagnostic", "code"),
    [
        (
            "open",
            "Cannot open SCM startup-completion event Global\\SC_AutoStartComplete",
            2,
        ),
        (
            "wait",
            "Cannot read SCM startup-completion event Global\\SC_AutoStartComplete",
            6,
        ),
        ("close", "Cannot close SCM startup-completion event handle", 87),
        ("unexpected", "Unexpected SCM startup event wait result: 128", None),
    ],
)
def test_failed_native_legacy_readiness_is_actionable_and_never_success(
    helper: ModuleType, native: Mock, failure: str, diagnostic: str, code: int | None
) -> None:
    helper.sys.getwindowsversion = lambda: SimpleNamespace(major=5, minor=2)
    native.last_error = code
    if failure == "open":
        native.kernel.OpenEventW.return_value = None
    elif failure == "wait":
        native.kernel.WaitForSingleObject.return_value = 0xFFFFFFFF
    elif failure == "close":
        native.kernel.CloseHandle.return_value = 0
    else:
        native.kernel.WaitForSingleObject.return_value = 128
    result = helper.observe_readiness(expected="success-token")
    assert result["rc"] == 1 and result["stdout"] == ""
    assert diagnostic in result["stderr"]
    if code is not None:
        assert str(native_error(code)) in result["stderr"]
    if failure == "open":
        native.kernel.WaitForSingleObject.assert_not_called()
        native.kernel.CloseHandle.assert_not_called()
    else:
        native.kernel.CloseHandle.assert_called_once_with(0x123456)
    native.registry.OpenKey.assert_not_called()
    native.process.assert_not_called()


def test_failed_event_wait_retains_private_error_before_handle_close_changes_it(
    helper: ModuleType, native: Mock
) -> None:
    helper.sys.getwindowsversion = lambda: SimpleNamespace(major=5, minor=1)

    def _failed_wait(_handle: int, _timeout: int) -> int:
        native.last_error = 1117
        return 0xFFFFFFFF

    def _successful_close(_handle: int) -> int:
        native.last_error = 0
        return 1

    native.kernel.WaitForSingleObject.side_effect = _failed_wait
    native.kernel.CloseHandle.side_effect = _successful_close
    result = helper.observe_readiness(expected="success-token")
    assert result["rc"] == 1 and result["stdout"] == ""
    assert str(native_error(1117)) in result["stderr"]
    assert native.last_error == 0
    native.kernel.CloseHandle.assert_called_once_with(0x123456)


def test_custom_legacy_readiness_retains_powershell_and_does_not_observe_scm(
    helper: ModuleType, native: Mock
) -> None:
    helper.sys.getwindowsversion = lambda: SimpleNamespace(major=5, minor=1)
    native.process.return_value = {"rc": 0, "stdout": "custom result", "stderr": ""}
    assert helper.observe_readiness("Write-Output custom", "success-token") == {
        "rc": 0,
        "stdout": "custom result",
        "stderr": "",
    }
    native.kernel.OpenEventW.assert_not_called()
    native.registry.OpenKey.assert_not_called()


@pytest.mark.parametrize(("major", "minor"), [(6, 0), (6, 1), (6, 2), (10, 0)])
def test_modern_readiness_retains_original_logon_key(
    helper: ModuleType, native: Mock, major: int, minor: int
) -> None:
    helper.sys.getwindowsversion = lambda: SimpleNamespace(major=major, minor=minor)
    assert helper.observe_readiness(expected="success-token")["rc"] == 0
    native.registry.OpenKey.assert_called_once_with(0x80000002, LOGON_KEY)
    native.kernel.OpenEventW.assert_not_called()
