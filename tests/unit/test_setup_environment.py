"""Fault-test Setup startup ordering, native casing and normal-action ownership."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These tests exercise the concrete native and normal-action extension points.
# pylint: disable=protected-access

import importlib
import ntpath
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
from ansible.errors import AnsibleError  # type: ignore[import-untyped]
from ansible.plugins.action import ActionBase  # type: ignore[import-untyped]

from plugins.action.setup import ActionModule
from tests.unit.test_python_action import _action


@pytest.fixture(name="native")
def load_native(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Import the native helper without requiring a Windows workstation.

    :param monkeypatch: Scoped helper imports and native API substitution.
    :returns: The actual native Setup helper.
    """
    monkeypatch.syspath_prepend(
        str(Path(__file__).resolve().parents[2] / "plugins/module_utils")
    )
    monkeypatch.setitem(sys.modules, "winreg", ModuleType("winreg"))
    monkeypatch.delitem(sys.modules, "legacy_windows_setup_native", raising=False)
    result = importlib.import_module("legacy_windows_setup_native")
    monkeypatch.setattr(result, "os", SimpleNamespace(path=ntpath))
    return result


@pytest.mark.parametrize(
    "overrides",
    [
        {},
        {
            "PSModulePath": "C:\\literal\\雪\\",
            "PSExecutionPolicyPreference": "RemoteSigned",
        },
    ],
)
def test_startup_precedes_literal_overrides_without_rebuilding_environment(
    native: Any, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, str]
) -> None:
    set_value = Mock(return_value=1)
    monkeypatch.setattr(
        native.ctypes,
        "WinDLL",
        Mock(return_value=SimpleNamespace(SetEnvironmentVariableW=set_value)),
        raising=False,
    )
    monkeypatch.setattr(
        native,
        "_registry",
        Mock(return_value=r"C:\Windows\System32\WindowsPowerShell\v1.0"),
    )
    read = Mock(
        return_value={"PATHEXT": ".EXE;.PY", "ProgramFiles": r"C:\Program Files"}
    )
    monkeypatch.setattr(native, "_environment", read)
    monkeypatch.setattr(native, "_startup_module_path", Mock(return_value="startup"))
    native.initialize_environment(overrides)
    read.assert_called_once_with(trim_trailing_backslashes=False)
    assert [call.args for call in set_value.call_args_list] == [
        ("PSExecutionPolicyPreference", "Unrestricted"),
        ("PSModulePath", "startup"),
        ("PATHEXT", ".EXE;.PY;.CPL"),
        *list(overrides.items()),
    ]


def test_legacy_absent_engine_only_applies_explicit_overrides(
    native: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    set_value = Mock(return_value=1)
    monkeypatch.setattr(
        native.ctypes,
        "WinDLL",
        Mock(return_value=SimpleNamespace(SetEnvironmentVariableW=set_value)),
        raising=False,
    )
    monkeypatch.setattr(native, "_registry", Mock(return_value=None))
    read = Mock(
        side_effect=AssertionError("No source engine must mean no fabricated startup.")
    )
    monkeypatch.setattr(native, "_environment", read)
    native.initialize_environment({})
    set_value.assert_not_called()
    native.initialize_environment({"MixedCase": "literal 雪\\"})
    set_value.assert_called_once_with("MixedCase", "literal 雪\\")
    read.assert_not_called()


@pytest.mark.parametrize("code", [5, 87, 203])
def test_native_environment_failure_preserves_actual_error_code(
    native: Any, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    monkeypatch.setattr(
        native.ctypes,
        "WinDLL",
        Mock(
            return_value=SimpleNamespace(SetEnvironmentVariableW=Mock(return_value=0))
        ),
        raising=False,
    )
    monkeypatch.setattr(native.ctypes, "get_last_error", lambda: code, raising=False)
    monkeypatch.setattr(
        native.ctypes,
        "WinError",
        lambda value: OSError(value, "native failure"),
        raising=False,
    )
    monkeypatch.setattr(native, "_registry", lambda *_args: None)
    with pytest.raises(OSError) as error:
        native.initialize_environment({"Name": "value"})
    assert error.value.errno == code


@pytest.mark.parametrize(
    "inherited, user_value, expected",
    [
        (
            r"%ProgramFiles%\WindowsPowerShell\Modules;"
            r"C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules",
            None,
            r"C:\Users\Caller\Documents\WindowsPowerShell\Modules;"
            r"C:\Program Files\WindowsPowerShell\Modules;"
            r"C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules",
        ),
        (
            r"C:\custom;C:\Windows\System32\WindowsPowerShell\v1.0\Modules",
            "custom",
            r"C:\custom;C:\Program Files\WindowsPowerShell\Modules;"
            r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules",
        ),
        (r"C:\custom", "custom", r"C:\custom"),
        (
            None,
            None,
            r"C:\Users\Caller\Documents\WindowsPowerShell\Modules;"
            r"C:\Program Files\WindowsPowerShell\Modules;"
            r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules",
        ),
    ],
)
def test_documented_startup_path_order_expansion_and_user_scope(
    native: Any,
    monkeypatch: pytest.MonkeyPatch,
    inherited: str | None,
    user_value: str | None,
    expected: str,
) -> None:
    environment = {"ProgramFiles": r"C:\Program Files"}
    if inherited is not None:
        environment["PSModulePath"] = inherited
    monkeypatch.setattr(
        native.winreg,
        "ExpandEnvironmentStrings",
        lambda value: value.replace("%ProgramFiles%", r"C:\Program Files"),
        raising=False,
    )
    monkeypatch.setattr(native, "_user_module_path", lambda: user_value)
    monkeypatch.setattr(
        native, "_documents_directory", lambda: r"C:\Users\Caller\Documents"
    )
    assert (
        native._startup_module_path(
            environment, r"C:\Windows\System32\WindowsPowerShell\v1.0"
        )
        == expected
    )


@pytest.mark.parametrize("overrides", [{}, {"MixedCase": "Café 雪 % & | ^ \\"}])
def test_actual_action_stages_before_startup_prefix_and_cleans_once(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, str]
) -> None:
    action, shell, events = _action(ActionModule, monkeypatch)
    shell._python_command = lambda script: script

    def _core(_self: object, output: dict[str, Any]) -> str:
        output.update(overrides)
        return "unused ordinary shell environment prefix"

    monkeypatch.setattr(ActionBase, "_compute_environment_string", _core)
    applied = Mock()
    monkeypatch.setitem(
        sys.modules,
        "legacy_windows_setup_native",
        SimpleNamespace(initialize_environment=applied),
    )
    child = Mock(return_value=0)
    monkeypatch.setattr("subprocess.call", child)
    monkeypatch.setattr(sys, "argv", ["launcher", "normal-module", "argument"])
    monkeypatch.setattr(sys, "path", list(sys.path))

    def _execute(**_kwargs: object) -> dict[str, object]:
        assert [event[0] for event in events] == ["mkdir"] + ["transfer"] * 14
        raw: dict[str, Any] = {}
        prefix = action._compute_environment_string(raw)
        assert raw == overrides and repr(shell.tmpdir) in prefix
        with pytest.raises(SystemExit) as exited:
            # Execute the generated launcher, not merely its string spelling.
            # pylint: disable=exec-used
            exec(
                compile(prefix, "setup-prefix", "exec"), {}
            )  # pylint: disable=exec-used
        assert exited.value.code == 0
        events.append(("module",))
        return {"changed": False}

    monkeypatch.setattr(action, "_execute_module", _execute)
    assert action.run(task_vars={}) == {"changed": False}
    applied.assert_called_once_with(overrides)
    child.assert_called_once_with(["normal-module", "argument"])
    assert events[-1][0] == "cleanup" and shell.tmpdir is None
    action.cleanup()
    assert [event[0] for event in events].count("cleanup") == 1


def test_failed_staging_never_executes_environment_and_still_cleans(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, shell, events = _action(ActionModule, monkeypatch)
    monkeypatch.setattr(
        action, "_transfer_file", Mock(side_effect=AnsibleError("stage denied"))
    )
    execute = Mock()
    monkeypatch.setattr(action, "_execute_module", execute)
    with pytest.raises(AnsibleError, match="stage denied"):
        action.run(task_vars={})
    execute.assert_not_called()
    assert events[-1][0] == "cleanup" and shell.tmpdir is None
