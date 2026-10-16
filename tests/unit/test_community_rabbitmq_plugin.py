"""Exercise the RabbitMQ payload through an independent installed-CLI boundary."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import os
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module


class RabbitMQ:  # pylint: disable=too-few-public-methods
    """Model explicit plugin selection independently of payload planning."""

    def __init__(self) -> None:
        self.enabled = ["rabbitmq_old"]
        self.calls: list[list[str]] = []
        self.failure: str | None = None

    def command(self, _executable: str, arguments: list[str]) -> dict[str, Any]:
        """Record a CLI call and update the independently observed selection.

        :param arguments: Literal vendor operation and arguments.
        :returns: Vendor exit status and streams.
        :raises AssertionError: The payload requested an unexpected vendor operation.
        """
        self.calls.append(arguments)
        operation = arguments[0]
        if self.failure == operation:
            return {"rc": 5, "stdout": "vendor output", "stderr": "access denied"}
        if operation == "list":
            assert arguments == ["list", "-E", "-m"]
            return {
                "rc": 0,
                "stdout": "\r\n".join(self.enabled) + "\r\n\r\n",
                "stderr": "",
            }
        if operation == "enable":
            self.enabled.append(arguments[1])
        elif operation == "disable":
            self.enabled.remove(arguments[1])
        else:
            raise AssertionError("Unexpected CLI command: " + operation)
        return {"rc": 0, "stdout": "", "stderr": ""}


@pytest.fixture(name="rabbitmq")
def rabbitmq_fixture(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[ModuleType, RabbitMQ, Path]:
    """Load a real payload with its installed-CLI boundary substituted.

    :param monkeypatch: Scoped native process substitution.
    :param tmp_path: Owned fake installation directory.
    :returns: Payload, independent vendor model and existing installation prefix.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    payload = load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_rabbitmq_plugin.py",
        "community_rabbitmq_plugin",
    )
    folder = tmp_path / "RabbitMQ Server" / "sbin"
    folder.mkdir(parents=True)
    (folder / "rabbitmq-plugins.exe").write_bytes(b"vendor")
    vendor = RabbitMQ()
    monkeypatch.setattr(payload, "_command", vendor.command)
    return payload, vendor, folder.parent


def execute(
    rabbitmq: tuple[ModuleType, RabbitMQ, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    **arguments: Any,
) -> tuple[int, dict[str, Any]]:
    """Execute the public JSON entrypoint against the modeled vendor.

    :param rabbitmq: Payload and independent CLI fixture.
    :param monkeypatch: Scoped command-line input substitution.
    :param capsys: JSON output capture.
    :param arguments: Overrides for the module's ordinary input values.
    :returns: JSON process status and result.
    """
    supplied = {"names": "rabbitmq_management", "prefix": str(rabbitmq[2])}
    supplied.update(arguments)
    path = rabbitmq[2] / "arguments.json"
    path.write_text(json.dumps(supplied), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["win_rabbitmq_plugin.py", str(path)])
    return invoke_payload(rabbitmq[0], capsys)


def test_enable_disables_unspecified_plugins_then_repeats_unchanged(
    rabbitmq: tuple[ModuleType, RabbitMQ, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    status, result = execute(rabbitmq, monkeypatch, capsys, _ansible_diff=True)
    assert status == 0
    assert result == {
        "changed": True,
        "enabled": ["rabbitmq_management"],
        "disabled": ["rabbitmq_old"],
        "diff": {"prepared": "+[rabbitmq_management]\n-[rabbitmq_old]\n"},
    }
    assert rabbitmq[1].enabled == ["rabbitmq_management"]
    assert rabbitmq[1].calls == [
        ["list", "-E", "-m"],
        ["enable", "rabbitmq_management"],
        ["disable", "rabbitmq_old"],
    ]
    assert execute(rabbitmq, monkeypatch, capsys)[1] == {
        "changed": False,
        "enabled": [],
        "disabled": [],
    }


def test_new_only_preserves_other_enabled_plugins(
    rabbitmq: tuple[ModuleType, RabbitMQ, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    status, result = execute(rabbitmq, monkeypatch, capsys, new_only=True)
    assert status == 0
    assert result["disabled"] == []
    assert rabbitmq[1].enabled == ["rabbitmq_old", "rabbitmq_management"]


def test_disable_only_requested_plugins_and_repeat(
    rabbitmq: tuple[ModuleType, RabbitMQ, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rabbitmq[1].enabled.append("rabbitmq_management")
    status, result = execute(
        rabbitmq, monkeypatch, capsys, state="disabled", _ansible_diff=True
    )
    assert status == 0
    assert result["disabled"] == ["rabbitmq_management"]
    assert result["diff"] == {"prepared": "-[rabbitmq_management]\n"}
    assert rabbitmq[1].enabled == ["rabbitmq_old"]
    assert (
        execute(rabbitmq, monkeypatch, capsys, state="disabled")[1]["changed"] is False
    )


@pytest.mark.parametrize("state", ["enabled", "disabled"])
def test_check_mode_lists_without_mutation(
    rabbitmq: tuple[ModuleType, RabbitMQ, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    state: str,
) -> None:
    rabbitmq[1].enabled.append("rabbitmq_management")
    status, result = execute(
        rabbitmq,
        monkeypatch,
        capsys,
        state=state,
        names="rabbitmq_old",
        _ansible_check_mode=True,
    )
    assert status == 0
    assert result["changed"] is True
    assert rabbitmq[1].enabled == ["rabbitmq_old", "rabbitmq_management"]
    assert rabbitmq[1].calls == [["list", "-E", "-m"]]


def test_alias_case_insensitive_membership_and_literal_comma_parts(
    rabbitmq: tuple[ModuleType, RabbitMQ, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    status, result = execute(
        rabbitmq, monkeypatch, capsys, names="RABBITMQ_OLD, new", new_only=True
    )
    assert status == 0
    assert result["enabled"] == [" new"]
    payload, vendor, prefix = rabbitmq
    argument_file = prefix / "alias.json"
    argument_file.write_text(
        json.dumps(
            {
                "name": "RABBITMQ_OLD",
                "new_only": True,
                "prefix": str(prefix),
                "ignored_legacy_option": "ignored",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["module", str(argument_file)])
    assert invoke_payload(payload, capsys)[1]["changed"] is False
    assert vendor.enabled == ["rabbitmq_old", " new"]


@pytest.mark.parametrize("operation", ["list", "enable", "disable"])
def test_vendor_errors_return_failure_and_preserve_completed_changes(
    rabbitmq: tuple[ModuleType, RabbitMQ, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    operation: str,
) -> None:
    rabbitmq[1].failure = operation
    status, result = execute(rabbitmq, monkeypatch, capsys)
    assert status == 1
    assert result["failed"] is True
    assert result["rc"] == 5
    assert result["stderr"] == "access denied"
    assert result["changed"] == (operation == "disable")


@pytest.mark.parametrize(
    "arguments",
    [{"names": ""}, {"names": None}, {"state": "invalid"}, {"new_only": "invalid"}],
)
def test_invalid_input_fails_before_cli_calls(
    rabbitmq: tuple[ModuleType, RabbitMQ, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: dict[str, Any],
) -> None:
    status, result = execute(rabbitmq, monkeypatch, capsys, **arguments)
    assert status == 1
    assert result["changed"] is False
    assert rabbitmq[1].calls == []


# Boundary checks deliberately inspect private discovery and quoting helpers;
# public behavior above still runs through the actual JSON module entrypoint.
# pylint: disable=protected-access
def test_discovery_prefers_bin_then_registry_then_path(
    rabbitmq: tuple[ModuleType, RabbitMQ, Path],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload, _vendor, prefix = rabbitmq
    (prefix / "bin").mkdir()
    expected = prefix / "bin" / "rabbitmq-plugins.bat"
    expected.write_bytes(b"vendor")
    assert payload._executable(str(prefix)) == str(expected)
    monkeypatch.setattr(payload, "_registry_prefix", lambda: str(prefix))
    assert payload._executable(None) == str(expected)
    monkeypatch.setattr(payload, "_registry_prefix", lambda: None)
    monkeypatch.setenv("PATH", str(prefix / "sbin"))
    assert payload._executable(None) == str(prefix / "sbin" / "rabbitmq-plugins.exe")
    with pytest.raises(ValueError, match="No binary folder"):
        payload._executable(str(tmp_path / "missing"))
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(ValueError, match="executable not found"):
        payload._executable(None)


def test_registry_discovery_uses_wow64_first_and_parses_quoted_uninstaller(
    rabbitmq: tuple[ModuleType, RabbitMQ, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = rabbitmq[0]
    opened: list[str] = []

    class Key:
        """Represent an opened registry handle."""

        def __enter__(self) -> "Key":
            return self

        def __exit__(self, *_arguments: object) -> None:
            return None

    def _open_key(_root: int, path: str, _reserved: int, _access: int) -> Key:
        opened.append(path)
        if len(opened) == 1:
            raise FileNotFoundError(path)
        return Key()

    values = {
        "UninstallString": '"C:\\Program Files\\RabbitMQ\\uninstall.exe"',
        "DisplayVersion": "3.6.15",
    }
    monkeypatch.setattr(
        payload,
        "winreg",
        SimpleNamespace(
            HKEY_LOCAL_MACHINE=1,
            KEY_READ=2,
            KEY_WOW64_64KEY=4,
            OpenKey=_open_key,
            QueryValueEx=lambda _key, name: (values[name], 1),
        ),
    )
    assert (
        payload._registry_prefix()
        == r"C:\Program Files\RabbitMQ\rabbitmq_server-3.6.15"
    )
    assert opened[0].startswith("SOFTWARE\\Wow6432Node\\")
    assert opened[1].startswith("SOFTWARE\\Microsoft\\")


def test_native_launch_uses_literal_windows_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(HELPER.parent))
    payload = load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_rabbitmq_plugin.py",
        "rabbitmq_native_launch",
    )
    calls: list[tuple[str, str, dict[str, Any]]] = []

    def _launch(
        executable: str, command: str, parameters: dict[str, Any]
    ) -> dict[str, Any]:
        calls.append((executable, command, parameters))
        return {"rc": 0}

    monkeypatch.setattr(payload, "run_command", _launch)
    payload._command(
        r"C:\RabbitMQ Server\rabbitmq-plugins.exe", ["enable", "literal&name"]
    )
    assert calls[0][0] == r"C:\RabbitMQ Server\rabbitmq-plugins.exe"
    assert (
        calls[0][1] == '"C:\\RabbitMQ Server\\rabbitmq-plugins.exe" enable literal&name'
    )


def test_batch_launch_is_environment_backed_with_autorun_and_delayed_expansion_off(
    rabbitmq: tuple[ModuleType, RabbitMQ, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = rabbitmq[0]
    calls: list[tuple[str, dict[str, Any]]] = []
    process = MagicMock(returncode=0)
    process.communicate.return_value = (b"rabbitmq_management\r\n", b"")
    process.__enter__.return_value = process

    def _popen(command: str, **kwargs: Any) -> MagicMock:
        calls.append((command, kwargs))
        return process

    monkeypatch.setattr(payload.subprocess, "Popen", _popen)
    executable = r"C:\Rabbit MQ & %literal%!\rabbitmq-plugins.bat"
    result = payload._batch_command(executable, ["list", "-E", "-m"])
    assert result["stdout"] == "rabbitmq_management\r\n"
    command, options = calls[0]
    assert executable not in command
    assert '/d /v:off /s /c ""%LEGACY_RABBITMQ_COMMAND%" "list" "-E" "-m""' in command
    assert options["env"]["LEGACY_RABBITMQ_COMMAND"] == executable
    assert "shell" not in options
    assert "LEGACY_RABBITMQ_COMMAND" not in os.environ


@pytest.mark.parametrize(
    "plugin",
    [
        'x"&echo hacked',
        "x&echo hacked",
        "x|cmd",
        "%PATH%",
        "x\ncmd",
        "x^&y",
        "x!v!",
        "x(y)",
    ],
)
def test_batch_rejects_control_syntax_without_starting_any_process(
    rabbitmq: tuple[ModuleType, RabbitMQ, Path],
    monkeypatch: pytest.MonkeyPatch,
    plugin: str,
) -> None:
    payload = rabbitmq[0]
    monkeypatch.setattr(
        payload.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("unsafe process launch"),
    )
    with pytest.raises(ValueError, match="shell metacharacters"):
        payload._batch_command(r"C:\RabbitMQ\rabbitmq-plugins.bat", ["enable", plugin])
