"""Exercise Scoop's public payloads with independent installed-tool responses."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module


@pytest.fixture(name="vendor")
def vendor_fixture(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Isolate the vendor boundary while loading the maintained helper.

    :param monkeypatch: Scoped target-helper import paths and vendor replies.
    :returns: Actual helper plus independent command outcomes.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(
        str(ROOT / "legacy_community_windows/plugins/module_utils")
    )
    helper = __import__("legacy_community_windows_scoop")
    state = SimpleNamespace(
        helper=helper,
        path="C:\\Scoop\\shims\\scoop.ps1",
        calls=[],
        apps=[],
        buckets=[],
        rc=0,
        stdout="Installed fixture",
        bootstraps=0,
    )
    monkeypatch.setattr(helper, "locate", lambda: state.path)
    monkeypatch.setattr(helper, "buckets", lambda _path: state.buckets)

    def command(path: str, arguments: list[str]) -> dict[str, Any]:
        """Supply an independent export or CLI mutation result.

        :param path: Actual selected Scoop script.
        :param arguments: Literal Scoop CLI arguments.
        :returns: Independent native vendor response.
        """
        state.calls.append((path, arguments))
        return {
            "rc": state.rc,
            "stdout": (
                json.dumps({"apps": state.apps})
                if arguments == ["export"]
                else state.stdout
            ),
            "stderr": "native error",
            "command": "observed literal command",
        }

    def bootstrap() -> dict[str, Any]:
        """Simulate the official installer becoming available on PATH.

        :returns: Independent installer response.
        """
        state.bootstraps += 1
        state.path = "C:\\Scoop\\shims\\scoop.ps1"
        return {"rc": 0, "stdout": "installed", "stderr": ""}

    monkeypatch.setattr(helper, "command", command)
    monkeypatch.setattr(helper, "bootstrap", bootstrap)
    return state


def _payload(name: str) -> ModuleType:
    return load_module(
        ROOT / "legacy_community_windows/plugins/modules" / (name + ".py"),
        "community_" + name,
    )


# Public payload execution keeps the JSON argv and output boundary explicit.
def _execute(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    name: str,
    arguments: dict[str, Any],
    _vendor: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> tuple[int, dict[str, Any]]:
    payload = _payload(name)
    argument_file = tmp_path / "arguments.json"
    argument_file.write_text(json.dumps(arguments), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [str(payload.__file__), str(argument_file)])
    return invoke_payload(payload, capsys)


@pytest.mark.parametrize("module", ["win_scoop", "win_scoop_bucket"])
def test_missing_scoop_check_mode_skips_without_installing(
    vendor: SimpleNamespace,
    module: str,
) -> None:
    vendor.path = None
    result = getattr(_payload(module), "_execute")(
        {"name": "fixture", "_ansible_check_mode": True}
    )
    assert result["skipped"] is True and result["changed"] is False
    assert vendor.calls == [] and vendor.bootstraps == 0


def test_package_install_bootstraps_only_the_package_module(
    vendor: SimpleNamespace,
) -> None:
    vendor.path = None
    result = getattr(_payload("win_scoop"), "_execute")({"name": "fixture"})
    assert result["changed"] is True and vendor.bootstraps == 1
    assert "installed during this task" in result["warnings"][0]
    vendor.path = None
    with pytest.raises(ValueError, match="Failed to find scoop.ps1"):
        getattr(_payload("win_scoop_bucket"), "_execute")({"name": "fixture"})
    assert vendor.bootstraps == 1


def test_package_install_selects_missing_scope_and_preserves_flags(
    vendor: SimpleNamespace,
) -> None:
    vendor.apps = [
        {
            "Name": "existing",
            "Version": "1",
            "Info": "Global install",
            "Source": "fixture",
        },
        {"Name": "wrong-scope", "Version": "1", "Info": "", "Source": "fixture"},
    ]
    result = getattr(_payload("win_scoop"), "_execute")(
        {
            "name": ["EXISTING", "wrong-scope", "missing"],
            "global": True,
            "arch": "32bit",
            "independent": True,
            "no_cache": True,
            "skip_checksum": True,
        }
    )
    assert result == {"changed": True, "rc": 0}
    assert vendor.calls[-1][1] == [
        "install",
        "wrong-scope",
        "missing",
        "--arch",
        "32bit",
        "--global",
        "--independent",
        "--no-cache",
        "--skip",
    ]


def test_package_repeat_is_unchanged_without_install_call(
    vendor: SimpleNamespace,
) -> None:
    vendor.apps = [{"Name": "fixture", "Info": "", "Version": "1", "Source": "main"}]
    assert (
        getattr(_payload("win_scoop"), "_execute")({"name": "FIXTURE"})["changed"]
        is False
    )
    assert [call[1] for call in vendor.calls] == [["export"]]


@pytest.mark.parametrize("check", [False, True])
def test_absent_always_attempts_broken_install_cleanup(
    vendor: SimpleNamespace, check: bool
) -> None:
    result = getattr(_payload("win_scoop"), "_execute")(
        {
            "name": "fixture",
            "state": "absent",
            "global": True,
            "purge": True,
            "_ansible_check_mode": check,
        }
    )
    assert result["changed"] is True
    assert [call[1] for call in vendor.calls] == (
        [["export"]]
        if check
        else [["export"], ["uninstall", "fixture", "--global", "--purge"]]
    )


def test_absent_not_installed_uses_vendor_message_to_report_unchanged(
    vendor: SimpleNamespace,
) -> None:
    vendor.stdout = "ERROR 'fixture' isn't installed."
    assert (
        getattr(_payload("win_scoop"), "_execute")(
            {"name": "fixture", "state": "absent"}
        )["changed"]
        is False
    )


def test_native_failure_retains_command_output_and_exit_status(
    vendor: SimpleNamespace,
) -> None:
    vendor.rc = 23
    result = getattr(_payload("win_scoop"), "_execute")({"name": "fixture"})
    assert result["failed"] is True and result["rc"] == 23
    assert result["stderr"] == "native error"
    assert result["command"] == "observed literal command"


@pytest.mark.parametrize(
    "state,installed,check,changed,operation",
    [
        ("present", [], False, True, "add"),
        ("present", ["FIXTURE"], False, False, "add"),
        ("absent", ["fixture"], False, True, "rm"),
        ("absent", [], False, False, "rm"),
        ("present", [], True, True, "add"),
    ],
)
# The table keeps state, prior state and preview behavior independent.
def test_bucket_changes_and_check_mode(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    vendor: SimpleNamespace,
    state: str,
    installed: list[str],
    check: bool,
    changed: bool,
    operation: str,
) -> None:
    vendor.buckets = installed
    result = getattr(_payload("win_scoop_bucket"), "_execute")(
        {
            "name": "fixture",
            "repo": "C:\\local repository",
            "state": state,
            "_ansible_check_mode": check,
        }
    )
    assert result["changed"] is changed and result["rc"] == 0
    assert [call[1] for call in vendor.calls] == (
        [["bucket", operation, "fixture", "C:\\local repository"]]
        if changed and not check
        else []
    )


@pytest.mark.parametrize(
    "output,expected",
    [
        (
            '{"apps":[{"Name":"ok","Info":"Global install, 32bit"},'
            '{"Name":"broken","Info":"Install failed"}]}',
            [{"name": "ok", "global": True}],
        ),
        (
            "fixture (v:1.0) *global* [main]{32bit}\nother (v:2) [main]\n",
            [{"name": "fixture", "global": True}, {"name": "other", "global": False}],
        ),
    ],
)
def test_installed_export_formats(
    vendor: SimpleNamespace, output: str, expected: list[dict[str, Any]]
) -> None:
    assert vendor.helper.packages(output) == expected


def test_public_json_entrypoint_reports_changed_result(
    vendor: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    status, result = _execute(
        "win_scoop",
        {"name": "fixture", "_ansible_verbosity": 2},
        vendor,
        monkeypatch,
        tmp_path,
        capsys,
    )
    assert status == 0 and result["changed"] is True
    assert result["stdout"] == "Installed fixture"
