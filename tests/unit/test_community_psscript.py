"""Verify script-management input and result contracts at the public boundary."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module


@pytest.fixture(name="payload")
def payload_fixture(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the real Python payload and target-compatible vendor helper.

    :param monkeypatch: Scoped helper import paths.
    :returns: Payload with no engine calls performed during import.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(
        str(ROOT / "legacy_community_windows/plugins/module_utils")
    )
    return load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_psscript.py",
        "community_script_management",
    )


def _run(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    arguments: dict[str, Any],
) -> tuple[int, dict[str, Any]]:
    argument_file = tmp_path / "script.json"
    argument_file.write_text(json.dumps(arguments), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [str(payload.__file__), str(argument_file)])
    return invoke_payload(payload, capsys)


@pytest.mark.parametrize("check_mode", [False, True])
def test_version_scope_and_credentials_remain_data_only(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    check_mode: bool,
) -> None:
    received: list[dict[str, Any]] = []
    script_name = "Fixture';throw 'not code'"

    def invoke(operation: str, parameters: dict[str, Any]) -> dict[str, Any]:
        """Observe converted values without simulating installed vendor commands.

        :param operation: Fixed vendor operation text.
        :param parameters: Public values carried only in JSON.
        :returns: Independently selected operation result.
        """
        assert script_name not in operation
        assert "fixture-secret" not in operation
        received.append(parameters)
        return {"changed": True}

    # This public script request must remain visible independently of the
    # module/repository frontends that use the same JSON invocation shape.
    # pylint: disable=duplicate-code
    monkeypatch.setattr(payload, "invoke", invoke)
    status, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {
            "name": script_name,
            "repository": "FixtureRepo",
            "scope": "current_user",
            "required_version": "1.2.3",
            "source_username": "fixture-user",
            "source_password": "fixture-secret",
            "allow_prerelease": "yes",
            "_ansible_check_mode": check_mode,
        },
    )
    # pylint: enable=duplicate-code
    assert status == 0
    assert result == {"changed": True}
    assert received == [
        {
            "name": script_name,
            "repository": "FixtureRepo",
            "scope": "current_user",
            "state": "present",
            "required_version": "1.2.3",
            "minimum_version": None,
            "maximum_version": None,
            "source_username": "fixture-user",
            "source_password": "fixture-secret",
            "allow_prerelease": True,
            "check_mode": check_mode,
        }
    ]


@pytest.mark.parametrize(
    "invalid",
    [
        ({}, "name is required"),
        ({"name": "Fixture", "scope": "machine"}, "scope must"),
        ({"name": "Fixture", "state": "installed"}, "state must"),
        (
            {"name": "Fixture", "required_version": "1", "maximum_version": "2"},
            "required_version cannot",
        ),
        (
            {"name": "Fixture", "state": "latest", "minimum_version": "1"},
            "version options cannot",
        ),
        (
            {"name": "Fixture", "state": "absent", "repository": "FixtureRepo"},
            "repository cannot",
        ),
        ({"name": "Fixture", "source_username": "user"}, "supplied together"),
        ({"name": "Fixture", "source_password": "secret"}, "supplied together"),
    ],
)
def test_invalid_combinations_never_launch_the_installed_engine(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    invalid: tuple[dict[str, Any], str],
) -> None:
    def unexpected(*_arguments: Any) -> None:
        pytest.fail("Invalid script options must not launch PowerShell")

    monkeypatch.setattr(payload, "invoke", unexpected)
    arguments, message = invalid
    status, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 1
    assert message in result["msg"]


def test_partial_vendor_failure_preserves_changed_and_warning_fields(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def invoke(_operation: str, parameters: dict[str, Any]) -> dict[str, Any]:
        """Return a failure after an independently chosen uninstall mutation.

        :param parameters: Converted public options.
        :returns: Vendor failure containing observable partial-change state.
        """
        assert parameters["state"] == "absent"
        assert parameters["scope"] == "all_users"
        return {
            "changed": True,
            "failed": True,
            "msg": "vendor uninstall failed",
            "warnings": ["vendor warning"],
        }

    monkeypatch.setattr(payload, "invoke", invoke)
    status, result = _run(
        payload, monkeypatch, tmp_path, capsys, {"name": "Fixture", "state": "absent"}
    )
    assert status == 1
    assert result["changed"] is True
    assert result["msg"] == "vendor uninstall failed"
    assert result["warnings"] == ["vendor warning"]
