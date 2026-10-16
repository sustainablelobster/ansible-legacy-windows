"""Verify module-management requests and results at the public JSON boundary."""

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
    """Load the real module-management payload without launching the vendor.

    :param monkeypatch: Scoped target-helper import paths.
    :returns: Actual management payload.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(
        str(ROOT / "legacy_community_windows/plugins/module_utils")
    )
    return load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_psmodule.py",
        "community_module_management",
    )


def _run(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    arguments: dict[str, Any],
) -> tuple[int, dict[str, Any]]:
    argument_file = tmp_path / "module.json"
    argument_file.write_text(json.dumps(arguments), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [str(payload.__file__), str(argument_file)])
    return invoke_payload(payload, capsys)


@pytest.mark.parametrize("check_mode", [False, True])
def test_module_options_and_check_mode_are_carried_only_as_data(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    check_mode: bool,
) -> None:
    received: list[dict[str, Any]] = []
    module_name = "Fixture';throw 'not code'"

    def invoke(operation: str, parameters: dict[str, Any]) -> dict[str, Any]:
        """Observe real request conversion without simulating vendor algorithms.

        :param operation: Fixed vendor operation script.
        :param parameters: Public options conveyed through JSON only.
        :returns: Independently selected successful vendor result.
        """
        assert module_name not in operation
        assert "fixture-secret" not in operation
        received.append(parameters)
        return {
            "changed": True,
            "output": "fixture installed",
            "nuget_changed": False,
            "repository_changed": False,
        }

    # Exercise this public payload directly, even though sibling modules use
    # the same JSON invocation shape with their own independently chosen options.
    # pylint: disable=duplicate-code
    monkeypatch.setattr(payload, "invoke", invoke)
    status, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {
            "name": module_name,
            "required_version": "1.2.3-preview",
            "repository": "FixtureRepo",
            "username": "fixture-user",
            "password": "fixture-secret",
            "allow_clobber": "yes",
            "allow_prerelease": True,
            "skip_publisher_check": True,
            "accept_license": True,
            "force": True,
            "_ansible_check_mode": check_mode,
        },
    )
    # pylint: enable=duplicate-code
    assert status == 0
    assert result["changed"] is True
    assert result["output"] == "fixture installed"
    assert received == [
        {
            "name": module_name,
            "required_version": "1.2.3-preview",
            "minimum_version": None,
            "maximum_version": None,
            "repository": "FixtureRepo",
            "username": "fixture-user",
            "password": "fixture-secret",
            "allow_clobber": True,
            "skip_publisher_check": True,
            "allow_prerelease": True,
            "accept_license": True,
            "force": True,
            "state": "present",
            "check_mode": check_mode,
        }
    ]


@pytest.mark.parametrize("state", ["present", "latest", "absent"])
def test_vendor_partial_changes_and_failures_are_not_rewritten(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    state: str,
) -> None:
    vendor_result = {
        "changed": True,
        "failed": True,
        "msg": "independent provider failure",
        "output": "prerequisite installed",
        "nuget_changed": True,
        "repository_changed": False,
    }

    def invoke(_operation: str, parameters: dict[str, Any]) -> dict[str, Any]:
        """Return independently selected failure state from the vendor boundary.

        :param parameters: Actual converted request.
        :returns: Partial-mutation failure containing public state fields.
        """
        assert parameters["state"] == state
        return vendor_result

    monkeypatch.setattr(payload, "invoke", invoke)
    status, result = _run(
        payload, monkeypatch, tmp_path, capsys, {"name": "Fixture", "state": state}
    )
    assert status == 1
    assert result == vendor_result


@pytest.mark.parametrize(
    "invalid",
    [
        ({}, "name is required"),
        ({"name": "Fixture", "state": "installed"}, "state must"),
        ({"name": "Fixture", "force": "maybe"}, "force"),
    ],
)
def test_invalid_public_inputs_fail_before_engine_launch(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    invalid: tuple[dict[str, Any], str],
) -> None:
    def unexpected(*_arguments: Any) -> None:
        pytest.fail("Invalid module options must not launch PowerShell")

    # Invalid public options must be rejected independently by this frontend.
    # pylint: disable=duplicate-code
    monkeypatch.setattr(payload, "invoke", unexpected)
    arguments, message = invalid
    status, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 1
    assert message in result["msg"]
    # pylint: enable=duplicate-code
