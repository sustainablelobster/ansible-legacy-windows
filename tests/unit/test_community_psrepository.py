"""Exercise repository management at the public JSON payload boundary."""

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
    """Load repository management with its actual target-compatible helpers.

    :param monkeypatch: Scoped helper import paths.
    :returns: Actual management payload, without launching PowerShell.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(
        str(ROOT / "legacy_community_windows/plugins/module_utils")
    )
    return load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_psrepository.py",
        "community_repository_management",
    )


def _run(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    arguments: dict[str, Any],
) -> tuple[int, dict[str, Any]]:
    argument_file = tmp_path / "repository.json"
    argument_file.write_text(json.dumps(arguments), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [str(payload.__file__), str(argument_file)])
    return invoke_payload(payload, capsys)


@pytest.mark.parametrize("check_mode", [False, True])
def test_registration_aliases_and_check_mode_are_data_only(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    check_mode: bool,
) -> None:
    received: list[dict[str, Any]] = []
    source = "https://example.invalid/feed';throw 'not code'"

    def invoke(operation: str, parameters: dict[str, Any]) -> dict[str, Any]:
        """Observe converted values without interpreting the fixed vendor script.

        :param operation: Fixed installed-engine operation.
        :param parameters: JSON-safe public option values.
        :returns: Independent vendor change result.
        """
        assert source not in operation
        received.append(parameters)
        return {"changed": True, "warnings": ["fixture warning"]}

    # Keep the public repository request visible instead of hiding its options
    # behind a shared invocation fixture for otherwise independent payloads.
    # pylint: disable=duplicate-code
    monkeypatch.setattr(payload, "invoke", invoke)
    status, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {
            "name": "Fixture",
            "source": source,
            "installation_policy": "UNTRUSTED",
            "force": "yes",
            "_ansible_check_mode": check_mode,
        },
    )
    # pylint: enable=duplicate-code
    assert status == 0
    assert result == {"changed": True, "warnings": ["fixture warning"]}
    assert received == [
        {
            "name": "Fixture",
            "source_location": source,
            "script_source_location": None,
            "publish_location": None,
            "script_publish_location": None,
            "installation_policy": "untrusted",
            "proxy": None,
            "username": None,
            "password": None,
            "state": "present",
            "force": True,
            "check_mode": check_mode,
        }
    ]


def test_absent_requests_and_partial_failures_preserve_vendor_result(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def invoke(_operation: str, parameters: dict[str, Any]) -> dict[str, Any]:
        """Model an error after the installed engine performed a mutation.

        :param parameters: Converted public values.
        :returns: Independent vendor partial-mutation failure.
        """
        assert parameters["state"] == "absent"
        assert parameters["source_location"] == "file:///C:/primary"
        return {"changed": True, "failed": True, "msg": "vendor denied removal"}

    # This direct invocation verifies the repository-specific alias precedence.
    # pylint: disable=duplicate-code
    monkeypatch.setattr(payload, "invoke", invoke)
    status, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {
            "name": "Fixture",
            "state": "ABSENT",
            "source_location": "file:///C:/primary",
            "source": "file:///C:/ignored-alias",
        },
    )
    # pylint: enable=duplicate-code
    assert status == 1
    assert result == {
        "changed": True,
        "failed": True,
        "msg": "vendor denied removal",
    }


@pytest.mark.parametrize(
    "invalid",
    [
        ({}, "name is required"),
        ({"name": "Fixture", "state": "latest"}, "state must"),
        (
            {"name": "Fixture", "installation_policy": "ignored"},
            "installation_policy must",
        ),
        ({"name": "Fixture", "force": "maybe"}, "force"),
    ],
)
def test_invalid_public_options_fail_before_engine_launch(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    invalid: tuple[dict[str, Any], str],
) -> None:
    def unexpected(*_arguments: Any) -> None:
        pytest.fail("Invalid options must not launch the installed engine")

    # Reject this module's public options before calling its vendor boundary.
    # pylint: disable=duplicate-code
    monkeypatch.setattr(payload, "invoke", unexpected)
    arguments, message = invalid
    status, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 1
    assert message in result["msg"]
    # pylint: enable=duplicate-code
