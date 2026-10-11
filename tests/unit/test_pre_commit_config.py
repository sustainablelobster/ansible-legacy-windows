"""Keep Ansible payload exemptions limited to the executable-shebang check."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import re
from pathlib import Path
from typing import Any

import pytest

# The pinned developer environment provides PyYAML without typing stubs.
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]


def _configuration() -> dict[str, Any]:
    document: dict[str, Any] = yaml.safe_load(
        (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    )
    return document


def _hook(hook_id: str) -> dict[str, Any]:
    hook: dict[str, Any] = next(
        hook
        for repository in _configuration()["repos"]
        for hook in repository["hooks"]
        if hook["id"] == hook_id
    )
    return hook


@pytest.mark.parametrize(
    "path",
    [
        "plugins/modules/win_ping.py",
        "plugins/modules/win_updates.py",
        "plugins/module_utils/legacy_windows_async_wrapper.py",
    ],
)
def test_ansible_payloads_are_exempt_from_executable_shebang_check(path: str) -> None:
    hook = _hook("check-shebang-scripts-are-executable")
    assert re.search(hook["exclude"], path)


@pytest.mark.parametrize(
    "path",
    [
        "scripts/ci_release.py",
        "plugins/action/win_ping.py",
        "plugins/module_utils/legacy_windows_api.py",
        "plugins/module_utils/legacy_windows_async_wrapper_extra.py",
        "tests/integration/fixtures/legacy_windows_async_wrapper.py",
        "tests/plugins/modules/win_ping.py",
        "plugins/modules/nested/win_ping.py",
        "plugins/modules/win_ping.py.bak",
        "plugins/modules/README.md",
    ],
)
def test_other_paths_remain_subject_to_executable_shebang_check(path: str) -> None:
    hook = _hook("check-shebang-scripts-are-executable")
    assert not re.search(hook["exclude"], path)


@pytest.mark.parametrize(
    "hook_id",
    [
        "check-executables-have-shebangs",
        "check-merge-conflict",
        "trailing-whitespace",
    ],
)
@pytest.mark.parametrize(
    "path",
    [
        "plugins/modules/win_ping.py",
        "plugins/module_utils/legacy_windows_async_wrapper.py",
    ],
)
def test_payloads_are_not_excluded_from_other_generic_checks(
    hook_id: str, path: str
) -> None:
    config = _configuration()
    hook = _hook(hook_id)
    assert re.search(config.get("files", ""), path)
    assert not re.search(config.get("exclude", "^$"), path)
    assert re.search(hook.get("files", ""), path)
    assert not re.search(hook.get("exclude", "^$"), path)
