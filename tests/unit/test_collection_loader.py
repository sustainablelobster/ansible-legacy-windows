"""Resolve the checkout's actions regardless of test order or installed copies."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.unit.payload_support import ROOT


@pytest.mark.parametrize(
    "render_first", [True, False], ids=["render-first", "actions-first"]
)
def test_collection_actions_resolve_with_empty_search_paths(
    tmp_path: Path, render_first: bool
) -> None:
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\n", encoding="utf-8")
    collections = tmp_path / "empty collections"
    collections.mkdir()
    # Keep the isolation settings visible rather than sharing a subprocess fixture.
    # pylint: disable=duplicate-code
    environment = {
        **os.environ,
        "ANSIBLE_CONFIG": str(config),
        "ANSIBLE_COLLECTIONS_PATH": str(collections),
        "ANSIBLE_COLLECTIONS_SCAN_SYS_PATH": "false",
        "ANSIBLE_LOCAL_TEMP": str(tmp_path / "controller-tmp"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    environment.pop("ANSIBLE_ACTION_PLUGINS", None)
    # pylint: enable=duplicate-code
    environment.pop("PYTEST_ADDOPTS", None)
    action_file = ROOT / "tests/unit/test_python_action.py"
    cases = [
        f"{action_file}::{name}"
        for name in (
            "test_stages_only_required_helpers_and_normal_action_cleans_once",
            "test_ansible_task_validation_preserves_only_process_free_form",
        )
    ]
    render_case = (
        f"{ROOT / 'tests/unit/test_integration_paths.py'}::"
        "test_output_defaults_follow_controller_temporary_storage"
    )
    cases.insert(0 if render_first else len(cases), render_case)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "-W",
            "error:AnsibleCollectionFinder has already been configured:UserWarning",
            *cases,
        ],
        # Standard subprocess options do not warrant a wrapper for this test.
        # pylint: disable=duplicate-code
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    # pylint: enable=duplicate-code
    assert result.returncode == 0, result.stdout + result.stderr
