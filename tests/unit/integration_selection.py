"""Exercise effective fixture variables through a local Ansible play."""

# SPDX-License-Identifier: GPL-3.0-or-later

import subprocess
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


def assert_local_selection(
    tmp_path: Path,
    variables: dict[str, Any],
    conditions: list[str],
    vars_files: list[str],
    extra_vars: Path | None = None,
) -> None:
    """Require the fixture's effective variable selection without guest access.

    :param tmp_path: Isolated directory for the local assertion play.
    :param variables: Values used by the assertion, including expected cases.
    :param conditions: Ansible assertion expressions for the effective values.
    :param vars_files: Absolute variable files in the fixture's declared order.
    :param extra_vars: Optional correction matrix supplied with highest priority.
    :raises AssertionError: Ansible fails or reports a change or failure.
    """
    play = [
        {
            "hosts": "localhost",
            "gather_facts": False,
            "vars_files": vars_files,
            "vars": variables,
            "tasks": [
                {
                    "name": "Require exact fixture selection",
                    "ansible.builtin.assert": {"that": conditions},
                }
            ],
        }
    ]
    path = tmp_path / "selection.yml"
    path.write_text(yaml.safe_dump(play, sort_keys=False), encoding="utf-8")
    command = ["ansible-playbook", "-i", "localhost,", "-c", "local", str(path)]
    if extra_vars is not None:
        command += ["-e", "@" + str(extra_vars)]
    result = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "changed=0" in result.stdout and "failed=0" in result.stdout
