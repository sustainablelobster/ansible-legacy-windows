"""Guard the structured-script journal and actual effective matrix selection."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These private fixture functions are the ownership/recovery boundaries.
# pylint: disable=protected-access

from pathlib import Path

import pytest
import yaml  # type: ignore[import-untyped]

from tests.unit.integration_selection import assert_local_selection
from tests.unit.payload_support import ROOT


@pytest.mark.parametrize("correction", [False, True])
def test_effective_structured_powershell_matrix_selection(
    tmp_path: Path, correction: bool
) -> None:
    """Prove the selected public cases before a wrapper reserves a guest."""
    integration = ROOT / "tests/integration"
    original = yaml.safe_load((integration / "win_powershell.yml").read_text())[0]
    variables = yaml.safe_load((integration / "vars/win_powershell.yml").read_text())
    extra = integration / "vars/win_powershell_correction.yml"
    if correction:
        variables = yaml.safe_load(extra.read_text())
    expected = variables["powershell_cases"]
    assert (
        len(expected)
        == len({case["name"] for case in expected})
        == (2 if correction else 35)
    )
    assert sum(bool(case.get("failed")) for case in expected) == (
        1 if correction else 13
    )
    assert sum(bool(case.get("check")) for case in expected) == (0 if correction else 2)
    assert_local_selection(
        tmp_path,
        {"expected": expected},
        ["powershell_cases == expected", "not powershell_compare"],
        [str(integration / path) for path in original["vars_files"]],
        extra if correction else None,
    )


def test_effective_powershell_absence_modes(tmp_path: Path) -> None:
    """Prove both prerequisite modes before reserving the legacy guests."""
    integration = ROOT / "tests/integration"
    original = yaml.safe_load(
        (integration / "win_powershell_unavailable.yml").read_text()
    )[0]
    assert_local_selection(
        tmp_path,
        {"powershell_source_root": str(ROOT)},
        [
            "powershell_absence_modes == [false, true]",
            "'(3,4,4)' in powershell_absence_program",
            "'Win32_Service' in powershell_absence_program",
            "'Win32_NetworkAdapterConfiguration' in powershell_absence_program",
        ],
        [str(integration / path) for path in original["vars_files"]],
    )
