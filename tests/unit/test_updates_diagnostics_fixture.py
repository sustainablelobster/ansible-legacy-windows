"""Check the diagnostic fixture's embedded target observer before lab use."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
from pathlib import Path

# PyYAML is the existing fixture parser; Nix does not ship its optional stubs.
import yaml  # type: ignore[import-untyped]


def test_staging_observer_has_minimum_target_compatible_syntax() -> None:
    root = Path(__file__).resolve().parents[2]
    play = yaml.safe_load(
        (root / "tests/integration/win_updates_diagnostics.yml").read_text(
            encoding="utf-8"
        )
    )[0]
    program = play["vars"]["updates_diagnostics_staging"]
    ast.parse(program, feature_version=(3, 4))
    compile(program, "updates_diagnostics_staging", "exec")
