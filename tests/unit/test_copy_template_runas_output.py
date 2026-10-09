"""Reject paired incomplete output effects and unexpected workflow shapes."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
from typing import Any

import pytest

from scripts import verify_copy_template_runas_capture as verifier

# Reuse the maintained raw-capture fixture instead of a second synthetic matrix.
# Pytest discovers these imports through their explicitly declared fixture names.
# pylint: disable=unused-import
from tests.unit.test_copy_template_runas import _capture, _workflow_fixture

# pylint: enable=unused-import


@pytest.mark.parametrize("index", range(24))
def test_paired_unexpected_directories_fail_every_workflow_phase(
    capture: dict[str, Any], index: int
) -> None:
    row = capture["results"][index]
    for side in ("native", "original"):
        for phase in ("before", "after"):
            record = row[phase + "_" + side]
            observed = json.loads(record["stdout"])
            observed["output"]["unexpected"] = {
                "metadata": {
                    "attributes": 16,
                    "modification_time": 116444736015000000,
                },
                "security": {"owner": "S-1-5-32-544", "sddl": "O:BAD:"},
            }
            record["stdout"] = json.dumps(observed)
    with pytest.raises(AssertionError):
        verifier.verify_capture(capture)


@pytest.mark.parametrize(
    "field,value",
    [
        ("security", None),
        ("security", {}),
        ("security", {"owner": "S-1-5-32-544"}),
        ("security", {"sddl": "O:BAD:"}),
        ("security", {"owner": None, "sddl": "O:BAD:"}),
        ("security", {"owner": "S-1-5-32-544", "sddl": ""}),
        ("metadata", {}),
        ("metadata", {"attributes": 32}),
        ("metadata", {"attributes": True, "modification_time": 116444736015000000}),
        ("metadata", {"attributes": 16, "modification_time": 116444736015000000}),
        ("base64", None),
    ],
)
def test_identically_incomplete_paired_create_effects_are_rejected(
    capture: dict[str, Any], field: str, value: Any
) -> None:
    row = capture["results"][12]
    for side in ("native", "original"):
        record = row["after_" + side]
        observed = json.loads(record["stdout"])
        entry = observed["output"]["single.bin"]
        if value is None:
            del entry[field]
        else:
            entry[field] = value
        record["stdout"] = json.dumps(observed)
    with pytest.raises(AssertionError):
        verifier.verify_capture(capture)
