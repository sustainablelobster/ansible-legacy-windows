"""Distinguish actual WUA transfer callbacks from startup or finished packets."""

# SPDX-License-Identifier: GPL-3.0-or-later
# pylint: disable=protected-access

from pathlib import Path
from types import ModuleType

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="fixture")
def real_cancel_fixture() -> ModuleType:
    """Load only the stdlib fixture; do not call Windows APIs on the controller.

    :returns: The dedicated real-WUA cancellation observer.
    """
    return load_module(
        ROOT / "tests/integration/fixtures/win_updates_real_cancel.py",
        "tested_real_wua_cancel",
    )


@pytest.mark.parametrize(
    "tasks,finished,expected",
    [
        ([], False, False),
        (["started"], False, False),
        (["started", "search_result"], False, False),
        (["started", "search_result", "download"], False, True),
        (["started", "search_result", "download"], True, False),
        (["started", "download_result", "exit"], True, False),
    ],
)
def test_only_active_actual_download_callbacks_permit_caller_loss(
    fixture: ModuleType, tasks: list[str], finished: bool, expected: bool
) -> None:
    assert (
        fixture._active_download(
            {
                "finished": finished,
                "output": [
                    {"task": task, "result": {"progress": {"TotalBytesDownloaded": 1}}}
                    for task in tasks
                ],
            }
        )
        is expected
    )


def test_observer_compiles_on_the_controller_without_native_calls() -> None:
    source = (ROOT / "tests/integration/fixtures/win_updates_real_cancel.py").read_text(
        encoding="utf-8"
    )
    compile(source, str(Path("win_updates_real_cancel.py")), "exec")
