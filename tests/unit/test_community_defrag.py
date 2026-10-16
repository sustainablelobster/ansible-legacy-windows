"""Exercise the public volume optimizer's observable native invocation contract."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Native execution is replaced; volume selection and result handling are real.
# pylint: disable=protected-access

import subprocess
from types import ModuleType
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module


@pytest.fixture(name="payload")
def defrag_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the volume optimizer with a recorded process boundary.

    :param monkeypatch: Scoped imports and executable substitutions.
    :returns: Loaded target module.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    module = load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_defrag.py",
        "tested_community_defrag",
    )
    monkeypatch.setattr(
        module.shutil, "which", Mock(return_value=r"C:\Windows\System32\defrag.exe")
    )
    monkeypatch.setattr(
        module,
        "run_command",
        Mock(return_value={"rc": 0, "stdout": "Analysis completed.", "stderr": ""}),
    )
    return module


def test_default_invocation_matches_all_volume_verbose_selection(
    payload: ModuleType,
) -> None:
    result = payload._optimize({})
    assert result["changed"] is True and result["rc"] == 0
    assert result["stdout"] == "Analysis completed."
    assert result["stderr"] == ""
    assert result["cmd"] == r"C:\Windows\System32\defrag.exe /C /V"
    assert result["start"] and result["end"] and result["delta"]
    payload.run_command.assert_called_once_with(
        r"C:\Windows\System32\defrag.exe",
        result["cmd"],
        {"chdir": None, "stdin": None, "output_encoding_override": None},
    )


def test_preview_runs_analysis_not_consolidation_and_preserves_changed_contract(
    payload: ModuleType,
) -> None:
    result = payload._optimize(
        {
            "include_volumes": ["D", "C:\\owned mount\\"],
            "exclude_volumes": ["E"],
            "freespace_consolidation": True,
            "parallel": True,
            "priority": "normal",
            "_ansible_check_mode": True,
        }
    )
    assert result["changed"] is True
    assert result["cmd"] == subprocess.list2cmdline(
        [
            r"C:\Windows\System32\defrag.exe",
            "D:",
            "C:\\owned mount\\",
            "/E",
            "E:",
            "/A",
            "/H",
            "/M",
            "/V",
        ]
    )
    assert "/X" not in result["cmd"]


def test_free_space_consolidation_uses_native_flag(payload: ModuleType) -> None:
    assert payload._optimize(
        {"include_volumes": "D,E", "freespace_consolidation": True}
    )["cmd"].endswith("D: E: /X /V")


def test_nonzero_native_status_is_returned_not_reinterpreted(
    payload: ModuleType,
) -> None:
    payload.run_command.return_value = {
        "rc": 0x89000024,
        "failed": True,
        "msg": "non-zero return code",
        "stdout": "Not enough space.",
        "stderr": "Native diagnostic",
    }
    result = payload._optimize({"include_volumes": "D"})
    assert result["changed"] is True
    assert result["rc"] == 0x89000024
    assert result["stderr"] == "Native diagnostic"
    assert "failed" not in result


def test_process_failure_remains_actionable(payload: ModuleType) -> None:
    payload.run_command.return_value = {
        "rc": -1,
        "failed": True,
        "msg": "Could not create process",
    }
    result = payload._optimize({"include_volumes": "D"})
    assert result["failed"] is True
    assert result["msg"] == "Could not create process"


@pytest.mark.parametrize(
    "options",
    [
        {"priority": "urgent"},
        {"include_volumes": ["/C"]},
        {"exclude_volumes": ["-X"]},
        {"include_volumes": [""]},
    ],
)
def test_invalid_options_fail_before_execution(
    payload: ModuleType, options: dict[str, object]
) -> None:
    with pytest.raises(ValueError):
        payload._optimize(options)
    payload.run_command.assert_not_called()


def test_missing_executable_is_not_positive_coverage(payload: ModuleType) -> None:
    payload.shutil.which.return_value = None
    with pytest.raises(OSError, match="defrag.exe"):
        payload._optimize({"include_volumes": "D"})
    payload.run_command.assert_not_called()
