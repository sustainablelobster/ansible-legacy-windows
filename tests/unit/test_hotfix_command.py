"""Exercise the older installed DISM command's package-servicing contract."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Controller substitutes are not Windows execution evidence.
# pylint: disable=protected-access

from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="helper")
def command_helper() -> ModuleType:
    """Load the installed-tool backend without accessing Windows.

    :returns: Fresh target helper.
    """
    return load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_hotfix_command.py",
        "tested_hotfix_command",
    )


def _command(helper: ModuleType, output: str, status: int = 0) -> Any:
    command = helper.DismCommand("dism.exe")
    command._execute = Mock(return_value=(status, output))
    return command


def test_catalogue_retains_actual_order_and_pending_states(helper: ModuleType) -> None:
    command = _command(
        helper,
        "Package Identity : First\nState : Installed\n"
        "Package Identity : Second\nState : Install Pending\n",
    )
    assert command.catalogue() == [
        {"name": "First", "state": "Installed"},
        {"name": "Second", "state": "InstallPending"},
    ]
    command._execute.assert_called_once_with(["/Get-Packages"])


@pytest.mark.parametrize("by_path", [False, True])
@pytest.mark.parametrize("applicable", ["Yes", "No"])
def test_exact_package_selectors_and_real_applicability(
    helper: ModuleType, by_path: bool, applicable: str
) -> None:
    command = _command(
        helper,
        "Package Identity : Real\nState : Not Present\n"
        "Description : Fix for KB42\nApplicable : " + applicable,
    )
    assert command.information("literal name.cab", by_path) == {
        "name": "Real",
        "state": "NotPresent",
        "description": "Fix for KB42",
        "applicable": applicable == "Yes",
    }
    command._execute.assert_called_once_with(
        [
            "/Get-PackageInfo",
            ("/PackagePath:" if by_path else "/PackageName:") + "literal name.cab",
        ]
    )


@pytest.mark.parametrize(
    "output",
    [
        "Package Identity : Real\nState : Installed",
        "Package Identity : Real\nState : Installed\nDescription : KB42",
        "Package Identity : Real\nState : Installed\nDescription : KB42\n"
        "Applicable : Unknown",
    ],
)
def test_cab_inspection_never_fabricates_missing_applicability(
    helper: ModuleType, output: str
) -> None:
    with pytest.raises(OSError, match="incomplete|applicable"):
        _command(helper, output).information("source.cab", True)


@pytest.mark.parametrize("operation", ["add", "remove"])
@pytest.mark.parametrize("status", [0, 3010, 1000])
def test_native_servicing_preserves_literal_inputs_restart_and_failures(
    helper: ModuleType, operation: str, status: int
) -> None:
    command = _command(helper, "native result", status)
    if status == 1000:
        with pytest.raises(OSError, match="1000.*native result"):
            getattr(command, operation)("Literal Name")
    else:
        assert getattr(command, operation)("Literal Name") is (status == 3010)
    command._execute.assert_called_once_with(
        ["/Add-Package", "/PackagePath:Literal Name"]
        if operation == "add"
        else ["/Remove-Package", "/PackageName:Literal Name"]
    )


def test_owned_temporary_directory_is_removed_after_failure(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(OSError, match="native failure"):
        with helper.DismCommand("dism.exe") as command:
            path = Path(command._workspace)
            assert path.exists()
            monkeypatch.setattr(
                command, "_execute", Mock(return_value=(1, "native failure"))
            )
            command.add("source.cab")
    assert not path.exists()
