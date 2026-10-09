"""Check owned source guards and literal recovery in the hotfix lab fixture."""

# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

# Ansible supplies PyYAML; optional typing stubs are not a target dependency.
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tests/integration/vars/hotfix_fixture.yml"


@pytest.fixture(name="fixture")
def hotfix_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load maintained cleanup functions without Windows or lab connections.

    :param tmp_path: Private journal and workspace.
    :param monkeypatch: Scoped target imports and runtime substitutions.
    :returns: Fixture namespace, journal and service-control recorder.
    """
    source = yaml.safe_load(SOURCE.read_text(encoding="utf-8"))["hotfix_fixture"]
    source = source[: source.rindex("\nvalidate_workspace()")]
    source = source.replace("assert sys.version_info[:3] == (3,4,4)\n", "")
    source = source.replace("assert sys.version_info[:3] == (3, 4, 4)\n", "")
    start = source.index("SOURCE=") if "SOURCE=" in source else source.index("SOURCE =")
    end = source.index("import legacy_windows_hotfix")
    source = source[:start] + source[end:]
    control = Mock()
    for name in ("legacy_windows_hotfix", "legacy_windows_service", "winreg"):
        module = ModuleType(name)
        if name == "legacy_windows_service":
            module.control = control  # type: ignore[attr-defined]
        monkeypatch.setitem(__import__("sys").modules, name, module)
    monkeypatch.setenv("SystemRoot", "C:\\Windows")
    monkeypatch.setattr("sys.argv", ["fixture", str(tmp_path), "cleanup"])
    namespace: dict[str, Any] = {}
    exec(compile(source, str(SOURCE), "exec"), namespace)  # pylint: disable=exec-used
    before = {
        "packages": {
            "visible": [{"name": "visible", "state": "Installed"}],
            "native": [{"name": "hidden", "state": "Installed"}],
        },
        "hotfixes": [{"HotFixID": "KB42"}],
        "pending": {"key": None},
        "files": {"protected": {"sha256": "raw", "attributes": 32, "mtime": 7.125}},
        "temporary": ["existing-guid"],
        "services": {"TrustedInstaller": {"State": "Stopped", "StartMode": "Manual"}},
    }
    journal = {
        "workspace": str(tmp_path),
        "supported": True,
        "protected_paths": ["protected"],
        "complete": True,
        "before": before,
    }
    namespace["write"](journal)
    namespace["snapshot"] = lambda _record: copy.deepcopy(before)
    namespace["services"] = lambda: copy.deepcopy(before["services"])
    namespace["pending"] = lambda: copy.deepcopy(before["pending"])
    namespace["protected_files"] = lambda _paths: copy.deepcopy(before["files"])
    namespace["temporary"] = lambda: list(before["temporary"])
    return SimpleNamespace(namespace=namespace, journal=journal, control=control)


@pytest.mark.parametrize(
    "field", ["packages", "hotfixes", "pending", "files", "temporary", "services"]
)
def test_any_protected_change_blocks_cleanup_and_retains_journal(
    fixture: Any, field: str
) -> None:
    final = copy.deepcopy(fixture.journal["before"])
    final[field] = {"unexpected": "change"}
    fixture.namespace["snapshot"] = lambda _record: final
    if field == "services":
        fixture.namespace["services"] = lambda: final[field]
    with pytest.raises(AssertionError):
        fixture.namespace["cleanup"]()
    assert Path(fixture.namespace["JOURNAL"]).exists()
    assert not fixture.namespace["read"]().get("verified", False)


def test_literal_recovery_is_verified_before_journal_removal(fixture: Any) -> None:
    result = fixture.namespace["cleanup"]()
    assert result["restored"] is True and result["before"] == result["after"]
    assert Path(fixture.namespace["JOURNAL"]).exists()
    fixture.control.assert_not_called()
    assert fixture.namespace["finalize"]() == {"finalized": True}
    assert not Path(fixture.namespace["JOURNAL"]).exists()


@pytest.mark.parametrize("field", ["pending", "files", "temporary", "services"])
def test_finalize_rechecks_protected_fields_before_removing_journal(
    fixture: Any, field: str
) -> None:
    fixture.namespace["cleanup"]()
    function = {"files": "protected_files"}.get(field, field)
    fixture.namespace[function] = lambda *_: {"unexpected": "change"}
    with pytest.raises(AssertionError):
        fixture.namespace["finalize"]()
    assert Path(fixture.namespace["JOURNAL"]).exists()


def test_missing_journal_only_accepts_an_exactly_empty_workspace(fixture: Any) -> None:
    journal = Path(fixture.namespace["JOURNAL"])
    journal.unlink()
    Path(fixture.journal["workspace"], "unknown-partial").write_text(
        "retain", encoding="utf-8"
    )
    with pytest.raises(AssertionError):
        fixture.namespace["cleanup"]()
    with pytest.raises(AssertionError):
        fixture.namespace["finalize"]()


def test_wrong_workspace_in_journal_is_not_adopted(fixture: Any) -> None:
    fixture.journal["workspace"] = "another-workspace"
    Path(fixture.namespace["JOURNAL"]).write_text(
        json.dumps(fixture.journal), encoding="utf-8"
    )
    with pytest.raises(AssertionError):
        fixture.namespace["cleanup"]()


def test_service_recovery_only_restores_a_read_induced_start(fixture: Any) -> None:
    before = fixture.journal["before"]["services"]
    fixture.namespace["services"] = lambda: {
        "TrustedInstaller": {"State": "Running", "StartMode": "Manual"}
    }
    fixture.namespace["restore_service"](before)
    fixture.control.assert_called_once_with("TrustedInstaller", "stopped")


@pytest.mark.parametrize("change", [{"State": "Paused"}, {"StartMode": "Disabled"}])
def test_unrelated_service_configuration_is_not_restored_as_owned(
    fixture: Any, change: dict[str, str]
) -> None:
    before = fixture.journal["before"]["services"]
    current = copy.deepcopy(before)
    current["TrustedInstaller"].update(change)
    fixture.namespace["services"] = lambda: current
    with pytest.raises(AssertionError):
        fixture.namespace["restore_service"](before)
    fixture.control.assert_not_called()
