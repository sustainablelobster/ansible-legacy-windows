"""Exercise patch fixture ownership and strict recovery without lab access."""

# SPDX-License-Identifier: GPL-3.0-or-later
# The fixture exposes native boundaries for observable cleanup tests.
# pylint: disable=protected-access

import copy
import os
import runpy
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="fixture")
def msp_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load the maintained fixture with local native resource substitutes.

    :param tmp_path: Exact owned journal/workspace directory.
    :param monkeypatch: Scoped Windows-only imports and state observations.
    :returns: Fixture module with recorded pristine state and cleanup boundaries.
    """
    for name in (
        "winreg",
        "legacy_windows_acl",
        "legacy_windows_package_msi",
        "legacy_windows_service",
        "legacy_windows_wmi",
    ):
        helper = ModuleType(name)
        if name == "legacy_windows_wmi":
            helper.WmiConnection = Mock()  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, name, helper)
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "programs"))
    monkeypatch.delenv("ProgramFiles(x86)", raising=False)
    monkeypatch.setattr(sys, "argv", ["fixture", str(tmp_path), "cleanup"])
    module: Any = load_module(
        ROOT / "tests/integration/fixtures/package_msp_fixture.py", "tested_msp_fixture"
    )
    before = {
        "products": [{"id": "protected", "state": 5}],
        "patches": [{"patch": "protected", "product": "protected", "state": 1}],
        "state": -1,
        "services": {"MSIServer": {"State": "Stopped"}},
        "pending": {},
        "sources": {},
        "outputs": {},
        "uninstall_keys": {"owned": None},
    }
    module._write(
        {
            "workspace": str(tmp_path),
            "application": module.APPLICATION,
            "before": before,
            "complete": True,
            "verified": False,
        }
    )
    module._snapshot = lambda: copy.deepcopy(before)
    module._remove_owned_product = Mock()
    module._restore_sources = Mock()
    module._restore_service = Mock()
    return module


@pytest.mark.parametrize(
    "field",
    [
        "products",
        "patches",
        "state",
        "services",
        "pending",
        "sources",
        "outputs",
        "uninstall_keys",
    ],
)
def test_foreign_difference_keeps_unverified_journal(fixture: Any, field: str) -> None:
    final = fixture._snapshot()
    final[field] = {"foreign": "difference"}
    fixture._snapshot = lambda: final
    with pytest.raises(AssertionError):
        fixture._cleanup()
    assert Path(fixture.JOURNAL).exists() and fixture._read()["verified"] is False


def test_verified_cleanup_and_independent_finalize_leave_no_journal(
    fixture: Any,
) -> None:
    result = fixture._cleanup()
    assert result["restored"] and result["before"] == result["after"]
    assert fixture._read()["verified"]
    assert fixture._finalize() == {"finalized": True}
    assert not Path(fixture.JOURNAL).exists()


def test_finalize_reobserves_full_state(fixture: Any) -> None:
    fixture._cleanup()
    fixture._snapshot = lambda: {"foreign": "difference"}
    with pytest.raises(AssertionError):
        fixture._finalize()
    assert Path(fixture.JOURNAL).exists()


def test_workspace_and_application_ownership_are_both_required(fixture: Any) -> None:
    record = fixture._read()
    record["application"] = "foreign"
    fixture._write(record)
    with pytest.raises(AssertionError):
        fixture._cleanup()
    fixture._remove_owned_product.assert_not_called()


@pytest.mark.parametrize("operation", ["cleanup", "finalize"])
def test_missing_journal_never_adopts_unknown_files(
    fixture: Any, operation: str
) -> None:
    Path(fixture.JOURNAL).unlink()
    Path(fixture.ROOT, "unknown").write_text("retain", encoding="utf-8")
    with pytest.raises(AssertionError):
        getattr(fixture, "_" + operation)()
    fixture._remove_owned_product.assert_not_called()


def test_source_raw_acl_and_bytes_round_trip_without_normalization(
    fixture: Any,
) -> None:
    record = fixture._read()
    record["sources"] = {"patch.msp": {"bytes": b"\x00\xff", "acl": b"\x01\x00"}}
    fixture._write(record)
    assert fixture._read() == record


@pytest.mark.parametrize(
    "filename",
    ["semi;colon patch.msp", "", r"..\foreign.msp", "../foreign.msp", "patch.msi"],
)
def test_requested_patch_filename_stays_owned_and_uses_the_pinned_bytes(
    fixture: Any, filename: str
) -> None:
    source = ROOT / "tests/integration/fixtures/package_msp_fixture.py"
    if filename != "semi;colon patch.msp":
        with pytest.raises(AssertionError):
            runpy.run_path(
                str(source),
                init_globals={"PATCH_FILENAME": filename},
                run_name="tested_alias",
            )
        return
    namespace = runpy.run_path(
        str(source), init_globals={"PATCH_FILENAME": filename}, run_name="tested_alias"
    )
    assert namespace["DIGESTS"][filename] == fixture.DIGESTS["patch.msp"]
    assert set(namespace["DIGESTS"]) == {"patch.msi", "patch.msp", filename}


def test_protected_state_excludes_only_owned_product_and_transient_msi_state(
    fixture: Any,
) -> None:
    before = fixture._snapshot()
    after = copy.deepcopy(before)
    after["products"].append({"id": fixture.PRODUCT, "state": 5})
    after["patches"].append(
        {"patch": fixture.PATCH, "product": fixture.PRODUCT, "state": 1}
    )
    after["state"] = 5
    after["outputs"] = {"Sample.txt": b"owned"}
    after["uninstall_keys"] = {"owned": "installed"}
    after["services"]["MSIServer"]["State"] = "Running"
    assert fixture._protected(after) == fixture._protected(before)
    after["pending"] = {"foreign": "difference"}
    assert fixture._protected(after) != fixture._protected(before)


def test_owned_removal_refuses_foreign_application_files(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = load_module(
        ROOT / "tests/integration/fixtures/package_msp_fixture.py",
        "original_msp_fixture",
    )
    installer = SimpleNamespace(product_state=Mock(return_value=-1))
    context = Mock()
    context.__enter__ = Mock(return_value=installer)
    context.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(
        original.msi, "WindowsInstaller", lambda: context, raising=False
    )
    Path(original.APPLICATION).mkdir(parents=True)
    Path(original.APPLICATION, "foreign.txt").write_bytes(b"keep")
    with pytest.raises(AssertionError):
        original._remove_owned_product(fixture._read())
    assert os.path.isfile(os.path.join(original.APPLICATION, "foreign.txt"))
