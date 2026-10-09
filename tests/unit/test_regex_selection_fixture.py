"""Find faults in the owned-file journal and retained category result checks."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These tests exercise deliberately private fixture/verifier boundaries.
# pylint: disable=protected-access

import importlib.util
import json
import os
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from tests.unit.payload_support import ROOT


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(name="fixture")
def owned_fixture(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the target fixture without using native Windows APIs.

    :param monkeypatch: Restore deterministic local substitutes after each test.
    :returns: The fixture with portable file metadata/reset boundaries.
    """
    module = _load(
        ROOT / "tests/integration/fixtures/regex_selection.py", "regex_fixture"
    )
    monkeypatch.setattr(
        module, "_kernel", lambda: SimpleNamespace(GetFileAttributesW=lambda _path: 32)
    )

    def _reset(root: str, nonce: str) -> dict[str, bool]:
        module._owned(root, nonce)
        for name in module.FILES:
            stamp = module.STAMP + (0.25 if name == "É.txt" else 0)
            os.utime(Path(root) / "files" / name, (stamp, stamp))
        return {"reset": True}

    monkeypatch.setattr(module, "_reset", _reset)
    return module


def test_exact_file_journal_and_recoverable_closure(
    fixture: ModuleType, tmp_path: Path
) -> None:
    root = tmp_path / "legacy-windows-regex-selection-unit"
    root.mkdir()
    baseline = fixture._prepare(str(root))
    assert len(baseline["files"]) == 10
    assert fixture._observe(str(root), baseline["nonce"]) == baseline
    assert fixture._cleanup(str(root)) == {"before": baseline, "absent": True}
    assert not root.exists()


@pytest.mark.parametrize("fault", ["nonce", "foreign", "bytes", "mtime"])
def test_cleanup_rejects_unowned_or_changed_state(
    fixture: ModuleType, tmp_path: Path, fault: str
) -> None:
    root = tmp_path / "legacy-windows-regex-selection-unit"
    root.mkdir()
    baseline = fixture._prepare(str(root))
    if fault == "nonce":
        with pytest.raises(AssertionError):
            fixture._observe(str(root), "wrong")
        return
    if fault == "foreign":
        (root / "foreign.txt").write_text("not owned", encoding="utf-8")
    elif fault == "bytes":
        (root / "sentinel.bin").write_bytes(b"changed")
    else:
        os.utime(root / "files" / fixture.FILES[0], (1, 1))
    with pytest.raises(AssertionError):
        fixture._cleanup(str(root))
    assert root.exists() and (root / "journal.json").exists()
    assert baseline["nonce"]


def test_partial_preparation_recovery_rejects_foreign_names(
    fixture: ModuleType, tmp_path: Path
) -> None:
    root = tmp_path / "legacy-windows-regex-selection-unit"
    root.mkdir()
    baseline = fixture._prepare(str(root))
    journal = fixture._read(str(root / "journal.json"))
    journal["phase"] = "preparing"
    fixture._write(str(root / "journal.json"), journal)
    (root / "files" / fixture.FILES[0]).unlink()
    assert fixture._cleanup(str(root)) == {"before": None, "absent": True}
    assert baseline["nonce"]


def test_public_compare_preserves_json_types_and_array_order() -> None:
    verifier = _load(
        ROOT / "scripts/verify_regex_selection_capture.py", "regex_verifier"
    )
    verifier._same({"array": [1, 2], "value": False}, {"array": [1, 2], "value": False})
    for value in ({"array": [2, 1], "value": False}, {"array": [1, 2], "value": 0}):
        with pytest.raises(AssertionError):
            verifier._same({"array": [1, 2], "value": False}, value)
    assert json.loads(json.dumps({"opaque": "literal"})) == {"opaque": "literal"}
