"""Observe native registry command arguments, comparison and cleanup locally."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# The real request binder and native-command boundary remain explicit.
# pylint: disable=protected-access

import codecs
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module


@pytest.fixture(name="payload")
def regmerge_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load registry merging without exposing a real Windows registry.

    :param monkeypatch: Scoped module import and native boundary substitutions.
    :returns: Imported registry frontend.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    payload = load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_regmerge.py",
        "tested_community_regmerge",
    )
    monkeypatch.setattr(payload.os.path, "isfile", lambda _path: True)
    return payload


def test_content_uses_unicode_registry_format_and_is_removed(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths: list[Path] = []

    def _run(_executable: str, arguments: list[str]) -> dict[str, Any]:
        assert arguments[0] == "IMPORT"
        path = Path(arguments[1])
        paths.append(path)
        assert path.read_bytes().startswith(codecs.BOM_UTF16_LE)
        assert path.read_text(encoding="utf-16") == "Café 雪\n"
        return {"rc": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(payload, "_run_reg", _run)
    assert payload._merge({"content": "Café 雪"}) == {
        "changed": True,
        "compared": False,
    }
    assert paths and not paths[0].exists()


@pytest.mark.parametrize("existing", [True, False])
def test_comparison_detects_existing_and_missing_keys(
    payload: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing: bool
) -> None:
    source = tmp_path / "settings.reg"
    source.write_text('header\n\n[key]\n"value"="same"\n', encoding="utf-16")
    calls = []

    def _run(_executable: str, arguments: list[str]) -> dict[str, Any]:
        calls.append(arguments)
        if arguments[0] == "EXPORT":
            Path(arguments[2]).write_bytes(source.read_bytes())
        return {"rc": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(payload, "_key_exists", lambda _path: existing)
    monkeypatch.setattr(payload, "_run_reg", _run)
    result = payload._merge(
        {"path": str(source), "compare_to": "HKCU:\\Software\\Fixture"}
    )
    if existing:
        assert result == {"changed": False, "compared": True, "difference_count": 0}
        assert calls[0][1] == "HKCU\\Software\\Fixture"
        assert len(calls) == 1
    else:
        assert result == {
            "changed": True,
            "compared": False,
            "compare_to_key_found": False,
        }
        assert calls == [["IMPORT", str(source)]]


def test_comparison_imports_changed_values_and_counts_unmatched_lines(
    payload: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "settings.reg"
    source.write_text('"value"="new"\n', encoding="utf-16")
    calls = []

    def _run(_executable: str, arguments: list[str]) -> dict[str, Any]:
        calls.append(arguments)
        if arguments[0] == "EXPORT":
            Path(arguments[2]).write_text('"value"="old"\n', encoding="utf-16")
        return {"rc": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(payload, "_key_exists", lambda _path: True)
    monkeypatch.setattr(payload, "_run_reg", _run)
    result = payload._merge(
        {"path": str(source), "compare_to": "HKCU:\\Software\\Fixture"}
    )
    assert result["changed"] is True
    assert result["difference_count"] == 2
    assert [call[0] for call in calls] == ["EXPORT", "IMPORT"]


def test_check_mode_skips_without_starting_native_commands(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    command = Mock(side_effect=AssertionError("check mode must not import"))
    monkeypatch.setattr(payload, "_run_reg", command)
    result = payload._merge(
        {"content": "registry content", "_ansible_check_mode": True}
    )
    assert result["changed"] is False
    assert result["skipped"] is True
    command.assert_not_called()


def test_failed_import_retains_process_diagnostics_and_cleans_content(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = []

    def _fail(_executable: str, arguments: list[str]) -> dict[str, Any]:
        paths.append(Path(arguments[1]))
        return {"rc": 1, "stdout": "output", "stderr": "invalid registry file"}

    monkeypatch.setattr(payload, "_run_reg", _fail)
    result = payload._merge({"content": "invalid"})
    assert result["changed"] is False
    assert result["failed"] is True
    assert result["rc"] == 1
    assert result["stderr"] == "invalid registry file"
    assert not paths[0].exists()


@pytest.mark.parametrize("arguments", [{}, {"path": "file.reg", "content": "both"}])
def test_path_and_content_are_mutually_exclusive(
    payload: ModuleType, arguments: dict[str, Any]
) -> None:
    with pytest.raises(ValueError, match="arguments"):
        payload._merge(arguments)
