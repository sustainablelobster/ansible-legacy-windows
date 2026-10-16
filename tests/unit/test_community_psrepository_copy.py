"""Exercise native repository copying using real released CLIXML fixtures."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
import xml.etree.ElementTree as xml
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module

_FIXTURES = ROOT / "tests/integration/fixtures"
_SOURCE = _FIXTURES / "community_SampleRepositories.xml"
_CUSTOM = _FIXTURES / "community_UserCustomRepositories.xml"
_NAMESPACE = "{http://schemas.microsoft.com/powershell/2004/04}"


@pytest.fixture(name="payload")
def payload_fixture(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load native file/profile behavior with only Windows casing substituted.

    :param monkeypatch: Scoped helper paths and host-culture boundary.
    :returns: Real target payload with actual XML and file operations.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(
        str(ROOT / "legacy_community_windows/plugins/module_utils")
    )
    payload = load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_psrepository_copy.py",
        "community_repository_copy",
    )
    monkeypatch.setattr(payload.wildcard, "_current_lower", lambda: str.lower)
    return payload


def _run(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    arguments: dict[str, Any],
) -> tuple[int, dict[str, Any]]:
    argument_file = tmp_path / "repository-copy.json"
    argument_file.write_text(json.dumps(arguments), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [str(payload.__file__), str(argument_file)])
    return invoke_payload(payload, capsys)


def _destination(profile: Path) -> Path:
    return (
        profile
        / "AppData/Local/Microsoft/Windows/PowerShell/PowerShellGet/PSRepositories.xml"
    )


def test_released_fixture_round_trip_resolves_references_without_collisions(
    payload: ModuleType, tmp_path: Path
) -> None:
    repositories = payload.repository_file.read(str(_SOURCE))
    original = payload.repository_file.values(repositories)
    assert set(original) == {"FakeFileServer", "PSGallery", "FakeGet"}
    assert original["FakeGet"]["Trusted"] is True
    assert original["PSGallery"]["Trusted"] == {"IsPresent": False}
    output = tmp_path / "repositories.xml"
    payload.repository_file.write(str(output), repositories)
    assert (
        payload.repository_file.values(payload.repository_file.read(str(output)))
        == original
    )
    root = xml.parse(output).getroot()
    assert not list(root.iter(_NAMESPACE + "TNRef"))
    for kind in ("Obj", "TN"):
        references = [item.get("RefId") for item in root.iter(_NAMESPACE + kind)]
        assert len(references) == len(set(references))


def test_preview_does_not_create_files_then_copy_is_idempotent(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    profile = tmp_path / "FixtureUser"
    profile.mkdir()
    monkeypatch.setattr(payload, "_profile_paths", lambda: [str(profile)])
    arguments = {"source": str(_SOURCE), "_ansible_diff": True}
    status, preview = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {**arguments, "_ansible_check_mode": True},
    )
    destination = _destination(profile)
    assert status == 0 and preview["changed"] is True
    assert not destination.exists()
    assert set(preview["diff"]["after"][profile.name]) == {
        "FakeFileServer",
        "PSGallery",
        "FakeGet",
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0 and result["changed"] is True
    data = destination.read_bytes()
    status, repeated = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0 and repeated["changed"] is False
    assert destination.read_bytes() == data


def test_include_exclude_profile_and_repository_filters_use_windows_wildcards(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    selected = tmp_path / "FixtureA"
    excluded = tmp_path / "FixtureB"
    service = tmp_path / "systemprofile"
    for profile in (selected, excluded, service):
        profile.mkdir()
    monkeypatch.setattr(
        payload, "_profile_paths", lambda: [str(selected), str(excluded), str(service)]
    )
    # Keep the copy module's real public filter options explicit in this case.
    # pylint: disable=duplicate-code
    status, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {
            "source": str(_SOURCE),
            "name": "fake*",
            "exclude": ["*Server"],
            "profiles": ["Fixture[A-B]", "systemprofile"],
            "exclude_profiles": ["FixtureB", "systemprofile"],
        },
    )
    # pylint: enable=duplicate-code
    assert status == 0 and result == {"changed": True}
    assert set(
        payload.repository_file.names(
            payload.repository_file.read(str(_destination(selected)))
        ).values()
    ) == {"FakeGet"}
    assert not _destination(excluded).exists()
    assert not _destination(service).exists()


def test_merge_preserves_unselected_repositories_and_force_replaces_all(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    profile = tmp_path / "Fixture"
    destination = _destination(profile)
    destination.parent.mkdir(parents=True)
    destination.write_bytes(_CUSTOM.read_bytes())
    monkeypatch.setattr(payload, "_profile_paths", lambda: [str(profile)])
    arguments = {"source": str(_SOURCE), "name": "FakeFileServer"}
    status, merged = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0 and merged["changed"] is True
    names = payload.repository_file.names(
        payload.repository_file.read(str(destination))
    )
    assert set(names.values()) == {
        "CustomUserRepo",
        "PSGallery",
        "FakeGet",
        "FakeFileServer",
    }
    # Released force ignores repository include/exclude and copies the entire source.
    status, forced = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {**arguments, "force": True, "name": [], "exclude": ["*"]},
    )
    assert status == 0 and forced["changed"] is True
    assert set(
        payload.repository_file.names(
            payload.repository_file.read(str(destination))
        ).values()
    ) == {"FakeFileServer", "PSGallery", "FakeGet"}


def test_failure_after_an_earlier_profile_write_preserves_partial_changed_state(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    first, broken = tmp_path / "First", tmp_path / "Broken"
    first.mkdir()
    destination = _destination(broken)
    destination.parent.mkdir(parents=True)
    destination.write_text("not repository XML", encoding="utf-8")
    monkeypatch.setattr(payload, "_profile_paths", lambda: [str(first), str(broken)])
    status, result = _run(
        payload, monkeypatch, tmp_path, capsys, {"source": str(_SOURCE)}
    )
    assert status == 1 and result["changed"] is True
    assert "Invalid CLIXML dictionary" in result["msg"]
    assert _destination(first).exists()
    assert destination.read_text(encoding="utf-8") == "not repository XML"


def test_native_utf16_repository_files_and_escaped_names_are_supported(
    payload: ModuleType, tmp_path: Path
) -> None:
    source = tmp_path / "utf16.xml"
    source.write_text(
        _SOURCE.read_text(encoding="utf-8").replace("FakeGet", "Fake_x005F_x0041_"),
        encoding="utf-16",
    )
    repositories = payload.repository_file.read(str(source))
    assert "Fake_x0041_" in payload.repository_file.values(repositories)


def test_replacement_failure_preserves_the_previous_file_and_cleans_scratch(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    destination = tmp_path / "repositories.xml"
    destination.write_bytes(_CUSTOM.read_bytes())
    before = destination.read_bytes()

    def denied(_source: str, _destination: str) -> None:
        raise PermissionError("fixture denied replacement")

    monkeypatch.setattr(payload.repository_file.os, "replace", denied)
    with pytest.raises(PermissionError, match="fixture denied"):
        payload.repository_file.write(
            str(destination), payload.repository_file.read(str(_SOURCE))
        )
    assert destination.read_bytes() == before
    assert list(tmp_path.iterdir()) == [destination]
