"""Keep community packaging complete and controller-only code off target gates."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import re
from pathlib import Path

import pytest
import yaml  # type: ignore[import-untyped]

from scripts import check_collection as checker
from tests.unit import test_check_collection as collection_fixtures
from tests.unit.test_check_collection import _archive

source_plugins = collection_fixtures.source_plugins
COLLECTION = "legacy_community_windows"
ROOT = Path(__file__).resolve().parents[2]

# Exercise the checker's narrow archive boundaries independently of Galaxy builds.
# pylint: disable=protected-access


@pytest.mark.parametrize(
    "selected,expected",
    [
        ("legacy_windows", ("legacy_windows",)),
        ("legacy_ad", ("legacy_windows", "legacy_ad")),
        (COLLECTION, ("legacy_windows", COLLECTION)),
        ("all", ("legacy_windows", "legacy_ad", COLLECTION)),
    ],
)
def test_selected_collection_only_needs_its_actual_runtime_dependency(
    selected: str, expected: tuple[str, ...]
) -> None:
    assert checker._selected_collections(selected) == expected


@pytest.fixture(name="community_contents")
def community_source_files(plugins: dict[str, bytes]) -> dict[str, bytes]:
    """Create a complete small baseline to test missing-interface failures.

    :param plugins: Existing source inventory and isolated checker root.
    :returns: Collection-owned archive entries including its native plugins.
    """
    reference = {
        "modules": {"win_ping": {}, "psexec": {}},
        "lookups": {"laps_password": {}},
        "routing": {
            "modules": {"win_redirect": {"redirect": "ansible.windows.win_ping"}}
        },
    }
    fixture = checker.ROOT / "tests/fixtures/community_windows_contract.json"
    fixture.parent.mkdir(parents=True)
    fixture.write_text(json.dumps(reference))
    contents = {
        name: (name + "\n").encode()
        for name in checker._required_files(COLLECTION)
        if name not in ("MANIFEST.json", "FILES.json", "LICENSE")
    }
    contents.update(plugins)
    contents.update(
        {
            "LICENSE": b"license bytes\n",
            "plugins/modules/psexec.py": b"# controller module\n",
            "plugins/lookup/laps_password.py": b"# controller lookup\n",
            "meta/runtime.yml": (
                "plugin_routing:\n  modules:\n    win_redirect:\n"
                "      redirect: sustainablelobster.legacy_windows.win_ping\n"
            ).encode(),
        }
    )
    for name, data in contents.items():
        path = checker.ROOT / COLLECTION / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return contents


def test_community_archive_accepts_complete_interfaces_and_its_own_notices(
    tmp_path: Path, community_contents: dict[str, bytes]
) -> None:
    artifact = _archive(tmp_path, {}, collection=COLLECTION, extra=community_contents)
    checker._inspect_archive(artifact, collection=COLLECTION)


@pytest.mark.parametrize(
    "missing",
    ["plugins/modules/psexec.py", "plugins/lookup/laps_password.py"],
)
def test_incomplete_community_source_cannot_pass_packaging(
    tmp_path: Path, community_contents: dict[str, bytes], missing: str
) -> None:
    del community_contents[missing]
    (checker.ROOT / COLLECTION / missing).unlink()
    artifact = _archive(tmp_path, {}, collection=COLLECTION, extra=community_contents)
    with pytest.raises(SystemExit, match="baseline interfaces are missing"):
        checker._inspect_archive(artifact, collection=COLLECTION)


def test_community_archive_rejects_original_unadapted_redirects(
    tmp_path: Path, community_contents: dict[str, bytes]
) -> None:
    community_contents["meta/runtime.yml"] = community_contents[
        "meta/runtime.yml"
    ].replace(b"sustainablelobster.legacy_windows.", b"ansible.windows.")
    artifact = _archive(tmp_path, {}, collection=COLLECTION, extra=community_contents)
    with pytest.raises(SystemExit, match="routing differs"):
        checker._inspect_archive(artifact, collection=COLLECTION)


@pytest.mark.parametrize(
    "hook_id",
    [
        "black-target",
        "pylint-target",
        "black-controller",
        "pylint-controller",
        "mypy-controller",
        "vermin",
    ],
)
def test_controller_psexec_is_not_mistaken_for_windows_payload(hook_id: str) -> None:
    config = yaml.safe_load((ROOT / ".pre-commit-config.yaml").read_text())
    hook = next(
        item
        for repository in config["repos"]
        for item in repository["hooks"]
        if item.get("alias", item["id"]) == hook_id
    )
    path = COLLECTION + "/plugins/modules/psexec.py"
    selected = bool(re.search(hook["files"], path)) and not re.search(
        hook.get("exclude", r"^$"), path
    )
    assert selected == ("controller" in hook_id)
