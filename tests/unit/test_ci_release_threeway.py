"""Exercise all independently tagged subsets without any remote operations."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

import pytest
from ansible.errors import AnsibleError  # type: ignore[import-untyped]

from scripts import ci_release
from tests.unit import test_ci_release as release_fixtures
from tests.unit import test_ci_release_paired as paired_fixtures
from tests.unit.test_ci_release import COMMIT, Github, _galaxy_metadata
from tests.unit.test_ci_release_paired import (
    AD_TAG,
    WINDOWS_TAG,
    ReleasePair,
    _origin,
    _rebuilt_bundle,
)

# Reuse the existing local API fakes and exact candidate construction.
release_source = release_fixtures.release_source
paired_candidates = paired_fixtures.paired_candidates
COMMUNITY = "legacy_community_windows"
COMMUNITY_TAG = COMMUNITY + "/v1.0.0"
SUBSETS = (
    ("legacy_windows",),
    ("legacy_ad",),
    (COMMUNITY,),
    ("legacy_windows", "legacy_ad"),
    ("legacy_windows", COMMUNITY),
    ("legacy_ad", COMMUNITY),
    ci_release.COLLECTIONS,
)


def _enable_community(candidates: ReleasePair) -> None:
    candidates.github.tags[COMMUNITY_TAG] = COMMIT
    candidates.github.releases[COMMUNITY_TAG] = Github()


def _publish(candidates: ReleasePair) -> None:
    ci_release.publish_tagged(candidates.windows, candidates.ad, candidates.community)


@pytest.mark.parametrize("selected", SUBSETS)
def test_all_seven_tag_subsets_use_one_coordinator_and_dependency_order(
    pair: ReleasePair, monkeypatch: pytest.MonkeyPatch, selected: tuple[str, ...]
) -> None:
    _enable_community(pair)
    pair.github.tags = {name + "/v1.0.0": COMMIT for name in selected}
    if "legacy_windows" not in selected:
        pair.galaxy.metadata["legacy_windows"] = _galaxy_metadata("f" * 64)
    for collection in selected[:-1]:
        _origin(monkeypatch, collection + "/v1.0.0")
        _publish(pair)
        assert pair.events == []
    _origin(monkeypatch, selected[-1] + "/v1.0.0")
    _publish(pair)
    assert [
        event.split(":")[1]
        for event in pair.events
        if event.startswith("galaxy:") and event.endswith(":upload")
    ] == list(selected)
    assert set(pair.galaxy.metadata) == set(selected) | {"legacy_windows"}
    for collection in selected[:-1]:
        before = list(pair.events)
        _origin(monkeypatch, collection + "/v1.0.0")
        _publish(pair)
        assert pair.events == before


@pytest.mark.parametrize("failed", ["legacy_windows", "legacy_ad", COMMUNITY])
def test_import_failure_blocks_later_consumers_and_retained_retry_resumes(
    pair: ReleasePair, monkeypatch: pytest.MonkeyPatch, failed: str
) -> None:
    _enable_community(pair)
    _origin(monkeypatch, COMMUNITY_TAG)
    pair.galaxy.fail_import = failed
    with pytest.raises(AnsibleError, match="import failed"):
        _publish(pair)
    for name in ci_release.COLLECTIONS[ci_release.COLLECTIONS.index(failed) + 1 :]:
        assert pair.github.releases[name + "/v1.0.0"].release is None
        assert name not in pair.galaxy.pending
    pair.galaxy.fail_import = None
    pair.events.clear()
    _publish(pair)
    assert set(pair.galaxy.metadata) == set(ci_release.COLLECTIONS)
    retained = ci_release.COLLECTIONS[: ci_release.COLLECTIONS.index(failed) + 1]
    assert not any(
        event.startswith("github:" + name + "/v1.0.0")
        for name in retained
        for event in pair.events
    )


@pytest.mark.parametrize("bundle", ["windows", "ad", "community"])
def test_any_tampered_selected_bundle_blocks_every_publication(
    pair: ReleasePair, monkeypatch: pytest.MonkeyPatch, bundle: str
) -> None:
    _enable_community(pair)
    _origin(monkeypatch, COMMUNITY_TAG)
    (getattr(pair, bundle)[0] / "SHA256SUMS").write_text("tampered")
    with pytest.raises(SystemExit, match="checksum"):
        _publish(pair)
    assert pair.events == []


def test_original_ad_run_can_finish_its_partial_release_after_new_tag_arrives(
    pair: ReleasePair, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    pair.galaxy.fail_import = "legacy_ad"
    with pytest.raises(AnsibleError, match="import failed"):
        _publish(pair)
    rebuilt_ad = _rebuilt_bundle(pair.ad, tmp_path / "community-run-ad")
    _enable_community(pair)
    _origin(monkeypatch, COMMUNITY_TAG)
    pair.events.clear()
    with pytest.raises(SystemExit, match="original publication run"):
        ci_release.publish_tagged(pair.windows, rebuilt_ad, pair.community)
    assert pair.events == []
    _origin(monkeypatch, AD_TAG)
    pair.galaxy.fail_import = None
    _publish(pair)
    assert pair.galaxy.metadata["legacy_ad"].artifact_sha256 == pair.ad[1]
    assert COMMUNITY not in pair.galaxy.metadata
    _origin(monkeypatch, COMMUNITY_TAG)
    ci_release.publish_tagged(pair.windows, rebuilt_ad, pair.community)
    assert set(pair.galaxy.metadata) == set(ci_release.COLLECTIONS)


def test_existing_runtime_and_ad_are_not_republished_from_rebuilt_companions(
    pair: ReleasePair, monkeypatch: pytest.MonkeyPatch
) -> None:
    _enable_community(pair)
    pair.galaxy.metadata = {
        name: _galaxy_metadata("f" * 64, name=name)
        for name in ("legacy_windows", "legacy_ad")
    }
    _origin(monkeypatch, COMMUNITY_TAG)
    _publish(pair)
    assert [event for event in pair.events if event.endswith(":upload")] == [
        "github:" + COMMUNITY_TAG + ":upload",
        "github:" + COMMUNITY_TAG + ":upload",
        "galaxy:" + COMMUNITY + ":upload",
    ]


def test_new_consumer_alone_cannot_publish_without_compatible_runtime(
    pair: ReleasePair, monkeypatch: pytest.MonkeyPatch
) -> None:
    _enable_community(pair)
    del pair.github.tags[WINDOWS_TAG]
    del pair.github.tags[AD_TAG]
    _origin(monkeypatch, COMMUNITY_TAG)
    with pytest.raises(SystemExit, match="before publishing " + COMMUNITY):
        _publish(pair)
    assert pair.events == []
