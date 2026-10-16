"""Exercise same-commit collection publication using local API fakes only."""

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

import pytest

# Galaxy's maintained controller client is supplied without typing stubs.
from ansible.errors import AnsibleError  # type: ignore[import-untyped]
from ansible.galaxy.api import CollectionVersionMetadata  # type: ignore[import-untyped]

from scripts import ci_release
from tests.unit import test_ci_release as release_fixtures
from tests.unit.test_ci_release import (
    CHANGELOG,
    COMMIT,
    Github,
    _archive,
    _galaxy_error,
    _galaxy_metadata,
)

release_source = release_fixtures.release_source
WINDOWS_TAG = "legacy_windows/v1.0.0"
AD_TAG = "legacy_ad/v1.0.0"


# The fake exposes subprocess.run alone; a second method would not model its API.
class PairedGithub:  # pylint: disable=too-few-public-methods
    """Route the existing release fake to independent tags and release assets."""

    def __init__(self, events: list[str]) -> None:
        self.tags = {WINDOWS_TAG: COMMIT, AD_TAG: COMMIT}
        self.releases = {WINDOWS_TAG: Github(), AD_TAG: Github()}
        self.calls: list[list[str]] = []
        self.events = events

    def run(
        self, command: list[str], *, capture_output: bool, text: bool, check: bool
    ) -> subprocess.CompletedProcess[str]:
        """Answer tag reads and delegate immutable asset behavior by tag.

        :param command: GitHub CLI argument vector.
        :param capture_output: Whether output is captured.
        :param text: Whether text output is requested.
        :param check: Whether nonzero results raise automatically.
        :returns: The fake CLI result.
        """
        self.calls.append(command)
        if command[1] == "api":
            endpoint = command[2]
            if "/git/ref/tags/" in endpoint:
                tag = unquote(endpoint.split("/git/ref/tags/", 1)[1])
                if tag not in self.tags:
                    return subprocess.CompletedProcess(
                        command, 1, "", "gh: Not Found (HTTP 404)"
                    )
                return subprocess.CompletedProcess(
                    command,
                    0,
                    json.dumps({"object": {"type": "commit", "sha": self.tags[tag]}}),
                    "",
                )
            if endpoint.endswith("/releases?per_page=100"):
                payload = [
                    release.release
                    for release in self.releases.values()
                    if release.release is not None
                ]
                return subprocess.CompletedProcess(
                    command, 0, json.dumps([payload]), ""
                )
            tag = unquote(endpoint.split("/releases/tags/", 1)[1])
        else:
            tag = command[3]
            if command[2] != "download":
                self.events.append("github:" + tag + ":" + command[2])
        return self.releases[tag].run(
            command, capture_output=capture_output, text=text, check=check
        )


class PairedGalaxy:
    """Expose collection versions only after the corresponding import succeeds."""

    def __init__(self, events: list[str]) -> None:
        self.metadata: dict[str, CollectionVersionMetadata] = {}
        self.pending: dict[str, CollectionVersionMetadata] = {}
        self.events = events
        self.fail_import: str | None = None

    def get_collection_version_metadata(
        self, namespace: str, name: str, version: str
    ) -> CollectionVersionMetadata:
        """Return the available version or a real Galaxy-style 404.

        :param namespace: Collection namespace.
        :param name: Collection name.
        :param version: Stable collection version.
        :returns: Published version metadata.
        :raises GalaxyError: If the version is absent.
        """
        assert (namespace, version) == (ci_release.NAMESPACE, "1.0.0")
        if name not in self.metadata:
            raise _galaxy_error(404, "absent")
        return self.metadata[name]

    def get_collection_versions(self, namespace: str, name: str) -> list[str]:
        """List only imported versions for dependency preflight.

        :param namespace: Collection namespace.
        :param name: Required runtime collection.
        :returns: Available stable versions.
        """
        assert (namespace, name) == (ci_release.NAMESPACE, "legacy_windows")
        return ["1.0.0"] if name in self.metadata else []

    def publish_collection(self, archive: str) -> str:
        """Remember the exact upload until its import completes.

        :param archive: Verified collection archive filename.
        :returns: Import task identifier.
        """
        path = Path(archive)
        collection = path.name.split("-")[1]
        self.events.append("galaxy:" + collection + ":upload")
        self.pending[collection] = _galaxy_metadata(
            hashlib.sha256(path.read_bytes()).hexdigest(), name=collection
        )
        return collection

    def wait_import_task(self, task: str, timeout: int = 0) -> None:
        """Make the imported version observable unless import fails.

        :param task: Collection import task identifier.
        :param timeout: Import timeout in seconds.
        :raises AnsibleError: If this import is configured to fail.
        """
        assert timeout == 600
        self.events.append("galaxy:" + task + ":import")
        if self.fail_import == task:
            raise AnsibleError("import failed: " + task)
        self.metadata[task] = self.pending[task]


@dataclass
class ReleasePair:
    """Keep each exact bundle beside the two fake publication destinations."""

    windows: tuple[Path, str]
    ad: tuple[Path, str]
    community: tuple[Path, str]
    github: PairedGithub
    galaxy: PairedGalaxy
    events: list[str]


def _origin(monkeypatch: pytest.MonkeyPatch, tag: str) -> None:
    monkeypatch.setenv("GITHUB_REF_NAME", tag)
    monkeypatch.setenv("GITHUB_REF", "refs/tags/" + tag)


@pytest.fixture(name="pair")
def paired_candidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: Path
) -> ReleasePair:
    """Prepare both checked bundles and substitute all remote interactions.

    :param tmp_path: Private temporary test source and bundle directories.
    :param monkeypatch: Fixture restoring source, API and environment changes.
    :param source: Existing Windows source and originating push environment.
    :returns: Exact bundles and observable fake publication destinations.
    """
    source_root = source.parent
    monkeypatch.setenv("GALAXY_API_KEY", "fake-token")
    _origin(monkeypatch, AD_TAG)
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    bundles = []
    for collection in ci_release.COLLECTIONS:
        directory = source_root / collection
        directory.mkdir(parents=True, exist_ok=True)
        dependency = (
            {"sustainablelobster.legacy_windows": ">=1.0.0,<2.0.0"}
            if collection != "legacy_windows"
            else {}
        )
        (directory / "galaxy.yml").write_text(
            "namespace: sustainablelobster\nname: "
            + collection
            + "\nversion: 1.0.0\ndependencies: "
            + json.dumps(dependency)
            + "\n"
        )
        (directory / "CHANGELOG.md").write_text(CHANGELOG)
        archive = directory / f"sustainablelobster-{collection}-1.0.0.tar.gz"
        _archive(archive, collection=collection, dependencies=dependency)
        output = tmp_path / collection
        ci_release.package(archive, output, None, collection)
        bundles.append((output, hashlib.sha256(archive.read_bytes()).hexdigest()))
    events: list[str] = []
    github = PairedGithub(events)
    galaxy = PairedGalaxy(events)
    monkeypatch.setattr(subprocess, "run", github.run)
    monkeypatch.setattr(ci_release, "_galaxy_api", lambda: galaxy)
    return ReleasePair(bundles[0], bundles[1], bundles[2], github, galaxy, events)


def test_ad_tag_publishes_windows_and_verifies_import_before_ad(
    pair: ReleasePair,
) -> None:
    ci_release.publish_tagged(pair.windows, pair.ad, pair.community)
    assert pair.events == [
        "github:" + WINDOWS_TAG + ":create",
        "github:" + WINDOWS_TAG + ":upload",
        "github:" + WINDOWS_TAG + ":upload",
        "github:" + WINDOWS_TAG + ":edit",
        "galaxy:legacy_windows:upload",
        "galaxy:legacy_windows:import",
        "github:" + AD_TAG + ":create",
        "github:" + AD_TAG + ":upload",
        "github:" + AD_TAG + ":upload",
        "github:" + AD_TAG + ":edit",
        "galaxy:legacy_ad:upload",
        "galaxy:legacy_ad:import",
    ]
    assert set(pair.galaxy.metadata) == {"legacy_windows", "legacy_ad"}


def test_windows_import_failure_blocks_all_ad_mutations(pair: ReleasePair) -> None:
    pair.galaxy.fail_import = "legacy_windows"
    with pytest.raises(AnsibleError, match="import failed"):
        ci_release.publish_tagged(pair.windows, pair.ad, pair.community)
    assert pair.github.releases[AD_TAG].release is None
    assert "legacy_ad" not in pair.galaxy.pending


def test_ad_retry_resumes_same_retained_windows_release_after_failed_import(
    pair: ReleasePair,
) -> None:
    pair.galaxy.fail_import = "legacy_windows"
    with pytest.raises(AnsibleError):
        ci_release.publish_tagged(pair.windows, pair.ad, pair.community)
    pair.galaxy.fail_import = None
    pair.events.clear()
    ci_release.publish_tagged(pair.windows, pair.ad, pair.community)
    assert not any(event.startswith("github:" + WINDOWS_TAG) for event in pair.events)
    assert set(pair.galaxy.metadata) == {"legacy_windows", "legacy_ad"}


def test_ad_retry_rejects_differing_existing_windows_candidate(
    pair: ReleasePair,
) -> None:
    ci_release.publish(*pair.windows, tag=WINDOWS_TAG)
    pair.github.releases[WINDOWS_TAG].assets["SHA256SUMS"] = b"other run"
    pair.events.clear()
    with pytest.raises(SystemExit, match="original publication run"):
        ci_release.publish_tagged(pair.windows, pair.ad, pair.community)
    assert pair.events == []


def _rebuilt_bundle(bundle: tuple[Path, str], destination: Path) -> tuple[Path, str]:
    shutil.copytree(bundle[0], destination)
    artifact = next(destination.glob("*.tar.gz"))
    contents = bytearray(artifact.read_bytes())
    # Change only the gzip modification-time header, preserving all archive members.
    contents[4] ^= 1
    artifact.write_bytes(contents)
    digest = hashlib.sha256(contents).hexdigest()
    manifest = destination / "release-manifest.json"
    document = json.loads(manifest.read_text())
    document["sha256"] = digest
    manifest.write_text(json.dumps(document))
    (destination / "SHA256SUMS").write_text(f"{digest}  {artifact.name}\n")
    return destination, digest


def test_original_windows_run_can_unblock_ad_after_its_tag_is_added(
    pair: ReleasePair, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _origin(monkeypatch, WINDOWS_TAG)
    del pair.github.tags[AD_TAG]
    pair.galaxy.fail_import = "legacy_windows"
    with pytest.raises(AnsibleError, match="import failed"):
        ci_release.publish_tagged(pair.windows, pair.ad, pair.community)
    assert pair.github.releases[WINDOWS_TAG].release is not None

    pair.github.tags[AD_TAG] = COMMIT
    rebuilt = _rebuilt_bundle(pair.windows, tmp_path / "ad-run-windows")
    _origin(monkeypatch, AD_TAG)
    with pytest.raises(SystemExit, match="original publication run"):
        ci_release.publish_tagged(rebuilt, pair.ad, pair.community)
    assert "legacy_ad" not in pair.galaxy.metadata

    _origin(monkeypatch, WINDOWS_TAG)
    pair.galaxy.fail_import = None
    pair.events.clear()
    ci_release.publish_tagged(pair.windows, pair.ad, pair.community)
    assert pair.galaxy.metadata["legacy_windows"].artifact_sha256 == pair.windows[1]
    assert not any(event.startswith("github:") for event in pair.events)

    _origin(monkeypatch, AD_TAG)
    ci_release.publish_tagged(rebuilt, pair.ad, pair.community)
    assert set(pair.galaxy.metadata) == {"legacy_windows", "legacy_ad"}


def test_secondary_windows_run_defers_if_existing_assets_belong_to_another_bundle(
    pair: ReleasePair, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ci_release.publish(*pair.windows, tag=WINDOWS_TAG)
    rebuilt = _rebuilt_bundle(pair.windows, tmp_path / "secondary-windows")
    _origin(monkeypatch, WINDOWS_TAG)
    pair.events.clear()
    ci_release.publish_tagged(rebuilt, pair.ad, pair.community)
    assert pair.events == [] and pair.galaxy.metadata == {}


def test_windows_retry_does_not_treat_asset_download_failure_as_a_mismatch(
    pair: ReleasePair, monkeypatch: pytest.MonkeyPatch
) -> None:
    ci_release.publish(*pair.windows, tag=WINDOWS_TAG)
    pair.github.releases[WINDOWS_TAG].failure = (
        ("release", "download"),
        "gh: Forbidden (HTTP 403)",
    )
    _origin(monkeypatch, WINDOWS_TAG)
    pair.events.clear()
    with pytest.raises(SystemExit, match="GitHub command failed.*Forbidden"):
        ci_release.publish_tagged(pair.windows, pair.ad, pair.community)
    assert pair.events == [] and pair.galaxy.metadata == {}


@pytest.mark.parametrize("ad_available", [False, True])
def test_windows_secondary_event_never_republishes_a_coordinated_pair(
    pair: ReleasePair, monkeypatch: pytest.MonkeyPatch, ad_available: bool
) -> None:
    _origin(monkeypatch, WINDOWS_TAG)
    if ad_available:
        pair.galaxy.metadata = {
            collection: _galaxy_metadata("f" * 64, name=collection)
            for collection in ci_release.COLLECTIONS
        }
    ci_release.publish_tagged(pair.windows, pair.ad, pair.community)
    assert pair.events == []


def test_windows_event_can_fill_missing_runtime_after_ad_is_already_published(
    pair: ReleasePair, monkeypatch: pytest.MonkeyPatch
) -> None:
    _origin(monkeypatch, WINDOWS_TAG)
    pair.galaxy.metadata["legacy_ad"] = _galaxy_metadata("f" * 64, name="legacy_ad")
    ci_release.publish_tagged(pair.windows, pair.ad, pair.community)
    assert pair.github.releases[AD_TAG].release is None
    assert set(pair.galaxy.metadata) == {"legacy_windows", "legacy_ad"}


def test_ad_accepts_already_published_runtime_without_recomparing_rebuilt_bytes(
    pair: ReleasePair,
) -> None:
    pair.galaxy.metadata["legacy_windows"] = _galaxy_metadata("f" * 64)
    ci_release.publish_tagged(pair.windows, pair.ad, pair.community)
    assert not any(event.startswith("github:" + WINDOWS_TAG) for event in pair.events)
    assert pair.galaxy.metadata["legacy_windows"].artifact_sha256 == "f" * 64
    assert "legacy_ad" in pair.galaxy.metadata


@pytest.mark.parametrize("companion_commit", [None, "b" * 40])
def test_unpaired_windows_tag_publishes_only_its_own_candidate(
    pair: ReleasePair, monkeypatch: pytest.MonkeyPatch, companion_commit: str | None
) -> None:
    _origin(monkeypatch, WINDOWS_TAG)
    if companion_commit is None:
        del pair.github.tags[AD_TAG]
    else:
        pair.github.tags[AD_TAG] = companion_commit
    ci_release.publish_tagged(pair.windows, pair.ad, pair.community)
    assert set(pair.galaxy.metadata) == {"legacy_windows"}
    assert pair.github.releases[AD_TAG].release is None


def test_unpaired_ad_still_requires_an_existing_compatible_runtime(
    pair: ReleasePair,
) -> None:
    del pair.github.tags[WINDOWS_TAG]
    with pytest.raises(SystemExit, match="before publishing legacy_ad"):
        ci_release.publish_tagged(pair.windows, pair.ad, pair.community)
    assert pair.events == []


@pytest.mark.parametrize("bundle", ["windows", "ad"])
def test_invalid_either_bundle_blocks_all_publication(
    pair: ReleasePair, bundle: str
) -> None:
    directory, _ = getattr(pair, bundle)
    (directory / "SHA256SUMS").write_text("tampered")
    with pytest.raises(SystemExit, match="checksum"):
        ci_release.publish_tagged(pair.windows, pair.ad, pair.community)
    assert pair.events == []


@pytest.mark.parametrize("tag", [WINDOWS_TAG, AD_TAG])
def test_moved_either_tag_blocks_all_publication(pair: ReleasePair, tag: str) -> None:
    pair.github.tags[tag] = "b" * 40
    with pytest.raises(SystemExit):
        ci_release.publish_tagged(pair.windows, pair.ad, pair.community)
    assert pair.events == []


@pytest.mark.parametrize(
    ("setting", "value"),
    [
        ("GITHUB_EVENT_NAME", "workflow_dispatch"),
        ("GITHUB_EVENT_NAME", "pull_request"),
        ("GITHUB_REPOSITORY", "another/fork"),
        ("GITHUB_REF_TYPE", "branch"),
        ("GITHUB_REF", "refs/tags/unrelated"),
        ("GITHUB_REF_NAME", "v1.0.0"),
        ("GITHUB_SHA", "b" * 40),
    ],
)
def test_paired_publication_preserves_originating_event_guards(
    pair: ReleasePair, monkeypatch: pytest.MonkeyPatch, setting: str, value: str
) -> None:
    monkeypatch.setenv(setting, value)
    with pytest.raises(SystemExit):
        ci_release.publish_tagged(pair.windows, pair.ad, pair.community)
    assert pair.events == [] and pair.github.calls == []


def test_incompatible_tagged_runtime_fails_before_publication(
    pair: ReleasePair,
) -> None:
    artifact = next(pair.ad[0].glob("*.tar.gz"))
    _archive(
        artifact,
        collection="legacy_ad",
        dependencies={"sustainablelobster.legacy_windows": ">=2.0.0"},
    )
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    manifest = pair.ad[0] / "release-manifest.json"
    document = json.loads(manifest.read_text())
    document["sha256"] = digest
    manifest.write_text(json.dumps(document))
    (pair.ad[0] / "SHA256SUMS").write_text(f"{digest}  {artifact.name}\n")
    with pytest.raises(SystemExit, match="does not satisfy"):
        ci_release.publish_tagged(pair.windows, (pair.ad[0], digest), pair.community)
    assert pair.events == []


def test_explicit_companion_does_not_allow_windows_origin_to_publish_ad(
    pair: ReleasePair, monkeypatch: pytest.MonkeyPatch
) -> None:
    _origin(monkeypatch, WINDOWS_TAG)
    with pytest.raises(SystemExit, match="Only a higher-priority tag"):
        ci_release.publish(*pair.ad, tag=AD_TAG)
    assert pair.events == [] and pair.github.calls == []


def test_explicit_companion_rejects_any_other_windows_version(
    pair: ReleasePair,
) -> None:
    with pytest.raises(SystemExit, match="exact source-version companion"):
        ci_release.publish(*pair.windows, tag="legacy_windows/v1.0.1")
    assert pair.events == [] and pair.github.calls == []


def test_origin_must_match_current_source_version(
    pair: ReleasePair, monkeypatch: pytest.MonkeyPatch
) -> None:
    _origin(monkeypatch, "legacy_ad/v1.0.1")
    with pytest.raises(SystemExit, match="tested source version"):
        ci_release.publish_tagged(pair.windows, pair.ad, pair.community)
    assert pair.events == [] and pair.github.calls == []


@pytest.mark.parametrize("field", ["name", "artifact_sha256"])
def test_existing_runtime_requires_valid_galaxy_metadata(
    pair: ReleasePair, field: str
) -> None:
    metadata = _galaxy_metadata("f" * 64)
    setattr(metadata, field, "invalid")
    pair.galaxy.metadata["legacy_windows"] = metadata
    with pytest.raises(SystemExit):
        ci_release.publish_tagged(pair.windows, pair.ad, pair.community)
    assert pair.events == []


def test_paired_galaxy_discovery_failure_blocks_even_github_mutations(
    pair: ReleasePair, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable() -> None:
        raise AnsibleError("Galaxy unavailable")

    monkeypatch.setattr(ci_release, "_galaxy_api", unavailable)
    with pytest.raises(AnsibleError, match="Galaxy unavailable"):
        ci_release.publish_tagged(pair.windows, pair.ad, pair.community)
    assert pair.events == []


def test_paired_cli_dispatches_both_verified_bundles(
    pair: ReleasePair, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "sys.argv",
        [
            "ci_release.py",
            "publish-tagged",
            "--windows-package-dir",
            str(pair.windows[0]),
            "--windows-sha256",
            pair.windows[1],
            "--ad-package-dir",
            str(pair.ad[0]),
            "--ad-sha256",
            pair.ad[1],
            "--community-package-dir",
            str(pair.community[0]),
            "--community-sha256",
            pair.community[1],
        ],
    )
    ci_release.main()
    assert set(pair.galaxy.metadata) == {"legacy_windows", "legacy_ad"}
