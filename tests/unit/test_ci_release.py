"""Exercise candidate preparation and guarded publication without remote writes."""

# Both release destinations exercise the same candidate and provenance fixtures.
# Keeping their cases together avoids duplicating that stateful release setup.
# pylint: disable=too-many-lines

import hashlib
import io
import json
import subprocess
import tarfile
from email.message import Message
from email.parser import BytesParser
from email.policy import default
from pathlib import Path
from typing import Any
from urllib.error import HTTPError

import pytest

# These controller APIs are supplied by the pinned, untyped Ansible dependency.
from ansible import constants as ansible_constants  # type: ignore[import-untyped]
from ansible.errors import AnsibleError  # type: ignore[import-untyped]
from ansible.galaxy import api as galaxy_api  # type: ignore[import-untyped]
from ansible.galaxy.api import (  # type: ignore[import-untyped]
    CollectionVersionMetadata,
    GalaxyError,
)
from ansible.galaxy.token import GalaxyToken  # type: ignore[import-untyped]

from scripts import ci_release

COMMIT = "a" * 40
FILENAME = "sustainablelobster-legacy_windows-1.0.0.tar.gz"
CHANGELOG = "# Changelog\n\n## 1.0.0\n\n- Verified release.\n\n## 0.9.0\n\n- Old.\n"


def _archive(path: Path, version: str = "1.0.0", changelog: str = CHANGELOG) -> None:
    contents = {
        "MANIFEST.json": json.dumps(
            {
                "collection_info": {
                    "namespace": "sustainablelobster",
                    "name": "legacy_windows",
                    "version": version,
                }
            }
        ),
        "CHANGELOG.md": changelog,
    }
    with tarfile.open(path, "w:gz") as archive:
        for name, value in contents.items():
            data = value.encode("utf-8")
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))


@pytest.fixture(name="source")
def release_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Create collection inputs and the originating tag environment.

    :param tmp_path: Isolated temporary test directory.
    :param monkeypatch: Fixture restoring source and environment substitutions.
    :returns: Source directory containing a collection candidate.
    """
    root = tmp_path / "source"
    root.mkdir()
    (root / "galaxy.yml").write_text(
        "namespace: sustainablelobster\nname: legacy_windows\nversion: 1.0.0\n",
        encoding="utf-8",
    )
    (root / "CHANGELOG.md").write_text(CHANGELOG, encoding="utf-8")
    _archive(root / FILENAME)
    monkeypatch.setattr(ci_release, "ROOT", root)
    for name, value in {
        "GITHUB_SHA": COMMIT,
        "GITHUB_EVENT_NAME": "push",
        "GITHUB_REPOSITORY": ci_release.REPOSITORY,
        "GITHUB_REF_TYPE": "tag",
        "GITHUB_REF_NAME": "v1.0.0",
        "GITHUB_REF": "refs/tags/v1.0.0",
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    return root


@pytest.fixture(name="candidate")
def release_candidate(source: Path, tmp_path: Path) -> tuple[Path, str]:
    """Prepare the exact candidate consumed by the publisher.

    :param source: Collection metadata and archive fixture.
    :param tmp_path: Isolated temporary test directory.
    :returns: Candidate directory and upstream-job SHA-256.
    """
    output = tmp_path / "package"
    ci_release.package(source / FILENAME, output, "v1.0.0")
    digest = hashlib.sha256((source / FILENAME).read_bytes()).hexdigest()
    return output, digest


# The CLI fake has one public method because subprocess.run is its whole contract.
class Github:  # pylint: disable=too-few-public-methods
    """Execute the subset of GitHub CLI needed by release behavior tests."""

    def __init__(self) -> None:
        self.commits = [COMMIT]
        self.annotated = False
        self.release: dict[str, object] | None = None
        self.assets: dict[str, bytes] = {}
        self.calls: list[list[str]] = []
        self.failure: tuple[tuple[str, ...], str] | None = None

    def run(
        self, command: list[str], *, capture_output: bool, text: bool, check: bool
    ) -> subprocess.CompletedProcess[str]:
        """Simulate CLI effects and record every read and mutation.

        :param command: GitHub CLI argument vector.
        :param capture_output: Whether output is captured.
        :param text: Whether subprocess text output is requested.
        :param check: Whether subprocess raises on a failed command.
        :returns: Successful or failed command result.
        """
        assert command[0] == "gh"
        assert capture_output and text and not check
        self.calls.append(command)
        if self.failure is not None:
            prefix, error = self.failure
            if tuple(command[1 : 1 + len(prefix)]) == prefix:
                return subprocess.CompletedProcess(command, 1, "", error)
        if command[1] == "api":
            return self._api(command)
        operation = command[2]
        if operation == "create":
            assert "--verify-tag" in command and "--draft" in command
            assert command[command.index("--target") + 1] == COMMIT
            self.release = {
                "tag_name": command[3],
                "name": command[command.index("--title") + 1],
                "body": Path(command[command.index("--notes-file") + 1]).read_text(
                    encoding="utf-8"
                ),
                "draft": True,
                "prerelease": False,
            }
        elif operation == "upload":
            assert "--clobber" not in command
            path = Path(command[4])
            assert path.name not in self.assets
            self.assets[path.name] = path.read_bytes()
        elif operation == "download":
            filename = command[command.index("--pattern") + 1]
            directory = Path(command[command.index("--dir") + 1])
            (directory / filename).write_bytes(self.assets[filename])
        else:
            assert operation == "edit" and "--draft=false" in command
            assert self.release is not None
            self.release["draft"] = False
        return subprocess.CompletedProcess(command, 0, "", "")

    def _api(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        endpoint = command[2]
        if "/git/ref/tags/" in endpoint:
            commit = self.commits[0]
            if len(self.commits) > 1:
                self.commits.pop(0)
            payload: object = {
                "object": {
                    "type": "tag" if self.annotated else "commit",
                    "sha": commit,
                }
            }
        elif "/git/tags/" in endpoint:
            payload = {"object": {"type": "commit", "sha": endpoint.rsplit("/", 1)[1]}}
        else:
            release = (
                None
                if self.release is None
                else {
                    **self.release,
                    "assets": [
                        {"name": name, "state": "uploaded"} for name in self.assets
                    ],
                }
            )
            if endpoint.endswith("/releases?per_page=100"):
                assert "--paginate" in command and "--slurp" in command
                payload = [[] if release is None else [release]]
            else:
                assert "/releases/tags/" in endpoint
                if release is None or release["draft"]:
                    return subprocess.CompletedProcess(
                        command, 1, "", "gh: Not Found (HTTP 404)\n"
                    )
                payload = release
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")


@pytest.fixture(name="github")
def fake_github(monkeypatch: pytest.MonkeyPatch) -> Github:
    """Substitute the GitHub CLI without making external calls.

    :param monkeypatch: Fixture restoring subprocess.run after the test.
    :returns: Stateful fake CLI for observing release behavior.
    """
    github = Github()
    monkeypatch.setattr(subprocess, "run", github.run)
    return github


def test_package_preserves_archive_and_reports_exact_digest(
    source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_file = tmp_path / "github-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))
    output = tmp_path / "package"
    ci_release.package(source / FILENAME, output, "v1.0.0")
    digest = hashlib.sha256((source / FILENAME).read_bytes()).hexdigest()
    assert (output / FILENAME).read_bytes() == (source / FILENAME).read_bytes()
    assert (output / "SHA256SUMS").read_text() == f"{digest}  {FILENAME}\n"
    assert (output / "release-notes.txt").read_text() == "- Verified release.\n"
    assert json.loads((output / "release-manifest.json").read_text()) == {
        "filename": FILENAME,
        "version": "1.0.0",
        "sha256": digest,
        "commit": COMMIT,
    }
    assert output_file.read_text() == (
        f"filename={FILENAME}\nversion=1.0.0\nsha256={digest}\n"
    )


@pytest.mark.parametrize(
    "tag", ["1.0.0", "v01.0.0", "v1.0.0-rc.1", "v1.0.0+build", "v1.0.1"]
)
def test_package_rejects_wrong_tags_before_creating_output(
    source: Path, tmp_path: Path, tag: str
) -> None:
    output = tmp_path / "package"
    with pytest.raises(SystemExit, match="Tag and collection version"):
        ci_release.package(source / FILENAME, output, tag)
    assert not output.exists()


@pytest.mark.parametrize("version", ["01.0.0", "1.0.0-rc.1", "1.0.0+build", "1.0"])
def test_package_rejects_invalid_source_version(
    source: Path, tmp_path: Path, version: str
) -> None:
    metadata = source / "galaxy.yml"
    metadata.write_text(metadata.read_text().replace("1.0.0", version))
    with pytest.raises(SystemExit, match="stable X.Y.Z"):
        ci_release.package(source / FILENAME, tmp_path / "package", None)


def test_package_rejects_archive_source_version_mismatch(
    source: Path, tmp_path: Path
) -> None:
    artifact = source / "sustainablelobster-legacy_windows-1.0.1.tar.gz"
    _archive(artifact, "1.0.1")
    with pytest.raises(SystemExit, match="versions disagree"):
        ci_release.package(artifact, tmp_path / "package", None)


@pytest.mark.parametrize("changelog", ["# Changelog\n", "# Changelog\n\n## 1.0.0\n"])
def test_package_rejects_missing_or_empty_release_notes(
    source: Path, tmp_path: Path, changelog: str
) -> None:
    (source / "CHANGELOG.md").write_text(changelog)
    _archive(source / FILENAME, changelog=changelog)
    with pytest.raises(SystemExit, match="Changelog"):
        ci_release.package(source / FILENAME, tmp_path / "package", None)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("GITHUB_EVENT_NAME", "workflow_dispatch"),
        ("GITHUB_EVENT_NAME", "pull_request"),
        ("GITHUB_REPOSITORY", "someone/fork"),
        ("GITHUB_REF_TYPE", "branch"),
        ("GITHUB_REF", "refs/heads/v1.0.0"),
        ("GITHUB_REF_NAME", "v1.0.0-rc.1"),
        ("GITHUB_SHA", "b" * 40),
    ],
)
def test_publish_rejects_invalid_provenance_without_github_calls(
    candidate: tuple[Path, str],
    github: Github,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    value: str,
) -> None:
    monkeypatch.setenv(name, value)
    with pytest.raises(SystemExit):
        ci_release.publish(*candidate)
    assert github.calls == []


@pytest.mark.parametrize(
    ("filename", "contents"),
    [
        (FILENAME, b"changed archive"),
        ("SHA256SUMS", b"bad checksum"),
        ("release-notes.txt", b"different release notes"),
        ("unexpected.txt", b"not a candidate asset"),
    ],
)
def test_publish_rejects_changed_candidate_without_github_calls(
    candidate: tuple[Path, str], github: Github, filename: str, contents: bytes
) -> None:
    package_dir, digest = candidate
    (package_dir / filename).write_bytes(contents)
    with pytest.raises(SystemExit):
        ci_release.publish(package_dir, digest)
    assert github.calls == []


def test_publish_rejects_digest_not_recorded_by_package_job(
    candidate: tuple[Path, str], github: Github
) -> None:
    with pytest.raises(SystemExit, match="SHA-256 differs"):
        ci_release.publish(candidate[0], "0" * 64)
    assert github.calls == []


@pytest.mark.parametrize("annotated", [False, True])
def test_publish_checks_tag_and_attaches_only_verified_assets(
    candidate: tuple[Path, str], github: Github, annotated: bool
) -> None:
    github.annotated = annotated
    ci_release.publish(*candidate)
    assert github.release is not None and github.release["draft"] is False
    assert set(github.assets) == {FILENAME, "SHA256SUMS"}
    assert github.assets[FILENAME] == (candidate[0] / FILENAME).read_bytes()
    assert github.calls[-2][1] == "api"
    assert "/git/" in github.calls[-2][2]
    assert github.calls[-1][1:4] == ["release", "edit", "v1.0.0"]


def test_tag_moved_before_any_mutation_is_rejected(
    candidate: tuple[Path, str], github: Github
) -> None:
    github.commits = ["b" * 40]
    with pytest.raises(SystemExit, match="Remote tag"):
        ci_release.publish(*candidate)
    assert all(command[1] == "api" for command in github.calls)


def test_tag_moved_after_uploads_leaves_draft_unpublished(
    candidate: tuple[Path, str], github: Github
) -> None:
    github.commits = [COMMIT, "b" * 40]
    with pytest.raises(SystemExit, match="Remote tag"):
        ci_release.publish(*candidate)
    assert github.release is not None and github.release["draft"] is True
    assert not any(command[1:3] == ["release", "edit"] for command in github.calls)


@pytest.mark.parametrize("error", ["gh: Forbidden (HTTP 403)", "connection timed out"])
def test_release_lookup_errors_do_not_create_a_release(
    candidate: tuple[Path, str], github: Github, error: str
) -> None:
    github.failure = (
        ("api", f"repos/{ci_release.REPOSITORY}/releases/tags/v1.0.0"),
        error,
    )
    with pytest.raises(SystemExit, match="GitHub command failed"):
        ci_release.publish(*candidate)
    assert github.release is None
    assert all(command[1] == "api" for command in github.calls)


def test_failed_upload_resumes_original_draft_without_replacement(
    candidate: tuple[Path, str], github: Github
) -> None:
    github.failure = (
        ("release", "upload", "v1.0.0", str(candidate[0] / "SHA256SUMS")),
        "upload failed",
    )
    with pytest.raises(SystemExit, match="upload failed"):
        ci_release.publish(*candidate)
    assert github.release is not None and github.release["draft"] is True
    assert set(github.assets) == {FILENAME}
    github.failure = None
    github.calls.clear()
    ci_release.publish(*candidate)
    assert github.release.get("draft") is False
    uploads = [
        command for command in github.calls if command[1:3] == ["release", "upload"]
    ]
    assert len(uploads) == 1 and Path(uploads[0][4]).name == "SHA256SUMS"
    assert not any(command[1:3] == ["release", "create"] for command in github.calls)


def test_matching_published_release_is_a_nonmutating_retry(
    candidate: tuple[Path, str], github: Github
) -> None:
    ci_release.publish(*candidate)
    github.calls.clear()
    ci_release.publish(*candidate)
    assert all(
        command[1] == "api" or command[2] == "download" for command in github.calls
    )


@pytest.mark.parametrize("draft", [False, True])
def test_conflicting_existing_asset_is_never_replaced(
    candidate: tuple[Path, str], github: Github, draft: bool
) -> None:
    ci_release.publish(*candidate)
    assert github.release is not None
    github.release["draft"] = draft
    github.assets[FILENAME] = b"different build of same version"
    github.calls.clear()
    with pytest.raises(SystemExit, match="asset differs"):
        ci_release.publish(*candidate)
    assert all(
        command[1] == "api" or command[2] == "download" for command in github.calls
    )


def test_existing_extra_asset_is_rejected_without_mutation(
    candidate: tuple[Path, str], github: Github
) -> None:
    ci_release.publish(*candidate)
    github.assets["unreviewed.zip"] = b"extra"
    github.calls.clear()
    with pytest.raises(SystemExit, match="unexpected assets"):
        ci_release.publish(*candidate)
    assert all(command[1] == "api" for command in github.calls)


def test_package_cli_uses_same_validation(
    source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "package"
    monkeypatch.setattr(
        "sys.argv",
        [
            "ci_release.py",
            "package",
            "--artifact",
            str(source / FILENAME),
            "--output-dir",
            str(output),
            "--tag",
            "v1.0.0",
        ],
    )
    ci_release.main()
    assert (output / FILENAME).exists()


def test_package_never_overwrites_prior_candidate(
    candidate: tuple[Path, str], source: Path
) -> None:
    output = candidate[0]
    before = {path.name: path.read_bytes() for path in output.iterdir()}
    with pytest.raises(SystemExit, match="must be empty"):
        ci_release.package(source / FILENAME, output, "v1.0.0")
    assert {path.name: path.read_bytes() for path in output.iterdir()} == before


def test_package_requires_tested_commit_before_creating_output(
    source: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GITHUB_SHA")
    output = tmp_path / "package"
    with pytest.raises(SystemExit, match="tested commit"):
        ci_release.package(source / FILENAME, output, "v1.0.0")
    assert not output.exists()


def test_missing_downloaded_notes_are_rejected_without_github_calls(
    candidate: tuple[Path, str], github: Github
) -> None:
    (candidate[0] / "release-notes.txt").unlink()
    with pytest.raises(SystemExit, match="missing or unexpected"):
        ci_release.publish(*candidate)
    assert github.calls == []


def test_candidate_symlink_is_rejected_without_github_calls(
    candidate: tuple[Path, str], github: Github, tmp_path: Path
) -> None:
    notes = candidate[0] / "release-notes.txt"
    outside = tmp_path / "notes"
    outside.write_bytes(notes.read_bytes())
    notes.unlink()
    notes.symlink_to(outside)
    with pytest.raises(SystemExit, match="ordinary files"):
        ci_release.publish(*candidate)
    assert github.calls == []


def test_draft_listing_error_does_not_create_a_release(
    candidate: tuple[Path, str], github: Github
) -> None:
    github.failure = (
        ("api", f"repos/{ci_release.REPOSITORY}/releases?per_page=100"),
        "gh: Forbidden (HTTP 403)",
    )
    with pytest.raises(SystemExit, match="GitHub command failed"):
        ci_release.publish(*candidate)
    assert github.release is None
    assert all(command[1] == "api" for command in github.calls)


@pytest.mark.parametrize(
    "field,value",
    [
        ("body", "conflicting content"),
        ("body", None),
        ("name", "conflicting content"),
        ("prerelease", True),
    ],
)
def test_existing_release_metadata_conflict_is_nonmutating(
    candidate: tuple[Path, str], github: Github, field: str, value: object
) -> None:
    ci_release.publish(*candidate)
    assert github.release is not None
    github.release[field] = value
    github.calls.clear()
    with pytest.raises(SystemExit, match="conflicting"):
        ci_release.publish(*candidate)
    assert all(command[1] == "api" for command in github.calls)


def test_publish_cli_uses_originating_tag_guard(
    candidate: tuple[Path, str], github: Github, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "sys.argv",
        [
            "ci_release.py",
            "publish",
            "--package-dir",
            str(candidate[0]),
            "--sha256",
            candidate[1],
        ],
    )
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    with pytest.raises(SystemExit, match="originating-repository tag push"):
        ci_release.main()
    assert github.calls == []


def test_malformed_downloaded_manifest_has_actionable_cli_failure(
    candidate: tuple[Path, str], github: Github, monkeypatch: pytest.MonkeyPatch
) -> None:
    (candidate[0] / "release-manifest.json").write_text("not JSON")
    monkeypatch.setattr(
        "sys.argv",
        [
            "ci_release.py",
            "publish",
            "--package-dir",
            str(candidate[0]),
            "--sha256",
            candidate[1],
        ],
    )
    with pytest.raises(SystemExit, match="Invalid release inputs or API response"):
        ci_release.main()
    assert github.calls == []


def _galaxy_error(status: int, message: str) -> GalaxyError:
    return GalaxyError(
        HTTPError(
            "https://galaxy.ansible.com/api/v3/collections/",
            status,
            message,
            Message(),
            io.BytesIO(json.dumps({"errors": [{"detail": message}]}).encode()),
        ),
        "Galaxy lookup failed",
    )


def _galaxy_metadata(
    digest: str,
    namespace: str = "sustainablelobster",
    name: str = "legacy_windows",
    version: str = "1.0.0",
) -> CollectionVersionMetadata:
    return CollectionVersionMetadata(
        namespace,
        name,
        version,
        "https://galaxy.ansible.com/download/" + FILENAME,
        digest,
        {},
        "https://galaxy.ansible.com/api/v3/collections/",
        [],
    )


class GalaxyPublisher:
    """Model Galaxy discovery, immutable versions and asynchronous imports."""

    def __init__(self, digest: str) -> None:
        self.created = False
        self.metadata: CollectionVersionMetadata | None = None
        self.imported_metadata: CollectionVersionMetadata | None = _galaxy_metadata(
            digest
        )
        self.errors: dict[str, AnsibleError] = {}
        self.uploads: list[tuple[Path, bytes]] = []
        self.waits: list[tuple[str, int]] = []

    @property
    def available_api_versions(self) -> dict[str, str]:
        """Discover supported APIs before querying a possibly absent version.

        :returns: The supported Galaxy API versions.
        :raises AnsibleError: If API discovery is configured to fail.
        """
        if "discovery" in self.errors:
            raise self.errors["discovery"]
        return {"v3": "v3/"}

    def get_collection_version_metadata(
        self, namespace: str, name: str, version: str
    ) -> CollectionVersionMetadata:
        """Return the exact version or the configured lookup failure.

        :param namespace: Expected collection namespace.
        :param name: Expected collection name.
        :param version: Expected immutable version.
        :returns: The remote version metadata.
        :raises AnsibleError: If version lookup is configured to fail.
        :raises GalaxyError: If the version does not exist.
        """
        assert (namespace, name, version) == (*ci_release.IDENTITY, "1.0.0")
        if "lookup" in self.errors:
            raise self.errors["lookup"]
        if self.metadata is None:
            raise _galaxy_error(404, "version not found")
        return self.metadata

    def publish_collection(self, archive: str) -> str:
        """Record the uploaded archive and return its asynchronous import task.

        :param archive: Path to the verified archive.
        :returns: The import task URL.
        :raises AnsibleError: If uploading is configured to fail.
        """
        path = Path(archive)
        self.uploads.append((path, path.read_bytes()))
        if "upload" in self.errors:
            raise self.errors["upload"]
        return "https://galaxy.ansible.com/api/v3/imports/collections/42/"

    def wait_import_task(self, task: str, timeout: int = 0) -> None:
        """Expose the imported version only after a successful wait.

        :param task: Import task returned by the upload.
        :param timeout: Maximum number of seconds to wait for import completion.
        :raises AnsibleError: If import completion is configured to fail.
        """
        self.waits.append((task, timeout))
        if "import" in self.errors:
            raise self.errors["import"]
        self.metadata = self.imported_metadata


@pytest.fixture(name="galaxy")
def fake_galaxy(
    candidate: tuple[Path, str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> GalaxyPublisher:
    """Replace the maintained Galaxy client without contacting a server.

    :param candidate: Prepared archive and its package-job digest.
    :param monkeypatch: Fixture restoring API and environment substitutions.
    :param tmp_path: Isolated storage for Ansible's local token-file lookup.
    :returns: Stateful fake API for observing version and import behavior.
    """
    galaxy = GalaxyPublisher(candidate[1])
    monkeypatch.setenv("GALAXY_API_KEY", "test-galaxy-token")
    monkeypatch.setattr(
        ansible_constants, "GALAXY_TOKEN_PATH", str(tmp_path / "galaxy-token")
    )

    def _create_api(
        galaxy_context: object, name: str, url: str, **options: object
    ) -> GalaxyPublisher:
        assert galaxy_context is None
        assert name == "release_galaxy"
        assert url == "https://galaxy.ansible.com/"
        assert options["no_cache"] is True
        token = options["token"]
        assert isinstance(token, GalaxyToken)
        assert token.headers() == {"Authorization": "Token test-galaxy-token"}
        galaxy.created = True
        return galaxy

    monkeypatch.setattr(ci_release, "GalaxyAPI", _create_api)
    return galaxy


@pytest.mark.parametrize("token", [None, "", " \t\n"])
def test_galaxy_publish_requires_token_before_remote_mutations(
    candidate: tuple[Path, str],
    github: Github,
    galaxy: GalaxyPublisher,
    monkeypatch: pytest.MonkeyPatch,
    token: str | None,
) -> None:
    if token is None:
        monkeypatch.delenv("GALAXY_API_KEY")
    else:
        monkeypatch.setenv("GALAXY_API_KEY", token)
    with pytest.raises(SystemExit, match="GALAXY_API_KEY"):
        ci_release.publish_galaxy(*candidate)
    assert not galaxy.created and galaxy.uploads == []
    assert github.release is None and github.assets == {}


@pytest.mark.parametrize(
    "setting",
    [
        ("GITHUB_EVENT_NAME", "workflow_dispatch"),
        ("GITHUB_EVENT_NAME", "pull_request"),
        ("GITHUB_REPOSITORY", "someone/fork"),
        ("GITHUB_REF_TYPE", "branch"),
        ("GITHUB_REF", "refs/heads/v1.0.0"),
        ("GITHUB_REF_NAME", "v1.0.0-rc.1"),
        ("GITHUB_SHA", "b" * 40),
    ],
)
def test_galaxy_publish_rejects_invalid_provenance_without_remote_calls(
    candidate: tuple[Path, str],
    github: Github,
    galaxy: GalaxyPublisher,
    monkeypatch: pytest.MonkeyPatch,
    setting: tuple[str, str],
) -> None:
    name, value = setting
    monkeypatch.setenv(name, value)
    with pytest.raises(SystemExit):
        ci_release.publish_galaxy(*candidate)
    assert github.calls == [] and not galaxy.created


@pytest.mark.parametrize(
    ("filename", "contents"),
    [
        (FILENAME, b"changed archive"),
        ("SHA256SUMS", b"bad checksum"),
        ("release-notes.txt", b"different release notes"),
        ("unexpected.txt", b"not a candidate asset"),
    ],
)
def test_galaxy_publish_rejects_changed_candidate_without_remote_calls(
    candidate: tuple[Path, str],
    github: Github,
    galaxy: GalaxyPublisher,
    filename: str,
    contents: bytes,
) -> None:
    (candidate[0] / filename).write_bytes(contents)
    with pytest.raises(SystemExit):
        ci_release.publish_galaxy(*candidate)
    assert github.calls == [] and not galaxy.created


def test_galaxy_publish_rejects_digest_not_recorded_by_package_job(
    candidate: tuple[Path, str], github: Github, galaxy: GalaxyPublisher
) -> None:
    with pytest.raises(SystemExit, match="SHA-256 differs"):
        ci_release.publish_galaxy(candidate[0], "0" * 64)
    assert github.calls == [] and not galaxy.created


def test_galaxy_publish_rejects_moved_tag_before_any_upload(
    candidate: tuple[Path, str], github: Github, galaxy: GalaxyPublisher
) -> None:
    github.commits = ["b" * 40]
    with pytest.raises(SystemExit, match="Remote tag"):
        ci_release.publish_galaxy(*candidate)
    assert galaxy.uploads == []
    assert all(command[1] == "api" for command in github.calls)


@pytest.mark.parametrize("annotated", [False, True])
def test_galaxy_existing_matching_archive_is_a_nonmutating_retry(
    candidate: tuple[Path, str],
    github: Github,
    galaxy: GalaxyPublisher,
    capsys: pytest.CaptureFixture[str],
    annotated: bool,
) -> None:
    galaxy.metadata = _galaxy_metadata(candidate[1])
    github.annotated = annotated
    ci_release.publish_galaxy(*candidate)
    assert galaxy.uploads == [] and galaxy.waits == []
    assert github.release is None and github.assets == {}
    assert "already published" in capsys.readouterr().out.lower()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("artifact_sha256", "0" * 64),
        ("namespace", "different"),
        ("name", "different"),
        ("version", "1.0.1"),
    ],
)
def test_galaxy_existing_conflicting_version_is_never_replaced(
    candidate: tuple[Path, str],
    github: Github,
    galaxy: GalaxyPublisher,
    field: str,
    value: str,
) -> None:
    metadata = _galaxy_metadata(candidate[1])
    setattr(metadata, field, value)
    galaxy.metadata = metadata
    with pytest.raises(SystemExit):
        ci_release.publish_galaxy(*candidate)
    assert galaxy.uploads == [] and galaxy.waits == []
    assert github.release is None and github.assets == {}


@pytest.mark.parametrize("status", [401, 403, 429, 500])
def test_galaxy_lookup_errors_are_not_mistaken_for_absent_versions(
    candidate: tuple[Path, str],
    github: Github,
    galaxy: GalaxyPublisher,
    status: int,
) -> None:
    galaxy.errors["lookup"] = _galaxy_error(status, "lookup unavailable")
    with pytest.raises((AnsibleError, SystemExit), match="lookup unavailable"):
        ci_release.publish_galaxy(*candidate)
    assert galaxy.uploads == [] and galaxy.waits == []
    assert github.release is None and github.assets == {}


def test_galaxy_network_error_does_not_trigger_upload(
    candidate: tuple[Path, str], github: Github, galaxy: GalaxyPublisher
) -> None:
    galaxy.errors["lookup"] = AnsibleError("connection timed out")
    with pytest.raises((AnsibleError, SystemExit), match="connection timed out"):
        ci_release.publish_galaxy(*candidate)
    assert galaxy.uploads == [] and galaxy.waits == []
    assert github.release is None and github.assets == {}


def test_galaxy_api_discovery_404_is_not_an_absent_collection_version(
    candidate: tuple[Path, str], github: Github, galaxy: GalaxyPublisher
) -> None:
    galaxy.errors["discovery"] = _galaxy_error(404, "API root not found")
    with pytest.raises((AnsibleError, SystemExit), match="API root not found"):
        ci_release.publish_galaxy(*candidate)
    assert galaxy.uploads == []
    assert github.release is None and github.assets == {}


def test_galaxy_publish_uploads_exact_verified_archive_and_waits_for_import(
    candidate: tuple[Path, str],
    github: Github,
    galaxy: GalaxyPublisher,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ci_release.publish_galaxy(*candidate)
    artifact = candidate[0] / FILENAME
    assert galaxy.uploads == [(artifact, artifact.read_bytes())]
    assert galaxy.waits == [
        ("https://galaxy.ansible.com/api/v3/imports/collections/42/", 600)
    ]
    assert galaxy.metadata is not None
    assert galaxy.metadata.artifact_sha256 == candidate[1]
    assert github.release is None and github.assets == {}
    assert "published verified" in capsys.readouterr().out.lower()


def test_galaxy_publish_checks_tag_again_before_upload(
    candidate: tuple[Path, str], github: Github, galaxy: GalaxyPublisher
) -> None:
    github.commits = [COMMIT, "b" * 40]
    with pytest.raises(SystemExit, match="Remote tag"):
        ci_release.publish_galaxy(*candidate)
    assert galaxy.uploads == [] and galaxy.waits == []


def test_galaxy_publish_reports_tag_moved_after_import(
    candidate: tuple[Path, str], github: Github, galaxy: GalaxyPublisher
) -> None:
    github.commits = [COMMIT, COMMIT, "b" * 40]
    with pytest.raises(SystemExit, match="Remote tag"):
        ci_release.publish_galaxy(*candidate)
    assert len(galaxy.uploads) == 1 and len(galaxy.waits) == 1


@pytest.mark.parametrize("stage", ["upload", "import"])
def test_galaxy_publish_propagates_upload_or_import_failure(
    candidate: tuple[Path, str],
    github: Github,
    galaxy: GalaxyPublisher,
    stage: str,
) -> None:
    galaxy.errors[stage] = AnsibleError(stage + " failed")
    with pytest.raises((AnsibleError, SystemExit), match=stage + " failed"):
        ci_release.publish_galaxy(*candidate)
    assert galaxy.metadata is None
    if stage == "upload":
        assert galaxy.waits == []
    assert github.release is None and github.assets == {}


@pytest.mark.parametrize("postcondition", ["absent", "digest", "identity"])
def test_galaxy_publish_requires_matching_version_after_import(
    candidate: tuple[Path, str],
    github: Github,
    galaxy: GalaxyPublisher,
    postcondition: str,
) -> None:
    if postcondition == "absent":
        galaxy.imported_metadata = None
    elif postcondition == "digest":
        galaxy.imported_metadata = _galaxy_metadata("0" * 64)
    else:
        galaxy.imported_metadata = _galaxy_metadata(candidate[1], name="different")
    with pytest.raises((AnsibleError, SystemExit)):
        ci_release.publish_galaxy(*candidate)
    assert len(galaxy.uploads) == 1 and len(galaxy.waits) == 1
    assert github.release is None and github.assets == {}


def test_galaxy_successful_retry_does_not_upload_again(
    candidate: tuple[Path, str], github: Github, galaxy: GalaxyPublisher
) -> None:
    ci_release.publish_galaxy(*candidate)
    original_uploads = galaxy.uploads.copy()
    original_waits = galaxy.waits.copy()
    ci_release.publish_galaxy(*candidate)
    assert galaxy.uploads == original_uploads and galaxy.waits == original_waits
    assert github.release is None and github.assets == {}


def test_galaxy_import_failure_can_retry_after_remote_completion(
    candidate: tuple[Path, str], github: Github, galaxy: GalaxyPublisher
) -> None:
    galaxy.errors["import"] = AnsibleError("import wait timed out")
    with pytest.raises((AnsibleError, SystemExit), match="timed out"):
        ci_release.publish_galaxy(*candidate)
    original_uploads = galaxy.uploads.copy()
    original_waits = galaxy.waits.copy()
    galaxy.metadata = _galaxy_metadata(candidate[1])
    ci_release.publish_galaxy(*candidate)
    assert galaxy.uploads == original_uploads and galaxy.waits == original_waits
    assert github.release is None and github.assets == {}


def test_galaxy_publish_cli_dispatches_verified_candidate(
    candidate: tuple[Path, str],
    github: Github,
    galaxy: GalaxyPublisher,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "sys.argv",
        [
            "ci_release.py",
            "publish-galaxy",
            "--package-dir",
            str(candidate[0]),
            "--sha256",
            candidate[1],
        ],
    )
    ci_release.main()
    assert galaxy.uploads == [
        (candidate[0] / FILENAME, (candidate[0] / FILENAME).read_bytes())
    ]
    assert github.release is None and github.assets == {}


def test_galaxy_publish_cli_reports_client_failure_as_clean_exit(
    candidate: tuple[Path, str],
    github: Github,
    galaxy: GalaxyPublisher,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    galaxy.errors["lookup"] = AnsibleError("Galaxy authentication rejected")
    monkeypatch.setattr(
        "sys.argv",
        [
            "ci_release.py",
            "publish-galaxy",
            "--package-dir",
            str(candidate[0]),
            "--sha256",
            candidate[1],
        ],
    )
    with pytest.raises(SystemExit, match="Galaxy authentication rejected"):
        ci_release.main()
    assert galaxy.uploads == []
    assert github.release is None and github.assets == {}


def test_galaxy_publish_uses_pinned_client_for_authenticated_import(
    candidate: tuple[Path, str],
    github: Github,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("GALAXY_API_KEY", "test-galaxy-token")
    monkeypatch.setattr(
        ansible_constants, "GALAXY_TOKEN_PATH", str(tmp_path / "galaxy-token")
    )
    monkeypatch.setattr(
        ansible_constants, "GALAXY_CACHE_DIR", str(tmp_path / "galaxy-cache")
    )
    published = False
    uploads: list[bytes] = []
    import_tasks: list[str] = []
    artifact = candidate[0] / FILENAME
    metadata_url = (
        "https://galaxy.ansible.com/api/v3/collections/"
        "sustainablelobster/legacy_windows/versions/1.0.0/"
    )
    task_url = "https://galaxy.ansible.com/api/v3/imports/collections/42/"

    # Mirror the maintained client's HTTP boundary to inspect auth and TLS options.
    def _open_url(  # pylint: disable=too-many-arguments
        url: str,
        *,
        data: bytes | None,
        validate_certs: bool,
        headers: dict[str, str],
        method: str | None,
        timeout: int,
        http_agent: str,
        follow_redirects: str,
    ) -> io.BytesIO:
        nonlocal published
        assert validate_certs is True
        assert headers["Authorization"] == "Token test-galaxy-token"
        assert timeout > 0 and http_agent and follow_redirects == "safe"
        payload: dict[str, Any]
        if url == "https://galaxy.ansible.com/api/":
            assert method in (None, "GET") and data is None
            payload = {"available_versions": {"v3": "v3/"}}
        elif url == metadata_url:
            assert method in (None, "GET") and data is None
            if not published:
                raise HTTPError(
                    url, 404, "Not Found", Message(), io.BytesIO(b'{"errors": []}')
                )
            payload = {
                "namespace": {"name": "sustainablelobster"},
                "collection": {"name": "legacy_windows"},
                "version": "1.0.0",
                "download_url": "https://galaxy.ansible.com/download/" + FILENAME,
                "artifact": {"sha256": candidate[1]},
                "metadata": {"dependencies": {}},
                "href": metadata_url,
            }
        elif url == "https://galaxy.ansible.com/api/v3/artifacts/collections/":
            assert method == "POST" and data is not None
            assert headers["Content-type"].startswith("multipart/form-data;")
            multipart = BytesParser(policy=default).parsebytes(
                b"Content-Type: "
                + headers["Content-type"].encode()
                + b"\r\n\r\n"
                + data
            )
            parts = {
                part.get_param("name", header="content-disposition"): part.get_payload(
                    decode=True
                )
                for part in multipart.iter_parts()
            }
            assert parts == {
                "file": artifact.read_bytes(),
                "sha256": candidate[1].encode(),
            }
            uploads.append(data)
            payload = {"task": task_url}
        else:
            assert url == task_url and method == "GET" and data is None
            import_tasks.append(url)
            published = True
            payload = {
                "state": "completed",
                "finished_at": "2026-10-12T00:00:00Z",
                "messages": [],
            }
        return io.BytesIO(json.dumps(payload).encode())

    monkeypatch.setattr(galaxy_api, "open_url", _open_url)
    ci_release.publish_galaxy(*candidate)
    assert len(uploads) == 1 and import_tasks == [task_url]
    ci_release.publish_galaxy(*candidate)
    assert len(uploads) == 1 and import_tasks == [task_url]
    assert github.release is None and github.assets == {}
