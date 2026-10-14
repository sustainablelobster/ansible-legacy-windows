"""Prepare verified collection assets and publish an originating tag release.

Copyright (c) 2026 sustainablelobster. Licensed under GPL-3.0-or-later.
This developer script never runs Windows payloads or creates Git tags.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import quote

# These development dependencies lack typing stubs and never run on targets.
import yaml  # type: ignore[import-untyped]
from ansible.errors import AnsibleError  # type: ignore[import-untyped]
from ansible.galaxy.api import GalaxyAPI, GalaxyError  # type: ignore[import-untyped]
from ansible.galaxy.dependency_resolution.versioning import (  # type: ignore[import-untyped]
    meets_requirements,
)
from ansible.galaxy.token import GalaxyToken  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "sustainablelobster/ansible-legacy-windows"
NAMESPACE = "sustainablelobster"
COLLECTIONS = ("legacy_windows", "legacy_ad")
VERSION = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
SIDECARS = {"SHA256SUMS", "release-notes.txt", "release-manifest.json"}


def _version(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(VERSION, value) is None:
        raise SystemExit("Release version must be stable X.Y.Z without leading zeros")
    return value


def _commit() -> str:
    commit = os.environ.get("GITHUB_SHA", "")
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise SystemExit("GITHUB_SHA must identify the tested commit")
    return commit


def _hash(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _tag_collection(tag: str) -> tuple[str, str]:
    for collection in COLLECTIONS:
        prefix = collection + "/v"
        if tag.startswith(prefix):
            return collection, _version(tag[len(prefix) :])
    raise SystemExit(
        "Publishing requires a stable legacy_windows/vX.Y.Z or legacy_ad/vX.Y.Z tag"
    )


def _archive_metadata(
    artifact: Path, collection: str
) -> tuple[str, str, dict[str, str]]:
    with tarfile.open(artifact) as archive:
        contents = {}
        for name in ("MANIFEST.json", "CHANGELOG.md"):
            members = [member for member in archive.getmembers() if member.name == name]
            if len(members) != 1 or not members[0].isfile():
                raise SystemExit("Archive needs exactly one regular file: " + name)
            stream = archive.extractfile(members[0])
            assert stream is not None
            with stream:
                contents[name] = stream.read().decode("utf-8")
    info = json.loads(contents["MANIFEST.json"])["collection_info"]
    if collection not in COLLECTIONS or (info.get("namespace"), info.get("name")) != (
        NAMESPACE,
        collection,
    ):
        raise SystemExit("Archive has the wrong collection identity")
    version = _version(info.get("version"))
    if artifact.name != f"{NAMESPACE}-{collection}-{version}.tar.gz":
        raise SystemExit("Archive filename does not match its collection version")
    dependencies = info.get("dependencies", {})
    if not isinstance(dependencies, dict) or any(
        not isinstance(name, str) or not isinstance(requirement, str)
        for name, requirement in dependencies.items()
    ):
        raise SystemExit("Archive collection dependencies must be string requirements")
    if collection == "legacy_ad" and not dependencies.get(
        NAMESPACE + ".legacy_windows"
    ):
        raise SystemExit("AD archive must declare its Windows runtime dependency")
    return version, contents["CHANGELOG.md"], dependencies


def _notes(changelog: str, version: str) -> str:
    sections = list(re.finditer(r"^## ([^\r\n]+)\r?$", changelog, re.MULTILINE))
    matching = [
        index for index, section in enumerate(sections) if section[1] == version
    ]
    if len(matching) != 1:
        raise SystemExit("Changelog needs exactly one section for " + version)
    index = matching[0]
    end = sections[index + 1].start() if index + 1 < len(sections) else len(changelog)
    notes = changelog[sections[index].end() : end].strip()
    if not notes:
        raise SystemExit("Changelog release section is empty")
    return notes + "\n"


def package(
    artifact: Path,
    output_dir: Path,
    tag: str | None,
    collection: str = "legacy_windows",
) -> None:
    """Stage an already checked archive and its immutable release information.

    :param artifact: Exact archive accepted by the packaging check.
    :param output_dir: Directory receiving the four uploaded candidate files.
    :param tag: Stable version tag, or None for a nonpublishing CI build.
    :param collection: Collection whose checked archive is being prepared.
    :raises SystemExit: If source, archive, tag, or tested commit disagree.
    """
    version, changelog, dependencies = _archive_metadata(artifact, collection)
    source_root = ROOT / collection
    source = yaml.safe_load((source_root / "galaxy.yml").read_text(encoding="utf-8"))
    if (source.get("namespace"), source.get("name")) != (NAMESPACE, collection):
        raise SystemExit("galaxy.yml has the wrong collection identity")
    if _version(source.get("version")) != version:
        raise SystemExit("galaxy.yml and archive versions disagree")
    if source.get("dependencies", {}) != dependencies:
        raise SystemExit("galaxy.yml and archive dependencies disagree")
    if tag is not None and _tag_collection(tag) != (collection, version):
        raise SystemExit("Tag and collection version disagree")
    if changelog != (source_root / "CHANGELOG.md").read_text(encoding="utf-8"):
        raise SystemExit("Archive changelog differs from the tested checkout")
    notes = _notes(changelog, version)
    commit = _commit()
    digest = _hash(artifact)
    if output_dir.exists() and any(output_dir.iterdir()):
        raise SystemExit("Package output directory must be empty")
    output_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(artifact, output_dir / artifact.name)
    (output_dir / "SHA256SUMS").write_text(
        f"{digest}  {artifact.name}\n", encoding="utf-8"
    )
    (output_dir / "release-notes.txt").write_text(notes, encoding="utf-8")
    (output_dir / "release-manifest.json").write_text(
        json.dumps(
            {
                "filename": artifact.name,
                "version": version,
                "sha256": digest,
                "commit": commit,
                "collection": NAMESPACE + "." + collection,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    if output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("a", encoding="utf-8") as stream:
            stream.write(
                f"filename={artifact.name}\nversion={version}\nsha256={digest}\n"
            )
    print(f"Prepared {artifact.name}: sha256={digest}")


def _gh(*arguments: str, missing_ok: bool = False) -> str | None:
    result = subprocess.run(
        ["gh", *arguments], capture_output=True, text=True, check=False
    )
    if result.returncode:
        if missing_ok and re.search(r"\(HTTP 404\)", result.stderr):
            return None
        raise SystemExit("GitHub command failed: " + result.stderr.strip())
    return result.stdout


def _api(endpoint: str, missing_ok: bool = False) -> dict[str, Any] | None:
    response = _gh("api", f"repos/{REPOSITORY}/{endpoint}", missing_ok=missing_ok)
    if response is None:
        return None
    document: dict[str, Any] = json.loads(response)
    return document


def _tag_commit(tag: str, *, missing_ok: bool = False) -> str | None:
    reference = _api("git/ref/tags/" + quote(tag, safe=""), missing_ok=missing_ok)
    if reference is None:
        return None
    target = reference["object"]
    while target["type"] == "tag":
        annotated = _api("git/tags/" + target["sha"])
        assert annotated is not None
        target = annotated["object"]
    return target["sha"] if target["type"] == "commit" else None


def _require_tag_commit(tag: str, commit: str) -> None:
    if _tag_commit(tag) != commit:
        raise SystemExit("Remote tag no longer resolves to the tested commit")


def _find_release(tag: str) -> dict[str, Any] | None:
    release = _api("releases/tags/" + quote(tag, safe=""), missing_ok=True)
    if release is not None:
        return release
    # The by-tag REST endpoint omits drafts; authenticated listings include them.
    response = _gh(
        "api", f"repos/{REPOSITORY}/releases?per_page=100", "--paginate", "--slurp"
    )
    assert response is not None
    matches = [
        item
        for page in json.loads(response)
        for item in page
        if item["tag_name"] == tag
    ]
    if len(matches) > 1:
        raise SystemExit("Multiple existing releases use this tag; inspect them")
    return matches[0] if matches else None


def _candidate(package_dir: Path, expected_sha256: str, tag: str) -> tuple[Path, str]:
    collection, tagged_version = _tag_collection(tag)
    manifest = json.loads((package_dir / "release-manifest.json").read_text("utf-8"))
    version = _version(manifest.get("version"))
    filename = f"{NAMESPACE}-{collection}-{version}.tar.gz"
    if (
        manifest.get("filename") != filename
        or tagged_version != version
        or manifest.get("collection") != NAMESPACE + "." + collection
    ):
        raise SystemExit("Downloaded manifest and release tag disagree")
    if manifest.get("commit") != _commit():
        raise SystemExit("Downloaded candidate belongs to a different tested commit")
    if {path.name for path in package_dir.iterdir()} != SIDECARS | {filename}:
        raise SystemExit("Downloaded candidate has missing or unexpected files")
    if any(not path.is_file() or path.is_symlink() for path in package_dir.iterdir()):
        raise SystemExit("Downloaded candidate must contain ordinary files only")
    artifact = package_dir / filename
    if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise SystemExit("Expected SHA-256 must come from the successful package job")
    if manifest.get("sha256") != expected_sha256 or _hash(artifact) != expected_sha256:
        raise SystemExit("Downloaded archive SHA-256 differs from the package job")
    if (package_dir / "SHA256SUMS").read_text("utf-8") != (
        f"{expected_sha256}  {filename}\n"
    ):
        raise SystemExit("Downloaded checksum file does not match the candidate")
    archived_version, changelog, _ = _archive_metadata(artifact, collection)
    notes = _notes(changelog, archived_version)
    if archived_version != version:
        raise SystemExit("Downloaded manifest and archive versions disagree")
    if (package_dir / "release-notes.txt").read_text("utf-8") != notes:
        raise SystemExit("Downloaded release notes differ from the checked archive")
    return artifact, notes


def _existing_assets(release: dict[str, Any], tag: str, files: list[Path]) -> set[str]:
    expected = {path.name: path for path in files}
    assets = release["assets"]
    names = [asset["name"] for asset in assets]
    if len(names) != len(set(names)) or set(names) - set(expected):
        raise SystemExit("Existing release has conflicting or unexpected assets")
    with tempfile.TemporaryDirectory(prefix="legacy-collection-release-") as directory:
        for asset in assets:
            if asset["state"] != "uploaded":
                raise SystemExit(
                    "Existing release has an incomplete upload; inspect it"
                )
            _gh(
                "release",
                "download",
                tag,
                "--repo",
                REPOSITORY,
                "--pattern",
                asset["name"],
                "--dir",
                directory,
            )
            if _hash(Path(directory) / asset["name"]) != _hash(expected[asset["name"]]):
                raise SystemExit("Existing release asset differs: " + asset["name"])
    return set(names)


def _originating_tag() -> str:
    if (
        os.environ.get("GITHUB_EVENT_NAME") != "push"
        or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
        or os.environ.get("GITHUB_REF_TYPE") != "tag"
    ):
        raise SystemExit("Publishing requires an originating-repository tag push")
    tag = os.environ.get("GITHUB_REF_NAME", "")
    _tag_collection(tag)
    if os.environ.get("GITHUB_REF") != "refs/tags/" + tag:
        raise SystemExit("Publishing requires the originating tag reference")
    return tag


def _source_tag(collection: str) -> str:
    source = yaml.safe_load((ROOT / collection / "galaxy.yml").read_text("utf-8"))
    if (source.get("namespace"), source.get("name")) != (NAMESPACE, collection):
        raise SystemExit("galaxy.yml has the wrong collection identity")
    return collection + "/v" + _version(source.get("version"))


def _publication_candidate(
    package_dir: Path, expected_sha256: str, tag: str | None = None
) -> tuple[Path, str, str]:
    origin = _originating_tag()
    if tag is None:
        tag = origin
    elif tag != origin:
        if (
            _tag_collection(origin)[0] != "legacy_ad"
            or origin != _source_tag("legacy_ad")
            or tag != _source_tag("legacy_windows")
        ):
            raise SystemExit("Only an AD tag may publish its exact Windows companion")
        _require_tag_commit(origin, _commit())
    artifact, notes = _candidate(package_dir, expected_sha256, tag)
    _require_tag_commit(tag, _commit())
    return artifact, notes, tag


def _galaxy_api() -> GalaxyAPI:
    token = os.environ.get("GALAXY_API_KEY", "")
    if not token.strip():
        raise SystemExit("Set the GALAXY_API_KEY repository secret before publishing")
    api = GalaxyAPI(
        None,
        "release_galaxy",
        "https://galaxy.ansible.com/",
        token=GalaxyToken(token),
        no_cache=True,
    )
    # Discover first: a missing API root is not an absent collection version.
    if "v3" not in api.available_api_versions:
        raise SystemExit("Galaxy collection publication requires API v3")
    return api


def _require_published_runtime(artifact: Path, collection: str, api: GalaxyAPI) -> None:
    if collection != "legacy_ad":
        return
    _, _, dependencies = _archive_metadata(artifact, collection)
    requirement = dependencies[NAMESPACE + ".legacy_windows"]
    try:
        versions = api.get_collection_versions(NAMESPACE, "legacy_windows")
    except GalaxyError as error:
        if error.http_code != 404:
            raise
        versions = []
    for version in versions:
        if re.fullmatch(VERSION, version) is None or not meets_requirements(
            version, requirement
        ):
            continue
        metadata = api.get_collection_version_metadata(
            NAMESPACE, "legacy_windows", version
        )
        if (metadata.namespace, metadata.name, metadata.version) != (
            NAMESPACE,
            "legacy_windows",
            version,
        ):
            raise SystemExit("Galaxy returned conflicting Windows runtime metadata")
        if re.fullmatch(r"[0-9a-f]{64}", metadata.artifact_sha256) is None:
            raise SystemExit("Published Windows runtime has no valid archive SHA-256")
        return
    raise SystemExit(
        "Publish a stable sustainablelobster.legacy_windows version satisfying "
        + requirement
        + " before publishing legacy_ad"
    )


def preflight(
    package_dir: Path, expected_sha256: str, *, tag: str | None = None
) -> None:
    """Verify the candidate and its published runtime without remote mutations.

    :param package_dir: Download of the successful package job's four files.
    :param expected_sha256: Digest recorded by that same package job.
    :param tag: Exact Windows companion tag when invoked by an AD coordinator.
    :raises SystemExit: If provenance or the published Windows runtime is invalid.
    :raises AnsibleError: If Galaxy discovery or dependency lookup fails.
    """
    artifact, _, tag = _publication_candidate(package_dir, expected_sha256, tag)
    collection, _ = _tag_collection(tag)
    if collection == "legacy_ad":
        _require_published_runtime(artifact, collection, _galaxy_api())
    print("Verified publication prerequisites: " + tag)


def publish(package_dir: Path, expected_sha256: str, *, tag: str | None = None) -> None:
    """Publish or safely resume the verified artifact for this tag push.

    :param package_dir: Download of the successful package job's four files.
    :param expected_sha256: Digest recorded by that same package job.
    :param tag: Exact Windows companion tag when invoked by an AD coordinator.
    :raises SystemExit: If provenance, remote tag, assets, or GitHub calls fail.
    :raises AnsibleError: If AD's published Windows runtime cannot be verified.
    """
    artifact, notes, tag = _publication_candidate(package_dir, expected_sha256, tag)
    collection, _ = _tag_collection(tag)
    if collection == "legacy_ad":
        _require_published_runtime(artifact, collection, _galaxy_api())
    commit = _commit()
    release = _find_release(tag)
    files = [artifact, package_dir / "SHA256SUMS"]
    existing: set[str] = set()
    if release is not None:
        if release["tag_name"] != tag or release["name"] != tag:
            raise SystemExit("Existing release has conflicting metadata")
        if (release["body"] or "").strip() != notes.strip() or release["prerelease"]:
            raise SystemExit(
                "Existing release has conflicting notes or prerelease state"
            )
        existing = _existing_assets(release, tag, files)
        if not release["draft"]:
            if existing != {path.name for path in files}:
                raise SystemExit("Published release is missing candidate assets")
            _require_tag_commit(tag, commit)
            print("Matching release is already published: " + tag)
            return
    else:
        _gh(
            "release",
            "create",
            tag,
            "--repo",
            REPOSITORY,
            "--verify-tag",
            "--target",
            commit,
            "--draft",
            "--title",
            tag,
            "--notes-file",
            str(package_dir / "release-notes.txt"),
        )
    for path in files:
        if path.name not in existing:
            _gh("release", "upload", tag, str(path), "--repo", REPOSITORY)
    _require_tag_commit(tag, commit)
    _gh("release", "edit", tag, "--repo", REPOSITORY, "--draft=false")
    print("Published verified release: " + tag)


def _published_digest(api: GalaxyAPI, collection: str, version: str) -> str | None:
    try:
        metadata = api.get_collection_version_metadata(NAMESPACE, collection, version)
    except GalaxyError as error:
        if error.http_code == 404:
            return None
        raise
    if (metadata.namespace, metadata.name, metadata.version) != (
        NAMESPACE,
        collection,
        version,
    ):
        raise SystemExit("Galaxy returned conflicting collection identity or version")
    digest: object = metadata.artifact_sha256
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise SystemExit("Published Galaxy version has no valid archive SHA-256")
    return digest


def _galaxy_version_matches(
    api: GalaxyAPI, collection: str, version: str, digest: str
) -> bool:
    published = _published_digest(api, collection, version)
    if published is None:
        return False
    if published != digest:
        raise SystemExit("Existing Galaxy version has conflicting archive SHA-256")
    return True


def publish_galaxy(
    package_dir: Path, expected_sha256: str, *, tag: str | None = None
) -> None:
    """Import the verified archive to Galaxy, or accept an identical version.

    :param package_dir: Download of the successful package job's four files.
    :param expected_sha256: Digest recorded by that same package job.
    :param tag: Exact Windows companion tag when invoked by an AD coordinator.
    :raises SystemExit: If credentials, provenance or published content disagree.
    :raises AnsibleError: If Galaxy discovery, upload or import fails.
    """
    token = os.environ.get("GALAXY_API_KEY", "")
    if not token.strip():
        raise SystemExit("Set the GALAXY_API_KEY repository secret before publishing")
    artifact, _, tag = _publication_candidate(package_dir, expected_sha256, tag)
    collection, version = _tag_collection(tag)
    api = _galaxy_api()
    _require_published_runtime(artifact, collection, api)
    if _galaxy_version_matches(api, collection, version, expected_sha256):
        _require_tag_commit(tag, _commit())
        print(
            "Matching Galaxy version is already published: "
            + collection
            + " "
            + version
        )
        return
    _require_tag_commit(tag, _commit())
    task = api.publish_collection(str(artifact))
    api.wait_import_task(task, timeout=600)
    # A successful upload or polling return alone does not prove availability.
    if not _galaxy_version_matches(api, collection, version, expected_sha256):
        raise SystemExit("Galaxy import did not make the verified version available")
    _require_tag_commit(tag, _commit())
    print("Published verified Galaxy version: " + collection + " " + version)


def _publish_windows_companion(
    package_dir: Path, expected_sha256: str, tag: str
) -> None:
    try:
        publish(package_dir, expected_sha256, tag=tag)
    except SystemExit as error:
        if not str(error).startswith("Existing release asset differs:"):
            raise
        raise SystemExit(
            "Existing Windows release uses a different candidate; retry its "
            "original publication run before the AD run"
        ) from error
    publish_galaxy(package_dir, expected_sha256, tag=tag)


def _matching_windows_release(package_dir: Path, digest: str, tag: str) -> bool:
    release = _find_release(tag)
    if release is None:
        return False
    artifact, _ = _candidate(package_dir, digest, tag)
    try:
        return bool(
            _existing_assets(release, tag, [artifact, package_dir / "SHA256SUMS"])
        )
    except SystemExit as error:
        if str(error).startswith("Existing release asset differs:"):
            return False
        raise


def publish_tagged(
    windows_package_dir: Path,
    windows_sha256: str,
    ad_package_dir: Path,
    ad_sha256: str,
) -> None:
    """Publish same-commit tags together, with AD coordinating Windows first.

    :param windows_package_dir: Verified Windows bundle from this workflow run.
    :param windows_sha256: Windows digest recorded by the package job.
    :param ad_package_dir: Verified AD bundle from this workflow run.
    :param ad_sha256: AD digest recorded by the package job.
    :raises SystemExit: If provenance, candidates, dependencies or retries conflict.
    :raises AnsibleError: If a Galaxy lookup or publication fails.
    """
    origin = _originating_tag()
    collection = _tag_collection(origin)[0]
    bundles = {
        "legacy_windows": (windows_package_dir, windows_sha256),
        "legacy_ad": (ad_package_dir, ad_sha256),
    }
    if origin != _source_tag(collection):
        raise SystemExit("Originating tag differs from the tested source version")
    _publication_candidate(*bundles[collection])
    api = _galaxy_api()
    other = "legacy_ad" if collection == "legacy_windows" else "legacy_windows"
    companion = _source_tag(other)
    if _tag_commit(companion, missing_ok=True) != _commit():
        preflight(*bundles[collection])
        publish(*bundles[collection])
        publish_galaxy(*bundles[collection])
        return
    tags = {collection: origin, other: companion}
    artifacts = {
        name: _candidate(*bundles[name], tags[name])[0] for name in COLLECTIONS
    }
    dependencies = _archive_metadata(artifacts["legacy_ad"], "legacy_ad")[2]
    if not meets_requirements(
        _tag_collection(tags["legacy_windows"])[1],
        dependencies[NAMESPACE + ".legacy_windows"],
    ):
        raise SystemExit("Tagged Windows runtime does not satisfy the AD dependency")
    # Both tags and bundles must be valid before the first publication mutation.
    for tag in tags.values():
        _require_tag_commit(tag, _commit())
    windows_published = _published_digest(
        api, "legacy_windows", _tag_collection(tags["legacy_windows"])[1]
    )
    if collection == "legacy_windows":
        # A retained standalone run may own the only safe retry of its assets.
        if windows_published is not None or (
            _published_digest(api, "legacy_ad", _tag_collection(tags["legacy_ad"])[1])
            is None
            and not _matching_windows_release(
                *bundles["legacy_windows"], tags["legacy_windows"]
            )
        ):
            print("Same-commit AD tag coordinates publication: " + companion)
            return
    elif windows_published is None:
        _publish_windows_companion(*bundles["legacy_windows"], tags["legacy_windows"])
    preflight(*bundles[collection])
    publish(*bundles[collection])
    publish_galaxy(*bundles[collection])


def main() -> None:
    """Run candidate preparation or guarded publication.

    :raises SystemExit: If arguments, candidate validation, or publication fail.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("package", help="Stage a checked archive for CI")
    prepare.add_argument("--artifact", type=Path, required=True)
    prepare.add_argument("--output-dir", type=Path, required=True)
    prepare.add_argument("--tag")
    prepare.add_argument("--collection", choices=COLLECTIONS, required=True)
    for command, help_text in (
        ("publish", "Publish a stable tag push to GitHub"),
        ("publish-galaxy", "Publish a stable tag push to Ansible Galaxy"),
        ("preflight", "Verify publication prerequisites without publishing"),
    ):
        release = commands.add_parser(command, help=help_text)
        release.add_argument("--package-dir", type=Path, required=True)
        release.add_argument("--sha256", required=True)
    tagged = commands.add_parser("publish-tagged", help="Publish coordinated tags")
    tagged.add_argument("--windows-package-dir", type=Path, required=True)
    tagged.add_argument("--windows-sha256", required=True)
    tagged.add_argument("--ad-package-dir", type=Path, required=True)
    tagged.add_argument("--ad-sha256", required=True)
    arguments = parser.parse_args()
    try:
        if arguments.command == "package":
            package(
                arguments.artifact,
                arguments.output_dir,
                arguments.tag,
                arguments.collection,
            )
        elif arguments.command == "publish-tagged":
            publish_tagged(
                arguments.windows_package_dir,
                arguments.windows_sha256,
                arguments.ad_package_dir,
                arguments.ad_sha256,
            )
        elif arguments.command == "publish":
            publish(arguments.package_dir, arguments.sha256)
        elif arguments.command == "publish-galaxy":
            publish_galaxy(arguments.package_dir, arguments.sha256)
        else:
            preflight(arguments.package_dir, arguments.sha256)
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        tarfile.TarError,
        yaml.YAMLError,
        AnsibleError,
    ) as error:
        raise SystemExit(
            "Invalid release inputs or API response: " + str(error)
        ) from error


if __name__ == "__main__":
    main()
