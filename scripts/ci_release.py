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

# PyYAML is supplied by the locked development environment, not Windows targets.
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "sustainablelobster/ansible-legacy-windows"
IDENTITY = ("sustainablelobster", "legacy_windows")
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


def _archive_metadata(artifact: Path) -> tuple[str, str]:
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
    if (info.get("namespace"), info.get("name")) != IDENTITY:
        raise SystemExit("Archive has the wrong collection identity")
    version = _version(info.get("version"))
    if artifact.name != f"{IDENTITY[0]}-{IDENTITY[1]}-{version}.tar.gz":
        raise SystemExit("Archive filename does not match its collection version")
    return version, contents["CHANGELOG.md"]


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


def package(artifact: Path, output_dir: Path, tag: str | None) -> None:
    """Stage an already checked archive and its immutable release information.

    :param artifact: Exact archive accepted by the packaging check.
    :param output_dir: Directory receiving the four uploaded candidate files.
    :param tag: Stable version tag, or None for a nonpublishing CI build.
    :raises SystemExit: If source, archive, tag, or tested commit disagree.
    """
    version, changelog = _archive_metadata(artifact)
    source = yaml.safe_load((ROOT / "galaxy.yml").read_text(encoding="utf-8"))
    if (source.get("namespace"), source.get("name")) != IDENTITY:
        raise SystemExit("galaxy.yml has the wrong collection identity")
    if _version(source.get("version")) != version:
        raise SystemExit("galaxy.yml and archive versions disagree")
    if tag is not None and tag != "v" + version:
        raise SystemExit("Tag and collection version disagree")
    if changelog != (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"):
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


def _require_tag_commit(tag: str, commit: str) -> None:
    reference = _api("git/ref/tags/" + tag)
    assert reference is not None
    target = reference["object"]
    while target["type"] == "tag":
        annotated = _api("git/tags/" + target["sha"])
        assert annotated is not None
        target = annotated["object"]
    if target["type"] != "commit" or target["sha"] != commit:
        raise SystemExit("Remote tag no longer resolves to the tested commit")


def _find_release(tag: str) -> dict[str, Any] | None:
    release = _api("releases/tags/" + tag, missing_ok=True)
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
    manifest = json.loads((package_dir / "release-manifest.json").read_text("utf-8"))
    version = _version(manifest.get("version"))
    filename = f"{IDENTITY[0]}-{IDENTITY[1]}-{version}.tar.gz"
    if manifest.get("filename") != filename or tag != "v" + version:
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
    archived_version, changelog = _archive_metadata(artifact)
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
    with tempfile.TemporaryDirectory(prefix="legacy-windows-release-") as directory:
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


def publish(package_dir: Path, expected_sha256: str) -> None:
    """Publish or safely resume the verified artifact for this tag push.

    :param package_dir: Download of the successful package job's four files.
    :param expected_sha256: Digest recorded by that same package job.
    :raises SystemExit: If provenance, remote tag, assets, or GitHub calls fail.
    """
    if (
        os.environ.get("GITHUB_EVENT_NAME") != "push"
        or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
        or os.environ.get("GITHUB_REF_TYPE") != "tag"
    ):
        raise SystemExit("Publishing requires an originating-repository tag push")
    tag = os.environ.get("GITHUB_REF_NAME", "")
    if not tag.startswith("v"):
        raise SystemExit("Publishing requires a stable vX.Y.Z tag")
    _version(tag[1:])
    if os.environ.get("GITHUB_REF") != "refs/tags/" + tag:
        raise SystemExit("Publishing requires the originating tag reference")
    artifact, notes = _candidate(package_dir, expected_sha256, tag)
    commit = _commit()
    _require_tag_commit(tag, commit)
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
    release = commands.add_parser("publish", help="Publish a stable tag push only")
    release.add_argument("--package-dir", type=Path, required=True)
    release.add_argument("--sha256", required=True)
    arguments = parser.parse_args()
    try:
        if arguments.command == "package":
            package(arguments.artifact, arguments.output_dir, arguments.tag)
        else:
            publish(arguments.package_dir, arguments.sha256)
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        tarfile.TarError,
        yaml.YAMLError,
    ) as error:
        raise SystemExit(
            "Invalid release inputs or API response: " + str(error)
        ) from error


if __name__ == "__main__":
    main()
