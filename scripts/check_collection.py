"""Build and install the selected collections in a disposable local directory."""

import argparse
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IDENTITY = ("sustainablelobster", "legacy_windows")
COLLECTION_NAMES = ("legacy_windows", "legacy_ad")
LICENSE_AND_NOTICE_FILES = (
    "LICENSE",
    "NOTICE",
    "LICENSES/ansible-windows-GPL-3.0-or-later.txt",
    "LICENSES/convertdate-MIT.txt",
    "LICENSES/microsoft-referencesource-MIT.txt",
    "LICENSES/coreclr-MIT.txt",
    "LICENSES/Unicode-3.0.txt",
)
REQUIRED_FILES = {
    "MANIFEST.json",
    "FILES.json",
    *LICENSE_AND_NOTICE_FILES,
    "CHANGELOG.md",
    "README.md",
    "meta/runtime.yml",
    "docs/usage.md",
    "docs/runtime.md",
    "plugins/modules/README.md",
    "plugins/module_utils/README.md",
    "plugins/action/README.md",
    "plugins/plugin_utils/_updates_hresult.py",
    "plugins/module_utils/legacy_windows_regex_categories.py",
}
FORBIDDEN_FILES = {
    "plugins/plugin_utils/_updates_hresult_data.py",
}
EXCLUDED_ROOTS = {
    "legacy_windows",
    "legacy_ad",
    ".git",
    ".github",
    ".gitattributes",
    ".gitignore",
    ".venv",
    ".cache",
    ".ansible",
    ".pytest_cache",
    ".mypy_cache",
    ".rumdl_cache",
    ".direnv",
    ".pre-commit-config.yaml",
    ".ansible-lint.yml",
    ".yamllint.yml",
    "dist",
    "tmp",
    "inventory",
    "inventories",
    "tests",
    "scripts",
    "AGENTS.md",
    "justfile",
    "flake.nix",
    "flake.lock",
    "result",
    "pyproject.toml",
    "galaxy.yml",
}


def _collection_root(name: str) -> Path:
    return ROOT / name


def _collection_notices(name: str) -> tuple[str, ...]:
    if name == "legacy_windows":
        return LICENSE_AND_NOTICE_FILES
    return ("LICENSE", "NOTICE", "LICENSES/microsoft-ad-GPL-3.0-or-later.txt")


def _required_files(name: str) -> set[str]:
    if name == "legacy_windows":
        return REQUIRED_FILES
    return {
        "MANIFEST.json",
        "FILES.json",
        *_collection_notices(name),
        "CHANGELOG.md",
        "README.md",
        "meta/runtime.yml",
        "docs/usage.md",
        "docs/coverage.md",
    }


def _read_member(archive: tarfile.TarFile, name: str) -> bytes:
    member = archive.extractfile(name)
    if member is None:
        raise SystemExit("Artifact entry is not a file: " + name)
    with member:
        return member.read()


def _plugin_files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted((root / "plugins").rglob("*"))
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
    }


def _validate_manifest(manifest: bytes, collection: str = "legacy_windows") -> None:
    info = json.loads(manifest)["collection_info"]
    if (info["namespace"], info["name"]) != (IDENTITY[0], collection):
        raise SystemExit("Artifact has the wrong collection identity")
    if info.get("license_file") != "LICENSE" or info.get("license"):
        raise SystemExit(
            "Artifact must declare license_file: LICENSE without a license list"
        )


def _verify_plugin_inventory(
    archive: tarfile.TarFile, plugins: dict[str, bytes]
) -> None:
    archived_plugins = {
        member.name
        for member in archive.getmembers()
        if member.isfile() and Path(member.name).parts[0] == "plugins"
    }
    if archived_plugins != set(plugins):
        raise SystemExit(
            "Artifact plugin inventory differs from source; missing: "
            + ", ".join(sorted(set(plugins) - archived_plugins))
            + "; extra: "
            + ", ".join(sorted(archived_plugins - set(plugins)))
        )
    for name, contents in plugins.items():
        if _read_member(archive, name) != contents:
            raise SystemExit("Artifact plugin differs from source: " + name)


def _inspect_archive(
    artifact: Path,
    plugins: dict[str, bytes] | None = None,
    *,
    collection: str = "legacy_windows",
) -> bytes:
    root = _collection_root(collection)
    if plugins is None:
        plugins = _plugin_files(root)
    with tarfile.open(artifact) as archive:
        names = set(archive.getnames())
        forbidden = FORBIDDEN_FILES & names
        if forbidden:
            raise SystemExit(
                "Artifact includes removed implementation: "
                + ", ".join(sorted(forbidden))
            )
        missing = _required_files(collection) - names
        if missing:
            raise SystemExit("Artifact is missing: " + ", ".join(sorted(missing)))
        for name in sorted(names):
            path = Path(name)
            first = path.parts[0]
            if (
                first in EXCLUDED_ROOTS
                or first == ".env"
                or first.startswith((".env.", "inventory.", "result-"))
                or "__pycache__" in path.parts
                or name.endswith((".pyc", ".tar.gz"))
            ):
                raise SystemExit("Artifact includes excluded path: " + name)
        _verify_plugin_inventory(archive, plugins)
        manifest = _read_member(archive, "MANIFEST.json")
        _validate_manifest(manifest, collection)
        for notice in _collection_notices(collection):
            if _read_member(archive, notice) != (root / notice).read_bytes():
                raise SystemExit(
                    "Artifact license or notice differs from source: " + notice
                )
    return manifest


def _provided_archives(paths: list[Path], names: tuple[str, ...]) -> dict[str, Path]:
    artifacts: dict[str, Path] = {}
    for path in paths:
        artifact = path.resolve()
        with tarfile.open(artifact) as archive:
            info = json.loads(_read_member(archive, "MANIFEST.json"))["collection_info"]
        name = info.get("name")
        if info.get("namespace") != IDENTITY[0] or name not in names:
            raise SystemExit("Archive is not one of the selected collections")
        if name in artifacts:
            raise SystemExit("Multiple archives supplied for " + name)
        artifacts[name] = artifact
    if set(artifacts) != set(names):
        raise SystemExit("Supply archives for: " + ", ".join(names))
    return artifacts


def _verify_installation(
    collections: Path, collection: str, plugins: dict[str, bytes], manifest: bytes
) -> None:
    root = _collection_root(collection)
    installed = collections / "ansible_collections" / IDENTITY[0] / collection
    if (installed / "MANIFEST.json").read_bytes() != manifest:
        raise SystemExit("Installed manifest differs from the built artifact")
    if _plugin_files(installed) != plugins:
        raise SystemExit("Installed plugin paths or bytes differ from source")
    for required in _required_files(collection):
        if not (installed / required).is_file():
            raise SystemExit("Installed collection is missing: " + required)
    for notice in _collection_notices(collection):
        if (installed / notice).read_bytes() != (root / notice).read_bytes():
            raise SystemExit(
                "Installed license or notice differs from source: " + notice
            )


def _build_archive(
    galaxy: list[str], root: Path, output: Path, environment: dict[str, str]
) -> Path:
    output.mkdir()
    subprocess.run(
        [*galaxy, "build", "--output-path", str(output)],
        cwd=root,
        env=environment,
        check=True,
    )
    (artifact,) = output.glob("*.tar.gz")
    return artifact


def main() -> None:
    """Check selected packages and offline dependency resolution without hosts.

    :raises SystemExit: If the collection artifact or installation is invalid.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--collection",
        choices=("all", *COLLECTION_NAMES),
        default="all",
        help="Collection to check; AD also needs the local Windows runtime archive.",
    )
    parser.add_argument(
        "--artifact",
        type=Path,
        action="append",
        help="Use a built archive; supply both archives when checking AD or all.",
    )
    arguments = parser.parse_args()
    names = (
        COLLECTION_NAMES
        if arguments.collection in ("all", "legacy_ad")
        else ("legacy_windows",)
    )
    with tempfile.TemporaryDirectory(prefix="legacy-collections-check-") as directory:
        temporary = Path(directory)
        collections = temporary / "collections"
        environment = {
            **os.environ,
            "ANSIBLE_COLLECTIONS_PATH": str(collections),
            "ANSIBLE_LOCAL_TEMP": str(temporary / "ansible-tmp"),
        }
        galaxy = [sys.executable, "-m", "ansible.cli.galaxy", "collection"]
        artifacts = (
            _provided_archives(arguments.artifact, names)
            if arguments.artifact is not None
            else {}
        )
        snapshots: dict[str, tuple[dict[str, bytes], bytes]] = {}
        for name in names:
            root = _collection_root(name)
            if arguments.artifact is None:
                artifacts[name] = _build_archive(
                    galaxy, root, temporary / name, environment
                )
            plugins = _plugin_files(root)
            manifest = _inspect_archive(artifacts[name], plugins, collection=name)
            snapshots[name] = (plugins, manifest)
        subprocess.run(
            [
                *galaxy,
                "install",
                *(str(artifacts[name]) for name in names),
                "--collections-path",
                str(collections),
                "--offline",
            ],
            cwd=ROOT,
            env=environment,
            check=True,
        )
        for name in names:
            _verify_installation(collections, name, *snapshots[name])
        print(
            "PASS: collection metadata, all plugin bytes, exclusions, "
            "and offline dependency resolution for " + ", ".join(names)
        )
        print("This checks packaging only; it does not execute Windows payloads.")


if __name__ == "__main__":
    main()
