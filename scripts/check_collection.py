"""Build and install the collection in a disposable local directory."""

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
    "docs/development.md",
    "docs/usage.md",
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


def _validate_manifest(manifest: bytes) -> None:
    info = json.loads(manifest)["collection_info"]
    if (info["namespace"], info["name"]) != IDENTITY:
        raise SystemExit("Artifact has the wrong collection identity")
    if info.get("license_file") != "LICENSE" or info.get("license"):
        raise SystemExit(
            "Artifact must declare license_file: LICENSE without a license list"
        )


def _inspect_archive(artifact: Path, plugins: dict[str, bytes] | None = None) -> bytes:
    if plugins is None:
        plugins = _plugin_files(ROOT)
    with tarfile.open(artifact) as archive:
        names = set(archive.getnames())
        forbidden = FORBIDDEN_FILES & names
        if forbidden:
            raise SystemExit(
                "Artifact includes removed implementation: "
                + ", ".join(sorted(forbidden))
            )
        missing = REQUIRED_FILES - names
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
        archived_plugins = {
            member.name
            for member in archive.getmembers()
            if member.isfile() and Path(member.name).parts[0] == "plugins"
        }
        if archived_plugins != set(plugins):
            missing_plugins = sorted(set(plugins) - archived_plugins)
            extra_plugins = sorted(archived_plugins - set(plugins))
            raise SystemExit(
                "Artifact plugin inventory differs from source; missing: "
                + ", ".join(missing_plugins)
                + "; extra: "
                + ", ".join(extra_plugins)
            )
        for name, contents in plugins.items():
            if _read_member(archive, name) != contents:
                raise SystemExit("Artifact plugin differs from source: " + name)
        manifest = _read_member(archive, "MANIFEST.json")
        _validate_manifest(manifest)
        for notice in LICENSE_AND_NOTICE_FILES:
            if _read_member(archive, notice) != (ROOT / notice).read_bytes():
                raise SystemExit(
                    "Artifact license or notice differs from source: " + notice
                )
    return manifest


def main() -> None:
    """Check collection packaging and installation without contacting hosts.

    :raises SystemExit: If the collection artifact or installation is invalid.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--artifact",
        type=Path,
        help="Check and offline-install an existing archive instead of building one.",
    )
    arguments = parser.parse_args()
    plugins = _plugin_files(ROOT)
    with tempfile.TemporaryDirectory(prefix="legacy-windows-check-") as directory:
        temporary = Path(directory)
        collections = temporary / "collections"
        environment = {
            **os.environ,
            "ANSIBLE_COLLECTIONS_PATH": str(collections),
            "ANSIBLE_LOCAL_TEMP": str(temporary / "ansible-tmp"),
        }
        galaxy = [sys.executable, "-m", "ansible.cli.galaxy", "collection"]
        if arguments.artifact is None:
            subprocess.run(
                [*galaxy, "build", "--output-path", str(temporary)],
                cwd=ROOT,
                env=environment,
                check=True,
            )
            (artifact,) = temporary.glob("*.tar.gz")
        else:
            artifact = arguments.artifact.resolve()
        manifest = _inspect_archive(artifact, plugins)

        subprocess.run(
            [
                *galaxy,
                "install",
                str(artifact),
                "--collections-path",
                str(collections),
                "--offline",
                "--no-deps",
            ],
            cwd=ROOT,
            env=environment,
            check=True,
        )
        installed = collections / "ansible_collections" / IDENTITY[0] / IDENTITY[1]
        installed_manifest = (installed / "MANIFEST.json").read_bytes()
        if installed_manifest != manifest:
            raise SystemExit("Installed manifest differs from the built artifact")
        if _plugin_files(installed) != plugins:
            raise SystemExit("Installed plugin paths or bytes differ from source")
        for name in REQUIRED_FILES:
            if not (installed / name).is_file():
                raise SystemExit("Installed collection is missing: " + name)
        for notice in LICENSE_AND_NOTICE_FILES:
            if (installed / notice).read_bytes() != (ROOT / notice).read_bytes():
                raise SystemExit(
                    "Installed license or notice differs from source: " + notice
                )
        print(
            "PASS: collection metadata, all plugin bytes, exclusions, "
            "and offline installation"
        )
        print("This checks packaging only; it does not execute Windows payloads.")


if __name__ == "__main__":
    main()
