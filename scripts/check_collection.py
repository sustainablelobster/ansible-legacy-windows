"""Build and install the collection in a disposable local directory."""

import json
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IDENTITY = ("sustainablelobster", "legacy_windows")
REQUIRED_FILES = {
    "MANIFEST.json",
    "FILES.json",
    "LICENSE",
    "CHANGELOG.md",
    "README.md",
    "meta/runtime.yml",
    "docs/compatibility.md",
    "docs/development.md",
    "docs/status.md",
    "plugins/modules/README.md",
    "plugins/module_utils/README.md",
    "plugins/action/README.md",
}
EXCLUDED_ROOTS = {
    ".git",
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


def _inspect_archive(artifact: Path) -> bytes:
    with tarfile.open(artifact) as archive:
        names = set(archive.getnames())
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
        manifest = _read_member(archive, "MANIFEST.json")
        info = json.loads(manifest)["collection_info"]
        if (info["namespace"], info["name"]) != IDENTITY:
            raise SystemExit("Artifact has the wrong collection identity")
        if _read_member(archive, "LICENSE") != (ROOT / "LICENSE").read_bytes():
            raise SystemExit("Artifact license differs from the source license")
    return manifest


def main() -> None:
    """Check collection packaging and installation without contacting hosts.

    :raises SystemExit: If the collection artifact or installation is invalid.
    """
    with tempfile.TemporaryDirectory(prefix="legacy-windows-check-") as directory:
        temporary = Path(directory)
        collections = temporary / "collections"
        environment = {
            **os.environ,
            "ANSIBLE_COLLECTIONS_PATH": str(collections),
            "ANSIBLE_LOCAL_TEMP": str(temporary / "ansible-tmp"),
        }
        galaxy = [sys.executable, "-m", "ansible.cli.galaxy", "collection"]
        subprocess.run(
            [*galaxy, "build", "--output-path", str(temporary)],
            cwd=ROOT,
            env=environment,
            check=True,
        )
        (artifact,) = temporary.glob("*.tar.gz")
        manifest = _inspect_archive(artifact)

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
        for name in REQUIRED_FILES:
            if not (installed / name).is_file():
                raise SystemExit("Installed collection is missing: " + name)
        if (installed / "LICENSE").read_bytes() != (ROOT / "LICENSE").read_bytes():
            raise SystemExit("Installed license differs from the source license")
        print(
            "PASS: collection metadata, contents, exclusions, and offline installation"
        )
        print("This checks packaging only; it does not execute Windows payloads.")


if __name__ == "__main__":
    main()
