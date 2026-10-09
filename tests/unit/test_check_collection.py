"""Verify that packaging rejects missing, stale and altered plugin content."""

import io
import json
import tarfile
from pathlib import Path

import pytest

from scripts import check_collection as checker

# Archive validation is the behavior under test; these helpers are private
# because the only public entry point also invokes the real build and install.
# pylint: disable=protected-access


@pytest.fixture(name="plugins")
def source_plugins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, bytes]:
    """Create source plugins and notices without needing a Git index.

    :param tmp_path: Isolated directory allocated by Pytest.
    :param monkeypatch: Fixture restoring the packaging checker's configuration.
    :returns: Exact plugin paths and bytes expected in the collection.
    """
    root = tmp_path / "source"
    contents = {
        "plugins/modules/win_ping.py": b"print('pong')\n",
        "plugins/action/win_ping.py": b"# controller action\n",
        "plugins/modules/README.md": b"Module documentation\n",
    }
    for name, data in {**contents, "LICENSE": b"license bytes\n"}.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    cache = root / "plugins/modules/__pycache__/win_ping.pyc"
    cache.parent.mkdir()
    cache.write_bytes(b"cache")
    monkeypatch.setattr(checker, "ROOT", root)
    monkeypatch.setattr(checker, "LICENSE_AND_NOTICE_FILES", ("LICENSE",))
    monkeypatch.setattr(
        checker, "REQUIRED_FILES", {"MANIFEST.json", "FILES.json", "LICENSE"}
    )
    return contents


def _archive(tmp_path: Path, plugins: dict[str, bytes]) -> Path:
    manifest = json.dumps(
        {
            "collection_info": {
                "namespace": "sustainablelobster",
                "name": "legacy_windows",
                "license": ["GPL-3.0-or-later", "MIT", "Unicode-3.0"],
            }
        }
    ).encode("utf-8")
    files = {
        **plugins,
        "MANIFEST.json": manifest,
        "FILES.json": b"{}",
        "LICENSE": b"license bytes\n",
    }
    path = tmp_path / "collection.tar"
    with tarfile.open(path, "w") as archive:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return path


def test_source_inventory_includes_untracked_plugins_not_caches(
    plugins: dict[str, bytes],
) -> None:
    assert checker._plugin_files(checker.ROOT) == plugins


def test_archive_accepts_exact_plugin_paths_and_bytes(
    tmp_path: Path, plugins: dict[str, bytes]
) -> None:
    manifest = checker._inspect_archive(_archive(tmp_path, plugins), plugins)
    assert json.loads(manifest)["collection_info"]["name"] == "legacy_windows"


def test_archive_rejects_a_missing_module(
    tmp_path: Path, plugins: dict[str, bytes]
) -> None:
    incomplete = dict(plugins)
    del incomplete["plugins/modules/win_ping.py"]
    with pytest.raises(SystemExit, match="missing: plugins/modules/win_ping.py"):
        checker._inspect_archive(_archive(tmp_path, incomplete), plugins)


def test_archive_rejects_an_extra_stale_helper(
    tmp_path: Path, plugins: dict[str, bytes]
) -> None:
    stale = dict(plugins, **{"plugins/module_utils/removed.py": b"stale\n"})
    with pytest.raises(SystemExit, match="extra: plugins/module_utils/removed.py"):
        checker._inspect_archive(_archive(tmp_path, stale), plugins)


def test_archive_rejects_altered_plugin_bytes(
    tmp_path: Path, plugins: dict[str, bytes]
) -> None:
    altered = dict(plugins)
    altered["plugins/modules/win_ping.py"] = b"print('wrong')\n"
    with pytest.raises(SystemExit, match="plugin differs from source"):
        checker._inspect_archive(_archive(tmp_path, altered), plugins)


@pytest.mark.parametrize(
    "name",
    [
        "tmp/inventory.yml",
        ".env",
        ".github/workflows/ci.yml",
        ".gitattributes",
        "plugins/modules/__pycache__/cached.pyc",
    ],
)
def test_archive_rejects_private_inputs_and_caches(
    tmp_path: Path, plugins: dict[str, bytes], name: str
) -> None:
    included = dict(plugins, **{name: b"not distributable\n"})
    with pytest.raises(SystemExit, match="excluded path"):
        checker._inspect_archive(_archive(tmp_path, included), plugins)


def test_archive_rejects_github_directory(
    tmp_path: Path, plugins: dict[str, bytes]
) -> None:
    artifact = _archive(tmp_path, plugins)
    with tarfile.open(artifact, "a") as archive:
        directory = tarfile.TarInfo(".github")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
    with pytest.raises(SystemExit, match="excluded path: \\.github"):
        checker._inspect_archive(artifact, plugins)
