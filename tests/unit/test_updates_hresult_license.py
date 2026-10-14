"""Verify numeric update diagnostics and collection distribution licenses."""

# SPDX-License-Identifier: GPL-3.0-or-later

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils import (
    _updates_hresult as formatter,
)

from scripts import check_collection as packaging

ROOT = Path(__file__).resolve().parents[2] / "legacy_windows"
GPL_LICENSE = "LICENSES/ansible-windows-GPL-3.0-or-later.txt"
UNICODE_LICENSE = "LICENSES/Unicode-3.0.txt"
REGEX_CATEGORY_DATA_FILE = "plugins/module_utils/legacy_windows_regex_categories.py"
FORMATTER_FILE = "plugins/plugin_utils/_updates_hresult.py"


@pytest.mark.parametrize(
    ("hresult", "expected"),
    [
        (0, "Windows Update HRESULT 0x00000000"),
        (0x00240001, "Windows Update HRESULT 0x00240001"),
        (0x80240022, "Windows Update HRESULT 0x80240022"),
        (12345, "Windows Update HRESULT 0x00003039"),
        (-1, "Windows Update HRESULT 0xFFFFFFFF"),
        (-2145124323, "Windows Update HRESULT 0x8024001D"),
        (0x100000001, "Windows Update HRESULT 0x00000001"),
        (-0x100000001, "Windows Update HRESULT 0xFFFFFFFF"),
    ],
)
def test_hresult_diagnostics_show_unsigned_32_bit_codes(
    hresult: int, expected: str
) -> None:
    assert formatter.describe_hresult(hresult) == expected


@pytest.mark.parametrize("description", [None, "", " \r\n "])
def test_missing_description_retains_numeric_fallback(description: str | None) -> None:
    assert formatter.describe_hresult(-2147024891, description) == (
        "Windows Update HRESULT 0x80070005"
    )


def test_native_description_keeps_language_and_hexadecimal_code() -> None:
    assert formatter.describe_hresult(-2147024891, "  Accès refusé.\r\n") == (
        "Accès refusé. (Windows Update HRESULT 0x80070005)"
    )


def test_formatter_retains_the_project_license() -> None:
    source = (ROOT / FORMATTER_FILE).read_text(encoding="utf-8")
    assert "# SPDX-License-Identifier: GPL-3.0-or-later" in source


def test_upstream_reference_retains_its_gpl_notice_and_license() -> None:
    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    assert GPL_LICENSE in notice
    assert "GPL-3.0-or-later" in notice
    # The recorded ansible.windows 3.8.0 release's COPYING file is retained intact.
    assert hashlib.sha256((ROOT / GPL_LICENSE).read_bytes()).hexdigest() == (
        "0ae0485a5bd37a63e63603596417e4eb0e653334fa6c7f932ca3a0e85d4af227"
    )


@pytest.mark.parametrize("removed", sorted(packaging.FORBIDDEN_FILES))
def test_removed_hresult_table_is_not_maintained_or_attributed(removed: str) -> None:
    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    assert not (ROOT / removed).exists()
    assert removed not in notice


@pytest.mark.parametrize(
    "license_name",
    [
        "LICENSES/convertdate-MIT.txt",
        "LICENSES/microsoft-referencesource-MIT.txt",
        UNICODE_LICENSE,
    ],
)
def test_incorporated_material_keeps_its_notice_and_license(license_name: str) -> None:
    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    assert license_name in notice
    assert (ROOT / license_name).is_file()


def test_removed_uri_hashtable_emulation_is_not_shipped_or_attributed() -> None:
    helper = ROOT / "plugins/module_utils/legacy_windows_uri_json.py"
    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    assert not helper.exists()
    assert str(helper.relative_to(ROOT)) not in notice
    assert "40705020f56b7634f247e355b1745df362ecd9a7" not in notice


@pytest.fixture(name="built_collection", scope="module")
def _built_collection(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build one real collection archive without accessing a host or service.

    :param tmp_path_factory: Pytest's isolated module temporary directories.
    :returns: The collection archive produced by Ansible Galaxy locally.
    """
    directory = tmp_path_factory.mktemp("hresult-collection")
    subprocess.run(
        [
            sys.executable,
            "-m",
            "ansible.cli.galaxy",
            "collection",
            "build",
            "--output-path",
            str(directory),
        ],
        cwd=ROOT,
        env={**os.environ, "ANSIBLE_LOCAL_TEMP": str(directory / "ansible-tmp")},
        check=True,
        capture_output=True,
        text=True,
    )
    (artifact,) = directory.glob("*.tar.gz")
    return artifact


def test_real_archive_and_offline_install_preserve_licenses_and_diagnostics(
    built_collection: Path, tmp_path: Path
) -> None:
    # This is controller packaging evidence, not Windows runtime evidence.
    # Exercise the archive gate directly, without invoking an Ansible target.
    manifest = packaging._inspect_archive(  # pylint: disable=protected-access
        built_collection
    )
    collection_info = json.loads(manifest)["collection_info"]
    assert collection_info["authors"] == ["sustainablelobster"]
    assert collection_info["license_file"] == "LICENSE"
    assert not collection_info["license"]
    subprocess.run(
        [
            sys.executable,
            "-m",
            "ansible.cli.galaxy",
            "collection",
            "install",
            str(built_collection),
            "--collections-path",
            str(tmp_path),
            "--offline",
            "--no-deps",
        ],
        cwd=ROOT,
        env={**os.environ, "ANSIBLE_LOCAL_TEMP": str(tmp_path / "ansible-tmp")},
        check=True,
        capture_output=True,
        text=True,
    )
    installed = tmp_path / "ansible_collections/sustainablelobster/legacy_windows"
    assert (installed / "MANIFEST.json").read_bytes() == manifest
    for name in (
        *packaging.LICENSE_AND_NOTICE_FILES,
        FORMATTER_FILE,
        REGEX_CATEGORY_DATA_FILE,
    ):
        assert (installed / name).read_bytes() == (ROOT / name).read_bytes()
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "from ansible_collections.sustainablelobster.legacy_windows.plugins."
            "plugin_utils._updates_hresult import describe_hresult; "
            "print(describe_hresult(0x00240001)); print(describe_hresult(-1))",
        ],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(tmp_path)},
        check=True,
        capture_output=True,
        text=True,
    )
    assert completed.stdout.splitlines() == [
        "Windows Update HRESULT 0x00240001",
        "Windows Update HRESULT 0xFFFFFFFF",
    ]


def _modified_members(
    archive: tarfile.TarFile, omitted: str, replaced: dict[str, bytes]
) -> Iterator[tuple[tarfile.TarInfo, bytes | None]]:
    for member in archive.getmembers():
        if member.name == omitted:
            continue
        extracted = archive.extractfile(member) if member.isfile() else None
        data = extracted.read() if extracted is not None else None
        if extracted is not None:
            extracted.close()
        if member.name in replaced:
            data = replaced[member.name]
            member.size = len(data)
        yield member, data


@pytest.mark.parametrize(
    "omitted",
    [
        *packaging.LICENSE_AND_NOTICE_FILES,
        FORMATTER_FILE,
        REGEX_CATEGORY_DATA_FILE,
    ],
)
def test_packaging_rejects_missing_license_or_shipped_dependency(
    built_collection: Path, tmp_path: Path, omitted: str
) -> None:
    altered = tmp_path / "missing.tar.gz"
    with (
        tarfile.open(built_collection) as original,
        tarfile.open(altered, "w:gz") as new,
    ):
        for member, data in _modified_members(original, omitted, {}):
            new.addfile(member, io.BytesIO(data) if data is not None else None)
    with pytest.raises(SystemExit, match="Artifact is missing: " + omitted):
        # The private archive gate is the behavior being tested here.
        packaging._inspect_archive(altered)  # pylint: disable=protected-access


@pytest.mark.parametrize("notice", packaging.LICENSE_AND_NOTICE_FILES)
def test_packaging_rejects_changed_license_or_notice(
    built_collection: Path, tmp_path: Path, notice: str
) -> None:
    altered = tmp_path / "changed.tar.gz"
    with (
        tarfile.open(built_collection) as original,
        tarfile.open(altered, "w:gz") as new,
    ):
        for member, data in _modified_members(original, "", {notice: b"incorrect\n"}):
            new.addfile(member, io.BytesIO(data) if data is not None else None)
    with pytest.raises(SystemExit, match="Artifact license or notice differs"):
        # The private archive gate is the behavior being tested here.
        packaging._inspect_archive(altered)  # pylint: disable=protected-access


@pytest.mark.parametrize("license_file", [None, "", "COPYING", "NOTICE", GPL_LICENSE])
def test_packaging_rejects_missing_or_incorrect_license_file_selection(
    built_collection: Path, tmp_path: Path, license_file: str | None
) -> None:
    altered = tmp_path / "metadata.tar.gz"
    with (
        tarfile.open(built_collection) as original,
        tarfile.open(altered, "w:gz") as new,
    ):
        manifest_file = original.extractfile("MANIFEST.json")
        assert manifest_file is not None
        with manifest_file:
            manifest = json.load(manifest_file)
        if license_file is None:
            del manifest["collection_info"]["license_file"]
        else:
            manifest["collection_info"]["license_file"] = license_file
        replaced = {"MANIFEST.json": json.dumps(manifest).encode("utf-8")}
        for member, data in _modified_members(original, "", replaced):
            new.addfile(member, io.BytesIO(data) if data is not None else None)
    with pytest.raises(
        SystemExit,
        match="Artifact must declare license_file: LICENSE without a license list",
    ):
        # The private archive gate is the behavior being tested here.
        packaging._inspect_archive(altered)  # pylint: disable=protected-access


@pytest.mark.parametrize("removed", sorted(packaging.FORBIDDEN_FILES))
def test_packaging_rejects_reintroduced_hresult_table(
    built_collection: Path, tmp_path: Path, removed: str
) -> None:
    altered = tmp_path / "removed.tar.gz"
    with (
        tarfile.open(built_collection) as original,
        tarfile.open(altered, "w:gz") as new,
    ):
        for member, data in _modified_members(original, "", {}):
            new.addfile(member, io.BytesIO(data) if data is not None else None)
        data = b"Previously removed material\n"
        member = tarfile.TarInfo(removed)
        member.size = len(data)
        new.addfile(member, io.BytesIO(data))
    with pytest.raises(SystemExit, match="Artifact includes removed implementation"):
        packaging._inspect_archive(altered)  # pylint: disable=protected-access


@pytest.mark.parametrize(
    "licenses",
    [
        ["GPL-3.0-or-later"],
        ["MIT"],
        ["Unicode-3.0"],
        ["GPL-3.0-or-later", "MIT", "Unicode-3.0"],
        ["Apache-2.0"],
    ],
)
def test_packaging_rejects_license_list_alongside_license_file(
    built_collection: Path, tmp_path: Path, licenses: list[str]
) -> None:
    altered = tmp_path / "wrong-license-metadata.tar.gz"
    with (
        tarfile.open(built_collection) as original,
        tarfile.open(altered, "w:gz") as new,
    ):
        manifest_file = original.extractfile("MANIFEST.json")
        assert manifest_file is not None
        with manifest_file:
            manifest = json.load(manifest_file)
        manifest["collection_info"]["license"] = licenses
        replaced = {"MANIFEST.json": json.dumps(manifest).encode("utf-8")}
        for member, data in _modified_members(original, "", replaced):
            new.addfile(member, io.BytesIO(data) if data is not None else None)
    with pytest.raises(
        SystemExit,
        match="Artifact must declare license_file: LICENSE without a license list",
    ):
        packaging._inspect_archive(altered)  # pylint: disable=protected-access
