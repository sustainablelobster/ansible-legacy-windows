"""Initialize Ansible's process-wide loader with the checkout under test."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

# Ansible's controller interfaces have no distributed typing metadata.
from ansible.plugins.loader import init_plugin_loader  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT

_COLLECTIONS = pytest.StashKey[TemporaryDirectory[str]]()


def pytest_configure(config: pytest.Config) -> None:
    """Expose source collections before importing controller test modules.

    :param config: Current pytest configuration, owning the disposable namespace.
    """
    # Pytest owns this namespace across configure/unconfigure, not one block.
    directory = TemporaryDirectory(  # pylint: disable=consider-using-with
        prefix="legacy-source-collections-"
    )
    config.stash[_COLLECTIONS] = directory
    namespace = Path(directory.name) / "ansible_collections" / "sustainablelobster"
    namespace.mkdir(parents=True)
    (namespace / "legacy_windows").symlink_to(
        ROOT / "legacy_windows", target_is_directory=True
    )
    (namespace / "legacy_ad").symlink_to(ROOT / "legacy_ad", target_is_directory=True)
    (namespace / "legacy_community_windows").symlink_to(
        ROOT / "legacy_community_windows", target_is_directory=True
    )
    init_plugin_loader([directory.name])


def pytest_unconfigure(config: pytest.Config) -> None:
    """Remove only the source namespace owned by this pytest invocation.

    :param config: Current pytest configuration.
    """
    if directory := config.stash.get(_COLLECTIONS, None):
        directory.cleanup()


@pytest.fixture(scope="session", autouse=True)
def source_collection(pytestconfig: pytest.Config) -> Path:
    """Make the checkout available before any test uses Ansible's global loader.

    :param pytestconfig: Configuration holding the pre-collection namespace.
    :returns: The source collection's temporary namespace path.
    """
    return (
        Path(pytestconfig.stash[_COLLECTIONS].name)
        / "ansible_collections"
        / "sustainablelobster"
        / "legacy_windows"
    )
