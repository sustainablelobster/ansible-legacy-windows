"""Initialize Ansible's process-wide loader with the checkout under test."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

import pytest

# Ansible's controller interfaces have no distributed typing metadata.
from ansible.plugins.loader import init_plugin_loader  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


@pytest.fixture(scope="session", autouse=True)
def source_collection(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Make the checkout available before any test uses Ansible's global loader.

    :param tmp_path_factory: Pytest's scoped temporary-directory factory.
    :returns: The source collection's temporary namespace path.
    """
    collections = tmp_path_factory.mktemp("source-collections")
    namespace = collections / "ansible_collections" / "sustainablelobster"
    namespace.mkdir(parents=True)
    collection = namespace / "legacy_windows"
    collection.symlink_to(ROOT, target_is_directory=True)
    init_plugin_loader([str(collections)])
    return collection
