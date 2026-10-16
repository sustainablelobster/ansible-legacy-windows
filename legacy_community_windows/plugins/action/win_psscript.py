"""Stage the fixed PowerShellGet script-management operation."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


# Ansible's established action hierarchy is extended directly. Each vendor
# operation explicitly names its small helper closure instead of a registry.
# pylint: disable=duplicate-code
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Manage installed scripts through the shared Windows execution runtime."""

    COLLECTION_MODULE_UTILS = (
        Path(__file__).resolve().parents[1]
        / "module_utils"
        / "legacy_community_windows_psget_engine.py",
    )
