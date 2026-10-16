"""Stage the fixed PowerShellGet repository-management operation."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


# Ansible's normal action has an established deep extension hierarchy.
# Each module deliberately states its own helper closure; a shared registry
# would hide this small and complete staging contract.
# pylint: disable=duplicate-code
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Manage repository registrations using the shared Windows runtime."""

    COLLECTION_MODULE_UTILS = (
        Path(__file__).resolve().parents[1]
        / "module_utils"
        / "legacy_community_windows_psget_engine.py",
    )
