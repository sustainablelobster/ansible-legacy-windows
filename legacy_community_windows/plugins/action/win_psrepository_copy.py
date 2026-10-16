"""Stage the native repository-file and profile selection helpers."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


# Ansible's normal action already has an established deep hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Copy repository registrations without requiring a PowerShell process."""

    # Each action names its staged helper directly rather than hiding it in a registry.
    # pylint: disable=duplicate-code
    COLLECTION_MODULE_UTILS = (
        Path(__file__).resolve().parents[1]
        / "module_utils"
        / "legacy_community_windows_clixml_dictionary.py",
    )
    EXTRA_MODULE_UTILS = (
        "legacy_windows_user_profile.py",
        "legacy_windows_find_match.py",
        "legacy_windows_regex.py",
        "legacy_windows_regex_categories.py",
    )
    # pylint: enable=duplicate-code
