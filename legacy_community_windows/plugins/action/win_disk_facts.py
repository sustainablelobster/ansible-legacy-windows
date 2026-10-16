"""Stage native disk facts and their explicit WMI and device boundaries."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Read installed storage providers without importing modern target packages."""

    # Keep the staged dependency list explicit for each independently usable action.
    # pylint: disable=duplicate-code
    EXTRA_MODULE_UTILS = (
        "legacy_windows_owner.py",
        "legacy_windows_group.py",
        "legacy_windows_account.py",
        "legacy_windows_wmi.py",
    )
    COLLECTION_MODULE_UTILS = tuple(
        Path(__file__).resolve().parents[1] / "module_utils" / (name + ".py")
        for name in (
            "legacy_community_windows_disk",
            "legacy_community_windows_disk_facts",
            "legacy_community_windows_disk_facts_native",
        )
    )
    # pylint: enable=duplicate-code
