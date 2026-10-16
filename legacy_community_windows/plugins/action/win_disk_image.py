"""Stage native virtual-disk, volume and token APIs through the Windows runtime."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Execute image mounting with the installed native provider."""

    # Keep the staged dependency list explicit for each independently usable action.
    # pylint: disable=duplicate-code
    EXTRA_MODULE_UTILS = (
        "legacy_windows_owner.py",
        "legacy_windows_group.py",
        "legacy_windows_account.py",
        "legacy_windows_wmi.py",
    )
    COLLECTION_MODULE_UTILS = (
        Path(__file__).resolve().parents[1]
        / "module_utils"
        / "legacy_community_windows_disk_image.py",
    )
    # pylint: enable=duplicate-code
