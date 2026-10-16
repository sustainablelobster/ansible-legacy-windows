"""Stage native scheduled-task facts through the Windows runtime."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


# Reading and managing tasks need the same explicitly staged native backends.
# Keeping their closures visible avoids a separate action-dispatch abstraction.
# pylint: disable=duplicate-code
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Read task definitions using the installed native scheduler capabilities."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_wmi.py",
        "legacy_windows_account.py",
        "legacy_windows_service.py",
    )
    COLLECTION_MODULE_UTILS = tuple(
        Path(__file__).resolve().parents[1] / "module_utils" / filename
        for filename in (
            "legacy_community_windows_scheduled_task.py",
            "legacy_community_windows_scheduled_task_native.py",
            "legacy_community_windows_scheduled_task_legacy.py",
            "legacy_community_windows_scheduled_task_legacy_native.py",
            "legacy_community_windows_scheduled_task_stat.py",
        )
    )
