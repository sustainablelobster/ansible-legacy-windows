"""Stage native scheduled-task management through the Windows runtime."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Run task management with explicit modern and legacy native helpers."""

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
        )
    )
