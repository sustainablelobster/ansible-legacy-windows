"""Stage native power-plan management using the shared Python runtime."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Stage only the PowrProf helper needed by the power-plan payload."""

    COLLECTION_MODULE_UTILS = (
        Path(__file__).resolve().parents[1]
        / "module_utils"
        / "legacy_community_windows_power.py",
    )
