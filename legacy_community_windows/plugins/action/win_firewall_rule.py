"""Stage native firewall-rule management through the Windows runtime."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Execute the firewall facilities with an explicit native helper closure."""

    # Keep the staged dependency list explicit for each independently usable action.
    # pylint: disable=duplicate-code
    EXTRA_MODULE_UTILS = ("legacy_windows_wmi.py",)
    COLLECTION_MODULE_UTILS = tuple(
        Path(__file__).resolve().parents[1] / "module_utils" / filename
        for filename in (
            "legacy_community_windows_firewall_rule.py",
            "legacy_community_windows_firewall_rule_native.py",
        )
    )
    # pylint: enable=duplicate-code
