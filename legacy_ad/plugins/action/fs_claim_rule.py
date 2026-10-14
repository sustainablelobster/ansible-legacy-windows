"""Stage the Python AD FS adapter alongside the shared Windows runtime."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


# Each public action independently stages this same required helper closure.
# pylint: disable=duplicate-code
# Ansible supplies the fixed normal-action extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Run claim-rule management through installed vendor commands."""

    COLLECTION_MODULE_UTILS = tuple(
        Path(__file__).resolve().parents[1] / "module_utils" / filename
        for filename in (
            "legacy_ad_result.py",
            "legacy_ad_arguments.py",
            "legacy_ad_adfs.py",
        )
    )


# pylint: enable=duplicate-code
