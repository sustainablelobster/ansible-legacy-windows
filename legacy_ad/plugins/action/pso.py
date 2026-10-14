"""Stage native PSO operations through the shared Windows runtime."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Manage password policy objects with an explicit target helper closure."""

    EXTRA_MODULE_UTILS = ("legacy_windows_account.py",)
    # Each action lists its target dependencies so staging can be reviewed locally.
    # pylint: disable=duplicate-code
    COLLECTION_MODULE_UTILS = tuple(
        Path(__file__).resolve().parents[1] / "module_utils" / name
        for name in (
            "legacy_ad_arguments.py",
            "legacy_ad_ldap.py",
            "legacy_ad_filter.py",
            "legacy_ad_schema.py",
            "legacy_ad_object.py",
            "legacy_ad_account.py",
            "legacy_ad_result.py",
            "legacy_ad_policy_pso.py",
        )
    )
    # pylint: enable=duplicate-code
