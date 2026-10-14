"""Stage native subnet helpers and use shared Windows execution."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


# Keep each action's complete helper closure explicit and independently auditable.
# pylint: disable=duplicate-code
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Manage replication subnets through the shared target execution runtime."""

    EXTRA_MODULE_UTILS = ("legacy_windows_account.py",)
    COLLECTION_MODULE_UTILS = tuple(
        Path(__file__).resolve().parents[1] / "module_utils" / filename
        for filename in (
            "legacy_ad_arguments.py",
            "legacy_ad_ldap.py",
            "legacy_ad_filter.py",
            "legacy_ad_schema.py",
            "legacy_ad_object.py",
            "legacy_ad_result.py",
            "legacy_ad_topology.py",
        )
    )


# pylint: enable=duplicate-code
