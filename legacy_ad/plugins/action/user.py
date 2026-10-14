"""Stage native user helpers and reuse shared Windows execution."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


# Keep the complete native closure explicit instead of a registry of helpers.
# pylint: disable=duplicate-code
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Manage AD users through the shared target execution runtime."""

    EXTRA_MODULE_UTILS = ("legacy_windows_account.py",)
    COLLECTION_MODULE_UTILS = tuple(
        Path(__file__).resolve().parents[1] / "module_utils" / filename
        for filename in (
            "legacy_ad_ldap.py",
            "legacy_ad_filter.py",
            "legacy_ad_schema.py",
            "legacy_ad_object.py",
            "legacy_ad_account.py",
            "legacy_ad_result.py",
            "legacy_ad_user.py",
        )
    )
