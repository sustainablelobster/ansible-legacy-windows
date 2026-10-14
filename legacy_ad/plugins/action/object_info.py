"""Stage AD-owned LDAP helpers and use the shared Windows execution runtime."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Run native LDAP queries on a Windows execution host."""

    EXTRA_MODULE_UTILS = ("legacy_windows_account.py",)
    COLLECTION_MODULE_UTILS = tuple(
        Path(__file__).resolve().parents[1] / "module_utils" / filename
        for filename in (
            "legacy_ad_ldap.py",
            "legacy_ad_filter.py",
            "legacy_ad_schema.py",
            "legacy_ad_result.py",
        )
    )
