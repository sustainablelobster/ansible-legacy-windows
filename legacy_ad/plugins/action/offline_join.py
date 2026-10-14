"""Stage account lookup and native offline provisioning helpers."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Generate the native offline join blob under the caller's Windows logon."""

    EXTRA_MODULE_UTILS = ("legacy_windows_account.py",)
    COLLECTION_MODULE_UTILS = tuple(
        Path(__file__).resolve().parents[1] / "module_utils" / name
        for name in (
            "legacy_ad_ldap.py",
            "legacy_ad_offline_join.py",
            "legacy_ad_result.py",
        )
    )
