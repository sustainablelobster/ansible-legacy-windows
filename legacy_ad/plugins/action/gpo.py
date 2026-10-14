"""Stage native GPO-link helpers through the shared Windows runtime."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Manage existing GPO links without staging unrelated object helpers."""

    COLLECTION_MODULE_UTILS = tuple(
        Path(__file__).resolve().parents[1] / "module_utils" / name
        for name in (
            "legacy_ad_arguments.py",
            "legacy_ad_ldap.py",
            "legacy_ad_result.py",
            "legacy_ad_policy_gpo.py",
        )
    )
