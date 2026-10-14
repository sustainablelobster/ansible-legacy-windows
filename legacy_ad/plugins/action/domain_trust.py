"""Stage explicit LDAP and native trust helpers through the Windows runtime."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Execute native domain trust management using its owned helper closure."""

    COLLECTION_MODULE_UTILS = tuple(
        Path(__file__).resolve().parents[1] / "module_utils" / filename
        for filename in (
            "legacy_ad_ldap.py",
            "legacy_ad_result.py",
            "legacy_ad_trust.py",
            "legacy_ad_trust_native.py",
        )
    )
