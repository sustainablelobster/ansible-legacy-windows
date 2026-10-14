"""Stage native LDAP KDS information and the shared Windows execution runtime."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


# Ansible supplies the fixed normal-action extension hierarchy.
# Both KDS entry points need this same explicit target helper closure.
# pylint: disable=duplicate-code
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Read directory KDS root-key metadata under the Windows execution identity."""

    COLLECTION_MODULE_UTILS = tuple(
        Path(__file__).resolve().parents[1] / "module_utils" / filename
        for filename in (
            "legacy_ad_arguments.py",
            "legacy_ad_ldap.py",
            "legacy_ad_kds.py",
        )
    )
