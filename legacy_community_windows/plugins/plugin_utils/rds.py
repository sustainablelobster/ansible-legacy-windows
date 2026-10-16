"""Stage the concrete native helper closure shared by gateway actions."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


class RdsAction(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Stage installed WMI, account and certificate helpers for gateway payloads."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_wmi.py",
        "legacy_windows_account.py",
        "legacy_windows_certificate_store.py",
    )
    COLLECTION_MODULE_UTILS = (
        Path(__file__).resolve().parents[1]
        / "module_utils"
        / "legacy_community_windows_rds.py",
    )
