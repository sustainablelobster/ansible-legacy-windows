"""Stage native Deduplication and its existing Server Manager dependency."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Execute the provider-backed payload without loading a PowerShell engine."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_regex.py",
        "legacy_windows_find_match.py",
        "legacy_windows_wmi.py",
        "legacy_windows_feature_legacy.py",
        "legacy_windows_feature_info.py",
        "legacy_windows_feature_manage.py",
    )
