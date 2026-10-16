"""Stage the concrete native helper closure shared by the five IIS actions."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


class IisAction(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Stage AppHost, ADSI and exact HTTP endpoint helpers for an IIS payload."""

    EXTRA_MODULE_UTILS = ("legacy_windows_wmi.py",)
    COLLECTION_MODULE_UTILS = tuple(
        Path(__file__).resolve().parents[1] / "module_utils" / filename
        for filename in (
            "legacy_community_windows_iis.py",
            "legacy_community_windows_iis_legacy.py",
            "legacy_community_windows_iis_native.py",
            "legacy_community_windows_iis_ssl.py",
        )
    )
