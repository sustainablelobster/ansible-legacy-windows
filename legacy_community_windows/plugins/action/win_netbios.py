"""Stage the native WMI provider for NetBIOS adapter configuration."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Use the existing Python target execution and WMI helper."""

    EXTRA_MODULE_UTILS = ("legacy_windows_wmi.py",)
