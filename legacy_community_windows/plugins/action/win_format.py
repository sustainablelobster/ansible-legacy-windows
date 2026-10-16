"""Stage the native WMI volume-formatting boundary."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Format an explicitly selected volume with the installed native provider."""

    EXTRA_MODULE_UTILS = ("legacy_windows_wmi.py",)
