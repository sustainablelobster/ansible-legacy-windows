"""Stage registry import through the shared Windows execution runtime."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Execute reg.exe import/export with BOM-aware text comparison."""

    EXTRA_MODULE_UTILS = ("legacy_windows_text.py",)
