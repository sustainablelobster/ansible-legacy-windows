"""Stage local security policy management through the Windows runtime."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Execute verified secedit operations with BOM-aware text parsing."""

    EXTRA_MODULE_UTILS = ("legacy_windows_text.py",)
