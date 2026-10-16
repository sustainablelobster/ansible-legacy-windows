"""Stage the installed Windows message utility's native process boundary."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Run msg.exe with the standard target argument and process helpers."""

    EXTRA_MODULE_UTILS = ("legacy_windows_process.py", "legacy_windows_text.py")
