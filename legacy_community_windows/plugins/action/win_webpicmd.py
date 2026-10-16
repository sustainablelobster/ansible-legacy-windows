"""Stage the native WebPI process execution helpers."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


# Ansible's normal action has an established deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Run an installed WebPI executable without replacing its vendor feed."""

    _supports_check_mode = False
    EXTRA_MODULE_UTILS = ("legacy_windows_process.py", "legacy_windows_text.py")
