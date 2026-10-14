"""Accept shell free-form commands and stage the native process helpers."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Execute a shell command through the native Windows Python payload."""

    EXTRA_MODULE_UTILS = ("legacy_windows_process.py", "legacy_windows_text.py")
    supports_raw_params = True
