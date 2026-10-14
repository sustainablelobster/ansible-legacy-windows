"""Stage native configured-profile operations for win_firewall."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Execute profile management through the Python payload."""

    EXTRA_MODULE_UTILS = ("legacy_windows_wmi.py", "legacy_windows_firewall.py")
