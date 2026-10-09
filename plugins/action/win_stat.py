"""Stage the native metadata and link helpers before executing win_stat."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils._module import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Inspect Windows filesystem entries with native Python JSON execution."""

    EXTRA_MODULE_UTILS = ("legacy_windows_stat.py", "legacy_windows_link.py")
