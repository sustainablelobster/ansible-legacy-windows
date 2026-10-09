"""Stage the native environment helper before executing win_environment."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils._module import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Manage Windows environment variables with native Python execution."""

    EXTRA_MODULE_UTILS = ("legacy_windows_environment.py",)
