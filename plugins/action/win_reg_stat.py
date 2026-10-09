"""Stage the native registry reader before executing win_reg_stat."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils._module import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Read Windows registry values with native Python execution."""

    EXTRA_MODULE_UTILS = ("legacy_windows_reg_stat.py",)
