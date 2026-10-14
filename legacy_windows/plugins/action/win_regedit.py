"""Stage native registry editing helpers before executing win_regedit."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Edit Windows registry keys and values with native Python execution."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_reg_stat.py",
        "legacy_windows_regedit.py",
        "legacy_windows_regedit_data.py",
    )
