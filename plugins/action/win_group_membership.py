"""Stage native helpers before executing win_group_membership."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils._module import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
# Each group action declares its required helpers explicitly, without importing
# the other module's action to share this short dependency list.
# pylint: disable=duplicate-code
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Manage existing local-group members with native Python execution."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_account.py",
        "legacy_windows_environment.py",
        "legacy_windows_group.py",
    )


# pylint: enable=duplicate-code
