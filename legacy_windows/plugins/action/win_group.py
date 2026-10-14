"""Stage native group and account helpers before executing win_group."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Manage local Windows groups with native Python execution."""

    # Keep the complete staging closure local instead of sharing unrelated lists.
    # pylint: disable=duplicate-code
    EXTRA_MODULE_UTILS = (
        "legacy_windows_account.py",
        "legacy_windows_environment.py",
        "legacy_windows_group.py",
    )
    # pylint: enable=duplicate-code
