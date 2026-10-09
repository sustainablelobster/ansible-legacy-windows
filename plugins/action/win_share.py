"""Stage the native SMB share and account helpers for win_share."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils._module import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Execute local share management through a Python payload."""

    # Keep the complete staging closure local instead of sharing unrelated lists.
    # pylint: disable=duplicate-code
    EXTRA_MODULE_UTILS = (
        "legacy_windows_account.py",
        "legacy_windows_environment.py",
        "legacy_windows_group.py",
        "legacy_windows_owner.py",
        "legacy_windows_share.py",
    )
    # pylint: enable=duplicate-code
