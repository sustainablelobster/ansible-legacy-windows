"""Stage native LSA user-right operations for the ordinary Python action."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Manage local user-right assignments through normal module execution."""

    # Keep the complete staging closure local instead of sharing unrelated lists.
    # pylint: disable=duplicate-code
    EXTRA_MODULE_UTILS = (
        "legacy_windows_account.py",
        "legacy_windows_group.py",
        "legacy_windows_owner.py",
        "legacy_windows_user_right.py",
    )
    # pylint: enable=duplicate-code
