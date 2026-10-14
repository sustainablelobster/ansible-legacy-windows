"""Stage native account, group, and expiration helpers before win_user."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Manage local Windows users with native Python execution."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_account.py",
        "legacy_windows_calendar.py",
        "legacy_windows_datetime.py",
        "legacy_windows_environment.py",
        "legacy_windows_group.py",
        "legacy_windows_time.py",
        "legacy_windows_user.py",
        "legacy_windows_user_time.py",
    )
