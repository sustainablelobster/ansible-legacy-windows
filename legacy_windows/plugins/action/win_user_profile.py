"""Stage native user-profile management for ordinary Python execution."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# The standard Ansible action provides the existing extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Manage profiles without loading the user's registry hive."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_account.py",
        "legacy_windows_environment.py",
        "legacy_windows_user_profile.py",
    )
