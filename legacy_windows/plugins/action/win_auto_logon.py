"""Stage native Winlogon and LSA operations for ordinary Python execution."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Configure automatic logon."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_account.py",
        "legacy_windows_environment.py",
        "legacy_windows_auto_logon.py",
    )
