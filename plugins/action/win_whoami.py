"""Stage native identity readers before executing the Python payload."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils._module import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Read Windows identity through native Python JSON execution."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_account.py",
        "legacy_windows_time.py",
        "legacy_windows_token.py",
        "legacy_windows_logon.py",
    )
