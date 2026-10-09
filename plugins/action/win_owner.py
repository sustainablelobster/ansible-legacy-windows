"""Stage native security and filesystem helpers for win_owner."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils._module import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Run the Python ownership payload with native Windows helpers."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_account.py",
        "legacy_windows_group.py",
        "legacy_windows_file.py",
        "legacy_windows_owner.py",
    )
