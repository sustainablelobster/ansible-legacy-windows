"""Stage path-variable helpers before executing the native win_path payload."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Manage Windows path variables through normal Ansible execution."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_environment.py",
        "legacy_windows_reg_stat.py",
        "legacy_windows_path.py",
    )
