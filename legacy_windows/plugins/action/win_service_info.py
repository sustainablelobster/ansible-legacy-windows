"""Stage the native helpers before executing win_service_info."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Read Windows services using native Python JSON execution."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_account.py",
        "legacy_windows_regex.py",
        "legacy_windows_find_match.py",
        "legacy_windows_service_config.py",
        "legacy_windows_service_info.py",
    )
