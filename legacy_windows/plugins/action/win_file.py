"""Stage the native filesystem and timestamp helpers before executing win_file."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Manage Windows files with native Python JSON execution."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_file.py",
        "legacy_windows_time.py",
        "legacy_windows_calendar.py",
        "legacy_windows_datetime.py",
    )
