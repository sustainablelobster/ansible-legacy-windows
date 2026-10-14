"""Stage the native search helpers before executing win_find."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Search Windows directories using native Python JSON execution."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_stat.py",
        "legacy_windows_link.py",
        "legacy_windows_time.py",
        "legacy_windows_find_match.py",
        "legacy_windows_regex.py",
        "legacy_windows_regex_categories.py",
    )
