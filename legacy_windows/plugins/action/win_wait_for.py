"""Stage native polling helpers before executing win_wait_for."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Wait for files, expressions, and TCP conditions on Windows."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_wait.py",
        "legacy_windows_regex.py",
        "legacy_windows_regex_categories.py",
        "legacy_windows_text.py",
    )
