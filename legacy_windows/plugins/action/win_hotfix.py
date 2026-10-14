"""Stage the native hotfix payload and its Python 3.4-compatible dependencies."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Manage hotfix packages through native DISM and shipped expand.exe."""

    # Keep the complete staging closure local instead of sharing unrelated lists.
    # pylint: disable=duplicate-code
    EXTRA_MODULE_UTILS = (
        "legacy_windows_regex.py",
        "legacy_windows_find_match.py",
        "legacy_windows_wmi.py",
        "legacy_windows_hotfix_command.py",
        "legacy_windows_hotfix.py",
    )
    # pylint: enable=duplicate-code
