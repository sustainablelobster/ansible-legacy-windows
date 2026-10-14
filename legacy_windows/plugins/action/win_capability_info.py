"""Stage native DISM and wildcard helpers for capability information."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Read Windows capabilities through the native Python payload."""

    # Keep the complete staging closure local instead of sharing unrelated lists.
    # pylint: disable=duplicate-code
    EXTRA_MODULE_UTILS = (
        "legacy_windows_regex.py",
        "legacy_windows_find_match.py",
        "legacy_windows_capability.py",
    )
    # pylint: enable=duplicate-code
