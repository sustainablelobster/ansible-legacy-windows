"""Stage native DISM management and its accepted capability metadata ABI."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Manage capabilities through the Python 3.4.4 payload."""

    # Keep the complete staging closure local instead of sharing unrelated lists.
    # pylint: disable=duplicate-code
    EXTRA_MODULE_UTILS = (
        "legacy_windows_regex.py",
        "legacy_windows_find_match.py",
        "legacy_windows_capability.py",
        "legacy_windows_capability_manage.py",
    )
    # pylint: enable=duplicate-code
