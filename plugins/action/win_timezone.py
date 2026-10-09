"""Stage native timezone management for the ordinary Python action."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils._module import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Select the machine timezone through normal module execution."""

    # Keep the complete staging closure local instead of sharing unrelated lists.
    # pylint: disable=duplicate-code
    EXTRA_MODULE_UTILS = (
        "legacy_windows_account.py",
        "legacy_windows_group.py",
        "legacy_windows_owner.py",
        "legacy_windows_time.py",
        "legacy_windows_environment.py",
        "legacy_windows_timezone.py",
    )
    # pylint: enable=duplicate-code
