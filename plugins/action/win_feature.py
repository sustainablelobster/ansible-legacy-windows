"""Stage native Windows Server feature management and its target helpers."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils._module import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Run the Python payload through the native Server Manager provider."""

    # Keep the complete staging closure local instead of sharing unrelated lists.
    # pylint: disable=duplicate-code
    EXTRA_MODULE_UTILS = (
        "legacy_windows_regex.py",
        "legacy_windows_find_match.py",
        "legacy_windows_wmi.py",
        "legacy_windows_feature_legacy.py",
        "legacy_windows_feature_info.py",
        "legacy_windows_feature_manage.py",
    )
    # pylint: enable=duplicate-code
