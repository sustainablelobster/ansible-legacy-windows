"""Stage native Server Manager metadata and its Python 3.4-compatible helpers."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils._module import PythonModuleAction


class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Read server feature metadata through the native deployment provider."""

    # Keep the complete staging closure local instead of sharing unrelated lists.
    # pylint: disable=duplicate-code
    EXTRA_MODULE_UTILS = (
        "legacy_windows_regex.py",
        "legacy_windows_find_match.py",
        "legacy_windows_wmi.py",
        "legacy_windows_feature_legacy.py",
        "legacy_windows_feature_info.py",
    )
    # pylint: enable=duplicate-code
