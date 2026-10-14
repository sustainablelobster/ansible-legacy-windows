"""Stage native hostname operations for the ordinary Python action."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Request a local computer rename through normal module execution."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_wmi.py",
        "legacy_windows_environment.py",
        "legacy_windows_hostname.py",
    )
