"""Stage the Python payload and classic DSC engine adapter."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# Ansible owns the connection and staging lifecycle used by this action.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Invoke a Windows PowerShell DSC resource."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_dsc_engine.py",
        "legacy_windows_dsc.py",
    )
