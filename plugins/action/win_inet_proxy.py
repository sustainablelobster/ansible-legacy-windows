"""Stage native WinINet proxy operations for the ordinary Python action."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils._module import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Configure WinINet connection settings through normal module execution."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_environment.py",
        "legacy_windows_inet_proxy.py",
    )
