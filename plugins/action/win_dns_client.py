"""Stage the native DNS payload and ordered WMI array helper."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils._module import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Manage native DNS settings through normal module execution."""

    EXTRA_MODULE_UTILS = ("legacy_windows_wmi.py", "legacy_windows_dns_client.py")
