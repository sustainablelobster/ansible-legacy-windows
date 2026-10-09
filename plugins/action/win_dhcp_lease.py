"""Stage the DHCP Server payload and its Python 3.4.4 native helpers."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils._module import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Manage DHCP Server records through normal Ansible module execution."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_wmi.py",
        "legacy_windows_time.py",
        "legacy_windows_environment.py",
        "legacy_windows_dhcp_api.py",
        "legacy_windows_dhcp_lease.py",
    )
