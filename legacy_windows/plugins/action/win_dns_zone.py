"""Stage the DNS zone payload and its native Windows helpers."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# The normal Ansible action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Manage zones through normal native Python module execution."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_wmi.py",
        "legacy_windows_dns_classic.py",
        "legacy_windows_dns_zone.py",
    )
