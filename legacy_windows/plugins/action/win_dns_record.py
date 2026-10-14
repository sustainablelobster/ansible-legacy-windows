"""Stage native DNS record management for normal Ansible execution."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# The normal Ansible action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Deliver the DNS payload and its native WMI helper closure."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_wmi.py",
        "legacy_windows_dns_classic.py",
        "legacy_windows_dns_record.py",
    )
