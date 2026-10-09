"""Stage native endpoint, process, and date readers before normal execution."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils._module import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Collect Windows endpoint facts through Python 3.4.4 JSON execution."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_wmi.py",
        "legacy_windows_process_info.py",
        "legacy_windows_ports.py",
        "legacy_windows_calendar.py",
        "legacy_windows_time.py",
        "legacy_windows_uformat.py",
    )
