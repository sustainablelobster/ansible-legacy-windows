"""Stage native classic-event-log helpers for win_eventlog."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Execute classic-log management through the Python payload."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_environment.py",
        "legacy_windows_eventlog.py",
    )
