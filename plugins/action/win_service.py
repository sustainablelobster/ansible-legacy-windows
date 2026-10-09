"""Stage the native service manager and account comparison helpers."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils._module import PythonModuleAction


# Ansible's ordinary action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Manage Windows services through the ordinary Python payload path."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_service.py",
        "legacy_windows_environment.py",
        "legacy_windows_account.py",
    )
