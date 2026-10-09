"""Stage the native mapped-drive payload and its target-only dependencies."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils._module import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Manage persistent user mappings through the ordinary Python action."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_account.py",
        "legacy_windows_environment.py",
        "legacy_windows_mapped_drive.py",
    )
