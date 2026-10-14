"""Stage the native credential store and Windows comparison helpers."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# The standard Ansible action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Manage credentials through ordinary Python module execution."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_credential.py",
        "legacy_windows_environment.py",
    )
