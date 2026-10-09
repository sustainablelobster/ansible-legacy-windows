"""Stage the native ACL helper for win_acl_inheritance."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils._module import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Run the Python ACL inheritance payload with native Windows helpers."""

    EXTRA_MODULE_UTILS = ("legacy_windows_acl_inheritance.py",)
