"""Stage native security helpers for the Windows access-rule payload."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Run win_acl with its complete target-side dependency closure."""

    # Keep the complete staging closure local instead of sharing unrelated lists.
    # pylint: disable=duplicate-code
    EXTRA_MODULE_UTILS = (
        "legacy_windows_account.py",
        "legacy_windows_group.py",
        "legacy_windows_owner.py",
        "legacy_windows_link.py",
        "legacy_windows_acl_inheritance.py",
        "legacy_windows_acl.py",
        "legacy_windows_certificate_acl.py",
    )
    # pylint: enable=duplicate-code
