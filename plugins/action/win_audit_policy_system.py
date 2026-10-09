"""Stage native system audit-policy operations for normal Python execution."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils._module import PythonModuleAction


# Ansible's standard action supplies the existing extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Manage advanced system audit policy through the native Windows utility."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_environment.py",
        "legacy_windows_process.py",
        "legacy_windows_text.py",
        "legacy_windows_audit_policy.py",
    )
