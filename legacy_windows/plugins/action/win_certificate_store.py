"""Stage the native certificate-store manager before Python execution."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Manage certificate files and stores through Python 3.4.4 execution."""

    EXTRA_MODULE_UTILS = ("legacy_windows_certificate_store.py",)
