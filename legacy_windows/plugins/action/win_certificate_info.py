"""Stage the native certificate reader before normal Python execution."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Read Windows certificate stores through Python 3.4.4 JSON execution."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_calendar.py",
        "legacy_windows_certificate.py",
    )
