"""Stage native regional settings for ordinary Python module execution."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.runtime import PythonModuleAction


# The standard Ansible action provides the existing extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Set Windows regional settings through the native Windows interfaces."""

    EXTRA_MODULE_UTILS = (
        "legacy_windows_environment.py",
        "legacy_windows_region.py",
    )
