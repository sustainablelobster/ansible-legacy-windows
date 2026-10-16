"""Stage native process execution for win_dotnet_ngen."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

# The shared runtime supplies Ansible's controller action interface.
from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


# Ansible's normal action has an established deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Run the Python payload with its explicit native process helper closure."""

    EXTRA_MODULE_UTILS = ("legacy_windows_process.py", "legacy_windows_text.py")
