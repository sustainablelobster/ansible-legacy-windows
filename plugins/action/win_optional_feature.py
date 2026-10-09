"""Stage shipped-native optional-feature management for win_optional_feature."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils._module import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Execute online feature management through the Python payload."""

    EXTRA_MODULE_UTILS = ("legacy_windows_optional_feature.py",)
