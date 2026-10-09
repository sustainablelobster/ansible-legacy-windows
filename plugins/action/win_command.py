"""Accept command free-form arguments and stage the native JSON helper."""

# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils._module import PythonModuleAction


# Ansible's normal action already has a deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Preserve command text for execution without an implicit shell."""

    supports_raw_params = True
    EXTRA_MODULE_UTILS = ("legacy_windows_process.py", "legacy_windows_text.py")
