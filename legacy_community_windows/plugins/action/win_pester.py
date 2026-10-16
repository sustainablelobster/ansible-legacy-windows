"""Stage Pester's bounded CLIXML dictionary request/result helper."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


# Ansible's normal action has an established deep extension hierarchy.
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Run installed Pester through native Python and its installed engine."""

    # Each action names its staged helper directly rather than hiding it in a registry.
    # pylint: disable=duplicate-code
    COLLECTION_MODULE_UTILS = (
        Path(__file__).resolve().parents[1]
        / "module_utils"
        / "legacy_community_windows_clixml_dictionary.py",
    )
    # pylint: enable=duplicate-code
