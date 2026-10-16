"""Stage native speech, text decoding and their Python 3.4-compatible imports."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Execute the native speech payload through the shared Windows runtime."""

    EXTRA_MODULE_UTILS = ("legacy_windows_wmi.py", "legacy_windows_text.py")
    COLLECTION_MODULE_UTILS = (
        Path(__file__).resolve().parents[1]
        / "module_utils"
        / "legacy_community_windows_speech.py",
    )
