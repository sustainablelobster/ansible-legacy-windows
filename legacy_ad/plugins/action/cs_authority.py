"""Stage Certificate Services authority helpers for shared Windows execution."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)


# Each action keeps its complete target helper closure explicit and auditable.
# pylint: disable=duplicate-code
class ActionModule(PythonModuleAction):  # pylint: disable=too-many-ancestors
    """Run native Certificate Services authority management."""

    EXTRA_MODULE_UTILS = ("legacy_windows_service.py",)
    COLLECTION_MODULE_UTILS = tuple(
        Path(__file__).resolve().parents[1] / "module_utils" / filename
        for filename in (
            "legacy_ad_result.py",
            "legacy_ad_cs_authority.py",
        )
    )


# pylint: enable=duplicate-code
