"""Stage native membership operations and reuse the Windows reboot action."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ..plugin_utils._reboot import RebootingAction


class ActionModule(RebootingAction):  # pylint: disable=too-many-ancestors
    """Manage domain/workgroup membership through the shared Python runtime."""

    EXTRA_MODULE_UTILS = ("legacy_windows_wmi.py",)
    COLLECTION_MODULE_UTILS = tuple(
        Path(__file__).resolve().parents[1] / "module_utils" / name
        for name in (
            "legacy_ad_arguments.py",
            "legacy_ad_membership.py",
            "legacy_ad_result.py",
        )
    )
