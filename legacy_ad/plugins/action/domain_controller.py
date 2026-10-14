"""Stage concrete promotion helpers and the released single-retry reboot action."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path

from ..plugin_utils._domain_promotion import DomainPromotionAction


# These three promotion entry points intentionally stage the same explicit closure.
# pylint: disable=duplicate-code
class ActionModule(DomainPromotionAction):  # pylint: disable=too-many-ancestors
    """Manage one native directory role operation and its optional reboot."""

    EXTRA_MODULE_UTILS = ("legacy_windows_wmi.py", "legacy_windows_service.py")
    COLLECTION_MODULE_UTILS = tuple(
        Path(__file__).resolve().parents[1] / "module_utils" / filename
        for filename in (
            "legacy_ad_ldap.py",
            "legacy_ad_result.py",
            "legacy_ad_domain.py",
            "legacy_ad_domain_native.py",
            "legacy_ad_trust_native.py",
        )
    )
