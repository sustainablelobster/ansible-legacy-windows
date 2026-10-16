"""Execute the released win_rds_settings interface with native gateway helpers."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.rds import RdsAction


class ActionModule(RdsAction):  # pylint: disable=too-many-ancestors
    """Use the common gateway closure through the installed Windows runtime."""
