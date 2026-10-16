"""Execute native IIS site management through the shared runtime."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

from ..plugin_utils.iis import IisAction


class ActionModule(IisAction):  # pylint: disable=too-many-ancestors
    """Run the win_iis_website target with its native IIS helper closure."""
