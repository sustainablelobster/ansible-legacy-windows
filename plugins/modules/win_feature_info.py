#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Return Server Manager feature metadata with a native Python 3.4.4 payload."""

# WANT_JSON

import legacy_windows_feature_info as feature_info  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_string,
    read_arguments,
    run_module,
)

# Ansible interfaces must be self-contained; repeated option/return text is
# interface documentation, not duplicated execution logic.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_feature_info
short_description: Read Windows Server feature information
version_added: '1.0.0'
description:
  - Returns Windows Server roles, role services, and features.
  - Uses the installed native Server Manager provider through Python 3.4.4.
  - Does not install or remove features.
options:
  name:
    description:
      - One feature identifier or case-insensitive Windows wildcard pattern.
      - C(*) and C(?) are wildcards; brackets and backticks are literal.
      - The default returns every available feature, preserving display-tree order.
      - A selector with no matches returns an empty list and C(exists=false).
    type: str
    default: '*'
attributes:
  check_mode:
    support: full
    description: Returns the same metadata without configuration changes.
  diff_mode:
    support: none
requirements:
  - Windows Server with the native Server Manager deployment provider or the installed ServerManagerCmd tool.
notes:
  - Availability depends on the installed provider, not the Windows build number.
  - The older ServerManagerCmd catalogue returns real names, installed states, types and hierarchy, plus numeric IDs available from installed Win32_ServerFeature metadata. Description, dependency, descriptor, service, BPA, event, post-configuration and other additional metadata are null, with a warning.
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Read all server feature information
  sustainablelobster.legacy_windows.win_feature_info:

- name: Read features related to Active Directory certificate services
  sustainablelobster.legacy_windows.win_feature_info:
    name: ADCS-*
"""

RETURN = r"""
exists:
  description: Whether any features match the selector.
  returned: success
  type: bool
features:
  description: Matching features in Server Manager display-tree order.
  returned: success
  type: list
  elements: dict
  contains:
    name:
      description: Feature identifier.
      type: str
    display_name:
      description: Localized display name.
      type: str
    description:
      description: Feature description.
      type: str
    installed:
      description: Whether the feature is installed.
      type: bool
    install_state:
      description: Installation state reported by Server Manager.
      type: str
    feature_type:
      description: Role, Role Service, or Feature.
      type: str
    path:
      description: Display names joined by backslashes from the root to this feature.
      type: str
    depth:
      description: Depth in the display hierarchy; root features have depth one.
      type: int
    depends_on:
      description: Non-ancestor dependencies, preserving provider order.
      type: list
      elements: str
    parent:
      description: Parent feature identifier, or null for a root feature.
      type: str
    server_component_descriptor:
      description: Native descriptor with CIM class, property, qualifier, and system metadata.
      type: dict
    sub_features:
      description: Direct child identifiers, preserving display-tree order.
      type: list
      elements: str
    system_service:
      description: Monitored Windows service names, preserving provider order.
      type: list
      elements: str
    best_practices_model_id:
      description: Best Practices Analyzer model identifier.
      type: str
    event_query:
      description: Associated event query filename, or an empty string.
      type: str
    post_configuration_needed:
      description: Whether an installed feature needs post-installation configuration.
      type: bool
    additional_info:
      description: InstallName, MajorVersion, MinorVersion, and NumericId metadata.
      type: dict
"""
# pylint: enable=duplicate-code


def execute():
    """Bind the public selector and return read-only feature metadata.

    :returns: Unchanged result containing exists and the complete feature list.
    :rtype: dict
    :raises ValueError: The selector cannot be bound or matched.
    :raises OSError: The Server Manager provider cannot return metadata.
    """
    arguments = read_arguments(
        ("name",), "sustainablelobster.legacy_windows.win_feature_info"
    )
    name = as_string(arguments.get("name", "*"), "name")
    if name in (None, ""):
        return {
            "changed": False,
            "failed": True,
            "msg": "Unhandled exception while executing module: Cannot validate "
            "argument on parameter 'Name'. The argument is null or empty. "
            "Provide an argument that is not null or empty, and then try the command again.",
        }
    try:
        features = feature_info.features(name)
    except OSError as error:
        if getattr(error, "hresult", None) != 0x8004100E:
            raise
        return {
            "changed": False,
            "failed": True,
            "msg": "Windows Server Manager deployment provider is unavailable.",
        }
    result = {"changed": False, "exists": bool(features), "features": features}
    if any(
        "server_component_descriptor" in feature
        and feature["server_component_descriptor"] is None
        for feature in features
    ):
        result["warnings"] = [
            "The older ServerManagerCmd catalogue does not expose description, "
            "dependency, descriptor, service, BPA, event, post-configuration or "
            "additional metadata other than available installed numeric IDs; "
            "unavailable fields are null."
        ]
    return result


def main():
    """Run the staged Ansible JSON payload.

    :raises SystemExit: With zero for success or one for failure.
    """
    run_module(execute)


if __name__ == "__main__":
    main()
