#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# Copyright: (c) 2018, Ansible Project
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage XML content using native Windows XPath and DOM operations."""

# WANT_JSON

from legacy_community_windows_xml import manage  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_path,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_xml
short_description: Manages XML file content on Windows hosts
description:
  - Manage XML elements, attributes and text selected by XPath.
  - Uses the installed MSXML 6.0 or 3.0 native document engine.
options:
  attribute:
    description: Attribute name; required when type=attribute.
    type: str
  count:
    description: Return the number of nodes matched by xpath.
    type: bool
    default: false
  content:
    description: Return attributes or text of the selected nodes without modifying them.
    type: str
    choices: [attribute, text]
  backup:
    description: Create a timestamped backup before saving changed XML.
    type: bool
    default: false
  fragment:
    description: XML fragment, attribute value or text content to set; not required for absence, counting or reading.
    type: str
    required: false
    aliases: [xmlstring]
  path:
    description: Path of the existing XML file.
    type: path
    required: true
    aliases: [dest, file]
  state:
    description: Whether selected elements or attributes should be present or absent.
    type: str
    default: present
    choices: [present, absent]
  type:
    description: Kind of content to modify.
    type: str
    default: element
    choices: [attribute, element, text]
  xpath:
    description: XPath query selecting the nodes to read or modify.
    type: str
    required: true
  preserve_whitespace:
    description: Preserve insignificant whitespace when loading and saving XML.
    type: bool
    default: false
notes:
  - Supports element, attribute and text operations, not namespace, processing-instruction, comment or document-node mutation.
  - External DTD and entity resolution is disabled. Queries use the installed MSXML XPath engine; a root namespace prefix is registered automatically.
  - Serialization, indentation and comparison diagnostics can differ from upstream's .NET XML engine. Unchanged files retain their exact bytes.
  - Check mode predicts element removals without saving, correcting upstream's unchanged report for that case.
author:
  - sustainablelobster
  - Richard Levenberg (@richardcs)
  - Jon Hawkesworth (@jhawkesworth)
seealso:
  - module: community.general.xml
"""

EXAMPLES = r"""
- name: Read matching attributes
  sustainablelobster.legacy_community_windows.win_xml:
    path: C:\Data\Books.xml
    xpath: /books/works
    content: attribute

- name: Add a nested configuration element
  sustainablelobster.legacy_community_windows.win_xml:
    path: C:\Data\config.xml
    xpath: /config
    fragment: '<setting name="enabled">true</setting>'
"""

RETURN = r"""
backup_file:
  description: Path of the original XML backup.
  returned: when backup=true and XML is saved
  type: str
count:
  description: Number of nodes selected by xpath.
  returned: when count=true
  type: int
matches:
  description: Nodes read with content.
  returned: when content=attribute or content=text
  type: list
msg:
  description: Description of the result.
  returned: when an operation or node lookup produces a message
  type: str
err:
  description: XML comparison diagnostics.
  returned: for element insertion with verbosity greater than two
  type: list
"""

_PARAMETERS = (
    "attribute",
    "count",
    "content",
    "backup",
    "fragment",
    "xmlstring",
    "path",
    "dest",
    "file",
    "state",
    "type",
    "xpath",
    "preserve_whitespace",
)


def _parameters(arguments):
    result = {}
    for name, default in (
        ("attribute", None),
        ("content", None),
        ("xpath", None),
        ("state", "present"),
        ("type", "element"),
    ):
        result[name] = as_string(arguments.get(name, default), name)
    result["path"] = as_path(
        next(
            (arguments[name] for name in ("path", "dest", "file") if name in arguments),
            None,
        ),
        "path",
    )
    result["fragment"] = as_string(
        arguments.get("fragment", arguments.get("xmlstring")), "fragment"
    )
    for name in ("count", "backup", "preserve_whitespace"):
        result[name] = as_bool(arguments.get(name, False), name)
    for name in ("path", "xpath"):
        if not result[name]:
            raise ValueError("Missing required argument: " + name)
    for name, choices in (
        ("state", ("present", "absent")),
        ("type", ("element", "attribute", "text")),
        ("content", (None, "attribute", "text")),
    ):
        if result[name] not in choices:
            raise ValueError("Invalid value for " + name + ": " + str(result[name]))
    if result["type"] == "attribute" and not result["attribute"]:
        raise ValueError("attribute is required with type=attribute")
    result["verbosity"] = int(arguments.get("_ansible_verbosity") or 0)
    return result


def _execute():
    arguments = read_arguments(
        _PARAMETERS,
        "sustainablelobster.legacy_community_windows.win_xml",
        allow_unknown=True,
    )
    return manage(
        _parameters(arguments),
        as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
    )


def main():
    """Read a WANT_JSON request and return its native XML result."""
    run_module(_execute)


if __name__ == "__main__":
    main()
