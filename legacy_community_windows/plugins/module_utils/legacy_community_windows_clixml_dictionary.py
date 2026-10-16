# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read and write the CLIXML dictionaries used by repositories and Pester."""

import copy
import math
import os
import re
import tempfile
import xml.etree.ElementTree as xml

_NAMESPACE = "http://schemas.microsoft.com/powershell/2004/04"
_ESCAPE = re.compile(r"_x([0-9a-fA-F]{4})_")


def _tag(name):
    return "{" + _NAMESPACE + "}" + name


def _text(value):
    return _ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), value or "")


def _expand(element, objects, types, active):
    kind = element.tag.rsplit("}", 1)[-1]
    reference = element.get("RefId")
    if kind == "Ref":
        if reference in active:
            raise ValueError("CLIXML dictionary contains a cyclic object reference.")
        if reference not in objects:
            raise ValueError(
                "CLIXML dictionary contains an unresolved object reference."
            )
        expanded = _expand(objects[reference], objects, types, active)
        if "N" in element.attrib:
            expanded.set("N", element.get("N"))
        return expanded
    if kind == "TNRef":
        if reference not in types:
            raise ValueError("CLIXML dictionary contains an unresolved type reference.")
        return _expand(types[reference], objects, types, active)
    expanded = xml.Element(
        element.tag,
        {key: value for key, value in element.attrib.items() if key != "RefId"},
    )
    expanded.text = element.text
    next_active = active | {reference} if kind == "Obj" else active
    for child in element:
        expanded.append(_expand(child, objects, types, next_active))
    return expanded


def read(path):
    """Read standalone dictionary entries with type/object references resolved.

    :param path: Existing CLIXML dictionary file.
    :type path: str
    :returns: Case-insensitive keys mapped to original-name and value XML pairs.
    :rtype: dict
    :raises OSError: The file cannot be read.
    :raises ValueError: The XML is not a supported CLIXML dictionary.
    """
    try:
        root = xml.parse(path).getroot()
    except xml.ParseError as error:
        raise ValueError("Invalid CLIXML dictionary: " + str(error)) from error
    if root.tag != _tag("Objs"):
        raise ValueError("Dictionary source is not PowerShell CLIXML.")
    objects = {item.get("RefId"): item for item in root.iter(_tag("Obj"))}
    types = {item.get("RefId"): item for item in root.iter(_tag("TN"))}
    dictionary = root.find(_tag("Obj") + "/" + _tag("DCT"))
    if dictionary is None:
        raise ValueError("CLIXML dictionary must contain a dictionary.")
    repositories = {}
    for entry in dictionary:
        children = list(entry)
        if entry.tag != _tag("En") or len(children) != 2:
            raise ValueError("CLIXML dictionary contains an invalid dictionary entry.")
        key, value = children
        if key.tag != _tag("S") or key.get("N") != "Key":
            raise ValueError("CLIXML dictionary dictionary keys must be strings.")
        name = _text(key.text)
        repositories[name.lower()] = (
            copy.deepcopy(key),
            _expand(value, objects, types, set()),
        )
    return repositories


def names(repositories):
    """Return original entry names without changing the case-insensitive keys.

    :param repositories: Dictionary entries returned by :func:`read`.
    :type repositories: dict
    :returns: Original names keyed by case-insensitive dictionary key.
    :rtype: dict
    """
    return {key: _text(value[0].text) for key, value in repositories.items()}


# CLIXML's distinct primitive tags are clearer as direct conversions than a
# registry of callback functions or intermediate mutable output state.
def _value(element):  # pylint: disable=too-many-return-statements
    kind = element.tag.rsplit("}", 1)[-1]
    if kind == "Nil":
        return None
    if kind == "B":
        return element.text.lower() == "true"
    if kind in ("I16", "I32", "I64", "U16", "U32", "U64", "By", "SB"):
        return int(element.text)
    if kind in ("Db", "Sg", "D"):
        return float(element.text)
    if kind == "Obj":
        dictionary = element.find(_tag("DCT"))
        if dictionary is not None:
            return {_value(entry[0]): _value(entry[1]) for entry in dictionary}
        for list_kind in ("LST", "IE", "QUE", "STK"):
            sequence = element.find(_tag(list_kind))
            if sequence is not None:
                return [_value(item) for item in sequence]
        properties = {}
        for property_kind in ("Props", "MS"):
            container = element.find(_tag(property_kind))
            if container is not None:
                properties.update(
                    (_text(item.get("N")), _value(item)) for item in container
                )
        if properties:
            return properties
        display = element.find(_tag("ToString"))
        return _text(display.text) if display is not None else {}
    return _text(element.text)


def values(repositories):
    """Return plain dictionary values for comparison, results and Ansible diffs.

    :param repositories: Dictionary entries returned by :func:`read`.
    :type repositories: dict
    :returns: Original entry names and their plain data fields.
    :rtype: dict
    """
    return {_text(key.text): _value(value) for key, value in repositories.values()}


def _encoded_text(value):
    value = _ESCAPE.sub(lambda match: "_x005F_" + match.group(0)[1:], value)
    return "".join(
        (
            "_x{0:04X}_".format(ord(character))
            if ord(character) < 32 or 0xD800 <= ord(character) <= 0xDFFF
            else character
        )
        for character in value
    )


# Input is deliberately restricted to JSON data, not arbitrary CLR objects.
def _data_element(value):  # pylint: disable=too-many-return-statements
    if value is None:
        return xml.Element(_tag("Nil"))
    if isinstance(value, bool):
        element = xml.Element(_tag("B"))
        element.text = "true" if value else "false"
        return element
    if isinstance(value, int):
        if not -(2**63) <= value < 2**63:
            raise ValueError("CLIXML request integers must fit a signed 64-bit value.")
        element = xml.Element(_tag("I64"))
        element.text = str(value)
        return element
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("CLIXML request numbers must be finite.")
        element = xml.Element(_tag("Db"))
        element.text = repr(value)
        return element
    if isinstance(value, str):
        element = xml.Element(_tag("S"))
        element.text = _encoded_text(value)
        return element
    if isinstance(value, list):
        element = xml.Element(_tag("Obj"))
        sequence = xml.SubElement(element, _tag("LST"))
        sequence.extend(_data_element(item) for item in value)
        return element
    if isinstance(value, dict):
        element = xml.Element(_tag("Obj"))
        dictionary = xml.SubElement(element, _tag("DCT"))
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("CLIXML request dictionary keys must be strings.")
            entry = xml.SubElement(dictionary, _tag("En"))
            key_element, value_element = _data_element(key), _data_element(item)
            key_element.set("N", "Key")
            value_element.set("N", "Value")
            entry.extend((key_element, value_element))
        return element
    raise ValueError("CLIXML request values must be plain JSON data.")


def from_values(dictionary):
    """Build CLIXML entries from a JSON-data dictionary for a fixed Pester request.

    :param dictionary: JSON-compatible request with string keys.
    :type dictionary: dict
    :returns: Case-insensitive keys and independent XML key/value entry pairs.
    :rtype: dict
    :raises ValueError: A value cannot be represented as plain CLIXML data.
    """
    entries = {}
    for key, value in dictionary.items():
        if not isinstance(key, str):
            raise ValueError("CLIXML request dictionary keys must be strings.")
        key_element, value_element = _data_element(key), _data_element(value)
        key_element.set("N", "Key")
        value_element.set("N", "Value")
        entries[key.lower()] = key_element, value_element
    return entries


def write(path, repositories):
    """Write independent dictionary entries with unique CLIXML reference IDs.

    :param path: Destination dictionary file in an existing parent directory.
    :type path: str
    :param repositories: Dictionary entries returned by :func:`read`.
    :type repositories: dict
    :raises OSError: The dictionary file cannot be written.
    """
    root = xml.Element(_tag("Objs"), {"Version": "1.1.0.1"})
    owner = xml.SubElement(root, _tag("Obj"))
    type_names = xml.SubElement(owner, _tag("TN"))
    for name in ("System.Collections.Hashtable", "System.Object"):
        xml.SubElement(type_names, _tag("T")).text = name
    dictionary = xml.SubElement(owner, _tag("DCT"))
    for key, value in repositories.values():
        entry = xml.SubElement(dictionary, _tag("En"))
        entry.extend((copy.deepcopy(key), copy.deepcopy(value)))
    for index, item in enumerate(root.iter(_tag("Obj"))):
        item.set("RefId", str(index))
    for index, item in enumerate(root.iter(_tag("TN"))):
        item.set("RefId", str(index))
    descriptor, temporary = tempfile.mkstemp(
        prefix=".clixml-", dir=os.path.dirname(path)
    )
    try:
        with os.fdopen(descriptor, "wb") as destination:
            xml.ElementTree(root).write(
                destination, encoding="utf-8", xml_declaration=True
            )
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
