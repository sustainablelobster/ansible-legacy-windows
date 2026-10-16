# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Apply upstream XML operations using owned native MSXML nodes."""

import datetime
import os
import shutil
from xml.sax.saxutils import quoteattr

# The collection action stages this Python 3.4-compatible native DOM helper.
# Pylint cannot resolve imports that are staged only on the Windows target.
# pylint: disable=import-error
from legacy_community_windows_xml_native import XmlDocument

# pylint: enable=import-error


def _load(owner, source, preserve_whitespace, fragment=False):
    document = owner.document
    document.put("preserveWhiteSpace", preserve_whitespace)
    loaded = document.call("loadXML" if fragment else "load", source)
    if not loaded:
        error = document.get("parseError")
        raise ValueError(
            "Failed to parse {0} as XML: {1}".format(
                "fragment" if fragment else "file at '{0}'".format(source),
                error.get("reason"),
            )
        )
    root = document.get("documentElement")
    prefix = root.get("prefix")
    namespace = root.get("namespaceURI")
    if prefix and namespace:
        document.call(
            "setProperty",
            "SelectionNamespaces",
            "xmlns:{0}={1}".format(prefix, quoteattr(namespace)),
        )
    return document


def _equal(actual, expected):
    if actual.get("nodeName") != expected.get("nodeName"):
        return False
    if actual.get("nodeType") != expected.get("nodeType"):
        return False
    if actual.get("nodeType") == 1:
        actual_attributes = actual.get("attributes").items()
        expected_attributes = expected.get("attributes").items()
        if [
            (node.get("nodeName"), node.get("nodeValue")) for node in actual_attributes
        ] != [
            (node.get("nodeName"), node.get("nodeValue"))
            for node in expected_attributes
        ]:
            return False
    actual_children = actual.get("childNodes").items()
    expected_children = expected.get("childNodes").items()
    return (
        len(actual_children) == len(expected_children)
        and all(
            _equal(left, right)
            for left, right in zip(actual_children, expected_children)
        )
        and actual.get("text") == expected.get("text")
    )


def _copy_fragment(document, source, namespace):
    result = document.call("createNode", 1, source.get("nodeName"), namespace or "")
    for attribute in source.get("attributes").items():
        result.call(
            "setAttribute", attribute.get("nodeName"), attribute.get("nodeValue")
        )
    for child in source.get("childNodes").items():
        if child.get("nodeType") == 1:
            result.call("appendChild", _copy_fragment(document, child, namespace))
        elif child.get("nodeType") == 3:
            # The upstream fragment copier sets InnerText rather than preserving
            # arbitrary mixed content, comments, CDATA or processing instructions.
            result.put("text", child.get("text"))
    return result


def _attributes(node, options):
    name = options["attribute"]
    fragment = options["fragment"] or ""
    if node.get("nodeType") == 2:
        if options["state"] == "absent":
            parent = node.call("selectSingleNode", "..")
            parent.call("removeAttribute", name)
            return True
        if node.get("nodeName") == name and node.get("nodeValue") != fragment:
            node.put("nodeValue", fragment)
            return True
        return False
    if node.get("nodeType") != 1:
        raise ValueError("Attribute operations require element or attribute nodes.")
    attribute = node.get("attributes").call("getNamedItem", name)
    if options["state"] == "absent":
        if attribute is not None:
            node.call("removeAttribute", name)
            return True
    elif attribute is None or attribute.get("nodeValue") != fragment:
        node.call("setAttribute", name, fragment)
        return True
    return False


def _insert_elements(document, nodes, options, result):
    changed = False
    with XmlDocument() as owner:
        fragment_document = _load(
            owner, options["fragment"] or "", False, fragment=True
        )
        fragment = fragment_document.get("documentElement")
        namespace = document.get("documentElement").get("namespaceURI")
        for node in nodes:
            if node.get("nodeType") == 9:
                node = node.get("documentElement")
            if node.get("nodeType") != 1:
                raise ValueError(
                    "Element insertion requires an element or document node."
                )
            candidate = _copy_fragment(document, fragment, namespace)
            children = node.get("childNodes").items() or [node]
            if not any(_equal(child, candidate) for child in children):
                node.call("appendChild", candidate)
                changed = True
            if options["verbosity"] > 2:
                result["err"] = (
                    []
                    if any(_equal(child, candidate) for child in children)
                    else [
                        "The existing child nodes differ from the requested XML fragment."
                    ]
                )
    return changed


def _edit(document, nodes, options, result):
    if options["type"] == "element" and options["state"] == "present":
        return _insert_elements(document, nodes, options, result)
    changed = False
    removed = []
    for node in nodes:
        kind = node.get("nodeType")
        if options["type"] == "attribute":
            changed = _attributes(node, options) or changed
        elif options["type"] == "text":
            if kind not in (1, 2, 3):
                raise ValueError(
                    "Text operations require element, attribute, or text nodes."
                )
            if node.get("text") != (options["fragment"] or ""):
                node.put("text", options["fragment"] or "")
                changed = True
        else:
            if kind not in (1, 3):
                raise ValueError(
                    "Element removal supports element and text nodes only."
                )
            if options["verbosity"] > 2:
                removed.append(node.get("xml"))
            parent = node.get("parentNode")
            parent.call("removeChild", node)
            changed = True
    if removed:
        result["removed"] = ", ".join(removed)
    return changed


def manage(options, check_mode=False):
    """Query or change XML content selected by the supplied native XPath.

    :param dict options: Normalized module arguments including verbosity.
    :param bool check_mode: Predict edits without saving or creating backups.
    :returns: Change, query content, count, and backup information.
    :rtype: dict
    :raises OSError: Native document loading, XPath, editing, or saving fails.
    :raises ValueError: The path, fragment, or selected node kind is invalid.
    """
    path = options["path"]
    if not os.path.isfile(path):
        raise ValueError(
            "Specified path {0} does not exist or is not a file.".format(path)
        )
    result = {"changed": False}
    with XmlDocument() as owner:
        document = _load(owner, path, options["preserve_whitespace"])
        nodes = document.call("selectNodes", options["xpath"]).items()
        if options["count"]:
            result["count"] = len(nodes)
            if not options["fragment"] and not options["content"]:
                return result
        if not nodes:
            result["msg"] = (
                "The supplied xpath did not match any nodes.  If this is unexpected, "
                "check your xpath is valid for the xml file at supplied path."
            )
            return result
        result["msg"] = "not changed"
        if options["content"]:
            matches = []
            for node in nodes:
                value = node.get("text") or None
                if options["content"] == "attribute":
                    attributes = node.get("attributes")
                    value = (
                        {}
                        if attributes is None
                        else {
                            attribute.get("nodeName"): attribute.get("nodeValue")
                            for attribute in attributes.items()
                        }
                    )
                matches.append({node.get("nodeName"): value})
            result["matches"] = matches
            return result
        result["changed"] = _edit(document, nodes, options, result)
        if result["changed"]:
            if check_mode:
                result["msg"] += " check mode"
            else:
                if options["backup"]:
                    backup = "{0}.{1}.{2}.bak".format(
                        path,
                        os.getpid(),
                        datetime.datetime.now().strftime("%Y%m%d-%H%M%S"),
                    )
                    shutil.copyfile(path, backup)
                    result["backup_file"] = backup
                document.call("save", path)
                result["msg"] = "{0} {1}".format(
                    options["type"],
                    "removed" if options["state"] == "absent" else "changed",
                )
    return result
