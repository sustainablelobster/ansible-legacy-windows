"""Verify XML module operations with an isolated DOM boundary, not Windows."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Private binders/native boundary substitution exercise the public request path.
# pylint: disable=protected-access

import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from xml.dom import minidom

import pytest

from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module


# These private DOM doubles mirror native proxy methods; their assertions are
# the boundary contract, without production API documentation on test methods.
# pylint: disable=missing-function-docstring,missing-return-doc,too-many-return-statements
class _Collection:
    def __init__(self, nodes: list[Any]) -> None:
        self.nodes = nodes

    def items(self) -> list["_Node"]:
        return [_Node(node) for node in self.nodes]

    def call(self, name: str, value: str) -> object:
        assert name == "getNamedItem"
        return next(
            (_Node(node) for node in self.nodes if node.nodeName == value), None
        )


class _Node:
    def __init__(self, node: Any) -> None:
        self.node = node

    def get(self, name: str) -> Any:
        node = self.node
        if name == "text":
            if node.nodeType in (2, 3):
                return node.nodeValue
            return "".join(
                _Node(child).get("text")
                for child in node.childNodes
                if child.nodeType != 8
            )
        if name == "xml":
            return node.toxml()
        if name == "childNodes":
            return _Collection(list(node.childNodes))
        if name == "attributes":
            return (
                _Collection(list(node.attributes.values()))
                if node.attributes
                else _Collection([])
            )
        value = getattr(node, name)
        return _Node(value) if name in ("documentElement", "parentNode") else value

    def put(self, name: str, value: Any) -> None:
        node = self.node
        if name == "text":
            if node.nodeType in (2, 3):
                node.nodeValue = value
            else:
                for child in list(node.childNodes):
                    node.removeChild(child)
                node.appendChild(node.ownerDocument.createTextNode(value))
        elif name == "nodeValue":
            node.nodeValue = value
        else:
            setattr(node, name, value)

    def call(self, name: str, *values: Any) -> Any:
        node = self.node
        if name == "setProperty":
            return None
        if name in ("load", "loadXML"):
            parsed = (
                minidom.parse(str(values[0]))
                if name == "load"
                else minidom.parseString(str(values[0]))
            )
            self.node = parsed
            return True
        if name == "selectNodes":
            xpath = values[0]
            if xpath == "/root":
                return _Collection([node.documentElement])
            if xpath == "//@name":
                return _Collection(
                    [
                        element.getAttributeNode("name")
                        for element in node.getElementsByTagName("item")
                        if element.hasAttribute("name")
                    ]
                )
            return _Collection(
                list(node.getElementsByTagName(str(xpath).removeprefix("//")))
            )
        if name == "selectSingleNode":
            assert values == ("..",)
            return _Node(node.ownerElement)
        if name == "createNode":
            return _Node(node.createElementNS(values[2] or None, values[1]))
        if name in ("appendChild", "removeChild"):
            return _Node(getattr(node, name)(values[0].node))
        if name == "save":
            Path(str(values[0])).write_bytes(node.toxml(encoding="utf-8"))
            return None
        return getattr(node, name)(*values)


class _Document:
    def __init__(self) -> None:
        self.document = _Node(minidom.Document())

    def __enter__(self) -> "_Document":
        return self

    def __exit__(self, *_arguments: object) -> None:
        return None


# pylint: enable=missing-function-docstring,missing-return-doc,too-many-return-statements


@pytest.fixture(name="payload")
def xml_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the frontend while substituting only the native DOM boundary.

    :param monkeypatch: Scoped imports and document substitution.
    :returns: Loaded XML frontend.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(
        str(ROOT / "legacy_community_windows/plugins/module_utils")
    )
    payload = load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_xml.py",
        "tested_community_xml",
    )
    monkeypatch.setattr(
        sys.modules["legacy_community_windows_xml"], "XmlDocument", _Document
    )
    return payload


def _apply(payload: ModuleType, path: Path, **options: object) -> dict[str, Any]:
    check_mode = options.pop("check", False)
    result: dict[str, Any] = payload.manage(
        payload._parameters({"path": str(path), "xpath": "//item", **options}),
        check_mode,
    )
    return result


@pytest.fixture(name="document")
def xml_file(tmp_path: Path) -> Path:
    """Provide existing XML with multiple selected elements.

    :param tmp_path: Isolated fixture directory.
    :returns: Path to the fixture XML.
    """
    path = tmp_path / "document.xml"
    path.write_text(
        '<root><item name="first">old</item><item name="second"/><empty/></root>',
        encoding="utf-8",
    )
    return path


def test_count_and_content_read_without_changes(
    payload: ModuleType, document: Path
) -> None:
    original = document.read_bytes()
    assert _apply(payload, document, count=True) == {"changed": False, "count": 2}
    assert _apply(payload, document, count=True, content="attribute") == {
        "changed": False,
        "count": 2,
        "msg": "not changed",
        "matches": [{"item": {"name": "first"}}, {"item": {"name": "second"}}],
    }
    assert _apply(payload, document, content="text")["matches"] == [
        {"item": "old"},
        {"item": None},
    ]
    assert document.read_bytes() == original


def test_no_match_never_parses_fragment_or_writes(
    payload: ModuleType, document: Path
) -> None:
    result = _apply(payload, document, xpath="//missing", fragment="<invalid")
    assert result["changed"] is False
    assert "did not match any nodes" in result["msg"]


@pytest.mark.parametrize("kind", ["text", "attribute"])
def test_multi_node_changes_are_idempotent_and_backed_up(
    payload: ModuleType, document: Path, kind: str
) -> None:
    original = document.read_bytes()
    options = {"type": kind, "fragment": "Café 雪", "backup": True}
    if kind == "attribute":
        options["attribute"] = "enabled"
    result = _apply(payload, document, **options)
    assert result["changed"] is True
    assert result["msg"] == kind + " changed"
    assert Path(result["backup_file"]).read_bytes() == original
    assert _apply(payload, document, **options)["changed"] is False


def test_attribute_nodes_can_be_updated_and_removed(
    payload: ModuleType, document: Path
) -> None:
    options = {
        "xpath": "//@name",
        "type": "attribute",
        "attribute": "name",
        "fragment": "shared",
    }
    assert _apply(payload, document, **options)["changed"] is True
    assert _apply(payload, document, **options)["changed"] is False
    options["state"] = "absent"
    assert _apply(payload, document, **options)["changed"] is True
    assert _apply(payload, document, **options)["changed"] is False


def test_element_insertion_and_removal(payload: ModuleType, document: Path) -> None:
    options = {"xpath": "/root", "fragment": '<child enabled="true">text</child>'}
    assert _apply(payload, document, **options)["changed"] is True
    assert _apply(payload, document, **options)["changed"] is False
    result = _apply(payload, document, xpath="//child", state="absent")
    assert result["changed"] is True
    assert result["msg"] == "element removed"
    assert (
        _apply(payload, document, xpath="//child", state="absent")["changed"] is False
    )


def test_element_can_be_added_under_empty_parent(
    payload: ModuleType, document: Path
) -> None:
    assert (
        _apply(payload, document, xpath="//empty", fragment="<child/>")["changed"]
        is True
    )
    assert (
        _apply(payload, document, xpath="//empty", fragment="<child/>")["changed"]
        is False
    )


@pytest.mark.parametrize(
    "options",
    [
        {"state": "absent"},
        {"type": "text", "fragment": "new"},
        {"type": "attribute", "attribute": "name", "fragment": "new"},
        {"xpath": "/root", "fragment": "<child/>"},
    ],
)
def test_check_mode_predicts_changes_without_saving_or_backup(
    payload: ModuleType, document: Path, options: dict[str, Any]
) -> None:
    original = document.read_bytes()
    result = _apply(payload, document, check=True, backup=True, **options)
    assert result["changed"] is True
    assert result["msg"].endswith(" check mode")
    assert document.read_bytes() == original
    assert not list(document.parent.glob("*.bak"))


@pytest.mark.parametrize(
    "case",
    [
        ({}, "path"),
        ({"path": "file"}, "xpath"),
        ({"path": "file", "xpath": "/", "type": "attribute"}, "attribute is required"),
        ({"path": "file", "xpath": "/", "type": "invalid"}, "Invalid value for type"),
        (
            {"path": "file", "xpath": "/", "content": "invalid"},
            "Invalid value for content",
        ),
        ({"path": "file", "xpath": "/", "state": "invalid"}, "Invalid value for state"),
    ],
)
def test_invalid_request_returns_actionable_json(
    payload: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    case: tuple[dict[str, Any], str],
) -> None:
    arguments, message = case
    path = tmp_path / "arguments.json"
    path.write_text(json.dumps(arguments), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["win_xml.py", str(path)])
    code, result = invoke_payload(payload, capsys)
    assert code == 1
    assert result["failed"] is True
    assert message in result["msg"]


def test_missing_file_rejected_before_native_dom(
    payload: ModuleType, tmp_path: Path
) -> None:
    with pytest.raises(ValueError, match="does not exist"):
        _apply(payload, tmp_path / "missing.xml", count=True)


@pytest.mark.parametrize("alias", ["path", "dest", "file"])
def test_path_and_fragment_aliases(payload: ModuleType, alias: str) -> None:
    result = payload._parameters(
        {alias: "C:/file.xml", "xpath": "/root", "xmlstring": "<child/>"}
    )
    assert result["path"] == "C:/file.xml"
    assert result["fragment"] == "<child/>"
