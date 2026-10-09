"""Exercise Server Manager selection and ownership at native ABI boundaries."""

# SPDX-License-Identifier: GPL-3.0-or-later
# ABI substitutes are controller-only evidence, not Windows execution.
# pylint: disable=protected-access

import ctypes
from contextlib import ExitStack
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="helper")
def native_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load native servicing without opening Windows libraries.

    :param monkeypatch: Scoped standalone helper import directory.
    :returns: Fresh native management helper.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    return load_module(
        ROOT / "plugins/module_utils/legacy_windows_feature_manage.py",
        "feature_manage_tested",
    )


# Explicit provider fields keep each selection graph readable at its call site.
# pylint: disable-next=too-many-arguments
def _component(
    name: str,
    identifier: int,
    *,
    parent: str = "",
    dependencies: tuple[str, ...] = (),
    default: bool = False,
    installed: int = 0,
    companions: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "UniqueName": name,
        "DisplayName": name,
        "NumericId": identifier,
        "ParentName": parent,
        "NonAncestorDependencies": list(dependencies),
        "InstallWithParentByDefault": default,
        "Installed": installed,
        "OptionalCompanions": [
            {"CompanionType": 0, "CompanionComponentName": item} for item in companions
        ],
        "Descriptor": {"__CLASS": "ServerComponent_" + name},
    }


def _options(**updates: Any) -> dict[str, Any]:
    options = {
        "names": ["Role"],
        "state": "present",
        "include_sub_features": False,
        "include_management_tools": False,
        "source": None,
    }
    options.update(updates)
    return options


@pytest.fixture(name="graph")
def feature_graph() -> Any:
    """Keep an ancestor reached first through an earlier dependency.

    :returns: Components and source-ordered direct children.
    """
    role = _component("Role", 1, companions=("Tools",))
    first = _component("First", 2, parent="Role", default=True)
    dependency_user = _component(
        "UsesDependency", 3, parent="First", dependencies=("Dependency",)
    )
    later = _component("Later", 4, parent="Role", default=True)
    dependency = _component("Dependency", 5, parent="Later", default=True)
    additional = _component("Additional", 6, parent="Later")
    tools = _component("Tools", 7, parent="ToolsParent")
    tools_parent = _component("ToolsParent", 8)
    return SimpleNamespace(
        components=[
            role,
            first,
            dependency_user,
            later,
            dependency,
            additional,
            tools,
            tools_parent,
        ],
        children={
            "Role": [first, later],
            "First": [dependency_user],
            "Later": [dependency, additional],
            "ToolsParent": [tools],
        },
    )


@pytest.mark.parametrize(
    "all_sub,tools,expected",
    [
        (False, False, [1, 2, 4, 5]),
        (True, False, [1, 2, 3, 5, 4, 6]),
        (False, True, [1, 2, 4, 5, 7, 8]),
        (True, True, [1, 2, 3, 5, 4, 6, 7, 8]),
    ],
)
def test_dependencies_ancestors_children_and_tools_keep_first_discovery_order(
    helper: ModuleType, graph: Any, all_sub: bool, tools: bool, expected: list[int]
) -> None:
    selected = helper._selection(
        _options(include_sub_features=all_sub, include_management_tools=tools),
        graph.components,
        graph.children,
    )
    assert [item["NumericId"] for item in selected] == expected


def test_dependency_selected_ancestor_still_expands_all_children_later(
    helper: ModuleType, graph: Any
) -> None:
    selected = helper._selection(
        _options(include_sub_features=True), graph.components, graph.children
    )
    assert [item["NumericId"] for item in selected] == [1, 2, 3, 5, 4, 6]


def test_duplicate_and_case_variants_share_one_selection(
    helper: ModuleType, graph: Any
) -> None:
    selected = helper._selection(
        _options(names=["role", "Role", "ROLE"]), graph.components, graph.children
    )
    assert [item["NumericId"] for item in selected] == [1, 2, 4, 5]


@pytest.mark.parametrize("name", ["Role*", "Role?", "[Role]", "Role`", "missing"])
def test_literal_names_reject_unknown_names_before_building_any_selection(
    helper: ModuleType, graph: Any, name: str
) -> None:
    with pytest.raises(ValueError, match="The name was not found"):
        helper._selection(
            _options(names=["Role", name]), graph.components, graph.children
        )


@pytest.mark.parametrize(
    "names,message",
    [
        (None, "argument is null or empty"),
        ([], "argument is null, empty"),
        ([""], "argument is null, empty"),
    ],
)
def test_null_and_empty_name_binding_diagnostics_are_distinct(
    helper: ModuleType, graph: Any, names: Any, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        helper._selection(_options(names=names), graph.components, graph.children)


@pytest.mark.parametrize("state", ["absent", None])
@pytest.mark.parametrize("include_sub", [False, True])
def test_removal_always_selects_all_installed_descendants_without_ancestors(
    helper: ModuleType, graph: Any, state: Any, include_sub: bool
) -> None:
    for component in graph.components:
        component["Installed"] = 1
    selected = helper._selection(
        _options(names=["First"], state=state, include_sub_features=include_sub),
        graph.components,
        graph.children,
    )
    assert [item["NumericId"] for item in selected] == [2, 3]


@pytest.mark.parametrize("installed", [1, 2, 3])
def test_already_present_and_pending_present_states_are_not_reinstalled(
    helper: ModuleType, installed: int
) -> None:
    component = _component("Role", 1, installed=installed)
    assert helper._selection(_options(), [component], {}) == []


def test_unavailable_provider_without_older_tool_is_not_hidden(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    failure = OSError("deployment provider unavailable")
    setattr(failure, "hresult", 0x8004100E)
    monkeypatch.setattr(helper.wmi, "WmiConnection", Mock(side_effect=failure))
    monkeypatch.setattr(
        helper.information.legacy, "executable", Mock(return_value=None)
    )
    with pytest.raises(OSError, match="deployment provider unavailable"):
        helper.manage(_options(), False)


@pytest.mark.parametrize("fails", [False, True])
def test_descriptor_array_stores_raw_interface_and_always_clears_its_owner(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, fails: bool
) -> None:
    automation = SimpleNamespace(
        SafeArrayCreateVector=Mock(return_value=501),
        SafeArrayPutElement=Mock(return_value=0),
        VariantClear=Mock(return_value=0),
    )
    connection = SimpleNamespace(_automation=automation)
    descriptor = ctypes.c_void_p(601)
    monkeypatch.setattr(helper, "_descriptor", lambda *_args: descriptor)
    calls = []

    def _put(this: Any, name: str, flags: int, value: Any, kind: int) -> int:
        assert this == 701 and name == "ServerComponentDescriptors"
        variant = ctypes.cast(value, ctypes.POINTER(helper.wmi._Variant)).contents
        assert variant.kind == 0x200D and variant.data.array == 501
        assert flags == kind == 0
        calls.append(name)
        return -2147217400 if fails else 0

    monkeypatch.setattr(helper.wmi, "_method", lambda *_args: _put)
    with ExitStack() as cleanup:
        if fails:
            with pytest.raises(OSError):
                helper._put_descriptors(
                    connection, cleanup, 701, [_component("Role", 1)]
                )
        else:
            helper._put_descriptors(connection, cleanup, 701, [_component("Role", 1)])
    automation.SafeArrayCreateVector.assert_called_once_with(13, 0, 1)
    array, position, pointer = automation.SafeArrayPutElement.call_args.args
    assert array == 501 and position._obj.value == 0 and pointer is descriptor
    automation.VariantClear.assert_called_once()
    assert calls == ["ServerComponentDescriptors"]


def test_descriptor_allocation_failure_still_clears_variant(helper: ModuleType) -> None:
    automation = SimpleNamespace(
        SafeArrayCreateVector=Mock(return_value=None), VariantClear=Mock(return_value=0)
    )
    with ExitStack() as cleanup, pytest.raises(MemoryError):
        helper._put_descriptors(
            SimpleNamespace(_automation=automation), cleanup, 701, []
        )
    automation.VariantClear.assert_called_once()


@pytest.mark.parametrize("check_mode", [False, True])
def test_idempotence_never_submits_a_servicing_request(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, check_mode: bool
) -> None:
    connection = MagicMock()
    monkeypatch.setattr(helper.wmi, "WmiConnection", lambda _namespace: connection)
    monkeypatch.setattr(helper.information, "_components", lambda _connection: [])
    monkeypatch.setattr(helper.information, "_feature_order", lambda _rows: ([], {}))
    monkeypatch.setattr(helper, "_selection", lambda *_args: [])
    service = Mock()
    monkeypatch.setattr(helper, "_service", service)
    result = helper.manage(_options(), check_mode)
    assert result["feature_result"] == [] and result["exitcode"] == "NoChangeNeeded"
    assert not result["changed"] and not result["reboot_required"]
    assert result["success"] and not result["failed"]
    service.assert_not_called()
