"""Exercise ownership at the feature provider's embedded COM boundary."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These ABI substitutes are controller-only evidence, not Windows execution.
# pylint: disable=protected-access

import ctypes
from types import ModuleType
from typing import Any
from unittest.mock import Mock
from uuid import UUID

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="helper")
def native_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the native WMI helper with the development interpreter.

    :param monkeypatch: Scoped standalone helper path.
    :returns: A fresh target helper, without opening Windows interfaces.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    return load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_wmi.py",
        "feature_wmi",
    )


def _pointer(destination: Any, value: int) -> None:
    ctypes.cast(destination, ctypes.POINTER(ctypes.c_void_p))[0] = value


@pytest.mark.parametrize("kind", [13, 0x200D])
@pytest.mark.parametrize("fails", [False, True])
def test_embedded_property_clears_owning_variant(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, kind: int, fails: bool
) -> None:
    automation = Mock()
    automation.VariantClear.return_value = 0

    def _get(_this: Any, name: str, flags: int, output: Any, *_rest: Any) -> int:
        assert name == "Descriptor" and flags == 0
        value = ctypes.cast(output, ctypes.POINTER(helper._Variant)).contents
        value.kind = kind
        value.data.bstr = 201
        return 0

    monkeypatch.setattr(helper, "_method", lambda *_args: _get)
    reader = Mock(return_value={"__CLASS": "ServerComponent_Test"})
    if fails:
        reader.side_effect = ValueError("bad embedded field")
    name = "_read_embedded_object" if kind == 13 else "_read_embedded_array"
    monkeypatch.setattr(helper, name, reader)
    if fails:
        with pytest.raises(ValueError, match="bad embedded field"):
            helper._read_property(100, automation, "Descriptor")
    else:
        assert (
            helper._read_property(100, automation, "Descriptor") == reader.return_value
        )
    reader.assert_called_once_with(automation, 201)
    automation.VariantClear.assert_called_once()


@pytest.mark.parametrize("fails", [False, True])
def test_embedded_object_queries_concrete_class_and_releases_metadata(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, fails: bool
) -> None:
    automation = Mock()
    releases: list[int] = []

    def _query(_this: Any, iid: Any, output: Any) -> int:
        assert (
            ctypes.string_at(iid, 16)
            == UUID("dc12a681-737f-11cf-884d-00aa004b2e24").bytes_le
        )
        _pointer(output, 202)
        return 0

    def _names(_this: Any, name: Any, flags: int, value: Any, output: Any) -> int:
        assert name is None and flags == 0x40 and value is None
        _pointer(output, 301)
        return 0

    def _method(_this: Any, slot: int, _result: Any, _arguments: Any) -> Any:
        return {0: _query, 7: _names}[slot]

    monkeypatch.setattr(helper, "_method", _method)
    monkeypatch.setattr(
        helper, "_release", lambda pointer: releases.append(pointer.value)
    )
    monkeypatch.setattr(helper, "_read_string_array", lambda *_args: ["Name", "Unset"])

    def _property(_instance: Any, _automation: Any, name: str) -> Any:
        if fails and name == "Name":
            raise ValueError("bad embedded field")
        return {"__CLASS": "MSFT_Test", "Name": "literal", "Unset": None}[name]

    monkeypatch.setattr(helper, "_read_property", _property)
    if fails:
        with pytest.raises(ValueError, match="bad embedded field"):
            helper._read_embedded_object(automation, 201)
    else:
        assert helper._read_embedded_object(automation, 201) == {
            "__CLASS": "MSFT_Test",
            "Name": "literal",
            "Unset": None,
        }
    assert releases == [202]
    assert automation.SafeArrayDestroy.call_args.args[0].value == 301


@pytest.mark.parametrize("fails", [False, True])
def test_embedded_array_preserves_lower_bound_order_and_releases_copies(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, fails: bool
) -> None:
    automation = Mock()
    automation.SafeArrayGetDim.return_value = 1
    releases: list[int] = []

    def _bound(_array: Any, dimension: int, output: Any, number: int) -> int:
        assert dimension == 1
        ctypes.cast(output, ctypes.POINTER(ctypes.c_int32))[0] = number
        return 0

    automation.SafeArrayGetLBound.side_effect = lambda array, dim, out: _bound(
        array, dim, out, 4
    )
    automation.SafeArrayGetUBound.side_effect = lambda array, dim, out: _bound(
        array, dim, out, 5
    )

    def _element(_array: Any, position: Any, output: Any) -> int:
        index = ctypes.cast(position, ctypes.POINTER(ctypes.c_int32))[0]
        _pointer(output, 200 + index)
        return 0

    automation.SafeArrayGetElement.side_effect = _element
    monkeypatch.setattr(
        helper, "_release", lambda pointer: releases.append(pointer.value)
    )

    def _object(_automation: Any, pointer: Any) -> dict[str, int]:
        if fails and pointer.value == 205:
            raise ValueError("bad second object")
        return {"id": pointer.value}

    monkeypatch.setattr(helper, "_read_embedded_object", _object)
    if fails:
        with pytest.raises(ValueError, match="bad second object"):
            helper._read_embedded_array(automation, 300)
    else:
        assert helper._read_embedded_array(automation, 300) == [
            {"id": 204},
            {"id": 205},
        ]
    assert releases == [204, 205]


def test_embedded_nulls_and_multidimensional_arrays(
    helper: ModuleType,
) -> None:
    automation = Mock()
    assert helper._read_embedded_object(automation, None) is None
    assert helper._read_embedded_array(automation, None) == []
    automation.SafeArrayGetDim.return_value = 2
    with pytest.raises(ValueError, match="one dimension"):
        helper._read_embedded_array(automation, 300)
    automation.SafeArrayGetElement.assert_not_called()


@pytest.fixture(name="feature")
def feature_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the dedicated deployment helper without native Windows calls.

    :param monkeypatch: Scoped target helper path.
    :returns: Feature metadata functions with controllable COM boundaries.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    return load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_feature_info.py",
        "feature_native",
    )


@pytest.mark.parametrize("fails", [False, True])
def test_embedded_request_addref_is_released_even_when_put_fails(
    feature: ModuleType, monkeypatch: pytest.MonkeyPatch, fails: bool
) -> None:
    automation = Mock()
    automation.VariantClear.return_value = 0
    events: list[str] = []

    def _put(_this: Any, name: str, flags: int, output: Any, cim_type: int) -> int:
        value = ctypes.cast(output, ctypes.POINTER(feature.wmi._Variant)).contents
        assert name == "RequestGuid" and flags == cim_type == 0
        assert value.kind == 13 and value.data.bstr == 500
        events.append("put")
        return -2147217405 if fails else 0

    def _method(_this: Any, slot: int, _result: Any, _args: Any) -> Any:
        return {1: lambda *_args: events.append("addref"), 5: _put}[slot]

    monkeypatch.setattr(feature.wmi, "_method", _method)
    if fails:
        with pytest.raises(OSError, match="Put\\(RequestGuid\\)"):
            feature._put_request(100, automation, ctypes.c_void_p(500))
    else:
        feature._put_request(100, automation, ctypes.c_void_p(500))
    assert events == ["addref", "put"]
    automation.VariantClear.assert_called_once()


def test_provider_stream_preserves_chunks_and_uses_one_unique_request(
    feature: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = Mock()
    identifier = UUID(int=(1 << 80) + 19)
    monkeypatch.setattr(feature.uuid, "uuid4", lambda: identifier)
    monkeypatch.setattr(feature, "_spawn", lambda *_args: ctypes.c_void_p(500))
    write = Mock()
    monkeypatch.setattr(feature.wmi, "_put_string", write)
    sleep = Mock()
    monkeypatch.setattr(feature.time, "sleep", sleep)
    calls = Mock(
        side_effect=[
            {
                "ReturnValue": 0,
                "EnumerationState": {"RequestState": 0},
                "ServerComponents": [{"UniqueName": "One"}],
            },
            {
                "ReturnValue": 0,
                "EnumerationState": {"RequestState": 1},
                "ServerComponents": [{"UniqueName": "Two"}],
            },
        ]
    )
    monkeypatch.setattr(feature, "_enumeration_call", calls)
    assert feature._components(connection) == [
        {"UniqueName": "One"},
        {"UniqueName": "Two"},
    ]
    assert write.call_args_list[0].args[2:] == ("HighHalf", str(1 << 16))
    assert write.call_args_list[1].args[2:] == ("LowHalf", "19")
    assert [call.args[1] for call in calls.call_args_list] == [
        "GetServerComponentsAsync",
        "GetEnumerationRequestState",
    ]
    assert calls.call_args_list[0].args[2] is calls.call_args_list[1].args[2]
    sleep.assert_called_once_with(0.1)


@pytest.mark.parametrize(
    "result,message",
    [
        (
            {
                "ReturnValue": 9,
                "EnumerationState": {"RequestState": 1},
                "ServerComponents": [],
            },
            "returned 9",
        ),
        (
            {
                "ReturnValue": 0,
                "EnumerationState": {
                    "RequestState": 2,
                    "Error": {"ErrorMessage": "actual provider failure"},
                },
                "ServerComponents": [],
            },
            "actual provider failure",
        ),
        (
            {
                "ReturnValue": 0,
                "EnumerationState": {"RequestState": 8},
                "ServerComponents": [],
            },
            "unknown enumeration state",
        ),
    ],
)
def test_provider_failure_cannot_return_partial_success(
    feature: ModuleType, monkeypatch: pytest.MonkeyPatch, result: Any, message: str
) -> None:
    monkeypatch.setattr(feature, "_spawn", lambda *_args: ctypes.c_void_p(500))
    monkeypatch.setattr(feature.wmi, "_put_string", Mock())
    monkeypatch.setattr(feature, "_enumeration_call", Mock(return_value=result))
    with pytest.raises(OSError, match=message):
        feature._components(Mock())


@pytest.mark.parametrize(
    "pattern,name,expected",
    [
        ("adcs-*", "ADCS-Cert-Authority", True),
        ("ADCS-Cert-Authorit?", "ADCS-Cert-Authority", True),
        ("A*-*cate", "AD-Certificate", True),
        ("ADCS-Cert-[Aa]uthority", "ADCS-Cert-Authority", False),
        ("[", "DHCP", False),
        ("ADCS-Cert-Authorit`y", "ADCS-Cert-Authority", False),
        ("ADCS-Cert-Authority ", "ADCS-Cert-Authority", False),
        ("ADCS-Cert-Authority,AD-Certificate", "ADCS-Cert-Authority", False),
        ("A.*", "AD-Certificate", False),
    ],
)
def test_server_manager_wildcards_do_not_use_powershell_bracket_language(
    feature: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    pattern: str,
    name: str,
    expected: bool,
) -> None:
    monkeypatch.setattr(feature.match, "_current_lower", lambda: str.lower)
    assert feature._selector(pattern)(name) is expected


def test_tree_order_places_roles_before_features_and_default_children_first(
    feature: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _component(
        name: str, display: str, parent: str, kind: int, default: bool = False
    ) -> dict[str, Any]:
        return {
            "UniqueName": name,
            "DisplayName": display,
            "ParentName": parent,
            "FeatureType": kind,
            "InstallWithParentByDefault": default,
        }

    rows = [
        _component("Z", "A feature", "", 2),
        _component("R", "Z role", "", 0),
        _component("C1", "A child", "R", 1),
        _component("C2", "Z default", "R", 1, True),
    ]
    monkeypatch.setattr(
        feature, "_display_comparison", lambda: lambda item: item["DisplayName"]
    )
    ordered, children = feature._feature_order(rows)
    assert [item["UniqueName"] for item in ordered] == ["R", "C2", "C1", "Z"]
    assert [item["UniqueName"] for item in children["R"]] == ["C2", "C1"]


@pytest.mark.parametrize(
    "state,status", [(0, "Available"), (1, "Installed"), (5, "Removed")]
)
def test_full_projection_preserves_observed_states_arrays_nulls_and_info(
    feature: ModuleType, monkeypatch: pytest.MonkeyPatch, state: int, status: str
) -> None:
    descriptor = {"complete": "native CIM metadata"}
    monkeypatch.setattr(feature, "_descriptor", lambda *_args: descriptor)
    component = {
        "UniqueName": "Child",
        "DisplayName": "Child display",
        "Description": "full description",
        "ParentName": "Root",
        "Installed": state,
        "FeatureType": 1,
        "NonAncestorDependencies": ["Second", "First"],
        "Descriptor": {"__CLASS": "ServerComponent_Child"},
        "SystemServices": [{"Name": "SvcB"}, {"Name": "SvcA"}],
        "BestPracticeModels": ["NativeModel"],
        "EventQuery": "Native.Events.xml",
        "ConfigurationStatus": 3,
        "Deploys": ["NativeCBS"],
        "MajorVersion": 2,
        "MinorVersion": 3,
        "NumericId": 47,
    }
    result = feature._feature_projection(
        Mock(),
        component,
        {"Root": {"DisplayName": "Root display", "ParentName": ""}},
        {"Child": []},
        {},
    )
    assert result == {
        "name": "Child",
        "display_name": "Child display",
        "description": "full description",
        "installed": state == 1,
        "install_state": status,
        "feature_type": "Role Service",
        "path": "Root display\\Child display",
        "depth": 2,
        "depends_on": ["Second", "First"],
        "parent": "Root",
        "server_component_descriptor": descriptor,
        "sub_features": [],
        "system_service": ["SvcB", "SvcA"],
        "best_practices_model_id": "NativeModel",
        "event_query": "Native.Events.xml",
        "post_configuration_needed": False,
        "additional_info": {
            "InstallName": ["NativeCBS"],
            "MajorVersion": 2,
            "MinorVersion": 3,
            "NumericId": 47,
        },
    }
