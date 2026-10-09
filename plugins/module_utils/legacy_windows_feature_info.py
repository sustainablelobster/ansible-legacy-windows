# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read Server Manager feature metadata through its native WMI provider."""

import ctypes
import re
import time
import uuid
from contextlib import ExitStack
from functools import cmp_to_key

import legacy_windows_feature_legacy as legacy  # pylint: disable=import-error
import legacy_windows_find_match as match  # pylint: disable=import-error
import legacy_windows_wmi as wmi  # pylint: disable=import-error

# Server Manager's embedded request needs native COM input construction, not
# the shared reader's deliberately smaller scalar/string-array input contract.
# pylint: disable=protected-access

_NAMESPACE = r"ROOT\Microsoft\Windows\ServerManager"
_TASK_CLASS = "MSFT_ServerManagerDeploymentTasks"
_CIM_TYPES = {3: 7, 8: 14, 11: 1, 19: 6, 0x2008: 30}


def _spawn(connection, cleanup, class_name):
    # This provider owns the spawned request object and its COM reference.
    # pylint: disable=duplicate-code
    definition = wmi._get_object(
        connection._services, connection._automation, cleanup, class_name
    )
    instance = wmi._POINTER()
    cleanup.callback(wmi._release, instance)
    spawn = wmi._method(definition, 15, wmi._LONG, [wmi._LONG, wmi._POINTER_OUT])
    wmi._check(
        spawn(definition, 0, ctypes.byref(instance)), "IWbemClassObject.SpawnInstance"
    )
    return instance
    # pylint: enable=duplicate-code


def _put_request(instance, automation, request):
    # The request GUID's AddRef and VariantClear belong to this provider call.
    # pylint: disable=duplicate-code
    value = wmi._Variant(kind=13)
    value.data.bstr = request.value
    # VariantClear releases the added reference, while the request's original
    # reference remains owned by the surrounding enumeration cleanup stack.
    wmi._method(request, 1, wmi._ULONG, [])(request)
    try:
        put = wmi._method(
            instance,
            5,
            wmi._LONG,
            [ctypes.c_wchar_p, wmi._LONG, ctypes.POINTER(wmi._Variant), wmi._LONG],
        )
        wmi._check(
            put(instance, "RequestGuid", 0, ctypes.byref(value), 0),
            "IWbemClassObject.Put(RequestGuid)",
        )
    finally:
        wmi._check(automation.VariantClear(ctypes.byref(value)), "VariantClear")
    # pylint: enable=duplicate-code


def _enumeration_call(connection, method_name, request):
    with ExitStack() as cleanup:
        inputs = connection._method_inputs(cleanup, _TASK_CLASS, method_name, {})
        _put_request(inputs, connection._automation, request)
        # This provider owns the COM output object through enumeration decoding.
        # pylint: disable=duplicate-code
        output = wmi._POINTER()
        cleanup.callback(wmi._release, output)
        execute = wmi._method(
            connection._services,
            24,
            wmi._LONG,
            [
                wmi._POINTER,
                wmi._POINTER,
                wmi._LONG,
                wmi._POINTER,
                wmi._POINTER,
                wmi._POINTER_OUT,
                wmi._POINTER,
            ],
        )
        wmi._check(
            execute(
                connection._services,
                wmi._bstr(connection._automation, cleanup, _TASK_CLASS),
                wmi._bstr(connection._automation, cleanup, method_name),
                0,
                None,
                inputs,
                ctypes.byref(output),
                None,
            ),
            "IWbemServices.ExecMethod({0})".format(method_name),
        )
        # pylint: enable=duplicate-code
        result = connection._properties(output, ["ReturnValue", "EnumerationState"])
        try:
            result["ServerComponents"] = wmi._read_property(
                output, connection._automation, "ServerComponents"
            )
        except OSError as error:
            # Streaming output is absent until this asynchronous request has
            # produced components. Do not hide other provider failures.
            if getattr(error, "hresult", None) != 0x80041002:
                raise
            result["ServerComponents"] = []
        return result


def _components(connection):
    with ExitStack() as cleanup:
        # Keep the request GUID's native halves within its enumeration lifetime.
        # pylint: disable=duplicate-code
        request = _spawn(connection, cleanup, "MSFT_ServerManagerRequestGuid")
        identifier = uuid.uuid4().int
        wmi._put_string(
            request, connection._automation, "HighHalf", str(identifier >> 64)
        )
        wmi._put_string(
            request,
            connection._automation,
            "LowHalf",
            str(identifier & ((1 << 64) - 1)),
        )
        # pylint: enable=duplicate-code
        method = "GetServerComponentsAsync"
        components = []
        while True:
            result = _enumeration_call(connection, method, request)
            state = result["EnumerationState"]
            if result["ReturnValue"]:
                raise OSError(
                    "Server Manager enumeration returned {0}.".format(
                        result["ReturnValue"]
                    )
                )
            components.extend(result["ServerComponents"] or [])
            if state["RequestState"] == 1:
                return components
            if state["RequestState"] == 2:
                error = state.get("Error") or {}
                raise OSError(
                    error.get("ErrorMessage") or "Server Manager enumeration failed."
                )
            if state["RequestState"] != 0:
                raise OSError("Server Manager returned an unknown enumeration state.")
            time.sleep(0.1)
            method = "GetEnumerationRequestState"


def _qualifiers(connection, instance, property_name=None):
    with ExitStack() as cleanup:
        qualifiers = wmi._POINTER()
        cleanup.callback(wmi._release, qualifiers)
        if property_name is None:
            get_set = wmi._method(instance, 3, wmi._LONG, [wmi._POINTER_OUT])
            status = get_set(instance, ctypes.byref(qualifiers))
        else:
            get_set = wmi._method(
                instance, 11, wmi._LONG, [ctypes.c_wchar_p, wmi._POINTER_OUT]
            )
            status = get_set(instance, property_name, ctypes.byref(qualifiers))
        wmi._check(status, "IWbemClassObject.GetQualifierSet")
        names = wmi._POINTER()
        get_names = wmi._method(qualifiers, 6, wmi._LONG, [wmi._LONG, wmi._POINTER_OUT])
        wmi._check(
            get_names(qualifiers, 0, ctypes.byref(names)), "IWbemQualifierSet.GetNames"
        )
        if names:
            cleanup.callback(connection._automation.SafeArrayDestroy, names)
        get = wmi._method(
            qualifiers,
            3,
            wmi._LONG,
            [
                ctypes.c_wchar_p,
                wmi._LONG,
                ctypes.POINTER(wmi._Variant),
                ctypes.POINTER(wmi._LONG),
            ],
        )
        result = []
        for name in wmi._read_string_array(connection._automation, names.value):
            value, flavor = wmi._Variant(), wmi._LONG()
            try:
                wmi._check(
                    get(qualifiers, name, 0, ctypes.byref(value), ctypes.byref(flavor)),
                    "IWbemQualifierSet.Get({0})".format(name),
                )
                item = _qualifier_value(connection._automation, value)
                item.update(name=name, flavor=flavor.value)
                result.append(item)
            finally:
                wmi._check(
                    connection._automation.VariantClear(ctypes.byref(value)),
                    "VariantClear",
                )
        return result


def _qualifier_value(automation, value):
    if value.kind == 8:
        return {
            "value": ctypes.wstring_at(
                value.data.bstr, automation.SysStringLen(value.data.bstr)
            ),
            "type": 14,
        }
    if value.kind == 11:
        return {"value": value.data.signed16 != 0, "type": 1}
    if value.kind == 3:
        return {"value": value.data.signed32, "type": 7}
    raise ValueError(
        "Unsupported Server Manager qualifier type {0}.".format(value.kind)
    )


def _property_type(instance, name):
    cim_type = wmi._LONG()
    get = wmi._method(
        instance,
        4,
        wmi._LONG,
        [
            ctypes.c_wchar_p,
            wmi._LONG,
            ctypes.POINTER(wmi._Variant),
            ctypes.POINTER(wmi._LONG),
            ctypes.POINTER(wmi._LONG),
        ],
    )
    wmi._check(
        get(instance, name, 0, None, ctypes.byref(cim_type), None),
        "IWbemClassObject.Get({0})".format(name),
    )
    if cim_type.value not in _CIM_TYPES:
        raise ValueError(
            "Unsupported Server Manager descriptor CIM type {0}.".format(cim_type.value)
        )
    return _CIM_TYPES[cim_type.value]


def _qualifier_projection(qualifier):
    name, flavor = qualifier["name"], qualifier["flavor"]
    flags = ["DisableOverride" if flavor & 0x10 else "EnableOverride"]
    # The MI representation exposes Server Manager's instance qualifiers on
    # the concrete class as ToSubclass; locale remains class-restricted.
    flags.append("Restricted" if name == "locale" else "ToSubclass")
    # Server Manager declares DisplayName translatable. The unamended COM
    # view retains its identifier but omits this MI qualifier flag; asking
    # for amended values instead changes the public locale and qualifiers.
    if flavor & 0x80 or name == "DisplayName":
        flags.append("Translatable")
    return {
        "Name": name,
        "Value": qualifier["value"],
        "CimType": qualifier["type"],
        "Flags": ", ".join(flags),
    }


def _class_metadata(connection, class_name, classes):
    if class_name in classes:
        return classes[class_name]
    with ExitStack() as cleanup:
        definition = wmi._get_object(
            connection._services, connection._automation, cleanup, class_name
        )

        def _read(name):
            return wmi._read_property(definition, connection._automation, name)

        parent_name = _read("__SUPERCLASS")
        parent = (
            _class_metadata(connection, parent_name, classes) if parent_name else None
        )
        inherited = [
            q
            for q in (parent["CimClassQualifiers"] if parent else [])
            if q["Name"] != "locale"
        ]
        qualifiers = [
            _qualifier_projection(q) for q in _qualifiers(connection, definition)
        ]
        namespace = _read("__NAMESPACE").replace("\\", "/")
        system = {
            "ClassName": class_name,
            "Namespace": namespace,
            "Path": None,
            "ServerName": _read("__SERVER"),
        }
        metadata = {
            "CimClassMethods": [],
            "CimClassProperties": _class_properties(connection, definition),
            "CimClassQualifiers": inherited + qualifiers,
            "CimSuperClass": parent,
            "CimSuperClassName": parent_name,
            "CimSystemProperties": system,
        }
        classes[class_name] = metadata
        return metadata


def _class_properties(connection, definition):
    with ExitStack() as cleanup:
        property_names = wmi._POINTER()
        get_names = wmi._method(
            definition,
            7,
            wmi._LONG,
            [
                ctypes.c_wchar_p,
                wmi._LONG,
                ctypes.POINTER(wmi._Variant),
                wmi._POINTER_OUT,
            ],
        )
        wmi._check(
            get_names(definition, None, 0x40, None, ctypes.byref(property_names)),
            "IWbemClassObject.GetNames",
        )
        if property_names:
            cleanup.callback(connection._automation.SafeArrayDestroy, property_names)
        properties = []
        for name in wmi._read_string_array(
            connection._automation, property_names.value
        ):
            value = wmi._read_property(definition, connection._automation, name)
            properties.append(
                {
                    "Name": name,
                    "CimType": _property_type(definition, name),
                    "Flags": "Property" + (", NullValue" if value is None else ""),
                    "Value": value,
                    "ReferenceClassName": None,
                    "Qualifiers": [
                        _qualifier_projection(q)
                        for q in _qualifiers(connection, definition, name)
                        if q["name"] != "CIMTYPE"
                    ],
                }
            )
        return properties


def _descriptor(connection, values, classes):
    metadata = _class_metadata(connection, values["__CLASS"], classes)
    properties = []
    result = {
        "CimClass": metadata,
        "CimInstanceProperties": properties,
        "CimSystemProperties": dict(metadata["CimSystemProperties"]),
        "PSComputerName": None,
    }
    for definition in metadata["CimClassProperties"]:
        name = definition["Name"]
        value = values[name]
        result[name] = value
        properties.append(
            {
                "Name": name,
                "Value": value,
                "CimType": definition["CimType"],
                "Flags": "Property, NotModified"
                + (", NullValue" if value is None else ""),
                "IsValueModified": False,
            }
        )
    return result


def _display_comparison():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    # Keep this independently staged wrapper's native ABI declarations local.
    # pylint: disable=duplicate-code
    kernel.GetUserDefaultLCID.argtypes = []
    kernel.GetUserDefaultLCID.restype = ctypes.c_uint32
    kernel.CompareStringW.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    kernel.CompareStringW.restype = ctypes.c_int
    # pylint: enable=duplicate-code
    locale = kernel.GetUserDefaultLCID()

    def _compare(left, right):
        result = kernel.CompareStringW(
            locale, 0, left["DisplayName"], -1, right["DisplayName"], -1
        )
        if not result:
            raise ctypes.WinError(ctypes.get_last_error())
        return result - 2

    return cmp_to_key(_compare)


def _feature_order(components):
    by_name = {component["UniqueName"]: component for component in components}
    compare = _display_comparison()
    children = {}
    for component in components:
        children.setdefault(component["ParentName"] or None, []).append(component)
    ordered = []

    def _append(component):
        ordered.append(component)
        siblings = sorted(children.get(component["UniqueName"], []), key=compare)
        siblings.sort(key=lambda item: not item["InstallWithParentByDefault"])
        children[component["UniqueName"]] = siblings
        for child in siblings:
            _append(child)

    roots = sorted(children.get(None, []), key=compare)
    roots.sort(key=lambda item: item["FeatureType"])
    for root in roots:
        _append(root)
    if len(ordered) != len(by_name):
        raise ValueError("Server Manager returned an inconsistent feature hierarchy.")
    return ordered, children


def _selector(pattern):
    lower = match._current_lower()

    def _normalize(value):
        return "".join(lower(character) for character in match._utf16_units(value))

    # Server Manager supports * and ?, but treats brackets and backticks
    # literally. Its selector is not PowerShell's bracket wildcard language.
    expression = re.escape(_normalize(pattern)).replace(r"\*", ".*").replace(r"\?", ".")
    compiled = re.compile(r"\A" + expression + r"\Z", re.DOTALL)
    return lambda name: compiled.match(_normalize(name)) is not None


def features(name):
    """Return the matching Server Manager feature metadata in display-tree order.

    :param name: One case-insensitive Windows wildcard selector.
    :type name: str
    :returns: The source's complete projected feature dictionaries.
    :rtype: list
    :raises OSError: The native Server Manager provider is unavailable or fails.
    :raises ValueError: A selector or reached descriptor type is unsupported.
    """
    try:
        return _native_features(name)
    except OSError as error:
        if getattr(error, "hresult", None) not in (0x8004100E, 0x80041010):
            raise
        tool = legacy.executable()
        if tool is None:
            raise
    with legacy.ServerManager(tool) as manager:
        components = manager.catalogue()
    ordered, children = _feature_order(components)
    selected = _selector(name)
    by_name = {component["UniqueName"]: component for component in ordered}
    return [
        _legacy_projection(component, by_name, children)
        for component in ordered
        if selected(component["UniqueName"])
    ]


def _native_features(name):
    with wmi.WmiConnection(_NAMESPACE) as connection:
        selected = _selector(name)
        ordered, children = _feature_order(_components(connection))
        by_name = {component["UniqueName"]: component for component in ordered}
        classes, result = {}, []
        for component in ordered:
            if not selected(component["UniqueName"]):
                continue
            result.append(
                _feature_projection(connection, component, by_name, children, classes)
            )
        return result


def _legacy_projection(component, by_name, children):
    name = component["UniqueName"]
    ancestry = [component["DisplayName"]]
    parent = component["ParentName"]
    while parent:
        ancestor = by_name[parent]
        ancestry.insert(0, ancestor["DisplayName"])
        parent = ancestor["ParentName"]
    return {
        "name": name,
        "display_name": component["DisplayName"],
        "description": None,
        "installed": bool(component["Installed"]),
        "install_state": "Installed" if component["Installed"] else "Available",
        "feature_type": {0: "Role", 1: "Role Service", 2: "Feature"}[
            component["FeatureType"]
        ],
        "path": "\\".join(ancestry),
        "depth": len(ancestry),
        "depends_on": None,
        "parent": component["ParentName"] or None,
        "server_component_descriptor": None,
        "sub_features": [child["UniqueName"] for child in children.get(name, [])],
        "system_service": None,
        "best_practices_model_id": None,
        "event_query": None,
        "post_configuration_needed": None,
        "additional_info": {
            "InstallName": None,
            "MajorVersion": None,
            "MinorVersion": None,
            "NumericId": component["NumericId"],
        },
    }


def _feature_projection(connection, component, by_name, children, classes):
    feature_name = component["UniqueName"]
    ancestry = [component["DisplayName"]]
    ancestor = component["ParentName"]
    while ancestor:
        parent = by_name[ancestor]
        ancestry.insert(0, parent["DisplayName"])
        ancestor = parent["ParentName"]
    installed = component["Installed"]
    states = {
        0: "Available",
        1: "Installed",
        2: "Installed",
        3: "Installed",
        4: "Removed",
        5: "Removed",
        6: "Unknown",
    }
    if installed not in states:
        raise ValueError(
            "Server Manager returned an unknown feature installation state."
        )
    return {
        "name": feature_name,
        "display_name": component["DisplayName"],
        "description": component["Description"],
        "installed": installed in (1, 2, 3),
        "install_state": states[installed],
        "feature_type": {0: "Role", 1: "Role Service", 2: "Feature"}[
            component["FeatureType"]
        ],
        "path": "\\".join(ancestry),
        "depth": len(ancestry),
        "depends_on": component["NonAncestorDependencies"] or [],
        "parent": component["ParentName"] or None,
        "server_component_descriptor": _descriptor(
            connection, component["Descriptor"], classes
        ),
        "sub_features": [
            child["UniqueName"] for child in children.get(feature_name, [])
        ],
        "system_service": [
            service["Name"] for service in component["SystemServices"] or []
        ],
        "best_practices_model_id": ";".join(component["BestPracticeModels"] or []),
        "event_query": component["EventQuery"],
        "post_configuration_needed": installed in (1, 2, 3)
        and component["ConfigurationStatus"] in (0, 1),
        "additional_info": {
            "InstallName": component["Deploys"] or [],
            "MajorVersion": component["MajorVersion"],
            "MinorVersion": component["MinorVersion"],
            "NumericId": component["NumericId"],
        },
    }
