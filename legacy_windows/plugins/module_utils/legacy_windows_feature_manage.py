# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Select and service Windows Server features through native Server Manager."""

import ctypes
import time
import uuid
from contextlib import ExitStack

import legacy_windows_feature_info as information  # pylint: disable=import-error
import legacy_windows_wmi as wmi  # pylint: disable=import-error

# Embedded request inputs extend the shared reader's scalar input contract.
# Keep these Server Manager-specific COM operations beside their servicing owner.
# pylint: disable=protected-access


def _selection(options, components, children):
    names = options["names"]
    if names is None:
        raise ValueError(
            "Cannot validate argument on parameter 'Name'. The argument is null "
            "or empty. Provide an argument that is not null or empty, and then "
            "try the command again."
        )
    if not names or any(not name for name in names):
        raise ValueError(
            "Cannot validate argument on parameter 'Name'. The argument is null, "
            "empty, or an element of the argument collection contains a null "
            "value. Supply a collection that does not contain any null values "
            "and then try the command again."
        )
    by_name = {component["UniqueName"]: component for component in components}
    lookup = {name.lower(): name for name in by_name}
    requested = []
    for name in names:
        if name.lower() not in lookup:
            raise ValueError(
                "ArgumentNotValid: The role, role service, or feature name is "
                "not valid: '" + name + "'. The name was not found."
            )
        requested.append(lookup[name.lower()])
    selected, expanded, discovery = set(), set(), []
    installing = options["state"] == "present"

    def _add(name, include_children):
        component = by_name[name]
        new = name not in selected
        if new:
            selected.add(name)
            discovery.append(component)
            if installing:
                parent = component["ParentName"]
                if parent:
                    _add(parent, False)
                for dependency in component["NonAncestorDependencies"] or []:
                    _add(dependency, False)
        # A dependency may select an ancestor before the requested traversal
        # reaches it. Its children must still be expanded on that later visit.
        if name not in expanded and (include_children or not installing):
            expanded.add(name)
            for child in children.get(name, []):
                if (
                    not installing
                    or options["include_sub_features"]
                    or child["InstallWithParentByDefault"]
                ):
                    _add(child["UniqueName"], True)
        if new and options["include_management_tools"]:
            for companion in component["OptionalCompanions"] or []:
                if companion["CompanionType"] == 0:
                    _add(companion["CompanionComponentName"], True)

    for name in requested:
        _add(name, True)
    return [
        component
        for component in discovery
        if (component["Installed"] in (1, 2, 3)) != installing
    ]


def _descriptor(connection, cleanup, data):
    instance = information._spawn(connection, cleanup, data["__CLASS"])
    for name, value in data.items():
        if name == "__CLASS" or value is None:
            continue
        if isinstance(value, bool):
            wmi._put_boolean(instance, connection._automation, name, value)
        elif isinstance(value, str):
            wmi._put_string(instance, connection._automation, name, value)
        elif isinstance(value, int):
            wmi._put_integer(instance, connection._automation, name, value)
        elif isinstance(value, list) and all(isinstance(item, str) for item in value):
            wmi._put_string_array(instance, connection._automation, name, value)
        else:
            raise ValueError("Unsupported Server Manager descriptor field " + name)
    return instance


def _put_descriptors(connection, cleanup, instance, components):
    value = wmi._Variant(kind=0x200D)
    automation = connection._automation
    try:
        value.data.array = automation.SafeArrayCreateVector(13, 0, len(components))
        if not value.data.array:
            raise MemoryError("Could not allocate the Server Manager descriptor array.")
        for index, component in enumerate(components):
            descriptor = _descriptor(connection, cleanup, component["Descriptor"])
            position = wmi._LONG(index)
            # SafeArrayPutElement adds its own reference to this raw IUnknown
            # pointer. VariantClear owns that reference; cleanup owns the original.
            wmi._check(
                automation.SafeArrayPutElement(
                    value.data.array, ctypes.byref(position), descriptor
                ),
                "SafeArrayPutElement(ServerComponentDescriptors)",
            )
        # This provider owns its descriptor Variant and the matching native Put call.
        # pylint: disable=duplicate-code
        put = wmi._method(
            instance,
            5,
            wmi._LONG,
            [ctypes.c_wchar_p, wmi._LONG, ctypes.POINTER(wmi._Variant), wmi._LONG],
        )
        wmi._check(
            put(instance, "ServerComponentDescriptors", 0, ctypes.byref(value), 0),
            "IWbemClassObject.Put(ServerComponentDescriptors)",
        )
        # pylint: enable=duplicate-code
    finally:
        wmi._check(automation.VariantClear(ctypes.byref(value)), "VariantClear")


def _alteration_call(connection, request, method_name, inputs, components=None):
    with ExitStack() as cleanup:
        arguments = connection._method_inputs(
            cleanup, information._TASK_CLASS, method_name, inputs
        )
        information._put_request(arguments, connection._automation, request)
        if components is not None:
            _put_descriptors(connection, cleanup, arguments, components)
        output = wmi._POINTER()
        cleanup.callback(wmi._release, output)
        # Preserve this provider's input/output ownership at the COM call boundary.
        # pylint: disable=duplicate-code
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
                wmi._bstr(connection._automation, cleanup, information._TASK_CLASS),
                wmi._bstr(connection._automation, cleanup, method_name),
                0,
                None,
                arguments,
                ctypes.byref(output),
                None,
            ),
            "IWbemServices.ExecMethod({0})".format(method_name),
        )
        # pylint: enable=duplicate-code
        return connection._properties(output, ["ReturnValue", "AlterationState"])


def _service(connection, components, installing, source):
    with ExitStack() as cleanup:
        request = information._spawn(
            connection, cleanup, "MSFT_ServerManagerRequestGuid"
        )
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
        if installing:
            method = "AddServerComponentAsync"
            inputs = {"ScanForUpdates": False}
            if source:
                inputs["Source"] = [source]
        else:
            method = "RemoveServerComponentAsync"
            inputs = {"DeleteComponents": False}
        while True:
            response = _alteration_call(connection, request, method, inputs, components)
            if response["ReturnValue"]:
                raise OSError(
                    "Server Manager alteration returned {0}.".format(
                        response["ReturnValue"]
                    )
                )
            state = response["AlterationState"]
            if state["RequestState"] in (1, 2):
                return state
            if state["RequestState"] != 0:
                raise OSError("Server Manager returned an unknown alteration state.")
            time.sleep(0.1)
            method = "GetAlterationRequestState"
            inputs = {"KeepAlterationStateOnRestartRequired": False}
            components = None


def _result(components, reboot_required=False):
    return {
        "changed": bool(components),
        "exitcode": "Success" if components else "NoChangeNeeded",
        "feature_result": [
            {
                "id": component["NumericId"],
                "display_name": component["DisplayName"],
                "message": [],
                "reboot_required": reboot_required,
                "skip_reason": "NotSkipped",
                "success": True,
            }
            for component in components
        ],
        "reboot_required": reboot_required,
        "success": True,
        "failed": False,
    }


def manage(options, check_mode):
    """Validate and service the complete requested Server Manager feature batch.

    :param dict options: Bound names, state, subfeature/tool flags, and source.
    :param bool check_mode: Report selection without submitting servicing work.
    :returns: The upstream feature-result interface with restart and success flags.
    :rtype: dict
    :raises ValueError: Names cannot bind or the server provider is unavailable.
    :raises OSError: The provider cannot enumerate or execute the request.
    """
    with ExitStack() as cleanup:
        try:
            connection = cleanup.enter_context(
                wmi.WmiConnection(information._NAMESPACE)
            )
            components = information._components(connection)
        except OSError as error:
            if getattr(error, "hresult", None) not in (0x8004100E, 0x80041010):
                raise
            tool = information.legacy.executable()
            if tool is None:
                raise
            return _legacy_manage(tool, options, check_mode)
        _ordered, children = information._feature_order(components)
        selected = _selection(options, components, children)
        if check_mode or not selected:
            return _result(selected)
        state = _service(
            connection, selected, options["state"] == "present", options["source"]
        )
        if state["RequestState"] == 2:
            error = state.get("Error") or {}
            raise OSError(
                error.get("ErrorMessage") or "Server Manager servicing failed."
            )
        return _result(selected, state["RestartRequired"])


def _legacy_manage(tool, options, check_mode):
    with information.legacy.ServerManager(tool) as manager:
        before = manager.catalogue()
        ordered, children = information._feature_order(before)
        selected = _selection(options, ordered, children)
        if selected and options["source"] and options["state"] == "present":
            raise ValueError(
                "The installed ServerManagerCmd facility cannot override a feature "
                "installation source; omit source to use its local Windows payloads."
            )
        if check_mode or not selected:
            result = _result(selected)
        else:
            result = _legacy_service(manager, before, selected, options)
        result["warnings"] = [
            "The older ServerManagerCmd catalogue has no numeric feature IDs; "
            "IDs unavailable from installed Win32_ServerFeature metadata are null. "
            "Associated management tools follow this "
            "Windows facility's default behavior; it has no separate management-tool flag."
        ]
        return result


def _legacy_service(manager, before, selected, options):
    names = []
    for component in selected:
        if component["UniqueName"] not in names:
            names.append(component["UniqueName"])
    status, output, native_result = manager.change(
        names, options["state"] == "present", options["include_sub_features"]
    )
    original = {component["UniqueName"]: component for component in before}
    changed = [
        component
        for component in manager.catalogue()
        if component["Installed"] != original[component["UniqueName"]]["Installed"]
    ]
    # ServerManagerCmd distinguishes success requiring restart (3010),
    # failure requiring restart (1001), and a no-op (1003).
    reboot = status in (3010, 1001)
    if native_result is not None:
        reboot = reboot or any(
            node.get("RequiresReboot", "").lower() == "true"
            for node in native_result.iter()
        )
    result = _result(changed, reboot)
    if status not in (0, 3010, 1003) or (
        native_result is not None and native_result.get("Success") == "false"
    ):
        result.update(
            failed=True,
            success=False,
            exitcode="Failed",
            msg="ServerManagerCmd failed ({0}): {1}".format(status, output),
        )
    return result
