# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Express legacy IIS management using the installed ADSI metabase provider."""

import binascii
import ntpath
import time
from decimal import Decimal, InvalidOperation

# The frontend owns validation; this backend owns metabase feature translation.
from legacy_community_windows_iis import (  # pylint: disable=import-error
    _credentials,
    _name,
    _parameters,
    _path,
    _pool_info,
    _pool_result,
    _port,
    _virtual_path,
)

_ABSENT = (0x80070002, 0x80070003, 0x80005000, 0x80005005, 0x80005006, 0x8000500D)
_POOL_ATTRIBUTES = {
    "autoStart": "AppPoolAutoStart",
    "queueLength": "AppPoolQueueLength",
    "enable32BitAppOnWin64": "Enable32BitAppOnWin64",
    "cpu.limit": "CpuLimit",
    "cpu.action": "CpuAction",
    "cpu.resetInterval": "CpuResetInterval",
    "failure.rapidFailProtection": "RapidFailProtection",
    "failure.rapidFailProtectionInterval": "RapidFailProtectionInterval",
    "failure.rapidFailProtectionMaxCrashes": "RapidFailProtectionMaxCrashes",
    "processModel.identityType": "AppPoolIdentityType",
    "processModel.userName": "WAMUserName",
    "processModel.password": "WAMUserPass",
    "processModel.idleTimeout": "IdleTimeout",
    "processModel.maxProcesses": "MaxProcesses",
    "processModel.pingingEnabled": "PingingEnabled",
    "processModel.pingInterval": "PingInterval",
    "processModel.pingResponseTime": "PingResponseTime",
    "processModel.shutdownTimeLimit": "ShutdownTimeLimit",
    "processModel.startupTimeLimit": "StartupTimeLimit",
    "recycling.disallowOverlappingRotation": "DisallowOverlappingRotation",
    "recycling.disallowRotationOnConfigChange": "DisallowRotationOnConfigChange",
    "recycling.periodicRestart.time": "PeriodicRestartTime",
    "recycling.periodicRestart.requests": "PeriodicRestartRequests",
    "recycling.periodicRestart.memory": "PeriodicRestartMemory",
    "recycling.periodicRestart.privateMemory": "PeriodicRestartPrivateMemory",
    "recycling.periodicRestart.schedule": "PeriodicRestartSchedule",
}
_SITE_PARAMETERS = {
    "serverAutoStart": "ServerAutoStart",
    "limits.maxConnections": "MaxConnections",
    "limits.connectionTimeout": "ConnectionTimeout",
    "limits.maxBandwidth": "MaxBandwidth",
    "logFile.directory": "LogFileDirectory",
    "logFile.period": "LogFilePeriod",
    "logFile.truncateSize": "LogFileTruncateSize",
    "logFile.enabled": "LogType",
}
_MINUTE_DURATIONS = (
    "processModel.idleTimeout",
    "recycling.periodicRestart.time",
    "cpu.resetInterval",
    "failure.rapidFailProtectionInterval",
)


def _get(element, name, default=None):
    try:
        value = element.call("Get", name)
        # Metabase integer properties are DWORDs, but ADSI returns high-bit
        # values in signed VT_I4 slots. Preserve their unsigned schema value.
        if isinstance(value, int) and -(2**31) <= value < 0:
            return value + 2**32
        return value
    except OSError as error:
        if getattr(error, "hresult", None) in _ABSENT:
            return default
        raise


def _bind(automation, path):
    try:
        return automation.bind(path)
    except OSError as error:
        if getattr(error, "hresult", None) in _ABSENT:
            return None
        raise


def _children(container):
    return container.children()


def _site(root, name):
    for item in _children(root):
        if (
            item.get("Class").lower() == "iiswebserver"
            and str(_get(item, "ServerComment", "")).lower() == name.lower()
        ):
            return item
    return None


def _different(current, value):
    if isinstance(current, (list, tuple)) or isinstance(value, (list, tuple)):
        return list(current or []) != list(value or [])
    if isinstance(current, bool):
        from legacy_windows_module import (  # pylint: disable=import-error,import-outside-toplevel
            as_bool,
        )

        return current != as_bool(value, "IIS attribute")
    return str(current).lower() != str(value).lower()


def _update(element, values, preview=False):
    changed = False
    for name, value in values.items():
        if _different(_get(element, name), value):
            if not preview:
                element.call("Put", name, value)
            changed = True
    if changed and not preview:
        element.call("SetInfo")
    return changed


def _read_state(element, pool):
    element.call("GetInfo")
    return int(_get(element, "AppPoolState" if pool else "ServerState", 0))


def _settled_state(element, pool):
    deadline = time.monotonic() + 10
    while True:
        current = _read_state(element, pool)
        if current in (2, 4):
            return current
        if time.monotonic() >= deadline:
            raise OSError(
                "The IIS runtime state did not settle within 10 seconds; "
                "last state was {0}. Verify that W3SVC is running.".format(current)
            )
        time.sleep(0.05)


def _state(element, desired, pool=False, preview=False):
    requested = desired in ("started", "stopped", "restarted")
    current = _settled_state(element, pool) if requested else _read_state(element, pool)
    started, stopped = (2, 4) if pool else (2, 4)
    changed = (
        desired == "restarted"
        or desired == "started"
        and current != started
        or desired == "stopped"
        and current != stopped
    )
    if changed and not preview:
        if desired == "restarted" and pool and current == started:
            element.call("Recycle")
        else:
            if current == started and desired in ("restarted", "stopped"):
                element.call("Stop")
            if desired in ("restarted", "started"):
                element.call("Start")
    value = _settled_state(element, pool) if requested and not preview else current
    return changed, {2: "Started", 4: "Stopped", 1: "Starting", 3: "Stopping"}.get(
        value, "Unknown"
    )


def _timespan(value, minutes=False):
    if isinstance(value, str) and ":" in value:
        fields = value.split(":")
        days = int(fields.pop(0)) if len(fields) == 4 else 0
        if len(fields) != 3:
            raise ValueError("Legacy IIS durations must use [D:]HH:MM:SS syntax.")
        if "." in fields[0]:
            day, fields[0] = fields[0].split(".", 1)
            days += int(day)
        try:
            seconds = (
                days * 86400
                + int(fields[0]) * 3600
                + int(fields[1]) * 60
                + Decimal(fields[2])
            )
        except InvalidOperation as error:
            raise ValueError("The duration contains invalid seconds.") from error
        if not seconds.is_finite() or seconds < 0:
            raise ValueError("IIS durations must be finite and non-negative.")
        if seconds != int(seconds):
            raise ValueError(
                "The installed IIS metabase stores this duration in whole seconds."
            )
        seconds = int(seconds)
        if minutes and seconds % 60:
            raise ValueError(
                "The installed IIS metabase stores this duration in whole minutes."
            )
        return seconds // 60 if minutes else seconds
    return int(value)


def _pool_values(attributes):
    values = {}
    for key, value in attributes.items():
        if key == "managedPipelineMode" and str(value).lower() in ("classic", "1"):
            continue
        native = _POOL_ATTRIBUTES.get(key)
        if native is None:
            raise ValueError(
                "The installed IIS metabase cannot express application-pool attribute: "
                + key
            )
        if key == "processModel.identityType":
            identities = {
                "localsystem": 0,
                "localservice": 1,
                "networkservice": 2,
                "specificuser": 3,
            }
            value = identities.get(str(value).lower(), value)
            if str(value) not in ("0", "1", "2", "3"):
                raise ValueError(
                    "The installed IIS metabase does not support this application-pool identity."
                )
            value = int(value)
        elif key == "cpu.action":
            value = {"noaction": 0, "killw3wp": 1}.get(str(value).lower(), value)
            value = int(value)
        elif key == "recycling.periodicRestart.schedule":
            value = (
                value
                if isinstance(value, list)
                else [part.strip() for part in str(value).split(",")]
            )
        elif key in _MINUTE_DURATIONS:
            value = _timespan(value, True)
        elif key.endswith(("Interval", "TimeLimit", "ResponseTime")):
            value = _timespan(value)
        values[native] = value
    return values


def _pool_container(automation):
    root = automation.bind("IIS://localhost/W3SVC")
    return next(
        (entry for entry in _children(root) if entry.get("Name").lower() == "apppools"),
        None,
    )


def _find_pool(automation, name):
    container = _pool_container(automation)
    if container is None:
        return None
    # Match an actual child name rather than relying on inherited properties.
    return next(
        (
            entry
            for entry in _children(container)
            if entry.get("Name").lower() == name.lower()
        ),
        None,
    )


def _pool(automation, parameters):
    name, state = parameters["name"], parameters.get("state", "present")
    attributes = parameters.get("attributes") or {}
    if not isinstance(attributes, dict):
        raise ValueError("attributes must be a dictionary.")
    values = _pool_values(attributes)
    container = _pool_container(automation)
    if container is None:
        raise ValueError(
            "The installed IIS metabase does not expose application pools."
        )
    pool = _find_pool(automation, name)
    preview, changed = parameters.get("_ansible_check_mode", False), False
    if state == "absent":
        if pool is not None:
            if not preview:
                container.call("Delete", "IIsApplicationPool", name)
            changed = True
        pool = None
    else:
        if pool is None:
            changed = True
            if not preview:
                pool = container.call("Create", "IIsApplicationPool", name)
                for key, value in values.items():
                    pool.call("Put", key, value)
                pool.call("SetInfo")
        if pool is not None:
            changed = _update(pool, values, preview) or changed
            changed = _state(pool, state, True, preview)[0] or changed
    result = _pool_result(attributes, _pool_information(pool, name, state))
    if pool is not None:
        result["info"]["attributes"]["state"] = _state(pool, None, True)[1]
    result["changed"] = changed
    return result


def _pool_information(pool, name, state):
    info = _pool_info(name, state)
    if pool is not None:
        info["attributes"]["managedPipelineMode"] = "Classic"
        for key, native in _POOL_ATTRIBUTES.items():
            if "password" in key.lower():
                continue
            value = _get(pool, native)
            if value is None:
                continue
            parts, parent = key.split("."), info
            if len(parts) == 1:
                parent = info["attributes"]
            else:
                for part in parts[:-1]:
                    parent = parent[part]
            parent[parts[-1]] = _pool_info_value(key, value)
    return info


def _pool_info_value(key, value):
    if key == "processModel.identityType":
        return {
            0: "LocalSystem",
            1: "LocalService",
            2: "NetworkService",
            3: "SpecificUser",
        }.get(value, value)
    if key == "cpu.action":
        return {0: "NoAction", 1: "KillW3wp"}.get(value, value)
    if key in _MINUTE_DURATIONS or key.endswith(
        ("Interval", "TimeLimit", "ResponseTime")
    ):
        seconds = int(value) * (60 if key in _MINUTE_DURATIONS else 1)
        return "{0:02d}:{1:02d}:{2:02d}".format(
            seconds // 3600, seconds // 60 % 60, seconds % 60
        )
    return value


def _site_values(parameters):
    values = {}
    for key, value in _parameters(parameters.get("parameters")).items():
        native = next(
            (
                mapped
                for option, mapped in _SITE_PARAMETERS.items()
                if option.lower() == key.lower()
            ),
            None,
        )
        if native is None:
            raise ValueError(
                "The installed IIS metabase cannot express website parameter: " + key
            )
        if key.lower() == "logfile.period":
            value = {"daily": 1, "weekly": 2, "monthly": 3, "hourly": 4}.get(
                value.lower(), value
            )
        elif key.lower() == "limits.connectiontimeout":
            value = _timespan(value)
        values[native] = value
    return values


def _create_site(root, parameters, path, values):
    if not path:
        raise ValueError("Missing required argument: physical_path")
    ids = [
        int(item.get("Name"))
        for item in _children(root)
        if item.get("Class").lower() == "iiswebserver"
    ]
    identifier = int(parameters.get("site_id") or max(ids + [0]) + 1)
    if identifier < 1 or identifier in ids:
        raise ValueError("site_id must be positive and not already in use.")
    site = root.call("Create", "IIsWebServer", str(identifier))
    site.call("Put", "ServerComment", parameters["name"])
    site.call(
        "Put",
        "ServerBindings",
        [
            "{0}:{1}:{2}".format(
                "" if parameters.get("ip") in (None, "*") else parameters["ip"],
                _port(parameters.get("port") or 80),
                parameters.get("hostname") or "",
            )
        ],
    )
    for key, value in values.items():
        site.call("Put", key, value)
    site.call("SetInfo")
    directory = site.call("Create", "IIsWebVirtualDir", "ROOT")
    directory.call("Put", "Path", path)
    directory.call("Put", "AccessRead", True)
    directory.call("SetInfo")
    directory.call("AppCreate2", 2)
    return site, directory


def _website(automation, root, parameters):
    name, state = parameters["name"], parameters.get("state")
    site = _site(root, name)
    if state == "absent":
        if site is not None:
            root.call("Delete", "IIsWebServer", site.get("Name"))
        return {"changed": site is not None, "site": {}}
    path = _name(parameters, "physical_path")
    path = _path(path) if path else None
    pool = _name(parameters, "application_pool")
    if pool and _find_pool(automation, pool) is None:
        raise ValueError(
            "The requested application pool does not exist or is unavailable in this IIS metabase."
        )
    values = _site_values(parameters)
    changed = False
    if site is None:
        site, directory = _create_site(root, parameters, path, values)
        changed = True
    else:
        directory = automation.bind(site.get("ADsPath") + "/ROOT")
    changed = _update(site, values) or changed
    requested = {}
    if path and ntpath.normcase(
        ntpath.normpath(_get(directory, "Path", ""))
    ) != ntpath.normcase(ntpath.normpath(path)):
        requested["Path"] = path
    if pool:
        requested["AppPoolId"] = pool
    changed = _update(directory, requested) or changed
    state_changed, current = _state(site, state)
    return {
        "changed": changed or state_changed,
        "site": {
            "Name": _get(site, "ServerComment"),
            "ID": int(site.get("Name")),
            "State": current,
            "PhysicalPath": _get(directory, "Path"),
            "ApplicationPool": _get(directory, "AppPoolId"),
            "Bindings": list(_get(site, "ServerBindings", []) or [])
            + list(_get(site, "SecureBindings", []) or []),
        },
    }


def _application_values(automation, root_path, parameters, virtual_directory):
    physical = _name(parameters, "physical_path")
    physical = _path(physical) if physical else None
    credentials = _credentials(parameters)
    values = {
        "UNCUserName" if key == "userName" else "UNCPassword": value
        for key, value in credentials.items()
    }
    pool = _name(parameters, "application_pool")
    if not virtual_directory:
        pool = pool or _get(automation.bind(root_path), "AppPoolId")
        if pool:
            if _find_pool(automation, pool) is None:
                raise ValueError("The requested application pool does not exist.")
            values["AppPoolId"] = pool
    if physical:
        values["Path"] = physical
    return physical, values


def _application_parent(automation, root, parameters, virtual_directory):
    site = _site(root, parameters["site"])
    if site is None:
        raise ValueError("Unable to retrieve website with name " + parameters["site"])
    root_path = site.get("ADsPath") + "/ROOT"
    application = (
        _virtual_path(parameters["application"])
        if virtual_directory and parameters.get("application")
        else ""
    )
    parent_path = root_path + application
    parent = automation.bind(parent_path)
    path = _virtual_path(parameters["name"])
    return root_path, parent, path


def _application(automation, root, parameters, virtual_directory):
    root_path, parent, path = _application_parent(
        automation, root, parameters, virtual_directory
    )
    directory = _bind(automation, parent.get("ADsPath") + path)
    preview, changed = parameters.get("_ansible_check_mode", False), False
    if parameters.get("state", "present") == "absent":
        if directory is not None:
            if not preview:
                parent.call("Delete", "IIsWebVirtualDir", path[1:])
            changed = True
        return (
            {"changed": changed, "directory": {"PhysicalPath": None}}
            if virtual_directory
            else {
                "changed": changed,
                "physical_path": parameters.get("physical_path"),
                "application_pool": parameters.get("application_pool"),
            }
        )
    physical, values = _application_values(
        automation, root_path, parameters, virtual_directory
    )
    if directory is None:
        if not physical:
            raise ValueError("Missing required argument: physical_path")
        changed = True
        if not preview:
            directory = parent.call("Create", "IIsWebVirtualDir", path[1:])
            for key, value in values.items():
                directory.call("Put", key, value)
            directory.call("Put", "AccessRead", True)
            directory.call("SetInfo")
            if not virtual_directory:
                directory.call("AppCreate2", 2)
    elif not virtual_directory and not _get(directory, "AppRoot"):
        changed = True
        if not preview:
            directory.call("AppCreate2", 2)
    if directory is not None:
        changed = _update(directory, values, preview) or changed
    result = _application_result(directory, parameters, virtual_directory)
    result["changed"] = changed
    return result


def _application_result(directory, parameters, virtual_directory):
    if virtual_directory:
        return {
            "directory": {
                "PhysicalPath": (
                    _get(directory, "Path")
                    if directory
                    else parameters.get("physical_path")
                )
            },
        }
    result = {
        "physical_path": (
            _get(directory, "Path") if directory else parameters.get("physical_path")
        ),
        "application_pool": (
            _get(directory, "AppPoolId")
            if directory
            else parameters.get("application_pool")
        ),
    }
    if directory is not None:
        result["connect_as"] = (
            "specific_user" if _get(directory, "UNCUserName", "") else "pass_through"
        )
    return result


def _binding_spec(parameters):
    protocol = parameters.get("protocol") or "http"
    if protocol not in ("http", "https"):
        raise ValueError(
            "The installed IIS metabase supports only HTTP and HTTPS bindings."
        )
    if str(parameters.get("ssl_flags") or "0") != "0":
        raise ValueError(
            "The installed IIS metabase cannot express SNI or Central Certificate Store bindings."
        )
    header = parameters.get("host_header") or ""
    if header == "*":
        raise ValueError(
            "Omit host_header to select a catch-all binding; '*' is not valid."
        )
    certificate = parameters.get("certificate_hash") or ""
    if certificate and protocol != "https":
        raise ValueError("A certificate thumbprint requires protocol=https.")
    store = parameters.get("certificate_store_name") or ("MY" if certificate else "")
    if certificate:
        from legacy_community_windows_iis import (  # pylint: disable=import-error,import-outside-toplevel
            _certificate_exists,
        )

        _certificate_exists(certificate, store)
    native = "SecureBindings" if protocol == "https" else "ServerBindings"
    binding = "{0}:{1}:{2}".format(
        "" if parameters.get("ip") in (None, "*") else parameters["ip"],
        _port(parameters.get("port", 80)),
        header,
    )
    return {
        "protocol": protocol,
        "header": header,
        "certificate": certificate,
        "store": store,
        "native": native,
        "information": binding,
    }


def _certificate_info(site):
    value = _get(site, "SSLCertHash", []) or []
    return {
        "certificateHash": binascii.hexlify(bytes(value)).decode("ascii").upper(),
        "certificateStoreName": _get(site, "SSLStoreName", "") or "",
    }


def _binding(root, parameters):
    site = _site(root, parameters["name"])
    if site is None:
        raise ValueError("Unable to retrieve website with name " + parameters["name"])
    spec = _binding_spec(parameters)
    bindings = list(_get(site, spec["native"], []) or [])
    match = next(
        (entry for entry in bindings if entry.lower() == spec["information"].lower()),
        None,
    )
    absent, preview = parameters.get("state", "present") == "absent", parameters.get(
        "_ansible_check_mode", False
    )
    if absent and match is None:
        return {"changed": False}
    current = _certificate_info(site)
    changed, operation = False, "matched"
    values = {}
    if absent:
        bindings.remove(match)
        changed, operation = True, "removed"
    elif match is None:
        bindings.append(spec["information"])
        changed, operation = True, "added"
    if changed:
        values[spec["native"]] = bindings
    if spec["protocol"] == "https" and not absent:
        if (
            current["certificateHash"].lower() != spec["certificate"].lower()
            or current["certificateStoreName"].lower() != spec["store"].lower()
        ):
            values["SSLCertHash"] = (
                binascii.unhexlify(spec["certificate"]) if spec["certificate"] else b""
            )
            values["SSLStoreName"] = spec["store"]
            changed = True
            if operation == "matched":
                operation = "updated"
    if not preview:
        _update(site, values)
    info = {
        "bindingInformation": spec["information"],
        "ip": spec["information"].rsplit(":", 2)[0],
        "port": _port(parameters.get("port", 80)),
        "hostheader": spec["header"],
        "protocol": spec["protocol"],
        "certificateHash": (
            current["certificateHash"] if preview or absent else spec["certificate"]
        ),
        "certificateStoreName": (
            current["certificateStoreName"] if preview or absent else spec["store"]
        ),
        "sslFlags": "not supported",
    }
    return {
        "changed": changed,
        "operation_type": operation,
        "website_state": _state(site, None)[1],
        "binding_info": None if preview and operation == "added" else info,
    }


def manage_legacy(automation, module, parameters):
    """Apply only features represented by the installed IIS metabase schema.

    :param automation: Owning native Automation context.
    :type automation: object
    :param module: Released IIS module name.
    :type module: str
    :param parameters: Released IIS module arguments.
    :type parameters: dict
    :returns: Metabase result with upstream-shaped fields.
    :rtype: dict
    :raises OSError: The installed native provider rejects the requested operation.
    """
    root = automation.bind("IIS://localhost/W3SVC")
    if module == "win_iis_webapppool":
        return _pool(automation, parameters)
    if module == "win_iis_website":
        return _website(automation, root, parameters)
    if module == "win_iis_webbinding":
        return _binding(root, parameters)
    return _application(
        automation, root, parameters, module == "win_iis_virtualdirectory"
    )
