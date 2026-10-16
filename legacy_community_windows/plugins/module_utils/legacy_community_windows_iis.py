# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage IIS sites, applications, pools and bindings through native providers."""

# These five interfaces share configuration transactions and native ownership;
# keep the bounded post-commit read beside the lifecycle that owns its result.
# pylint: disable=too-many-lines

import binascii
import ctypes
import ntpath
import os
import re
import subprocess
import xml.etree.ElementTree as ET

from legacy_community_windows_iis_native import (  # pylint: disable=import-error
    IisAutomation,
)
from legacy_windows_module import as_bool, as_string  # pylint: disable=import-error

_APPHOST = "MACHINE/WEBROOT/APPHOST"
_STATES = {
    "win_iis_website": ("absent", "started", "stopped", "restarted"),
    "win_iis_webapppool": ("absent", "present", "started", "stopped", "restarted"),
}


def _items(collection):
    return [collection.call("Item", index) for index in range(collection.get("Count"))]


def _property(element, name):
    return element.get("Properties").call("Item", name)


def _get(element, name):
    return _property(element, name).get("Value")


def _set(element, name, value):
    _property(element, name).put("Value", value)


def _child(element, name):
    return element.get("ChildElements").call("Item", name)


def _find(collection, key, value):
    for index, element in enumerate(_items(collection)):
        if str(_get(element, key)).lower() == str(value).lower():
            return index, element
    return None, None


def _create(collection, tag, values):
    element = collection.call("CreateNewElement", tag)
    for key, value in values.items():
        _set(element, key, value)
    return element


def _name(parameters, key, required=False):
    value = parameters.get(key)
    if value is None or value == "":
        if required:
            raise ValueError("Missing required argument: " + key)
        return None
    value = as_string(value, key)
    if "\x00" in value:
        raise ValueError(key + " cannot contain a null character.")
    return value


def _path(value):
    if not os.path.isdir(value):
        raise ValueError(
            "specified folder must already exist: physical_path ({0})".format(value)
        )
    return os.path.abspath(value)


def _virtual_path(value):
    path = "/" + value.replace("\\", "/").strip("/")
    if path == "/" or any(part in ("", ".", "..") for part in path[1:].split("/")):
        raise ValueError(
            "name must identify a non-root IIS application or virtual directory."
        )
    return path


def _same_path(left, right):
    return ntpath.normcase(ntpath.normpath(left)) == ntpath.normcase(
        ntpath.normpath(right)
    )


def _absent_application(parameters, virtual_directory):
    if virtual_directory:
        return {"directory": {"PhysicalPath": None}}
    return {
        "physical_path": parameters.get("physical_path"),
        "application_pool": parameters.get("application_pool"),
    }


def _equal(current, desired):
    if isinstance(current, bool):
        return current == as_bool(desired, "IIS attribute")
    if isinstance(current, int) and not isinstance(desired, bool):
        try:
            return current == int(desired)
        except (ValueError, TypeError):
            return False
    return str(current).lower() == str(desired).lower()


def _change(element, values):
    changed = False
    for key, desired in values.items():
        current = _get(element, key)
        if not _equal(current, desired):
            _set(element, key, desired)
            changed = True
    return changed


def _credentials(parameters):
    mode = _name(parameters, "connect_as")
    if mode is None:
        return {}
    if mode == "pass_through":
        return {"userName": "", "password": ""}
    if mode != "specific_user":
        raise ValueError("connect_as must be pass_through or specific_user.")
    return {
        "userName": _name(parameters, "username", True),
        "password": _name(parameters, "password", True),
    }


def _port(value):
    try:
        number = int(value)
    except (ValueError, TypeError) as error:
        raise ValueError("port must be an integer.") from error
    if not 1 <= number <= 65535:
        raise ValueError("port must be between 1 and 65535.")
    return number


def _parameters(value):
    result = {}
    if value:
        for entry in value.split("|"):
            key, separator, item = entry.partition(":")
            if not key or not separator:
                raise ValueError("parameters entries must use property:value syntax.")
            result[key] = item
    return result


class AppHost:
    """Apply one validated IIS configuration transaction with native AppHost COM.

    :param automation: Owning initialized IIS Automation context.
    """

    def __init__(self, automation):
        self.manager = automation.create(
            "Microsoft.ApplicationHost.WritableAdminManager"
        )
        self.manager.put("CommitPath", _APPHOST)
        self.sites = self.manager.call(
            "GetAdminSection", "system.applicationHost/sites", _APPHOST
        ).get("Collection")
        self.pools_section = self.manager.call(
            "GetAdminSection", "system.applicationHost/applicationPools", _APPHOST
        )
        self.pools = self.pools_section.get("Collection")
        self.changed = False
        self.created = False

    def commit(self, preview):
        """Commit all pending validated changes unless this is check mode.

        :param preview: Whether changes are predicted without committing.
        :type preview: bool
        """
        if self.changed and not preview:
            self.manager.call("CommitChanges")

    def site(self, name):
        """Return a site or fail without modifying configuration.

        :param name: Native property, method, site or pool name.
        :type name: str
        :returns: Matching native site element.
        :rtype: object
        :raises OSError: The installed native provider rejects the requested operation.
        :raises ValueError: An argument or requested feature cannot be represented.
        """
        site = _find(self.sites, "name", name)[1]
        if site is None:
            raise ValueError("Unable to retrieve website with name " + name)
        return site

    def pool(self, name):
        """Verify a requested application pool exists before editing a site.

        :param name: Native property, method, site or pool name.
        :type name: str
        :raises OSError: The installed native provider rejects the requested operation.
        :raises ValueError: An argument or requested feature cannot be represented.
        """
        if _find(self.pools, "name", name)[1] is None:
            raise ValueError("Unable to retrieve application pool with name " + name)

    def root_application(self, site):
        """Return a site's root application element.

        :param site: Native site configuration element.
        :type site: object
        :returns: Root application configuration element.
        :rtype: object
        :raises OSError: The installed native provider rejects the requested operation.
        :raises ValueError: An argument or requested feature cannot be represented.
        """
        element = _find(site.get("Collection"), "path", "/")[1]
        if element is None:
            raise ValueError("The website has no root application.")
        return element

    def root_directory(self, application):
        """Return an application's root virtual directory element.

        :param application: Native application configuration element.
        :type application: object
        :returns: Root virtual directory configuration element.
        :rtype: object
        :raises OSError: The installed native provider rejects the requested operation.
        :raises ValueError: An argument or requested feature cannot be represented.
        """
        element = _find(application.get("Collection"), "path", "/")[1]
        if element is None:
            raise ValueError("The application has no root virtual directory.")
        return element

    def _create_site(self, parameters, path, pool):
        if not path:
            raise ValueError("Missing required argument: physical_path")
        occupied = [int(_get(item, "id")) for item in _items(self.sites)]
        try:
            identifier = int(parameters.get("site_id") or max(occupied + [0]) + 1)
        except (ValueError, TypeError) as error:
            raise ValueError("site_id must be a positive integer.") from error
        if identifier < 1 or identifier in occupied:
            raise ValueError("site_id must be positive and not already in use.")
        site = _create(
            self.sites, "site", {"name": parameters["name"], "id": identifier}
        )
        apps = site.get("Collection")
        application = _create(apps, "application", {"path": "/"})
        directories = application.get("Collection")
        directories.call(
            "AddElement",
            _create(
                directories, "virtualDirectory", {"path": "/", "physicalPath": path}
            ),
        )
        if pool:
            _set(application, "applicationPool", pool)
        apps.call("AddElement", application)
        binding_collection = _child(site, "bindings").get("Collection")
        binding_collection.call(
            "AddElement",
            _create(
                binding_collection,
                "binding",
                {
                    "protocol": "http",
                    "bindingInformation": "{0}:{1}:{2}".format(
                        parameters.get("ip") or "*",
                        _port(parameters.get("port") or 80),
                        parameters.get("hostname") or "",
                    ),
                },
            ),
        )
        self.sites.call("AddElement", site)
        return site

    def website(self, parameters):
        """Manage a site and return its observable upstream-shaped properties.

        :param parameters: Released IIS module arguments.
        :type parameters: dict
        :returns: Native operation result.
        :rtype: dict
        :raises OSError: The installed native provider rejects the requested operation.
        :raises ValueError: An argument or requested feature cannot be represented.
        """
        name, state = parameters["name"], parameters.get("state")
        index, site = _find(self.sites, "name", name)
        if state == "absent":
            if site is not None:
                self.sites.call("DeleteElement", index)
                self.changed = True
            return {"site": {}}
        path = _name(parameters, "physical_path")
        path = _path(path) if path else None
        pool = _name(parameters, "application_pool")
        if pool:
            self.pool(pool)
        if site is None:
            site = self._create_site(parameters, path, pool)
            self.changed, self.created = True, True
        application = self.root_application(site)
        if path:
            current = _get(self.root_directory(application), "physicalPath")
            if ntpath.normcase(ntpath.normpath(current)) != ntpath.normcase(
                ntpath.normpath(path)
            ):
                _set(self.root_directory(application), "physicalPath", path)
                self.changed = True
        if pool:
            self.changed = (
                _change(application, {"applicationPool": pool}) or self.changed
            )
        for key, value in _parameters(parameters.get("parameters")).items():
            self.changed = _attribute(site, key, value) or self.changed
        return {
            "site": {
                "Name": _get(site, "name"),
                "ID": _get(site, "id"),
                "PhysicalPath": _get(self.root_directory(application), "physicalPath"),
                "ApplicationPool": _get(application, "applicationPool"),
                "Bindings": [
                    _get(item, "bindingInformation")
                    for item in _items(_child(site, "bindings").get("Collection"))
                ],
            }
        }

    def _application_collection(self, parameters, virtual_directory):
        site = self.site(parameters["site"])
        parent = self.root_application(site)
        if not virtual_directory:
            return parent, site.get("Collection")
        if parameters.get("application"):
            parent = _find(
                site.get("Collection"), "path", _virtual_path(parameters["application"])
            )[1]
            if parent is None:
                raise ValueError("The requested parent application does not exist.")
        return parent, parent.get("Collection")

    def _create_application(self, collection, tag, path, physical_path):
        if not physical_path:
            raise ValueError("Missing required argument: physical_path")
        element = _create(collection, tag, {"path": path})
        if tag == "virtualDirectory":
            _set(element, "physicalPath", physical_path)
        else:
            directories = element.get("Collection")
            directories.call(
                "AddElement",
                _create(
                    directories,
                    "virtualDirectory",
                    {"path": "/", "physicalPath": physical_path},
                ),
            )
        collection.call("AddElement", element)
        self.changed = True
        return element

    def application(self, parameters, virtual_directory=False):
        """Manage an application or virtual directory within an existing site.

        :param parameters: Released module arguments.
        :type parameters: dict
        :param virtual_directory: Manage a virtual directory instead of an application.
        :type virtual_directory: bool
        :returns: Upstream application or directory fields.
        :rtype: dict
        :raises ValueError: The parent or requested path is invalid.
        """
        parent, collection = self._application_collection(parameters, virtual_directory)
        index, element = _find(collection, "path", _virtual_path(parameters["name"]))
        existed = element is not None
        before = (
            _application_info(element, self.root_directory(element))
            if (
                existed
                and not virtual_directory
                and parameters.get("_ansible_check_mode")
            )
            else None
        )
        if parameters.get("state", "present") == "absent":
            if existed:
                collection.call("DeleteElement", index)
                self.changed = True
            return _absent_application(parameters, virtual_directory)
        physical_path = _name(parameters, "physical_path")
        physical_path = _path(physical_path) if physical_path else None
        pool = _name(parameters, "application_pool")
        if not virtual_directory:
            pool = pool or _get(parent, "applicationPool")
            if pool:
                self.pool(pool)
        if not existed:
            element = self._create_application(
                collection,
                "virtualDirectory" if virtual_directory else "application",
                _virtual_path(parameters["name"]),
                physical_path,
            )
        directory = element if virtual_directory else self.root_directory(element)
        if physical_path and not _same_path(
            _get(directory, "physicalPath"), physical_path
        ):
            _set(directory, "physicalPath", physical_path)
            self.changed = True
        self.changed = _change(directory, _credentials(parameters)) or self.changed
        if virtual_directory:
            return {"directory": {"PhysicalPath": _get(directory, "physicalPath")}}
        if pool:
            self.changed = _change(element, {"applicationPool": pool}) or self.changed
        if parameters.get("_ansible_check_mode") and not existed:
            return _absent_application(parameters, False)
        return before if before is not None else _application_info(element, directory)

    def app_pool(self, parameters):
        """Manage pool attributes atomically, including nested schedule collections.

        :param parameters: Released IIS module arguments.
        :type parameters: dict
        :returns: Native operation result.
        :rtype: dict
        :raises OSError: The installed native provider rejects the requested operation.
        :raises ValueError: An argument or requested feature cannot be represented.
        """
        name, state = parameters["name"], parameters.get("state", "present")
        attributes = parameters.get("attributes") or {}
        if not isinstance(attributes, dict):
            raise ValueError("attributes must be a dictionary.")
        index, pool = _find(self.pools, "name", name)
        existing = pool is not None
        before = (
            _pool_configuration(pool, name, state)
            if (existing and parameters.get("_ansible_check_mode"))
            else None
        )
        if state == "absent":
            if existing:
                self.pools.call("DeleteElement", index)
                self.changed = True
            pool = None
        else:
            if pool is None:
                pool = _create(self.pools, "add", {"name": name})
                self.pools.call("AddElement", pool)
                self.changed = True
                self.created = True
            for key, value in attributes.items():
                # New scalar properties report schema, not inherited defaults.
                # Persist explicit values even when equal to a schema default.
                changed = _attribute(pool, key, value, force_scalar=not existing)
                self.changed = changed or self.changed
        info = (
            before
            if before is not None
            else _pool_configuration(
                pool if existing or not parameters.get("_ansible_check_mode") else None,
                name,
                state,
            )
        )
        return _pool_result(attributes, info)

    def binding(self, parameters):
        """Manage precisely one protocol/address/port/header binding.

        :param parameters: Released IIS module arguments.
        :type parameters: dict
        :returns: Native operation result.
        :rtype: dict
        :raises OSError: The installed native provider rejects the requested operation.
        :raises ValueError: An argument or requested feature cannot be represented.
        """
        site = self.site(parameters["name"])
        spec = _binding_parameters(parameters)
        collection = _child(site, "bindings").get("Collection")
        index, binding = _find_binding(collection, spec)
        absent = parameters.get("state", "present") == "absent"
        if absent and binding is None:
            return {}
        operation = "matched"
        if absent:
            result = _binding_info(binding, parameters)
            collection.call("DeleteElement", index)
            self.changed = True
            return {"operation_type": "removed", "binding_info": result}
        before = (
            _binding_info(binding, parameters)
            if (binding is not None and parameters.get("_ansible_check_mode"))
            else None
        )
        new = binding is None
        if new:
            binding = _create(
                collection,
                "binding",
                {
                    "protocol": spec["protocol"],
                    "bindingInformation": spec["information"],
                },
            )
        # A missing native schema attribute is the capability test for SNI/CCS.
        try:
            supported = _property(binding, "sslFlags")
        except OSError:
            supported = None
        if supported is None and int(spec["flags"]):
            raise ValueError(
                "The installed IIS binding schema does not support SNI "
                "or Central Certificate Store."
            )
        if supported is not None and not _equal(supported.get("Value"), spec["flags"]):
            supported.put("Value", spec["flags"])
            self.changed = True
        if spec["certificate"]:
            _certificate_exists(spec["certificate"], spec["store"])
        # SSL endpoint updates run after the configuration transaction commits.
        ssl = (
            _ssl_binding(
                parameters,
                spec["certificate"],
                spec["store"],
                spec["flags"],
                query=True,
            )
            if spec["protocol"] == "https"
            else {}
        )
        if spec["protocol"] == "https" and (
            ssl.get("certificateHash", "").lower() != spec["certificate"].lower()
            or ssl.get("certificateStoreName", "").lower() != spec["store"].lower()
            or int(spec["flags"]) > 1
            and not ssl.get("_exists", False)
        ):
            self.changed = True
            parameters["_ssl_update"] = (
                spec["certificate"],
                spec["store"],
                spec["flags"],
            )
        if new:
            collection.call("AddElement", binding)
            self.changed = True
        if new:
            operation = "added"
        elif self.changed:
            operation = "updated"
        result = before if before is not None else _binding_info(binding, parameters)
        if not parameters.get("_ansible_check_mode"):
            result.update(
                {
                    "certificateHash": spec["certificate"],
                    "certificateStoreName": spec["store"],
                }
            )
        return {
            "operation_type": operation,
            "binding_info": (
                None if new and parameters.get("_ansible_check_mode") else result
            ),
        }


def _find_binding(collection, spec):
    for position, item in enumerate(_items(collection)):
        if _equal(_get(item, "protocol"), spec["protocol"]) and _equal(
            _get(item, "bindingInformation"), spec["information"]
        ):
            return position, item
    return None, None


def _binding_parameters(parameters):
    protocol = parameters.get("protocol") or "http"
    header = parameters.get("host_header") or ""
    if header == "*":
        raise ValueError(
            "Omit host_header to select a catch-all binding; '*' is not valid."
        )
    flags = str(parameters.get("ssl_flags") or "0")
    if flags not in ("0", "1", "2", "3"):
        raise ValueError("ssl_flags must be 0, 1, 2 or 3.")
    if protocol != "https" and int(flags):
        raise ValueError("ssl_flags can only be set for HTTPS protocol.")
    certificate = parameters.get("certificate_hash") or ""
    store = parameters.get("certificate_store_name") or ("my" if certificate else "")
    if certificate and protocol != "https":
        raise ValueError("A certificate thumbprint requires protocol=https.")
    if int(flags) > 1 and (certificate or store):
        raise ValueError(
            "Central Certificate Store flags cannot be combined with certificate parameters."
        )
    information = "{0}:{1}:{2}".format(
        parameters.get("ip") or "*", _port(parameters.get("port", 80)), header
    )
    return {
        "protocol": protocol,
        "header": header,
        "flags": flags,
        "certificate": certificate,
        "store": store,
        "information": information,
    }


def _pool_info(name, state):
    return {
        "name": name,
        "state": state,
        "attributes": {},
        "cpu": {},
        "failure": {},
        "processModel": {},
        "recycling": {"periodicRestart": {}},
    }


def _pool_result(attributes, info):
    # Nested password attributes must never be echoed back to the controller.
    return {
        "attributes": {
            key: value
            for key, value in attributes.items()
            if "password" not in key.lower()
        },
        "info": info,
    }


def _pool_configuration(pool, name, state):
    info = _pool_info(name, state)
    if pool is not None:
        info["attributes"] = _properties(pool)
        for key in ("cpu", "failure", "processModel", "recycling"):
            info[key] = _properties(_child(pool, key))
        info["recycling"]["periodicRestart"] = _properties(
            _child(_child(pool, "recycling"), "periodicRestart")
        )
    return info


def _application_info(element, directory):
    return {
        "physical_path": _get(directory, "physicalPath"),
        "application_pool": _get(element, "applicationPool"),
        "connect_as": (
            "specific_user" if _get(directory, "userName") else "pass_through"
        ),
    }


def _properties(element):
    result = {}
    for attribute in _items(element.get("Properties")):
        name = attribute.get("Name")
        # AppHost also exposes a runtime-only state extension. It cannot be
        # read for an uncommitted new pool and is not a configuration attribute.
        if "password" not in name.lower() and name.lower() != "state":
            try:
                kind = attribute.get("Schema").get("Type")
                result[name] = attribute.get(
                    "StringValue" if kind in ("enum", "flags", "timeSpan") else "Value"
                )
            except OSError as error:
                raise OSError(
                    "Reading IIS attribute {0}: {1}".format(name, error)
                ) from error
    return result


def _attribute(element, path, value, force_scalar=False):
    if (
        not isinstance(path, str)
        or not path
        or any(not part for part in path.split("."))
    ):
        raise ValueError("IIS attribute names must be non-empty dotted paths.")
    parts = path.split(".")
    for part in parts[:-1]:
        element = _child(element, part)
    if isinstance(value, dict) and "Value" in value:
        value = value["Value"]
    try:
        attribute = _property(element, parts[-1])
    except OSError:
        attribute = None
    if attribute is not None:
        if attribute.get("Schema").get("Type") == "timeSpan" and isinstance(value, str):
            value = _duration_text(value)
        current = attribute.get("Value")
        # StringValue preserves enum labels while Value can be their integer.
        if not force_scalar and (
            _equal(current, value) or _equal(attribute.get("StringValue"), value)
        ):
            return False
        try:
            attribute.put("Value", value)
        except OSError as error:
            raise OSError(
                "Setting IIS attribute {0}: {1}".format(path, error)
            ) from error
        return True
    collection = _child(element, parts[-1]).get("Collection")
    values = (
        value
        if isinstance(value, list)
        else [item.strip() for item in str(value).split(",")]
    )
    current = [
        _property(item, "value").get("StringValue") for item in _items(collection)
    ]
    if len(current) == len(values) and all(
        _equal(left, right) for left, right in zip(current, values)
    ):
        return False
    replacements = [_create(collection, "add", {"value": item}) for item in values]
    collection.call("Clear")
    for replacement in replacements:
        collection.call("AddElement", replacement)
    return True


def _duration_text(value):
    fields = value.split(":")
    if len(fields) == 4:
        fields = [str(int(fields[0]) * 24 + int(fields[1]))] + fields[2:]
    if len(fields) == 3:
        if "." in fields[0]:
            days, hours = fields[0].split(".", 1)
            fields[0] = str(int(days) * 24 + int(hours))
        second, separator, fraction = fields[-1].partition(".")
        if separator and fraction and not fraction.strip("0"):
            fields[-1] = second
        fields[0] = fields[0].zfill(2)
        return ":".join(fields)
    return value


def _appcmd():
    root = os.environ.get("SystemRoot", r"C:\Windows")
    for folder in ("Sysnative", "System32"):
        filename = os.path.join(root, folder, "inetsrv", "appcmd.exe")
        if os.path.isfile(filename):
            return filename
    raise OSError(
        "IIS native AppCmd management tools are required for runtime state operations."
    )


def _run(arguments):
    with subprocess.Popen(
        arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ) as process:
        stdout, stderr = process.communicate()
        code = process.returncode
    if code:
        detail = (stderr or stdout).decode("utf-8", "replace").strip()
        raise OSError(
            "IIS native management command failed ({0}): {1}".format(code, detail)
        )
    return stdout


def _runtime_state(kind, name):
    xml = ET.fromstring(_run([_appcmd(), "list", kind, name, "/xml"]))
    entry = xml.find(kind.upper())
    return entry.get("state", "Unknown") if entry is not None else None


def _state(kind, name, desired, preview):
    current = _runtime_state(kind, name)
    changed = (
        desired == "restarted"
        or desired == "started"
        and current == "Stopped"
        or desired == "stopped"
        and current == "Started"
    )
    if changed and not preview:
        if desired == "restarted" and kind == "apppool" and current == "Started":
            _run([_appcmd(), "recycle", kind, name])
        else:
            if current == "Started" and desired in ("restarted", "stopped"):
                _run([_appcmd(), "stop", kind, name])
            if desired in ("restarted", "started"):
                _run([_appcmd(), "start", kind, name])
        current = _runtime_state(kind, name)
    return changed, current


def _binding_info(binding, parameters):
    information = _get(binding, "bindingInformation")
    ip, port, header = information.rsplit(":", 2)
    result = {
        "bindingInformation": information,
        "ip": ip,
        "port": int(port),
        "hostheader": header,
        "protocol": _get(binding, "protocol"),
        "certificateHash": "",
        "certificateStoreName": "",
    }
    try:
        result["sslFlags"] = int(_get(binding, "sslFlags"))
    except OSError:
        result["sslFlags"] = "not supported"
    if result["protocol"] == "https":
        flags = result["sslFlags"] if result["sslFlags"] != "not supported" else 0
        current = _ssl_binding(parameters, "", "", str(flags), query=True)
        result.update(
            {key: current[key] for key in ("certificateHash", "certificateStoreName")}
        )
    return result


def _certificate_exists(thumbprint, store):
    if not re.match(r"^[0-9a-fA-F]{40}$", thumbprint):
        raise ValueError("certificate_hash must be a 40-character SHA-1 thumbprint.")
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    pointer = ctypes.c_void_p
    crypt.CertOpenStore.argtypes = [
        pointer,
        ctypes.c_uint32,
        pointer,
        ctypes.c_uint32,
        pointer,
    ]
    crypt.CertOpenStore.restype = pointer
    crypt.CertFindCertificateInStore.argtypes = [
        pointer,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        pointer,
        pointer,
    ]
    crypt.CertFindCertificateInStore.restype = pointer
    crypt.CertFreeCertificateContext.argtypes = [pointer]
    crypt.CertFreeCertificateContext.restype = ctypes.c_int32
    crypt.CertCloseStore.argtypes = [pointer, ctypes.c_uint32]
    crypt.CertCloseStore.restype = ctypes.c_int32

    class _HashBlob(ctypes.Structure):  # pylint: disable=too-few-public-methods
        _fields_ = [("size", ctypes.c_uint32), ("data", pointer)]

    data = ctypes.create_string_buffer(binascii.unhexlify(thumbprint))
    blob = _HashBlob(20, ctypes.cast(data, pointer))
    name = ctypes.create_unicode_buffer(store)
    handle = crypt.CertOpenStore(10, 0, None, 0x00028000, ctypes.byref(name))
    if not handle:
        raise ctypes.WinError()
    try:
        certificate = crypt.CertFindCertificateInStore(
            handle, 0x00010001, 0, 0x00010000, ctypes.byref(blob), None
        )
        if not certificate:
            raise ValueError(
                "Unable to locate certificate in LocalMachine\\{0}: {1}".format(
                    store, thumbprint
                )
            )
        crypt.CertFreeCertificateContext(certificate)
    finally:
        crypt.CertCloseStore(handle, 0)


def _ssl_binding(parameters, certificate, store, flags, query=False):
    # HTTP.sys endpoint bindings are independent of the IIS site collection.
    # The dedicated native API helper handles exact endpoints without parsing
    # localized netsh output or touching another site's certificate bindings.
    from legacy_community_windows_iis_ssl import (  # pylint: disable=import-error,import-outside-toplevel
        endpoint,
    )

    return endpoint(parameters, certificate, store, flags, query)


def _manage(module, parameters):
    """Execute one released IIS interface against the installed native provider.

    :param module: Released IIS module name.
    :type module: str
    :param parameters: Released IIS module arguments.
    :type parameters: dict
    :returns: Upstream-shaped result fields and an accurate changed flag.
    :rtype: dict
    :raises OSError: The installed native provider rejects the requested operation.
    :raises ValueError: An argument or requested feature cannot be represented.
    """
    parameters = dict(parameters)
    if module == "win_iis_webbinding" and "name" not in parameters:
        parameters["name"] = parameters.get("website")
    if module == "win_iis_webapplication" and "physical_path" not in parameters:
        parameters["physical_path"] = parameters.get("path")
    parameters["name"] = _name(parameters, "name", True)
    state = parameters.get("state", None if module == "win_iis_website" else "present")
    if state is not None and state not in _STATES.get(module, ("absent", "present")):
        raise ValueError("Invalid state for " + module)
    preview = as_bool(
        parameters.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    if preview and module in ("win_iis_website", "win_iis_virtualdirectory"):
        return {
            "changed": False,
            "skipped": True,
            "msg": "The released interface does not support check mode.",
        }
    if module in ("win_iis_webapplication", "win_iis_virtualdirectory"):
        parameters["site"] = _name(parameters, "site", True)
    with IisAutomation() as automation:
        try:
            backend = AppHost(automation)
        except OSError as error:
            if getattr(error, "hresult", None) not in (0x80040154, 0x800401F3):
                raise
            from legacy_community_windows_iis_legacy import (  # pylint: disable=import-error,import-outside-toplevel
                manage_legacy,
            )

            return manage_legacy(automation, module, parameters)
        return _manage_apphost(backend, module, parameters, preview)


def manage(module, parameters):
    """Manage native IIS configuration without exposing supplied passwords.

    :param module: Released IIS interface name.
    :type module: str
    :param parameters: WANT_JSON arguments.
    :type parameters: dict
    :returns: Upstream-shaped configuration result and changed flag.
    :rtype: dict
    :raises OSError: The native provider rejects an operation.
    :raises ValueError: Arguments or requested features are invalid.
    """
    try:
        return _manage(module, parameters)
    except (OSError, ValueError) as error:
        message = str(error)
        secrets = [parameters.get("password")]
        attributes = parameters.get("attributes")
        if isinstance(attributes, dict):
            secrets.extend(
                value for key, value in attributes.items() if "password" in key.lower()
            )
        for secret in secrets:
            if isinstance(secret, str) and secret:
                message = message.replace(secret, "[redacted]")
        if message == str(error):
            raise
        if isinstance(error, OSError):
            raise OSError(message) from None
        raise ValueError(message) from None


def _manage_apphost(backend, module, parameters, preview):
    state = parameters.get("state", None if module == "win_iis_website" else "present")
    if module == "win_iis_website":
        result = backend.website(parameters)
    elif module == "win_iis_webapppool":
        result = backend.app_pool(parameters)
    elif module == "win_iis_webbinding":
        result = backend.binding(parameters)
    else:
        result = backend.application(parameters, module == "win_iis_virtualdirectory")
    backend.commit(preview)
    if module == "win_iis_webapppool" and backend.created and not preview:
        # The creating manager retains schema defaults even after committing.
        with IisAutomation() as automation:
            committed = AppHost(automation)
            pool = _find(committed.pools, "name", parameters["name"])[1]
            result["info"] = _pool_configuration(pool, parameters["name"], state)
    if module in ("win_iis_website", "win_iis_webapppool") and state != "absent":
        kind = "site" if module == "win_iis_website" else "apppool"
        # A check-mode-only creation has no runtime object to query.
        if not (preview and backend.created):
            changed, current = _state(kind, parameters["name"], state, preview)
            backend.changed = backend.changed or changed
            if module == "win_iis_website":
                result["site"]["State"] = current
            else:
                result["info"]["attributes"]["state"] = current
    if module == "win_iis_webbinding":
        if parameters.get("_ssl_update") and not preview:
            _ssl_binding(parameters, *parameters["_ssl_update"])
        if state != "absent" or result:
            result["website_state"] = _runtime_state("site", parameters["name"])
    result["changed"] = backend.changed
    return result
