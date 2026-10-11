#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage existing Windows certificates with a Python 3.4.4 payload."""

# WANT_JSON

import errno
import os

import legacy_windows_certificate_store as certificates  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_path,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_certificate_store
short_description: Import, export and remove certificates from Windows stores
version_added: '1.0.0'
description:
  - Manages existing certificates and associated private keys through native Windows APIs.
  - Imports PEM, DER, PKCS7 and PKCS12 files and exports DER, PEM and PKCS12 files.
  - Does not create certificates and requires input files on the Windows target.
options:
  state:
    description:
      - C(present) imports certificates from O(path).
      - C(absent) removes certificates selected by O(path), or by O(thumbprint) when no path is supplied.
      - C(exported) writes the certificate selected by O(thumbprint) to O(path).
    type: str
    choices: [absent, exported, present]
    default: present
  path:
    description:
      - Target certificate file to import, export or use as a removal selector.
      - Required for C(present) and C(exported).
    type: path
  thumbprint:
    description:
      - SHA-1 hexadecimal certificate selector for removal or export.
      - Required for C(exported).
    type: str
  store_name:
    description:
      - Name of an existing certificate store, such as C(My), C(Root), or a custom name.
      - C(CertificateAuthority) is mapped to the native C(CA) store.
    type: str
    default: My
  store_location:
    description:
      - C(CurrentUser) or C(LocalMachine) for system stores.
      - Windows service name when O(store_type=service).
    type: str
    default: LocalMachine
  store_type:
    description:
      - Select an existing system store or a service-account store.
      - Missing standard service-store registrations are created before opening the requested store.
    type: str
    choices: [service, system]
    default: system
  password:
    description:
      - Optional password for loading or exporting a PKCS12 file.
    type: str
  key_exportable:
    description:
      - Allow later export of private keys imported from an input PKCS12 file.
      - Does not change the export policy of an already imported certificate.
    type: bool
    default: true
  key_storage:
    description:
      - Native private-key container scope for PKCS12 imports.
      - C(default) follows the input file and Windows defaults.
    type: str
    choices: [default, machine, user]
    default: default
  file_type:
    description:
      - Encoding used when O(state=exported).
      - PKCS12 exports include an associated exportable private key when available.
    type: str
    choices: [der, pem, pkcs12]
    default: der
attributes:
  check_mode:
    support: full
    description:
      - Predicts certificate-store changes and suppresses exported file writes.
      - Matching the pinned source, reading PKCS12 inputs can persist keys even in check mode.
      - An existing export destination can be removed before serialization, including in check mode.
  diff_mode:
    support: none
notes:
  - Removing a certificate does not remove its persisted private-key container.
  - Export may remove the existing destination before a later serialization or file-write failure.
  - Native provider availability and private-key permissions can prevent PKCS12 operations.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Import a target certificate file
  sustainablelobster.legacy_windows.win_certificate_store:
    path: C:\Temp\application.pfx
    password: '{{ certificate_password }}'
    key_storage: machine

- name: Export a certificate without its private key
  sustainablelobster.legacy_windows.win_certificate_store:
    state: exported
    thumbprint: BD7AF104CF1872BDB518D95C9534EA941665FD27
    path: C:\Temp\application.pem
    file_type: pem

- name: Remove a selected certificate
  sustainablelobster.legacy_windows.win_certificate_store:
    state: absent
    thumbprint: BD7AF104CF1872BDB518D95C9534EA941665FD27
"""

RETURN = r"""
thumbprints:
  description: Selected certificate thumbprints in input or selection order, including already absent certificates.
  returned: success
  type: list
  elements: str
key_exported:
  description: The pinned source returns false after a successful new PKCS12 serialization, even when its key is included.
  returned: when a PKCS12 export is serialized rather than already matching
  type: bool
key_exportable:
  description: Whether the serialized PKCS12 certificate's associated key permits export.
  returned: when a PKCS12 export is serialized and the certificate has a private key
  type: bool
"""

_MODULE = "sustainablelobster.legacy_windows.win_certificate_store"
_DEFAULTS = {
    "state": "present",
    "path": None,
    "thumbprint": None,
    "store_name": "My",
    "store_location": "LocalMachine",
    "store_type": "system",
    "password": None,
    "key_exportable": True,
    "key_storage": "default",
    "file_type": "der",
}
_CHOICES = {
    "state": ("absent", "exported", "present"),
    "store_type": ("service", "system"),
    "key_storage": ("default", "machine", "user"),
    "file_type": ("der", "pem", "pkcs12"),
}


def _parameters(arguments):
    parameters = {
        name: as_string(arguments.get(name, default), name)
        for name, default in _DEFAULTS.items()
        if name not in ("path", "key_exportable")
    }
    parameters["path"] = as_path(arguments.get("path"), "path")
    exportable = arguments.get("key_exportable", True)
    parameters["key_exportable"] = (
        False if exportable is None else as_bool(exportable, "key_exportable")
    )
    for name, choices in _CHOICES.items():
        value = parameters[name]
        if value is not None and value.lower() not in choices:
            raise ValueError(
                "value of {0} must be one of: {1}. Got no match for: {2}".format(
                    name, ", ".join(choices), value
                )
            )
    state = parameters["state"]
    required = ("path", "thumbprint") if state == "exported" else ("path",)
    if state in ("present", "exported"):
        missing = [name for name in required if name not in arguments]
        if missing:
            raise ValueError(
                "state is {0} but all of the following are missing: {1}".format(
                    state, ", ".join(missing)
                )
            )
    if state == "absent" and "path" not in arguments and "thumbprint" not in arguments:
        raise ValueError(
            "state is absent but any of the following are missing: path, thumbprint"
        )
    for name in _CHOICES:
        if parameters[name] is not None:
            parameters[name] = parameters[name].lower()
    if (
        parameters["store_name"] is not None
        and parameters["store_name"].lower() == "certificateauthority"
    ):
        parameters["store_name"] = "CA"
    return parameters


def _failure(result, message, exception=False):
    result.update(failed=True, msg=message)
    if exception:
        result["exception"] = "(traceback unavailable)"
    return result


def _read(parameters, result):
    path = parameters["path"]
    if not os.path.isfile(path):
        _failure(
            result, "File at '" + path + "' either does not exist or is not a file"
        )
        return None
    try:
        return certificates.read_file(
            path,
            parameters["password"],
            parameters["key_exportable"],
            parameters["key_storage"],
        )
    except OSError as error:
        _failure(
            result,
            'Failed to load cert from file: Exception calling "Import" with '
            '"3" argument(s): "' + error.strerror + '"',
            True,
        )
        return None


def _absent(store, parameters, result, check_mode):
    if parameters["path"] is not None:
        loaded = _read(parameters, result)
        if loaded is None:
            return result
        with loaded:
            selected = [record["thumbprint"] for record in loaded.records]
    elif parameters["thumbprint"] is not None:
        selected = [parameters["thumbprint"]]
    else:
        selected = []
    for thumbprint in selected:
        result["thumbprints"].append(thumbprint)
        for record in certificates.matches(store.records, thumbprint):
            try:
                if not check_mode:
                    store.remove(record)
            except OSError as error:
                return _failure(
                    result,
                    "Unable to remove cert with thumbprint '"
                    + thumbprint
                    + "': "
                    + error.strerror,
                    True,
                )
            result["changed"] = True
    return result


def _present(store, parameters, result, check_mode):
    loaded = _read(parameters, result)
    if loaded is None:
        return result
    with loaded:
        for record in loaded.records:
            thumbprint = record["thumbprint"]
            result["thumbprints"].append(thumbprint)
            existing = certificates.matches(store.records, thumbprint)
            force = record["has_private_key"] and any(
                not previous["has_private_key"] for previous in existing
            )
            if not existing or force:
                try:
                    if not check_mode:
                        store.add(record)
                except OSError as error:
                    return _failure(
                        result,
                        "Unable to import certificate with thumbprint '"
                        + thumbprint
                        + "' with the current permissions: "
                        + error.strerror,
                        True,
                    )
                result["changed"] = True
    return result


def _file_type(parameters):
    try:
        with certificates.read_file(
            parameters["path"], parameters["password"], False, "default", persist=False
        ) as loaded:
            records = loaded.records
            with open(parameters["path"], "rb") as stream:
                prefix = stream.read(28)
            kind = "der"
            if prefix.startswith(b"-----BEGIN CERTIFICATE-----"):
                kind = "pem"
            elif prefix.startswith(b"-----BEGIN PKCS7-----"):
                kind = "pkcs7-ascii"
            elif len(records) > 1:
                kind = "pkcs7-binary"
            elif (records and records[0]["has_private_key"]) or parameters[
                "path"
            ].endswith((".pfx", ".p12")):
                kind = "pkcs12"
            return kind
    except OSError:
        # The source assumes any cryptographic decoding failure is a wrong PFX password.
        return "pkcs12"
    except NotImplementedError:
        # CryptoAPI already identified a PFX, but XP cannot import it ephemerally.
        # The source also recognizes these suffixes without requiring a key.
        return "pkcs12" if parameters["path"].endswith((".pfx", ".p12")) else "unknown"
    except Exception:  # pylint: disable=broad-exception-caught
        return "unknown"


def _write_export(path, data, result):
    try:
        with open(path, "wb") as stream:
            stream.write(data)
    except OSError as error:
        code = getattr(error, "winerror", error.errno)
        if code == 3 or error.errno == errno.ENOENT:
            category, detail = (
                "due to IO Exception",
                "Could not find a part of the path '" + os.path.abspath(path) + "'.",
            )
        elif code == 5 or error.errno == errno.EACCES:
            category, detail = (
                "due to permissions",
                "Access to the path '" + os.path.abspath(path) + "' is denied.",
            )
        else:
            category, detail = "due to IO Exception", error.strerror
        _failure(
            result,
            "Failed to write cert to file " + category + ": " + detail,
            True,
        )


def _matching_export_file(parameters, result):
    path = parameters["path"]
    if not os.path.isfile(path) or _file_type(parameters) != parameters["file_type"]:
        return False
    loaded = _read(parameters, result)
    if loaded is None:
        return False
    with loaded:
        return any(
            record["thumbprint"].lower() == parameters["thumbprint"].lower()
            for record in loaded.records
        )


def _export(store, parameters, result, check_mode):
    path, thumbprint = parameters["path"], parameters["thumbprint"]
    result["thumbprints"].append(thumbprint)
    if os.path.isdir(path):
        return _failure(
            result, "Cannot export cert to path '" + path + "' as it is a directory"
        )
    if _matching_export_file(parameters, result) or result.get("failed"):
        return result
    selected = certificates.matches(store.records, thumbprint)
    if len(selected) != 1:
        return _failure(
            result, "Found {0} certs when only expecting 1".format(len(selected))
        )
    if os.path.lexists(path):
        os.remove(path)
        result["changed"] = True
    record = selected[0]
    try:
        data = certificates.export_certificate(
            record, parameters["file_type"], parameters["password"]
        )
    except OSError as error:
        return _failure(
            result,
            "Failed to export certificate as bytes: Exception calling "
            '"Export" with "2" argument(s): "' + error.strerror + '"',
            True,
        )
    if parameters["file_type"] == "pkcs12":
        result["key_exported"] = False
        if record["has_private_key"]:
            result["key_exportable"] = certificates.key_exportable(record)
    if not check_mode:
        _write_export(path, data, result)
        if result.get("failed"):
            return result
    result["changed"] = True
    return result


def _manage(parameters, result, check_mode):
    location = parameters["store_location"]
    if parameters["store_type"] == "system":
        if location is None or location.lower() not in ("currentuser", "localmachine"):
            return _failure(
                result,
                "value of store_location must be one of: CurrentUser, LocalMachine. "
                "Got no match for: " + (location or ""),
            )
    else:
        names = certificates.service_name(location)
        if not names:
            return _failure(
                result,
                "value of store_location '"
                + location
                + "' is not a valid windows service",
            )
        if len(names) != 1:
            raise ValueError("Service store selection must resolve to one service")
        parameters["store_location"] = names[0]
        for name in certificates.missing_service_stores(names[0]):
            if not check_mode:
                certificates.register_service_store(names[0], name)
            result["changed"] = True
    try:
        store = certificates.open_store(
            parameters["store_name"],
            parameters["store_location"],
            parameters["store_type"],
            parameters["state"] == "exported",
        )
    except OSError as error:
        code = error.errno & 0xFFFFFFFF
        message = (
            "unable to find store '" + parameters["store_name"] + "'"
            if code in (2, 3)
            else (
                "unable to open the store with the current permissions"
                if code == 5
                else "unable to open the store"
            )
        )
        return _failure(
            result, message + ": (" + certificates.store_error(code) + ")", True
        )
    with store:
        state = parameters["state"]
        if state == "absent":
            return _absent(store, parameters, result, check_mode)
        if state == "exported":
            return _export(store, parameters, result, check_mode)
        return _present(store, parameters, result, check_mode)


def _redact(value, password):
    if not password:
        return value
    if isinstance(value, dict):
        return {key: _redact(item, password) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item, password) for item in value]
    if isinstance(value, str):
        return (
            "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
            if value == password
            else value.replace(password, "********")
        )
    return value


def _response():
    arguments = read_arguments(_DEFAULTS, _MODULE)
    password = as_string(arguments.get("password"), "password")
    try:
        parameters = _parameters(arguments)
    except ValueError as error:
        return {"changed": False, "failed": True, "msg": _redact(str(error), password)}
    result = {"changed": False, "thumbprints": []}
    try:
        _manage(
            parameters,
            result,
            as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
        )
    except Exception as error:  # pylint: disable=broad-exception-caught
        _failure(
            result, "Unhandled exception while executing module: " + str(error), True
        )
    return _redact(result, password)


def main():
    """Read one Ansible JSON request and emit complete certificate-store results.

    :raises SystemExit: After reporting success or failure to Ansible.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
