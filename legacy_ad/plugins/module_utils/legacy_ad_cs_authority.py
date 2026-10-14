# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage local CA extension configuration with the registry and native SCM."""

import collections
import re

import legacy_windows_service as services  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_dictionary,
    as_string,
    read_arguments,
)

try:
    import winreg
except ImportError:
    winreg = None

PARAMETERS = ("cdp", "aia", "restart_service")
_CONFIGURATION = r"SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"
_CDP_FLAGS = (
    ("publish_to_server", 1),
    ("publish_delta_to_server", 64),
    ("add_to_certificate_cdp", 2),
    ("add_to_freshest_crl", 4),
    ("add_to_crl_cdp", 8),
    ("add_to_crl_idp", 128),
)
_AIA_FLAGS = (("add_to_certificate_aia", 2), ("add_to_certificate_ocsp", 32))
# Certificate Services stores these documented UI variables as percent insertions.
_TOKENS = {
    "1": "ServerDNSName",
    "2": "ServerShortName",
    "3": "CAName",
    "4": "CertificateName",
    "6": "ConfigurationContainer",
    "7": "CATruncatedName",
    "8": "CRLNameSuffix",
    "9": "DeltaCRLAllowed",
    "10": "CDPObjectClass",
    "11": "CAObjectClass",
}


def _entries(value, label, flags):
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValueError(label + " must be a list of dictionaries.")
    entries = []
    for item in value:
        item = as_dictionary(item, label)
        if item is None or set(item) - ({"uri"} | {name for name, _mask in flags}):
            raise ValueError(
                label + " entries contain uri and documented Boolean flags only."
            )
        uri = as_string(item.get("uri"), label + ".uri")
        if uri is None or not uri or "\0" in uri:
            raise ValueError(
                label + " entries require a nonempty uri without NUL characters."
            )
        normalized = {"uri": uri}
        for name, _mask in flags:
            normalized[name] = as_bool(item.get(name, False), label + "." + name)
        if label == "cdp":
            protocol = uri.split(":", 1)[0].lower()
            if protocol in ("http", "https") and (
                normalized["publish_to_server"] or normalized["publish_delta_to_server"]
            ):
                raise ValueError(
                    "HTTP CDP locations cannot publish CRLs; use LDAP, file, local or UNC paths."
                )
            if normalized["add_to_crl_cdp"] and protocol != "ldap":
                raise ValueError("add_to_crl_cdp requires an LDAP CDP URI.")
        entries.append(normalized)
    return entries


def authority_arguments():
    """Read desired CA extension lists and the restart/check flags.

    :returns: Normalized public authority module arguments.
    :rtype: dict
    :raises ValueError: If entries, flags or URI combinations are invalid.
    """
    values = read_arguments(PARAMETERS, "sustainablelobster.legacy_ad.cs_authority")
    return {
        "cdp": _entries(values.get("cdp"), "cdp", _CDP_FLAGS),
        "aia": _entries(values.get("aia"), "aia", _AIA_FLAGS),
        "restart_service": as_bool(
            values.get("restart_service", True), "restart_service"
        ),
        "check_mode": as_bool(
            values.get("_ansible_check_mode", False), "_ansible_check_mode"
        ),
    }


def _decode(value, flags):
    prefix, separator, uri = value.partition(":")
    if not separator:
        raise ValueError("Malformed Certificate Services publication URL: " + value)
    try:
        mask = int(prefix)
    except ValueError as error:
        raise ValueError(
            "Malformed Certificate Services URL flag prefix: " + prefix
        ) from error
    uri = re.sub(
        r"%(11|10|[1-9])(?![0-9])",
        lambda match: (
            "<" + _TOKENS[match.group(1)] + ">"
            if match.group(1) in _TOKENS
            else match.group(0)
        ),
        uri,
    )
    entry = {"uri": uri}
    entry.update({name: bool(mask & bit) for name, bit in flags})
    return entry


def _encode(entry, flags):
    tokens = {name.lower(): number for number, name in _TOKENS.items()}
    uri = re.sub(
        r"<([^>]+)>",
        lambda match: (
            "%" + tokens[match.group(1).lower()]
            if match.group(1).lower() in tokens
            else match.group(0)
        ),
        entry["uri"],
    )
    mask = sum(bit for name, bit in flags if entry[name])
    return str(mask) + ":" + uri


def _key(entry, flags):
    return (
        entry["uri"]
        + "|"
        + "|".join("1" if entry[name] else "0" for name, _mask in flags)
    ).lower()


def _desired_values(current, desired, flags):
    available = collections.Counter(_key(entry, flags) for entry in desired)
    retained = []
    for value in current:
        key = _key(_decode(value, flags), flags)
        if available[key]:
            retained.append(value)
            available[key] -= 1
    for entry in desired:
        key = _key(entry, flags)
        if available[key]:
            retained.append(_encode(entry, flags))
            available[key] -= 1
    before = collections.Counter(
        _key(_decode(value, flags), flags) for value in current
    )
    after = collections.Counter(_key(entry, flags) for entry in desired)
    return None if before == after else retained


class AuthorityConfiguration:
    """Own the local CA's read handle, requesting write access only for changes."""

    def __init__(self):
        self.key = None
        self.path = None

    def __enter__(self):
        if winreg is None:
            raise ValueError(
                "Certificate-authority management requires a Windows CA target."
            )
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, _CONFIGURATION
            ) as configuration:
                active, kind = winreg.QueryValueEx(configuration, "Active")
                if kind != winreg.REG_SZ or not active:
                    raise ValueError(
                        "Certificate Services has no active local CA configuration."
                    )
            self.path = _CONFIGURATION + "\\" + active
            self.key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, self.path, 0, winreg.KEY_READ
            )
        except OSError as error:
            raise OSError(
                "Cannot open the existing local Certificate Services CA configuration: "
                + str(error)
            ) from error
        return self

    def __exit__(self, _kind, _value, _traceback):
        self.key.Close()

    def read(self, name):
        """Read a publication URL list without coercing malformed registry data.

        :param name: Existing CA extension registry value name.
        :type name: str
        :returns: Ordered publication URL strings.
        :rtype: list[str]
        :raises OSError: If the registry value cannot be read.
        :raises ValueError: If it is not a REG_MULTI_SZ list.
        """
        value, kind = winreg.QueryValueEx(self.key, name)
        if kind != winreg.REG_MULTI_SZ:
            raise ValueError(name + " must be a REG_MULTI_SZ CA configuration value.")
        return value

    def write(self, name, values):
        """Persist one ordered extension list for the CA's next service start.

        :param name: CA extension registry value name.
        :type name: str
        :param values: Desired ordered publication URL strings.
        :type values: list[str]
        :raises OSError: If the native registry write fails.
        """
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, self.path, 0, winreg.KEY_SET_VALUE
        ) as writable:
            winreg.SetValueEx(writable, name, 0, winreg.REG_MULTI_SZ, values)


def manage_authority(arguments, result):
    """Reconcile requested CA extension lists and optionally restart CertSvc.

    :param arguments: Validated extension lists and restart/check flags.
    :type arguments: dict
    :param result: Mutable result retaining changes if a later operation fails.
    :type result: dict
    :raises ValueError: If existing CA configuration is malformed or unsupported.
    :raises OSError: If registry access or a service control fails.
    """
    if arguments["cdp"] is None and arguments["aia"] is None:
        return
    with AuthorityConfiguration() as configuration:
        for label, name, flags in (
            ("cdp", "CRLPublicationURLs", _CDP_FLAGS),
            ("aia", "CACertPublicationURLs", _AIA_FLAGS),
        ):
            if arguments[label] is None:
                continue
            desired = _desired_values(configuration.read(name), arguments[label], flags)
            if desired is not None:
                result["changed"] = True
                if not arguments["check_mode"]:
                    configuration.write(name, desired)
    if (
        result["changed"]
        and arguments["restart_service"]
        and not arguments["check_mode"]
    ):
        services.control("CertSvc", "restarted", force=True)
