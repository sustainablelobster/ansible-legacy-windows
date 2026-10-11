#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
"""Manage DHCP Server leases and reservations."""

# WANT_JSON

import re

import legacy_windows_dhcp_lease as dhcp  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    DOTNET_WHITESPACE,
    as_bool,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_dhcp_lease
short_description: Manage Windows Server DHCP leases and reservations
version_added: '1.0.0'
description:
  - Creates, removes and converts IPv4 DHCP Server leases and reservations.
  - Delegate the task to a Windows machine with installed native DHCP Server management facilities.
  - Uses Python 3.4.4 or newer and the installed provider or DHCP Server management API.
options:
  type:
    description: Whether the requested address should be a lease or permanent reservation.
    type: str
    choices: [reservation, lease]
    default: reservation
  state:
    description: Whether the selected record should exist.
    type: str
    choices: [present, absent]
    default: present
  ip:
    description:
      - IPv4 client address to create or select.
      - Required when O(mac) is not supplied.
    type: str
  scope_id:
    description:
      - Optional scope filter when selecting an existing record.
      - Required to create a record that does not already exist.
    type: str
  mac:
    description:
      - Client identifier used to create or select the record, before falling back to O(ip).
      - Required when O(ip) is not supplied.
      - Accepts twelve characters or seventeen characters with separators as upstream.
    type: str
  duration:
    description:
      - Lease expiry offset in local calendar days when creating a lease.
      - Omitted or zero uses the server's default duration.
    type: int
  dns_hostname:
    description: Hostname of a new lease, or default name of a new reservation.
    type: str
  dns_regtype:
    description: DNS registration requested when creating a lease.
    type: str
    choices: [aptr, a, noreg]
    default: aptr
  reservation_name:
    description: Name of a created or updated reservation.
    type: str
  description:
    description: Description of a created lease or created/updated reservation.
    type: str
  computer_name:
    description: Optional name or address of the DHCP server managed through the local provider.
    type: str
requirements:
  - Native DHCP Server management provider or the installed Windows DHCP Server management API.
  - Permission to manage the selected DHCP server.
attributes:
  check_mode:
    support: full
    description: Predicts changes without writing server records.
  diff_mode:
    support: full
    description: Returns the existing record under before; no after field is produced upstream.
notes:
  - This module manages server records, not the target adapter's DHCP release or renewal.
  - Existing ordinary leases are not updated unless converted to reservations.
  - Existing reservation updates always predict changed in check mode, including repeats.
  - Lease-to-reservation check mode preserves upstream's failed null-pipeline binding.
  - Operations are not transactional; a later failure can leave earlier writes applied.
  - When the modern management provider is genuinely absent, the installed classic DHCP Server API manages ordinary IPv4 reservations and leases.
  - The classic API cannot set per-lease DNS registration flags. It preserves the existing server policy for O(dns_regtype=aptr) and rejects V(a) and V(noreg) before creation, including in check mode.
  - Native server and scope lease-duration settings are read for an omitted duration; no duration is invented.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Create a reservation in an existing scope
  sustainablelobster.legacy_windows.win_dhcp_lease:
    ip: 192.0.2.25
    scope_id: 192.0.2.0
    mac: 02:00:00:00:00:25
    reservation_name: build-client

- name: Remove the record selected by client address
  sustainablelobster.legacy_windows.win_dhcp_lease:
    ip: 192.0.2.25
    state: absent
"""

RETURN = r"""
lease:
  description: New or updated DHCP provider record; omitted for existing ordinary lease no-ops.
  returned: changed present operations outside check mode, or a failed removal
  type: dict
  contains:
    address_state:
      description: Provider address state.
      type: str
    client_id:
      description: Stored client identifier.
      type: str
    ip_address:
      description: Stored IPv4 client address.
      type: str
    scope_id:
      description: Stored IPv4 scope identifier.
      type: str
    name:
      description: Reservation name, or null when the lease projection lacks this property.
      type: str
    description:
      description: Stored record description.
      type: str
"""

_MODULE = "sustainablelobster.legacy_windows.win_dhcp_lease"
_PARAMETERS = (
    "type",
    "ip",
    "scope_id",
    "mac",
    "duration",
    "dns_hostname",
    "dns_regtype",
    "reservation_name",
    "description",
    "state",
    "computer_name",
)
_FIELDS = {
    "address_state": "AddressState",
    "client_id": "ClientId",
    "ip_address": "IPAddress",
    "scope_id": "ScopeId",
    "name": "Name",
    "description": "Description",
}


def _integer(value):
    if value is None:
        return None
    text = as_string(value, "duration").strip(DOTNET_WHITESPACE)
    if not re.match(r"^[+-]?[0-9]+$", text) or not -(2**31) <= int(text) < 2**31:
        raise ValueError("duration must be a signed 32-bit integer")
    return int(text)


def _parameters(arguments):
    result = {name: as_string(arguments.get(name), name) for name in _PARAMETERS}
    for name, choices, default in (
        ("state", ("absent", "present"), "present"),
        ("type", ("reservation", "lease"), "reservation"),
        ("dns_regtype", ("aptr", "a", "noreg"), "aptr"),
    ):
        value = as_string(arguments.get(name, default), name)
        if value is not None and value.lower() not in choices:
            raise ValueError("{0} must be one of: {1}".format(name, ", ".join(choices)))
        result[name] = value.lower() if value is not None else None
    result["duration"] = _integer(arguments.get("duration"))
    if result["state"] in ("present", "absent") and not any(
        arguments.get(name) is not None for name in ("mac", "ip")
    ):
        raise ValueError(
            "state is {0} but any of the following are missing: mac, ip".format(
                result["state"]
            )
        )
    return result


def _mac(value):
    if not value:
        return value
    if len(value) == 12:
        return "-".join(value[index : index + 2] for index in range(0, 12, 2))
    if len(value) == 17:
        return value.replace(":", "-")
    raise ValueError("The MAC Address is not properly formatted")


def _field(rows, name):
    values = [row.get(name) for row in rows]
    return values[0] if len(values) == 1 else values if values else None


def _public(rows):
    return {name: _field(rows, field) for name, field in _FIELDS.items()}


def _failed(result, message):
    result.update(failed=True, msg=message)
    return result


def _changed(before, after):
    for name in ("AddressState", "IPAddress", "ScopeId", "Name", "Description"):
        original, updated = _field(before, name), _field(after, name)
        if isinstance(original, list) or isinstance(updated, list):
            if original != updated:
                return True
        elif not dhcp.values_equal(original, updated):
            return True
    return False


def _reservation_parameters(parameters, rows, conversion=False):
    client_id = parameters["mac"] or _field(rows, "ClientId")
    name = parameters["reservation_name"]
    if not name:
        original = _field(rows, "Name")
        name = (
            "reservation-"
            + as_string(client_id if conversion else _field(rows, "ClientId"), "mac")
            if conversion or original is None
            else original
        )
    return {
        "ClientId": as_string(client_id, "mac"),
        "Description": parameters["description"] or _field(rows, "Description"),
        "Name": as_string(name, "reservation_name"),
    }


def _create(server, parameters, check_mode, result):
    if not parameters["scope_id"]:
        return _failed(
            result,
            "The scope_id parameter is required for state=present when a lease "
            "or reservation doesn't already exist",
        )
    if not parameters["mac"]:
        return _failed(
            result,
            "Could not create DHCP {0}: Cannot validate argument on parameter "
            "'ClientId'. The argument is null or empty. Provide an argument "
            "that is not null or empty, and then try the command again.".format(
                "reservation" if parameters["type"] == "reservation" else "lease"
            ),
        )
    values = {
        "ClientId": parameters["mac"],
        "IPAddress": dhcp.ipv4(parameters["ip"], "ip"),
        "ScopeId": dhcp.ipv4(parameters["scope_id"], "scope_id"),
    }
    if parameters["description"]:
        values["Description"] = parameters["description"]
    reservation = parameters["type"] == "reservation"
    if reservation:
        values["Name"] = (
            parameters["reservation_name"]
            or parameters["dns_hostname"]
            or "reservation-" + (parameters["mac"] or "")
        )
    else:
        if parameters["dns_hostname"]:
            values["HostName"] = parameters["dns_hostname"]
        if parameters["duration"]:
            values["LeaseExpiryTime"] = dhcp.lease_expiry(parameters["duration"])
        if parameters["dns_regtype"]:
            values["DnsRR"] = {"aptr": "AandPTR", "a": "A", "noreg": "NoRegistration"}[
                parameters["dns_regtype"]
            ]
        values["AddressState"] = "Active"
    try:
        server.validate_create("Reservation" if reservation else "Lease", values)
        if not check_mode:
            server.create("Reservation" if reservation else "Lease", values)
            result["lease"] = _public(
                server.get(values["ClientId"], values["ScopeId"], reservation)
            )
    except (OSError, ValueError) as error:
        return _failed(
            result,
            "Could not create DHCP {0}: {1}".format(
                "reservation" if reservation else "lease", error
            ),
        )
    result["changed"] = True
    return result


def _convert_to_lease(server, rows, check_mode, result):
    try:
        values = {
            "ClientId": as_string(_field(rows, "ClientId"), "mac"),
            "IPAddress": as_string(_field(rows, "IPAddress"), "ip"),
            "ScopeId": as_string(_field(rows, "ScopeId"), "scope_id"),
            "HostName": _field(rows, "HostName"),
            "AddressState": "Active",
        }
        server.validate_create("Lease", values)
        if not check_mode:
            server.remove(rows, True)
            server.create("Lease", values)
            result["lease"] = _public(
                server.get(_field(rows, "ClientId"), _field(rows, "ScopeId"))
            )
    except (OSError, ValueError) as error:
        return _failed(
            result, "Could not convert reservation to lease: {0}".format(error)
        )
    result["changed"] = True
    return result


def _update_reservation(server, parameters, check_mode, rows, result):
    reservation = any("reservation" in row["AddressState"].lower() for row in rows)
    if check_mode and not reservation:
        # Upstream skips its readback, then pipes the unset reservation to Set.
        return _failed(result, "Could not convert lease to a reservation")
    values = _reservation_parameters(parameters, rows, not reservation)
    try:
        for row in rows:
            server.validate_create(
                "Reservation",
                dict(values, IPAddress=row["IPAddress"], ScopeId=row["ScopeId"]),
            )
        if not check_mode:
            for row in rows:
                if not reservation:
                    server.create(
                        "Reservation",
                        dict(
                            values, IPAddress=row["IPAddress"], ScopeId=row["ScopeId"]
                        ),
                    )
                server.update(row["IPAddress"], values)
            # Existing-reservation readback intentionally selects the old ID.
            client_id = _field(rows, "ClientId") if reservation else values["ClientId"]
            updated = server.get(client_id, _field(rows, "ScopeId"))
            result["changed"] = _changed(rows, updated)
            result["lease"] = _public(updated)
        else:
            result["changed"] = True
    except (OSError, ValueError) as error:
        if reservation:
            # This source branch has no catch; its top-level wrapper drops diff.
            return _failed(
                {"changed": False},
                "Unhandled exception while executing module: " + str(error),
            )
        return _failed(result, "Could not convert lease to a reservation")
    return result


def _present(server, parameters, check_mode, rows, result):
    if not rows:
        return (
            _create(server, parameters, check_mode, result)
            if parameters["type"] in ("reservation", "lease")
            else result
        )
    if parameters["type"] == "lease":
        if any("reservation" in row["AddressState"].lower() for row in rows):
            return _convert_to_lease(server, rows, check_mode, result)
        return result
    if parameters["type"] == "reservation":
        return _update_reservation(server, parameters, check_mode, rows, result)
    return result


def _manage(server, parameters, check_mode):
    parameters["mac"] = _mac(parameters["mac"])
    rows = server.find(parameters["scope_id"], parameters["mac"], parameters["ip"])
    result = {"changed": False}
    if rows:
        result["diff"] = {"before": _public(rows)}
    reservation = any("reservation" in row["AddressState"].lower() for row in rows)
    if parameters["state"] == "absent":
        if not rows:
            result["msg"] = "The lease doesn't exist."
        else:
            try:
                if not check_mode:
                    server.remove(rows, reservation)
                result["changed"] = True
            except (OSError, ValueError) as error:
                result["lease"] = _public(rows)
                return _failed(
                    result, "Unable to remove lease/reservation: {0}".format(error)
                )
    elif parameters["state"] == "present":
        return _present(server, parameters, check_mode, rows, result)
    return result


def _response():
    arguments = read_arguments(_PARAMETERS, _MODULE)
    parameters = _parameters(arguments)
    check_mode = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    try:
        with dhcp.DhcpServer(parameters["computer_name"]) as server:
            return _manage(server, parameters, check_mode)
    except OSError as error:
        if "ConnectServer" in str(error):
            raise OSError(
                "The DhcpServer native management provider is unavailable: "
                + str(error)
            ) from error
        raise


def main():
    """Read one Ansible request and return its DHCP Server result.

    :raises SystemExit: After emitting one success or failure response.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
