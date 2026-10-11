# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
"""Manage DHCP records through the installed Windows Server management facilities."""

import ctypes
import datetime
import socket
import struct
import sys

from legacy_windows_dhcp_api import DhcpApi  # pylint: disable=import-error
from legacy_windows_environment import values_equal  # pylint: disable=import-error
from legacy_windows_time import (  # pylint: disable=import-error
    current_local_ticks,
    local_ticks_to_file_time,
)
from legacy_windows_wmi import WmiConnection  # pylint: disable=import-error

NAMESPACE = r"ROOT\Microsoft\Windows\DHCP"


def ipv4(value, name):
    """Bind an IPv4 string without interpolating it into a provider query.

    :param value: Address accepted by the Windows IPv4 cmdlet parameter.
    :type value: str or None
    :param str name: Parameter name used in an actionable failure.
    :returns: Canonical IPv4 text.
    :rtype: str
    :raises ValueError: The supplied value cannot identify an IPv4 address.
    """
    if not value or "\x00" in value or any(character.isspace() for character in value):
        raise ValueError("{0} must be an IPv4 address".format(name))
    try:
        return socket.inet_ntoa(socket.inet_aton(value))
    except OSError as error:
        raise ValueError("{0} must be an IPv4 address".format(name)) from error


def lease_expiry(duration):
    """Return the native local-calendar day addition as a UTC DMTF timestamp.

    :param int duration: Signed number of days added to the current local time.
    :returns: UTC expiry string suitable for the provider's datetime input.
    :rtype: str
    :raises ValueError: The expiry is outside the Windows datetime range.
    :raises OSError: Native timezone conversion fails.
    """
    ticks = current_local_ticks() + duration * 864000000000
    file_time = local_ticks_to_file_time(ticks)
    value = datetime.datetime(1601, 1, 1) + datetime.timedelta(
        microseconds=file_time // 10
    )
    return value.strftime("%Y%m%d%H%M%S") + ".{0:06d}+000".format(value.microsecond)


class DhcpServer:
    """Own one local DHCP provider connection, optionally managing a remote server.

    :param computer_name: Existing DHCP server's name, or None for the local server.
    :type computer_name: str or None
    """

    def __init__(self, computer_name=None):
        self._connection = WmiConnection(NAMESPACE)
        self._computer_name = computer_name
        self._native = False

    def __enter__(self):
        try:
            self._connection.__enter__()
        except OSError as error:
            if getattr(error, "hresult", None) not in (0x8004100E, 0x80041010):
                raise
        else:
            try:
                definitions = self._connection.query(
                    "SELECT * FROM meta_class WHERE __CLASS='PS_DhcpServerv4Lease'",
                    ["__CLASS"],
                )
            except BaseException:
                self._connection.__exit__(*sys.exc_info())
                raise
            if definitions:
                return self
            self._connection.__exit__(None, None, None)
        self._native = True
        return _ClassicDhcpServer(self._computer_name)

    def __exit__(self, exception_type, exception, traceback):
        if self._native:
            return None
        return self._connection.__exit__(exception_type, exception, traceback)

    def _call(self, kind, method, parameters):
        inputs = dict(parameters)
        if self._computer_name is not None:
            inputs["ComputerName"] = self._computer_name
        result = self._connection.call_method(
            "PS_DhcpServerv4" + kind,
            method,
            ["ReturnValue", "cmdletOutput"],
            inputs,
            allow_empty=True,
        )
        if result.get("ReturnValue"):
            raise ctypes.WinError(result["ReturnValue"])
        output = result.get("cmdletOutput")
        return output if isinstance(output, list) else [output] if output else []

    def validate_create(self, _kind, _parameters):
        """Leave ordinary typed request validation to the installed provider."""

    def find(self, scope_id, client_id, address):
        """Find active lease records, preferring client ID over address as upstream.

        :param scope_id: Optional scope filter.
        :type scope_id: str or None
        :param client_id: Optional normalized client identifier.
        :type client_id: str or None
        :param address: Optional original IPv4 selector spelling.
        :type address: str or None
        :returns: All matching provider records in provider scope/lease order.
        :rtype: list
        :raises OSError: The native provider cannot enumerate the DHCP server.
        """
        for field, value in (("ClientId", client_id), ("IPAddress", address)):
            if not value:
                continue
            if field == "IPAddress":
                try:
                    value = ipv4(value, "ip")
                except ValueError:
                    # Upstream's IPAddress comparison leaves invalid text unmatched.
                    pass
            parameters = {"ScopeId": [ipv4(scope_id, "scope_id")]} if scope_id else {}
            scopes = self._call("Scope", "Get", parameters)
            rows = []
            for scope in scopes:
                rows.extend(
                    self._call("Lease", "GetByScopeId", {"ScopeId": scope["ScopeId"]})
                )
            matches = [row for row in rows if values_equal(row.get(field) or "", value)]
            if matches:
                return matches
        return []

    def get(self, client_id, scope_id, reservation=False):
        """Read provider records by client ID after a write.

        :param str client_id: Client identifier used by the original getter.
        :param str scope_id: Scope containing the changed object.
        :param bool reservation: Read reservation rather than lease projections.
        :returns: Matching provider records.
        :rtype: list
        :raises OSError: The native getter fails or the selected client is absent.
        """
        records = self._call(
            "Reservation" if reservation else "Lease",
            "GetByClientId",
            {"ClientId": [client_id], "ScopeId": scope_id},
        )
        if not records:
            # The CDXML getter reports a missing selected client as an error.
            raise OSError(
                "Failed to get {0} information for ClientId {1} from DHCP server {2}.".format(
                    "reservation" if reservation else "lease",
                    client_id,
                    self._computer_name or socket.gethostname(),
                )
            )
        return records

    def create(self, kind, parameters):
        """Create one lease or reservation with the supplied provider parameters.

        :param str kind: Lease or Reservation.
        :param dict parameters: Typed provider input values.
        :raises OSError: Creation fails, including a native partial change.
        """
        self._call(kind, "Add", parameters)

    def update(self, address, parameters):
        """Update an existing reservation selected by its stored address.

        :param str address: Existing reservation's IPv4 address.
        :param dict parameters: Client ID, name and description replacement.
        :raises OSError: The native setter fails.
        """
        self._call("Reservation", "Set", dict(parameters, IPAddress=address))

    def remove(self, rows, reservation):
        """Remove the selected records sequentially, preserving native failures.

        :param list rows: Previously observed provider records.
        :param bool reservation: Select reservation rather than lease removal.
        :raises OSError: Removal fails; preceding removals may remain applied.
        """
        for row in rows:
            self._call(
                "Reservation" if reservation else "Lease",
                "RemoveByIPAddress",
                {"IPAddress": [row["IPAddress"]]},
            )


def _client_bytes(value):
    try:
        result = bytes.fromhex(value.replace("-", ""))
    except (AttributeError, ValueError) as error:
        raise ValueError(
            "The DHCP client identifier must contain hexadecimal bytes."
        ) from error
    if not result:
        raise ValueError("The DHCP client identifier must not be empty.")
    return result


def _client_id(value, scope):
    prefix = struct.pack("<I", struct.unpack("!I", socket.inet_aton(scope))[0])
    if len(value) > 5 and value[:4] == prefix and value[4] == 1:
        value = value[5:]
    return "-".join("{0:02X}".format(part) for part in bytearray(value))


def _expiry(value):
    parsed = datetime.datetime.strptime(value, "%Y%m%d%H%M%S.%f+000")
    elapsed = parsed - datetime.datetime(1601, 1, 1)
    return (
        elapsed.days * 86400 + elapsed.seconds
    ) * 10000000 + elapsed.microseconds * 10


class _ClassicDhcpServer:
    def __init__(self, computer_name=None):
        self.api = DhcpApi(computer_name)
        self._computer_name = computer_name

    def _rows(self, scope, reservation=False, all_leases=False):
        reserved = {row["address"] for row in self.api.reservations(scope)}
        result = []
        for row in self.api.clients(scope):
            is_reserved = row["address"] in reserved
            if reservation and not is_reserved:
                continue
            state = row["state"] & 3
            if not reservation and not all_leases and state != 1 and not is_reserved:
                continue
            address_state = (
                ("ActiveReservation" if state == 1 else "InactiveReservation")
                if is_reserved
                else ("Offered", "Active", "Declined", "Expired")[state]
            )
            result.append(
                {
                    "AddressState": address_state,
                    "ClientId": _client_id(row["hardware"], scope),
                    "IPAddress": row["address"],
                    "ScopeId": scope,
                    "HostName": row["name"],
                    "Description": row["comment"],
                    "Name": row["name"] if reservation else None,
                }
            )
        return result

    def find(self, scope_id, client_id, address):
        """Find active native entries, preserving client-ID selector precedence.

        :param scope_id: Optional subnet selector.
        :type scope_id: str or None
        :param client_id: Optional normalized DHCP client identifier.
        :type client_id: str or None
        :param address: Optional original IPv4 selector spelling.
        :type address: str or None
        :returns: Actual matching lease projections in native scope/client order.
        :rtype: list
        """
        for field, value in (("ClientId", client_id), ("IPAddress", address)):
            if not value:
                continue
            if field == "IPAddress":
                try:
                    value = ipv4(value, "ip")
                except ValueError:
                    pass
            scopes = [ipv4(scope_id, "scope_id")] if scope_id else self.api.subnets()
            rows = [row for scope in scopes for row in self._rows(scope)]
            matches = [row for row in rows if values_equal(row[field] or "", value)]
            if matches:
                return matches
        return []

    def get(self, client_id, scope_id, reservation=False):
        """Read changed native records by their actual client identifier.

        :param str client_id: Original client identifier used by readback.
        :param str scope_id: Containing subnet address.
        :param bool reservation: Return reservation rather than lease fields.
        :returns: Actual matching records.
        :rtype: list
        :raises OSError: The requested native client is absent.
        """
        rows = [
            row
            for row in self._rows(scope_id, reservation)
            if values_equal(row["ClientId"], client_id)
        ]
        if not rows:
            raise OSError(
                "Failed to get {0} information for ClientId {1} from DHCP server {2}.".format(
                    "reservation" if reservation else "lease",
                    client_id,
                    self._computer_name or socket.gethostname(),
                )
            )
        return rows

    def validate_create(self, kind, parameters):
        """Reject unsupported meaningful inputs before a write or preview.

        :param str kind: Lease or Reservation.
        :param dict parameters: Converted public record values.
        :raises ValueError: Native client data or a requested option is unsupported.
        """
        _client_bytes(parameters["ClientId"])
        for field in ("Name", "HostName", "Description"):
            if "\x00" in (parameters.get(field) or ""):
                raise ValueError(field + " must not contain a NUL character.")
        self.api.subnet(parameters["ScopeId"])
        if kind == "Lease" and parameters.get("DnsRR", "AandPTR") != "AandPTR":
            raise ValueError(
                "The installed classic DHCP API cannot set per-lease DNS registration; "
                "the existing server policy is preserved."
            )
        if kind == "Lease" and "LeaseExpiryTime" not in parameters:
            self.api.lease_duration(parameters["ScopeId"])

    def _new_client(self, parameters):
        scope = self.api.subnet(parameters["ScopeId"])
        expiry = parameters.get("LeaseExpiryTime")
        if expiry:
            expires = _expiry(expiry)
        else:
            seconds = self.api.lease_duration(parameters["ScopeId"])
            expires = local_ticks_to_file_time(
                current_local_ticks() + seconds * 10000000
            )
        return {
            "address": parameters["IPAddress"],
            "mask": scope["mask"],
            "hardware": _client_bytes(parameters["ClientId"]),
            "name": parameters.get("HostName"),
            "comment": parameters.get("Description"),
            "expires": expires,
            "owner": (0, None, None),
            "kind": 1,
        }

    def create(self, kind, parameters):
        """Create one client or reservation through the installed native API.

        :param str kind: Lease or Reservation.
        :param dict parameters: Typed converted record values.
        """
        self.validate_create(kind, parameters)
        reservation = kind == "Reservation"
        if reservation:
            self.api.reserve(
                parameters["ScopeId"],
                parameters["IPAddress"],
                _client_bytes(parameters["ClientId"]),
            )
            self.update(parameters["IPAddress"], parameters)
        else:
            self.api.save_client(self._new_client(parameters), create=True)

    def update(self, address, parameters):
        """Update the actual existing reservation selected by its stored address.

        :param str address: Literal observed existing reservation address.
        :param dict parameters: New client ID, name and description.
        :raises ValueError: A supplied string would be truncated by the native API.
        """
        for field in ("Name", "Description"):
            if "\x00" in (parameters.get(field) or ""):
                raise ValueError(field + " must not contain a NUL character.")
        original = self.api.client(address)
        scope = _text_scope(address, original["mask"])
        current = next(
            row for row in self.api.reservations(scope) if row["address"] == address
        )
        hardware = _client_bytes(parameters["ClientId"])
        if (
            _client_id(current["hardware"], scope).upper()
            != parameters["ClientId"].upper()
        ):
            self.api.reserve(scope, address, current["hardware"], remove=True)
            self.api.reserve(scope, address, hardware)
        original.update(
            hardware=hardware,
            name=parameters.get("Name"),
            comment=parameters.get("Description"),
        )
        self.api.save_client(original)

    def remove(self, rows, reservation):
        """Remove exactly the selected native records sequentially.

        :param list rows: Previously observed record projections.
        :param bool reservation: Remove reservation rather than ordinary client data.
        """
        for row in rows:
            if reservation:
                current = next(
                    item
                    for item in self.api.reservations(row["ScopeId"])
                    if item["address"] == row["IPAddress"]
                )
                self.api.reserve(
                    row["ScopeId"], row["IPAddress"], current["hardware"], remove=True
                )
            else:
                self.api.remove_client(row["IPAddress"])


def _text_scope(address, mask):
    value = (
        struct.unpack("!I", socket.inet_aton(address))[0]
        & struct.unpack("!I", socket.inet_aton(mask))[0]
    )
    return socket.inet_ntoa(struct.pack("!I", value))
