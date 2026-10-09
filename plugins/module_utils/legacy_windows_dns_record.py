# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage DNS records through the native provider used by DNS Server cmdlets."""

import base64
import binascii
import copy
import ctypes
import os
import re
import subprocess
import uuid
from collections import OrderedDict
from contextlib import ExitStack

import legacy_windows_dns_classic as classic  # pylint: disable=import-error
import legacy_windows_wmi as wmi  # pylint: disable=import-error

_NAMESPACE = r"ROOT\Microsoft\Windows\Dns"
_CLASS = "PS_DnsServerResourceRecord"
_PROPERTIES = {
    "A": "IPv4Address",
    "AAAA": "IPv6Address",
    "CNAME": "HostNameAlias",
    "DHCID": "DhcpIdentifier",
    "NS": "NameServer",
    "PTR": "PtrDomainName",
    "SRV": "DomainName",
    "TXT": "DescriptiveText",
}
_METHODS = {
    "A": "AddByA",
    "AAAA": "AddByAAAA",
    "CNAME": "AddByCName",
    "DHCID": "AddByDhcId",
    "NS": "AddByNs",
    "PTR": "AddByPtr",
    "SRV": "AddBySrv",
    "TXT": "AddByTxt",
}


def _interval(seconds):
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    return "{0:08d}{1:02d}{2:02d}{3:02d}.000000:000".format(
        days, hours, minutes, seconds
    )


def _seconds(interval):
    if not isinstance(interval, str) or len(interval) != 25 or interval[21:] != ":000":
        raise ValueError(
            "DNS Server returned an invalid TTL interval: {0!r}".format(interval)
        )
    return (
        int(interval[:8]) * 86400
        + int(interval[8:10]) * 3600
        + int(interval[10:12]) * 60
        + int(interval[12:14])
    )


def _record_value(record, kind):
    name = "DhcId" if kind == "DHCID" else _PROPERTIES[kind]
    value = record["RecordData"][name]
    if isinstance(value, list):
        return "System.String[]"
    return str(value)


def _line(options, name, ttl, value):
    zone = options["zone"]
    if options["zone_scope"] is not None:
        zone += "/" + options["zone_scope"]
    return "[{0}] {1} {2} IN {3} {4}\n".format(zone, name, ttl, options["type"], value)


def _display(options, records):
    kind = options["type"].upper()
    return "".join(
        _line(
            options,
            record["HostName"],
            _seconds(record["TimeToLive"]),
            _record_value(record, kind),
        )
        for record in records
    )


def _released_order(records):
    # These CIM records have no default sort key and compare equal by their
    # shared type name. Windows PowerShell's equal-key quicksort swaps each
    # partition inward, then sorts its halves. A plain reversal matches only
    # two/three rows; actual source probes cover 1..5, 8, 16, 17, 32 and 33 rows.
    ordered = list(records)
    pending = [(0, len(ordered))]
    while pending:
        start, stop = pending.pop()
        half = (stop - start) // 2
        ordered[start:stop] = reversed(ordered[start:stop])
        if half > 1:
            pending.extend(((start, start + half), (stop - half, stop)))
    return ordered


def _validate_dhcid(value):
    # The DNS provider strictly parses base64 even under WhatIf. Validation
    # must not add a record; the native CryptoAPI decoder accepts bad padding.
    try:
        decoded = base64.b64decode(
            value.translate(str.maketrans("", "", " \t\r\n")), validate=True
        )
    except (binascii.Error, ValueError) as error:
        raise OSError("DNS Server requires a nonempty base64 DHCID value.") from error
    if not decoded:
        raise OSError("DNS Server requires a nonempty base64 DHCID value.")


# DNS record methods accept embedded instances and UInt16 inputs which are not
# part of the shared WMI method contract. Keep this provider-specific encoding here.
# pylint: disable=protected-access
def _put_object(instance, name, value):
    variant = wmi._Variant(kind=13)
    variant.data.bstr = value.value
    put = wmi._method(
        instance,
        5,
        wmi._LONG,
        [ctypes.c_wchar_p, wmi._LONG, ctypes.POINTER(wmi._Variant), wmi._LONG],
    )
    # Put copies the borrowed interface; the surrounding ExitStack owns our reference.
    wmi._check(
        put(instance, name, 0, ctypes.byref(variant), 0),
        "IWbemClassObject.Put({0})".format(name),
    )


def _instance(connection, cleanup, values):
    definition = wmi._get_object(
        connection._services, connection._automation, cleanup, values["__CLASS"]
    )
    instance = wmi._POINTER()
    cleanup.callback(wmi._release, instance)
    spawn = wmi._method(definition, 15, wmi._LONG, [wmi._LONG, wmi._POINTER_OUT])
    wmi._check(
        spawn(definition, 0, ctypes.byref(instance)), "IWbemClassObject.SpawnInstance"
    )
    for name, value in values.items():
        if name.startswith("__"):
            continue
        if isinstance(value, dict):
            _put_object(instance, name, _instance(connection, cleanup, value))
        elif isinstance(value, bool):
            wmi._put_boolean(instance, connection._automation, name, value)
        elif isinstance(value, int):
            wmi._put_integer(instance, connection._automation, name, value)
        elif isinstance(value, list):
            wmi._put_string_array(instance, connection._automation, name, value)
        else:
            wmi._put_string(instance, connection._automation, name, value)
    return instance


# These exact COM signatures also occur in zone management. Keeping this leaf ABI
# beside its embedded-record and UInt16 encoders avoids a new shared provider API;
# record reconciliation below is still checked for duplication.
# pylint: disable=duplicate-code
def _provider_message(connection):
    automation = connection._automation
    automation.GetErrorInfo.argtypes = [wmi._ULONG, wmi._POINTER_OUT]
    automation.GetErrorInfo.restype = wmi._LONG
    with ExitStack() as cleanup:
        information = wmi._POINTER()
        cleanup.callback(wmi._release, information)
        if (
            automation.GetErrorInfo(0, ctypes.byref(information)) != 0
            or not information
        ):
            return None
        instance = wmi._POINTER()
        cleanup.callback(wmi._release, instance)
        identifier = wmi._Guid.from_buffer_copy(
            uuid.UUID("dc12a681-737f-11cf-884d-00aa004b2e24").bytes_le
        )
        query = wmi._method(
            information, 0, wmi._LONG, [ctypes.POINTER(wmi._Guid), wmi._POINTER_OUT]
        )
        if query(information, ctypes.byref(identifier), ctypes.byref(instance)) != 0:
            return None
        try:
            return wmi._read_property(instance, automation, "Message")
        except OSError:
            return None


def _call(connection, method, inputs, output=False):
    with ExitStack() as cleanup:
        special = {
            name: value
            for name, value in inputs.items()
            if isinstance(value, dict)
            or isinstance(value, int)
            and not isinstance(value, bool)
        }
        arguments = connection._method_inputs(
            cleanup,
            _CLASS,
            method,
            {name: value for name, value in inputs.items() if name not in special},
        )
        for name, value in special.items():
            if isinstance(value, dict):
                _put_object(arguments, name, _instance(connection, cleanup, value))
            else:
                wmi._put_integer(arguments, connection._automation, name, value)
        result = wmi._POINTER()
        cleanup.callback(wmi._release, result)
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
        status = execute(
            connection._services,
            wmi._bstr(connection._automation, cleanup, _CLASS),
            wmi._bstr(connection._automation, cleanup, method),
            0,
            None,
            arguments,
            ctypes.byref(result),
            None,
        )
        if status & 0x80000000:
            # Extended DNS diagnostics must be retrieved before any COM cleanup.
            message = _provider_message(connection)
            error = OSError(message or "DNS Server method {0} failed.".format(method))
            error.hresult = status & 0xFFFFFFFF
            raise error
        if not result:
            # Mutations without PassThru succeed without an output instance.
            return [] if output else None
        code = wmi._read_property(result, connection._automation, "ReturnValue")
        if code:
            raise OSError(
                "DNS Server method {0} returned error {1}: {2}".format(
                    method, code, ctypes.FormatError(code)
                )
            )
        return (
            wmi._read_property(result, connection._automation, "cmdletOutput")
            if output
            else None
        )


# pylint: enable=protected-access
# pylint: enable=duplicate-code


class _Records:
    def __init__(self, connection, options):
        self.connection = connection
        self.options = options
        self.location = {"ZoneName": options["zone"]}
        for option, field in (
            ("zone_scope", "ZoneScope"),
            ("computer_name", "ComputerName"),
        ):
            if options[option] is not None:
                self.location[field] = options[option]

    def read(self):
        """Read raw records with the released nonterminating-error policy.

        :returns: Native records, or an empty list after a read error.
        :rtype: list
        """
        try:
            return (
                _call(
                    self.connection,
                    "Get",
                    dict(
                        self.location,
                        Name=self.options["name"],
                        RRType=self.options["type"],
                        Node=True,
                    ),
                    True,
                )
                or []
            )
        except OSError:
            # The released module explicitly ignores errors from both record reads.
            return []

    def remove(self, record):
        """Remove the exact observed record, not every value at its owner name.

        :param dict record: Complete native record selected by reconciliation.
        :raises OSError: DNS Server rejects removal.
        """
        _call(
            self.connection,
            "RemoveByInputObject",
            dict(self.location, InputObject=record, Force=True),
        )

    def update(self, old, new):
        """Replace the exact observed record with its edited native object.

        :param dict old: Complete original native record.
        :param dict new: Copy with only the requested fields changed.
        :raises OSError: DNS Server rejects the replacement.
        """
        _call(
            self.connection,
            "Set",
            dict(self.location, OldInputObject=old, NewInputObject=new),
        )

    def add(self, value):
        """Add a value using the released type-specific provider arguments.

        :param str value: Value after hostname-suffix handling.
        :raises OSError: DNS Server rejects the addition.
        """
        options = self.options
        kind = options["type"].upper()
        arguments = dict(self.location, Name=options["name"])
        arguments[kind] = True
        arguments[_PROPERTIES[kind]] = value
        if kind == "SRV":
            arguments.update(
                Port=options["port"],
                Priority=options["priority"],
                Weight=options["weight"],
            )
        else:
            arguments["TimeToLive"] = _interval(options["ttl"])
        if options["aging"]:
            arguments["AgeRecord"] = True
        if options["allow_update_any"]:
            arguments["AllowUpdateAny"] = True
        _call(self.connection, _METHODS[kind], arguments)

    def validate_add(self, value):
        """Check nonmutating DHCID parsing required by the released provider.

        :param str value: Requested record value.
        :raises OSError: DHCID value is empty or cannot be decoded.
        """
        if self.options["type"].upper() == "DHCID":
            _validate_dhcid(value)


_CLASSIC_PROPERTIES = {
    "A": "IPAddress",
    "AAAA": "IPv6Address",
    "CNAME": "PrimaryName",
    "NS": "NSHost",
    "PTR": "PTRDomainName",
    "SRV": "SRVDomainName",
    "TXT": "DescriptiveText",
}


def _dns_tool():
    directory = "Sysnative" if os.environ.get("PROCESSOR_ARCHITEW6432") else "System32"
    path = os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"), directory, "dnscmd.exe"
    )
    return path if os.path.isfile(path) else None


def _classic_text(value):
    # This provider exposes DNS TXT's UTF-8 wire bytes through the Windows
    # ANSI code page. Decode valid UTF-8; retain existing non-UTF-8 text as-is.
    try:
        return value.encode("mbcs").decode("utf-8")
    except (UnicodeError, LookupError):
        return value


class _ClassicRecords:
    """Use real older DNS record classes and installed DNS administration tools."""

    def __init__(self, connection, options):
        self.connection = connection
        self.options = options
        self.kind = options["type"].upper()
        self.zone = options["zone"].rstrip(".")
        self.name = options["name"]
        if self.name == "@":
            self.owner = self.zone
        elif self.name.endswith("."):
            self.owner = self.name[:-1]
        else:
            self.owner = self.name + "." + self.zone
        self.tool = _dns_tool()
        if options["zone_scope"] is not None:
            raise ValueError(
                "The installed classic DNS facility does not provide zone scopes."
            )
        unicode_txt = self.kind == "TXT" and any(
            ord(character) > 127 for value in options["value"] for character in value
        )
        needs_tool = (
            self.kind == "DHCID"
            or options["value"]
            and (options["aging"] or options["allow_update_any"] or unicode_txt)
        )
        if needs_tool and not self.tool:
            raise ValueError(
                "This classic DNS request requires installed dnscmd.exe management tools."
            )
        if self.kind == "DHCID" and not re.search(
            r"\bDHCID\b", self._command(["/RecordAdd"], allowed_errors=(87,))
        ):
            raise ValueError(
                "Installed DNS administration tools do not provide DHCID records."
            )
        if self.kind != "DHCID":
            classes = connection.query(
                "SELECT * FROM meta_class WHERE __CLASS="
                + classic.literal("MicrosoftDNS_" + self.kind + "Type"),
                ["__CLASS"],
            )
            if not classes:
                raise ValueError(
                    "The installed classic DNS provider does not provide "
                    + self.kind
                    + " records."
                )
        if options["value"]:
            zones = connection.query(
                "SELECT * FROM MicrosoftDNS_Zone WHERE Name="
                + classic.literal(self.zone),
                ["Name"],
            )
            if len(zones) != 1:
                raise ValueError(
                    "Classic DNS requires an existing literal zone: " + self.zone
                )

    def _command(self, arguments, allowed_errors=()):
        command = [self.tool]
        if self.options["computer_name"] is not None:
            command.append(self.options["computer_name"])
        with subprocess.Popen(
            command + arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ) as process:
            stdout, stderr = process.communicate()
        output = stdout.decode("mbcs", "replace")
        if process.returncode and process.returncode not in allowed_errors:
            raise OSError(
                process.returncode,
                "DNS administration failed ({0}): {1}".format(
                    process.returncode,
                    (output + stderr.decode("mbcs", "replace")).strip(),
                ),
            )
        return output

    def _dhcid(self):
        output = self._command(
            ["/EnumRecords", self.zone, self.name, "/Type", "DHCID", "/Detail"],
            allowed_errors=(9701, 9714),
        )
        # /Detail exposes stable RPC field identifiers; do not parse translated
        # prose, addresses, headings or success messages.
        pattern = (
            r"dwTtlSeconds\s*=\s*(\d+)\s+dwTimeStamp\s*=\s*(\d+)"
            r"[^\r\n]*\bDHCID[\t ]+([A-Za-z0-9+/=]+)"
        )
        records = [
            {
                "HostName": self.name,
                "RecordType": "DHCID",
                "TimeToLive": _interval(int(ttl)),
                "Timestamp": int(timestamp) or None,
                "RecordData": {"DhcId": value},
            }
            for ttl, timestamp, value in re.findall(pattern, output)
        ]
        if not records and re.search(r"wType\s*=\s*DHCID\b", output):
            raise ValueError(
                "DNS administration returned unreadable DHCID metadata; no records were changed."
            )
        return records

    def _write_dhcid(self, arguments, value, ttl=None, aging=False):
        try:
            self._command(arguments)
        except OSError as error:
            if error.errno != 0xC0000005:
                raise
            # Some installed DNS tools crash after saving a DHCID. Accept only
            # an exact, fresh native confirmation; every other error stays failed.
            records = self._dhcid()
            if ttl is None:
                if not any(row["RecordData"]["DhcId"] == value for row in records):
                    return
            elif any(
                row["RecordData"]["DhcId"] == value
                and _seconds(row["TimeToLive"]) == ttl
                and (row["Timestamp"] is not None) == aging
                for row in records
            ):
                return
            raise

    def read(self):
        """Read the selected native records with upstream's read-error policy.

        :returns: Selected records, or no records after a native read failure.
        :rtype: list
        """
        try:
            if self.kind == "DHCID":
                return self._dhcid()
            field = _CLASSIC_PROPERTIES[self.kind]
            properties = ["__PATH", "OwnerName", "TTL", "Timestamp", field]
            if self.kind == "SRV":
                properties += ["Port", "Priority", "Weight"]
            rows = self.connection.query(
                "SELECT * FROM MicrosoftDNS_"
                + self.kind
                + "Type WHERE ContainerName="
                + classic.literal(self.zone)
                + " AND OwnerName="
                + classic.literal(self.owner),
                properties,
            )
        except OSError:
            return []
        records = []
        for row in rows:
            value = _classic_text(row[field]) if self.kind == "TXT" else row[field]
            data = {_PROPERTIES[self.kind]: value}
            if self.kind == "SRV":
                data.update(
                    {name: row[name] for name in ("Port", "Priority", "Weight")}
                )
            records.append(
                {
                    "HostName": self.name,
                    "RecordType": self.kind,
                    "TimeToLive": _interval(row["TTL"]),
                    "Timestamp": row["Timestamp"] or None,
                    "RecordData": data,
                    "__classic_row": row,
                }
            )
        return records

    def remove(self, record):
        """Remove only the exact observed record selected by reconciliation.

        :param dict record: Original native record projection.
        :raises OSError: The native deletion fails.
        """
        if self.kind == "DHCID":
            value = record["RecordData"]["DhcId"]
            self._write_dhcid(
                [
                    "/RecordDelete",
                    self.zone,
                    self.name,
                    self.kind,
                    value,
                    "/f",
                ],
                value,
            )
        else:
            classic.delete(self.connection, record["__classic_row"]["__PATH"])

    def update(self, old, new):
        """Update the exact observed record's lifetime and SRV parameters.

        :param dict old: Original selected record.
        :param dict new: Requested updated record.
        :raises OSError: The installed DNS facility rejects the edit.
        """
        if self.kind == "DHCID":
            arguments = ["/RecordAdd", self.zone, self.name]
            if old["Timestamp"] is not None:
                arguments.append("/Aging")
            ttl = _seconds(new["TimeToLive"])
            value = old["RecordData"]["DhcId"]
            self._write_dhcid(
                arguments
                + [
                    str(ttl),
                    self.kind,
                    value,
                ],
                value,
                ttl,
                old["Timestamp"] is not None,
            )
            return
        if (
            self.kind == "TXT"
            and self.tool
            and _classic_text(old["__classic_row"]["DescriptiveText"])
            != old["__classic_row"]["DescriptiveText"]
        ):
            # The older WMI TXT setter mishandles its ANSI-projected UTF-8 data.
            # DNSCmd updates the existing Unicode value without that lossy round trip.
            arguments = ["/RecordAdd", self.zone, self.name]
            if old["Timestamp"] is not None:
                arguments.append("/Aging")
            self._command(
                arguments
                + [
                    str(_seconds(new["TimeToLive"])),
                    "TXT",
                    old["RecordData"]["DescriptiveText"],
                ]
            )
            return
        inputs = {"TTL": _seconds(new["TimeToLive"])}
        if self.kind == "SRV":
            inputs.update(
                {
                    name: new["RecordData"][name]
                    for name in ("Port", "Priority", "Weight")
                }
            )
        if self.kind == "TXT":
            # TXT Modify requires its data even on a TTL-only edit. Preserve
            # the exact provider text rather than re-encoding the public value.
            inputs["DescriptiveText"] = old["__classic_row"]["DescriptiveText"]
        classic.call(self.connection, old["__classic_row"]["__PATH"], "Modify", inputs)

    def add(self, value):
        """Add one requested value without modifying other types at its owner.

        :param str value: Native value after public hostname normalization.
        :raises OSError: The installed facility rejects creation.
        """
        options = self.options
        if (
            self.kind in ("DHCID", "TXT")
            and self.tool
            or options["aging"]
            or options["allow_update_any"]
        ):
            arguments = ["/RecordAdd", self.zone, self.name]
            if options["aging"]:
                arguments.append("/Aging")
            if options["allow_update_any"]:
                arguments.append("/OpenAcl")
            arguments.append(str(options["ttl"]))
            arguments.append(self.kind)
            if self.kind == "SRV":
                arguments += [
                    str(options[name]) for name in ("priority", "weight", "port")
                ]
            if self.kind == "DHCID":
                self._write_dhcid(
                    arguments + [value], value, options["ttl"], options["aging"]
                )
            else:
                self._command(arguments + [value])
            return
        inputs = {
            "DnsServerName": options["computer_name"] or ".",
            "ContainerName": self.zone,
            "OwnerName": self.owner,
            "RecordClass": 1,
            "TTL": options["ttl"],
            _CLASSIC_PROPERTIES[self.kind]: value,
        }
        if self.kind == "SRV":
            inputs.update(
                {name.title(): options[name] for name in ("port", "priority", "weight")}
            )
        classic.call(
            self.connection,
            "MicrosoftDNS_" + self.kind + "Type",
            "CreateInstanceFromPropertyData",
            inputs,
        )

    def validate_add(self, value):
        """Validate DHCID without any DNS mutation, including check mode.

        :param str value: Requested record value.
        :raises OSError: DHCID cannot be decoded.
        """
        if self.kind == "DHCID":
            _validate_dhcid(value)


def _edited_record(record, options):
    kind = options["type"].upper()
    fields = ("port", "weight", "priority") if kind == "SRV" else ()
    if _seconds(record["TimeToLive"]) == options["ttl"] and all(
        record["RecordData"][name.title()] == options[name] for name in fields
    ):
        return None
    new = copy.deepcopy(record)
    new["TimeToLive"] = _interval(options["ttl"])
    for name in fields:
        new["RecordData"][name.title()] = options[name]
    return new


def _edited_line(options, record):
    kind = options["type"].upper()
    value = _record_value(record, kind)
    if kind == "SRV":
        # The released preview includes these fields on edits, not additions
        # or full real-state diffs. Preserve its port/weight/priority order.
        data = record["RecordData"]
        value += " {0} {1} {2}".format(data["Port"], data["Weight"], data["Priority"])
    return _line(options, record["HostName"], _seconds(record["TimeToLive"]), value)


def _manage(provider, options, check_mode, diff):
    kind = options["type"].upper()
    values = list(options["value"] or [])
    if (
        kind in ("CNAME", "NS", "PTR", "SRV")
        and values
        and not options["zone"].endswith(".")
    ):
        values = [value if value.endswith(".") else value + "." for value in values]
    before = _released_order(provider.read())
    changes = {"before": "", "after": ""}
    result = {"changed": False}
    required = OrderedDict((value.upper(), value) for value in values)
    for record in before:
        value = _record_value(record, kind)
        if (
            value.upper() not in required
            or (record["Timestamp"] is not None) != options["aging"]
        ):
            if not check_mode:
                provider.remove(record)
            changes["before"] += _line(
                options, record["HostName"], _seconds(record["TimeToLive"]), value
            )
            result["changed"] = True
            continue
        new = _edited_record(record, options)
        if new is not None:
            if not check_mode:
                provider.update(record, new)
            changes["before"] += _edited_line(options, record)
            changes["after"] += _edited_line(options, new)
            result["changed"] = True
        del required[value.upper()]
        values = list(required.values())
    for value in values:
        result["debug_splat_args"] = {options["type"]: True, _PROPERTIES[kind]: value}
        try:
            provider.validate_add(value)
            if not check_mode:
                provider.add(value)
        except OSError:
            result.update(
                failed=True,
                msg="Error adding DNS {0} resource {1} in zone {2} with value {3}".format(
                    options["type"], options["name"], options["zone"], value
                ),
            )
            return result
        changes["after"] += _line(options, options["name"], options["ttl"], value)
    if values:
        result["changed"] = True
    if diff:
        result["diff"] = (
            changes
            if check_mode
            else {
                "before": _display(options, before),
                "after": _display(options, _released_order(provider.read())),
            }
        )
    return result


def manage(options, check_mode, diff):
    """Apply a DNS record request through the installed native management provider.

    :param dict options: Converted public record parameters.
    :param bool check_mode: Predict changes without mutation.
    :param bool diff: Include the released textual record differences.
    :returns: Public Ansible result for the record request.
    :rtype: dict
    :raises OSError: DNS Server rejects a read-modify-write operation.
    :raises ValueError: The required native provider is unavailable or returns malformed data.
    """
    with ExitStack() as cleanup:
        # Keep record-specific provider discovery here; only genuine absence falls back.
        # pylint: disable=duplicate-code
        try:
            connection = cleanup.enter_context(wmi.WmiConnection(_NAMESPACE))
            definitions = connection.query(
                "SELECT * FROM meta_class WHERE __CLASS='PS_DnsServerResourceRecord'",
                ["__CLASS"],
            )
        except OSError as error:
            if not classic.unavailable(error):
                raise
            definitions = []
        if definitions:
            return _manage(_Records(connection, options), options, check_mode, diff)
        # pylint: enable=duplicate-code
    namespace = classic.NAMESPACE
    if options["computer_name"] is not None:
        namespace = "\\\\" + options["computer_name"] + "\\" + namespace
    try:
        with wmi.WmiConnection(namespace) as connection:
            return _manage(
                _ClassicRecords(connection, options), options, check_mode, diff
            )
    except OSError as error:
        if classic.unavailable(error):
            raise ValueError(
                "Windows DNS Server record management provider is unavailable "
                "(modern DNS and ROOT\\MicrosoftDNS)."
            ) from error
        raise
