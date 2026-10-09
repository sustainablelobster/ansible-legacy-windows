# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later

"""Seed and independently observe records only in a journal-owned DNS zone."""

import json
import os
import re
import subprocess
import sys
import tempfile
from contextlib import ExitStack

import legacy_windows_dns_classic as classic  # pylint: disable=import-error
import legacy_windows_dns_record as dns_record  # pylint: disable=import-error
import legacy_windows_wmi as wmi  # pylint: disable=import-error

_NAMESPACE = r"ROOT\Microsoft\Windows\Dns"
# This observer must select native fields independently of the payload's map.
# pylint: disable=duplicate-code
_RECORD_FIELDS = {
    "A": "IPAddress",
    "AAAA": "IPv6Address",
    "CNAME": "PrimaryName",
    "NS": "NSHost",
    "PTR": "PTRDomainName",
    "SRV": "SRVDomainName",
    "TXT": "DescriptiveText",
}
# pylint: enable=duplicate-code


def _owned_zone(workspace):
    assert os.path.basename(os.path.abspath(workspace)).startswith(
        "legacy-windows-dns-zone-"
    )
    assert os.path.samefile(
        os.path.dirname(os.path.abspath(workspace)), tempfile.gettempdir()
    )
    with open(
        os.path.join(workspace, "dns-zone-journal.json"), encoding="utf-8"
    ) as source:
        journal = json.load(source)
    assert journal["workspace"] == workspace and journal["prepared"] is not None
    assert len(journal["zones"]) == 1
    return journal["zones"][0]


def _options(zone, request):
    options = {
        "zone": zone,
        "name": "record",
        "type": "A",
        "value": [],
        "ttl": 3600,
        "aging": False,
        "allow_update_any": False,
        "computer_name": None,
        "zone_scope": None,
        "port": None,
        "weight": None,
        "priority": None,
    }
    options.update(request)
    assert options["zone"] == zone and options["computer_name"] is None
    assert options["zone_scope"] is None
    return options


def _observe(connection, options, classic_provider=False):
    if classic_provider:
        return _observe_classic(connection, options)
    # Enumerating the whole owned zone avoids suppressing a missing-record error.
    # Selection uses raw provider fields, not the module's reconciliation/read code.
    packet = connection.call_method(
        "PS_DnsServerResourceRecord",
        "Get",
        ["ReturnValue", "cmdletOutput"],
        {"ZoneName": options["zone"]},
    )
    assert packet["ReturnValue"] in (None, 0), packet
    rows = packet["cmdletOutput"] or []
    selected = [
        row
        for row in rows
        if row["HostName"].lower() == options["name"].lower()
        and row["RecordType"].lower() == options["type"].lower()
    ]
    return {"records": selected, "python": list(sys.version_info[:3])}


def _observe_classic(connection, options):
    zone = options["zone"]
    kind = options["type"].upper()
    owner = options["name"] + "." + zone
    fields = [
        "__CLASS",
        "__PATH",
        "OwnerName",
        "RecordData",
        "TextRepresentation",
        "TTL",
        "Timestamp",
    ]
    rows = connection.query(
        "SELECT * FROM MicrosoftDNS_ResourceRecord WHERE ContainerName="
        + classic.literal(zone),
        fields,
    )
    selected = [
        row
        for row in rows
        if row["OwnerName"].lower() == owner.lower()
        and row["__CLASS"].lower() == ("MicrosoftDNS_" + kind + "Type").lower()
    ]
    result = {
        "records": selected,
        "python": list(sys.version_info[:3]),
        "all_records": rows,
        "values": [],
        "ttls": [],
        "timestamps": [],
    }
    if kind in _RECORD_FIELDS:
        result.update(_classic_values(connection, zone, owner, kind))
    if kind == "DHCID":
        assert not selected
        result.update(_observe_dhcid(zone, options["name"]))
    return result


def _classic_values(connection, zone, owner, kind):
    field = _RECORD_FIELDS[kind]
    rows = connection.query(
        "SELECT * FROM MicrosoftDNS_"
        + kind
        + "Type WHERE ContainerName="
        + classic.literal(zone)
        + " AND OwnerName="
        + classic.literal(owner),
        [field, "TTL", "Timestamp"],
    )
    result = {"values": [], "ttls": [], "timestamps": []}
    for row in rows:
        value = row[field]
        if kind == "TXT":
            try:
                value = value.encode("mbcs").decode("utf-8")
            except UnicodeError:
                pass
        result["values"].append(value)
        result["ttls"].append(row["TTL"])
        result["timestamps"].append(row["Timestamp"])
    return result


def _observe_dhcid(zone, name):
    tool = os.path.join(os.environ["SystemRoot"], "System32", "dnscmd.exe")
    with subprocess.Popen(
        [tool, "/EnumRecords", zone, name, "/Type", "DHCID", "/Detail"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        stdout, stderr = process.communicate()
    result = {"records": [], "values": [], "ttls": [], "timestamps": []}
    text = stdout.decode("mbcs", "replace")
    if process.returncode in (9714, 9701):
        return result
    assert process.returncode == 0, (process.returncode, text, stderr)
    # Retain all real fields while removing only process-address noise that
    # changes between two nonmutating native reads.
    text = re.sub(r"(?m)^[\t ]*ptr[\t ]*=[\t ]*[0-9A-Fa-f]+[\t ]*\r?$", "", text)
    if re.search(r"wType\s*=\s*DHCID\b", text):
        result["records"] = [{"native_details": text}]
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("dwTtlSeconds"):
            result["ttls"].append(int(stripped.split("=", 1)[1]))
        if stripped.startswith("dwTimeStamp"):
            result["timestamps"].append(int(stripped.split("=", 1)[1].split()[0]))
            result["values"].append(stripped.split("DHCID", 1)[1].strip())
    return result


# Setup intentionally accesses just the private type-specific provider, not reconciliation.
# pylint: disable=protected-access
def _seed(connection, options, classic_provider=False):
    assert not _observe(connection, options, classic_provider)["records"]
    # Setup uses only type-specific additions, never the algorithm under test.
    # The independently observed public operation must still prove every mutation.
    provider_type = (
        dns_record._ClassicRecords if classic_provider else dns_record._Records
    )
    provider = provider_type(connection, options)
    for value in options["value"]:
        provider.add(value)
    return _observe(connection, options, classic_provider)


# pylint: enable=protected-access


def _main():
    assert sys.version_info[:3] == (3, 4, 4)
    workspace, operation, request = sys.argv[1:4]
    assert operation in ("observe", "seed")
    options = _options(_owned_zone(workspace), json.loads(request))
    with ExitStack() as cleanup:
        try:
            connection = cleanup.enter_context(wmi.WmiConnection(_NAMESPACE))
        except OSError as error:
            if not classic.unavailable(error):
                raise
            connection = cleanup.enter_context(wmi.WmiConnection(classic.NAMESPACE))
            classic_provider = True
        else:
            classic_provider = False
        result = (
            _observe(connection, options, classic_provider)
            if operation == "observe"
            else _seed(connection, options, classic_provider)
        )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    _main()
