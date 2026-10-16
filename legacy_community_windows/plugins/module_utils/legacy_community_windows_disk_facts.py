# -*- coding: utf-8 -*-
# Copyright 2017 Marc Tschapek <marc.tschapek@itelligence.de>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Collect released disk-fact shapes from modern and legacy native providers."""

import uuid

# These helpers are staged by the corresponding concrete action.
# pylint: disable=import-error
from legacy_community_windows_disk_facts_native import (
    FactsConnection,
    describe_disk,
    require_administrator,
    volume_details,
)
from legacy_windows_module import as_string

# pylint: enable=import-error

_STORAGE_NAMESPACE = "ROOT\\Microsoft\\Windows\\Storage"

_DISK_FIELDS = {
    "number": "Number",
    "size": "Size",
    "bus_type": "BusType",
    "friendly_name": "FriendlyName",
    "partition_style": "PartitionStyle",
    "partition_count": "NumberOfPartitions",
    "operational_status": "OperationalStatus",
    "sector_size": "PhysicalSectorSize",
    "read_only": "IsReadOnly",
    "bootable": "IsBoot",
    "system_disk": "IsSystem",
    "clustered": "IsClustered",
    "manufacturer": "Manufacturer",
    "model": "Model",
    "firmware_version": "FirmwareVersion",
    "location": "Location",
    "serial_number": "SerialNumber",
    "unique_id": "UniqueId",
    "guid": "Guid",
    "path": "Path",
}

_PHYSICAL_FIELDS = {
    "size": "Size",
    "allocated_size": "AllocatedSize",
    "device_id": "DeviceId",
    "friendly_name": "FriendlyName",
    "operational_status": "OperationalStatus",
    "health_status": "HealthStatus",
    "bus_type": "BusType",
    "usage_type": "Usage",
    "supported_usages": "SupportedUsages",
    "spindle_speed": "SpindleSpeed",
    "firmware_version": "FirmwareVersion",
    "physical_location": "PhysicalLocation",
    "manufacturer": "Manufacturer",
    "model": "Model",
    "can_pool": "CanPool",
    "indication_enabled": "IsIndicationEnabled",
    "partial": "IsPartial",
    "serial_number": "SerialNumber",
    "object_id": "ObjectId",
    "unique_id": "UniqueId",
    "media_type": "MediaType",
    "cannot_pool_reason": "CannotPoolReason",
}

_VIRTUAL_FIELDS = {
    "size": "Size",
    "allocated_size": "AllocatedSize",
    "footprint_on_pool": "FootprintOnPool",
    "name": "Name",
    "friendly_name": "FriendlyName",
    "operational_status": "OperationalStatus",
    "health_status": "HealthStatus",
    "provisioning_type": "ProvisioningType",
    "allocation_unit_size": "AllocationUnitSize",
    "media_type": "MediaType",
    "parity_layout": "ParityLayout",
    "access": "Access",
    "detached_reason": "DetachedReason",
    "write_cache_size": "WriteCacheSize",
    "fault_domain_awareness": "FaultDomainAwareness",
    "inter_leave": "InterLeave",
    "deduplication_enabled": "IsDeduplicationEnabled",
    "enclosure_aware": "IsEnclosureAware",
    "manual_attach": "IsManualAttach",
    "snapshot": "IsSnapshot",
    "tiered": "IsTiered",
    "physical_sector_size": "PhysicalSectorSize",
    "logical_sector_size": "LogicalSectorSize",
    "available_copies": "NumberOfAvailableCopies",
    "columns": "NumberOfColumns",
    "groups": "NumberOfGroups",
    "physical_disk_redundancy": "PhysicalDiskRedundancy",
    "read_cache_size": "ReadCacheSize",
    "request_no_spof": "RequestNoSinglePointOfFailure",
    "resiliency_setting_name": "ResiliencySettingName",
    "object_id": "ObjectId",
    "unique_id_format": "UniqueIdFormat",
    "unique_id": "UniqueId",
}

_WIN32_FIELDS = {
    "availability": "Availability",
    "bytes_per_sector": "BytesPerSector",
    "capabilities": "Capabilities",
    "capability_descriptions": "CapabilityDescriptions",
    "caption": "Caption",
    "compression_method": "CompressionMethod",
    "config_manager_error_code": "ConfigManagerErrorCode",
    "config_manager_user_config": "ConfigManagerUserConfig",
    "creation_class_name": "CreationClassName",
    "default_block_size": "DefaultBlockSize",
    "description": "Description",
    "device_id": "DeviceID",
    "error_cleared": "ErrorCleared",
    "error_description": "ErrorDescription",
    "error_methodology": "ErrorMethodology",
    "firmware_revision": "FirmwareRevision",
    "index": "Index",
    "install_date": "InstallDate",
    "interface_type": "InterfaceType",
    "last_error_code": "LastErrorCode",
    "manufacturer": "Manufacturer",
    "max_block_size": "MaxBlockSize",
    "max_media_size": "MaxMediaSize",
    "media_loaded": "MediaLoaded",
    "media_type": "MediaType",
    "min_block_size": "MinBlockSize",
    "model": "Model",
    "name": "Name",
    "needs_cleaning": "NeedsCleaning",
    "number_of_media_supported": "NumberOfMediaSupported",
    "partitions": "Partitions",
    "pnp_device_id": "PNPDeviceID",
    "power_management_capabilities": "PowerManagementCapabilities",
    "power_management_supported": "PowerManagementSupported",
    "scsi_bus": "SCSIBus",
    "scsi_logical_unit": "SCSILogicalUnit",
    "scsi_port": "SCSIPort",
    "scsi_target_id": "SCSITargetId",
    "sectors_per_track": "SectorsPerTrack",
    "serial_number": "SerialNumber",
    "signature": "Signature",
    "size": "Size",
    "status": "Status",
    "status_info": "StatusInfo",
    "system_creation_class_name": "SystemCreationClassName",
    "system_name": "SystemName",
    "total_cylinders": "TotalCylinders",
    "total_heads": "TotalHeads",
    "total_sectors": "TotalSectors",
    "total_tracks": "TotalTracks",
    "tracks_per_cylinder": "TracksPerCylinder",
}

_PARTITION_FIELDS = {
    "number": "PartitionNumber",
    "size": "Size",
    "type": "Type",
    "drive_letter": "DriveLetter",
    "transition_state": "TransitionState",
    "offset": "Offset",
    "hidden": "IsHidden",
    "shadow_copy": "IsShadowCopy",
    "guid": "Guid",
    "access_paths": "AccessPaths",
    "gpt_type": "GptType",
    "no_default_driveletter": "NoDefaultDriveLetter",
    "mbr_type": "MbrType",
    "active": "IsActive",
}

_VOLUME_FIELDS = {
    "size": "Size",
    "size_remaining": "SizeRemaining",
    "type": "FileSystem",
    "label": "FileSystemLabel",
    "health_status": "HealthStatus",
    "drive_type": "DriveType",
    "object_id": "ObjectId",
    "path": "Path",
    "allocation_unit_size": "AllocationUnitSize",
}

_NUMERIC_FIELDS = set(
    [
        "Count",
        "allocated_size",
        "allocation_unit_size",
        "availability",
        "available_copies",
        "bytes_per_sector",
        "columns",
        "config_manager_error_code",
        "default_block_size",
        "footprint_on_pool",
        "groups",
        "index",
        "inter_leave",
        "last_error_code",
        "logical_sector_size",
        "max_block_size",
        "max_media_size",
        "mbr_type",
        "min_block_size",
        "number",
        "number_of_media_supported",
        "offset",
        "parity_layout",
        "partition_count",
        "partitions",
        "physical_disk_redundancy",
        "physical_sector_size",
        "read_cache_size",
        "scsi_bus",
        "scsi_logical_unit",
        "scsi_port",
        "scsi_target_id",
        "sector_size",
        "sectors_per_track",
        "signature",
        "size",
        "size_remaining",
        "spindle_speed",
        "status_info",
        "total_cylinders",
        "total_heads",
        "total_sectors",
        "total_tracks",
        "tracks_per_cylinder",
        "transition_state",
        "write_cache_size",
    ]
)

_BUS = dict(
    enumerate(
        (
            "Unknown",
            "SCSI",
            "ATAPI",
            "ATA",
            "1394",
            "SSA",
            "Fibre Channel",
            "USB",
            "RAID",
            "iSCSI",
            "SAS",
            "SATA",
            "SD",
            "MMC",
            "Virtual",
            "File Backed Virtual",
            "Storage Spaces",
            "NVMe",
            "SCM",
            "UFS",
        )
    )
)
_HEALTH = {0: "Healthy", 1: "Warning", 2: "Unhealthy"}
_STATUS = dict(
    enumerate(
        (
            "Unknown",
            "Other",
            "OK",
            "Degraded",
            "Stressed",
            "Predictive Failure",
            "Error",
            "Non-Recoverable Error",
            "Starting",
            "Stopping",
            "Stopped",
            "In Service",
            "No Contact",
            "Lost Communication",
            "Aborted",
            "Dormant",
            "Supporting Entity in Error",
            "Completed",
        )
    )
)
_STATUS.update(
    {
        0xD010: "Online",
        0xD011: "Not Ready",
        0xD012: "No Media",
        0xD013: "Offline",
        0xD014: "Failed",
    }
)
_USAGE = dict(
    enumerate(
        ("Unknown", "Auto-Select", "Manual-Select", "Hot Spare", "Retired", "Journal")
    )
)
_POOL_REASON = dict(
    enumerate(
        (
            "Unknown",
            "Other",
            "In a Pool",
            "Not Healthy",
            "Removable Media",
            "In Use by Cluster",
            "Offline",
            "Insufficient Capacity",
            "Spare Disk",
            "Reserved by subsystem",
            "Starting",
        )
    )
)
_MEDIA = {0: "Unspecified", 3: "HDD", 4: "SSD", 5: "SCM"}
_MBR_TYPE = {
    1: "FAT12",
    4: "FAT16",
    5: "Extended",
    6: "FAT16",
    7: "IFS",
    11: "FAT32",
    12: "FAT32",
    14: "FAT16",
    15: "Extended",
    0x42: "LDM",
}
_GPT_TYPE = {
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "Basic",
    "e3c9e316-0b5c-4db8-817d-f92df00215ae": "Reserved",
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "System",
    "de94bba4-06d1-4d40-a16a-bfd50179d6ac": "Recovery",
}
_DEFAULT_FILTERS = (
    "physical_disk",
    "virtual_disk",
    "win32_disk_drive",
    "partitions",
    "volumes",
)


def _enum(value, labels):
    if value is None:
        return None
    if isinstance(value, list):
        return ", ".join(_enum(item, labels) for item in value)
    return labels.get(value, str(value))


def _project(row, fields):
    result = {name: row.get(property_name) for name, property_name in fields.items()}
    for name in _NUMERIC_FIELDS.intersection(result):
        if result[name] is not None:
            result[name] = int(result[name])
    return result


def _read_rows(connection, class_name, fields, extra=()):
    properties = sorted(set(fields.values()).union(extra, ("__PATH",)))
    return connection.query("SELECT * FROM " + class_name, properties)


def _optional_rows(connection, class_name, fields, warnings, extra=()):
    try:
        return _read_rows(connection, class_name, fields, extra)
    except OSError as error:
        if getattr(error, "hresult", None) not in (0x8004100E, 0x80041010):
            raise
        warnings.append("The installed provider does not expose " + class_name)
        return []


def _storage_group(row, fields):
    group = _project(row, fields)
    for name, labels in (
        ("bus_type", _BUS),
        ("operational_status", _STATUS),
        ("health_status", _HEALTH),
        ("media_type", _MEDIA),
        ("usage_type", _USAGE),
        ("cannot_pool_reason", _POOL_REASON),
        ("provisioning_type", {0: "Unknown", 1: "Thin", 2: "Fixed"}),
        (
            "access",
            {
                0: "Unknown",
                1: "Readable",
                2: "Writeable",
                3: "Read/Write",
                4: "Write Once",
            },
        ),
        (
            "unique_id_format",
            {
                0: "Vendor Specific",
                1: "Vendor Id",
                2: "EUI64",
                3: "FCPH Name",
                8: "SCSI Name String",
            },
        ),
        (
            "fault_domain_awareness",
            {
                0: "Unknown",
                1: "PhysicalDisk",
                2: "StorageEnclosure",
                3: "StorageScaleUnit",
                4: "StorageChassis",
                5: "StorageRack",
            },
        ),
    ):
        if name in group:
            group[name] = _enum(group[name], labels)
    if "supported_usages" in group and group["supported_usages"] is not None:
        usages = [_enum(item, _USAGE) for item in group["supported_usages"]]
        group["supported_usages"] = {"Count": len(usages), "value": usages}
    if group.get("can_pool"):
        group.pop("cannot_pool_reason", None)
    return group


def _drive_letter(value):
    if isinstance(value, int):
        return chr(value) if value else None
    return value or None


def _partition_type(partition):
    if partition.get("gpt_type"):
        identity = str(uuid.UUID(partition["gpt_type"]))
        return _GPT_TYPE.get(identity, "Unknown")
    return _MBR_TYPE.get(partition.get("mbr_type"), "Unknown")


def _modern_partitions(connection, disk, filters, warnings):
    # Type is a PowerShell-added display property, not a native CIM property.
    native_fields = {
        name: property_name
        for name, property_name in _PARTITION_FIELDS.items()
        if name != "type"
    }
    rows = _optional_rows(
        connection, "MSFT_Partition", native_fields, warnings, ("DiskNumber",)
    )
    volumes = (
        _optional_rows(connection, "MSFT_Volume", _VOLUME_FIELDS, warnings)
        if "volumes" in filters
        else []
    )
    result = []
    for row in rows:
        if row["DiskNumber"] != disk["number"]:
            continue
        part = _project(row, _PARTITION_FIELDS)
        part["type"] = _partition_type(part)
        part["drive_letter"] = _drive_letter(part["drive_letter"])
        if disk["partition_style"] == "GPT":
            part.pop("mbr_type", None)
            part.pop("active", None)
        else:
            part.pop("gpt_type", None)
            part.pop("no_default_driveletter", None)
        if volumes:
            paths = {path.casefold() for path in part["access_paths"] or []}
            matched = [
                volume
                for volume in volumes
                if volume["Path"] and volume["Path"].casefold() in paths
            ]
            if matched:
                part["volumes"] = [_volume_info(volume) for volume in matched]
        result.append(part)
    return result


def _volume_info(row):
    volume = _project(row, _VOLUME_FIELDS)
    volume["health_status"] = _enum(volume["health_status"], _HEALTH)
    volume["drive_type"] = _enum(
        volume["drive_type"],
        {
            0: "Unknown",
            1: "No Root Directory",
            2: "Removable",
            3: "Fixed",
            4: "Network",
            5: "CD-ROM",
            6: "RAMDisk",
        },
    )
    return volume


def _storage_groups(connection, disk, physical, filters):
    match = next(
        (item for item in physical if item["DeviceId"] == str(disk["number"])), None
    )
    if match is None:
        return
    if "physical_disk" in filters:
        disk["physical_disk"] = _storage_group(match, _PHYSICAL_FIELDS)
    if "virtual_disk" in filters:
        query = (
            "ASSOCIATORS OF {"
            + match["__PATH"]
            + "} WHERE AssocClass=MSFT_VirtualDiskToPhysicalDisk "
            "ResultClass=MSFT_VirtualDisk"
        )
        virtual = connection.query(query, sorted(set(_VIRTUAL_FIELDS.values())))
        if virtual:
            projected = [_storage_group(item, _VIRTUAL_FIELDS) for item in virtual]
            disk["virtual_disk"] = (
                projected[0]
                if len(projected) == 1
                else {name: [item[name] for item in projected] for name in projected[0]}
            )


def _modern_disks(connection, filters, warnings):
    rows = _read_rows(connection, "MSFT_Disk", _DISK_FIELDS)
    physical = (
        _optional_rows(connection, "MSFT_PhysicalDisk", _PHYSICAL_FIELDS, warnings)
        if set(filters).intersection(("physical_disk", "virtual_disk"))
        else []
    )
    win32 = []
    if "win32_disk_drive" in filters:
        with FactsConnection() as legacy:
            win32 = _read_rows(legacy, "Win32_DiskDrive", _WIN32_FIELDS)
            connection.missing_properties.update(legacy.missing_properties)
    disks = []
    for row in rows:
        if row["Number"] is None:
            continue
        disk = _project(row, _DISK_FIELDS)
        disk["bus_type"] = _enum(disk["bus_type"], _BUS)
        disk["operational_status"] = _enum(disk["operational_status"], _STATUS)
        disk["partition_style"] = _enum(
            disk["partition_style"], {0: "RAW", 1: "MBR", 2: "GPT"}
        )
        _storage_groups(connection, disk, physical, filters)
        legacy_match = next(
            (item for item in win32 if item["Index"] == disk["number"]), None
        )
        if legacy_match is not None:
            disk["win32_disk_drive"] = _project(legacy_match, _WIN32_FIELDS)
        if set(filters).intersection(("partitions", "volumes")):
            partitions = _modern_partitions(connection, disk, filters, warnings)
            if partitions:
                disk["partitions"] = partitions
        disks.append(disk)
    return disks


def _legacy_volume(connection, row):
    fields = ("Size", "FreeSpace", "FileSystem", "VolumeName", "DriveType", "DeviceID")
    path = row["__PATH"]
    query = (
        "ASSOCIATORS OF {"
        + path
        + "} WHERE AssocClass=Win32_LogicalDiskToPartition ResultClass=Win32_LogicalDisk"
    )
    volumes = connection.query(query, fields)
    result = [
        {
            "size": int(volume["Size"]) if volume["Size"] is not None else None,
            "size_remaining": (
                int(volume["FreeSpace"]) if volume["FreeSpace"] is not None else None
            ),
            "type": volume["FileSystem"],
            "label": volume["VolumeName"],
            "health_status": None,
            "drive_type": _enum(
                volume["DriveType"],
                {2: "Removable", 3: "Fixed", 4: "Network", 5: "CD-ROM", 6: "RAMDisk"},
            ),
            "object_id": None,
            "_drive_path": volume["DeviceID"] + "\\",
        }
        for volume in volumes
    ]
    for volume in result:
        volume.update(volume_details(volume["_drive_path"]))
    return result


def _legacy_partitions(connection, rows, metadata, filters):
    result = []
    for entry in metadata["partitions"]:
        part = {name: None for name in _PARTITION_FIELDS}
        part.update(entry)
        part["type"] = _partition_type(part)
        row = next(
            (item for item in rows if int(item["StartingOffset"]) == entry["offset"]),
            None,
        )
        if row is not None:
            volumes = _legacy_volume(connection, row)
            part["access_paths"] = [
                path
                for volume in volumes
                for path in (volume["_drive_path"], volume["path"])
            ]
            part["drive_letter"] = volumes[0]["_drive_path"][0] if volumes else None
            if volumes and "volumes" in filters:
                part["volumes"] = [
                    {
                        key: value
                        for key, value in volume.items()
                        if key != "_drive_path"
                    }
                    for volume in volumes
                ]
        if metadata["layout"]["style"] != "gpt":
            part.pop("gpt_type", None)
            part.pop("no_default_driveletter", None)
        else:
            part.pop("mbr_type", None)
            part.pop("active", None)
        result.append(part)
    return result


def _legacy_device_strings(device, row):
    result = {}
    for name, property_name in (
        ("manufacturer", "Manufacturer"),
        ("model", "Model"),
        ("firmware_version", "FirmwareRevision"),
        ("serial_number", "SerialNumber"),
    ):
        value = device.get(name) or row[property_name]
        result[name] = value if value and value.strip() else None
    return result


def _legacy_disks(connection, filters, warnings):
    rows = _read_rows(connection, "Win32_DiskDrive", _WIN32_FIELDS)
    partition_rows = (
        connection.query(
            "SELECT * FROM Win32_DiskPartition",
            ("__PATH", "DiskIndex", "StartingOffset"),
        )
        if set(filters).intersection(("partitions", "volumes"))
        else []
    )
    warnings.append(
        "Modern storage metadata is unavailable. Unsupported facts are null; "
        "legacy unique_id is the disk-layout identifier. Directory-only volume "
        "mounts are not associated by the legacy provider."
    )
    disks = []
    for row in rows:
        metadata = describe_disk(row["DeviceID"])
        warnings.extend(metadata.get("warnings", []))
        layout, device = metadata["layout"], metadata["device"]
        attributes = layout["attributes"]
        disk = {name: None for name in _DISK_FIELDS}
        disk.update(
            number=int(row["Index"]),
            size=metadata.get("size")
            or (int(row["Size"]) if row["Size"] is not None else None),
            bus_type=_enum(device.get("bus_type"), _BUS),
            friendly_name=row["Model"],
            partition_style=layout["style"].upper(),
            partition_count=len(metadata["partitions"]),
            sector_size=metadata["sector_size"] or row["BytesPerSector"],
            read_only=bool(attributes & 2) if attributes is not None else None,
            operational_status=(
                ("Offline" if attributes & 1 else "Online")
                if attributes is not None
                else None
            ),
            unique_id=layout["uniqueid"],
            guid="{" + layout["uniqueid"] + "}" if layout["style"] == "gpt" else None,
            path=row["DeviceID"],
        )
        disk.update(_legacy_device_strings(device, row))
        if "physical_disk" in filters:
            physical = {name: None for name in _PHYSICAL_FIELDS}
            physical.update(
                {name: value for name, value in disk.items() if name in physical}
            )
            physical["device_id"] = str(disk["number"])
            disk["physical_disk"] = physical
        if "win32_disk_drive" in filters:
            disk["win32_disk_drive"] = _project(row, _WIN32_FIELDS)
        if set(filters).intersection(("partitions", "volumes")):
            selected = [
                item for item in partition_rows if item["DiskIndex"] == disk["number"]
            ]
            parts = _legacy_partitions(connection, selected, metadata, filters)
            if parts:
                disk["partitions"] = parts
        disks.append(disk)
    return disks


def collect_facts(arguments):
    """Read the public fact groups using the actual installed storage provider.

    :param dict arguments: Module filter and internal Ansible arguments.
    :returns: Unchanged result containing the released ansible_disks fact.
    :rtype: dict
    :raises ValueError: A filter or native fact has an invalid value.
    :raises OSError: Required native provider access fails.
    """
    filters = arguments.get("filter")
    if filters is None:
        filters = list(_DEFAULT_FILTERS)
    if not isinstance(filters, list):
        filters = str(filters).split(",")
    filters = [as_string(value, "filter") for value in filters]
    if any(value not in _DEFAULT_FILTERS for value in filters):
        raise ValueError("filter must contain only " + ", ".join(_DEFAULT_FILTERS))
    require_administrator()
    warnings = []
    try:
        with FactsConnection(_STORAGE_NAMESPACE) as connection:
            disks = _modern_disks(connection, filters, warnings)
            missing = connection.missing_properties
    except OSError as error:
        if getattr(error, "hresult", None) not in (0x8004100E, 0x80041010):
            raise
        with FactsConnection() as connection:
            disks = _legacy_disks(connection, filters, warnings)
            missing = connection.missing_properties
    if missing:
        warnings.append(
            "Installed providers omit these fields; they are null: "
            + ", ".join(sorted(missing))
        )
    result = {
        "changed": False,
        "ansible_facts": {
            "ansible_disks": sorted(disks, key=lambda disk: disk["number"])
        },
    }
    if warnings:
        result["warnings"] = warnings
    return result
