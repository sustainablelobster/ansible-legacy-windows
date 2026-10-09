# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read the selected setup facts using native Windows APIs and WMI."""

# Fixed native collectors and process startup share these ABI/registry reads;
# splitting only for the line count would add another staged target dependency.
# pylint: disable=too-many-lines

import base64
import contextlib
import ctypes
import datetime
import fnmatch
import glob
import json
import math
import os
import shutil
import struct
import subprocess
import tempfile
import time
import uuid

try:
    import winreg
except ImportError:
    winreg = None

import legacy_windows_account as account  # pylint: disable=import-error
import legacy_windows_async_native as async_native  # pylint: disable=import-error
import legacy_windows_group as group  # pylint: disable=import-error
import legacy_windows_setup_date as date_time  # pylint: disable=import-error
import legacy_windows_setup_network as network  # pylint: disable=import-error
import legacy_windows_setup_winrm as winrm  # pylint: disable=import-error

# The action stages the WMI sibling alongside this target-only helper.
# pylint: disable=import-error
from legacy_windows_wmi import (  # pylint: disable=import-error
    WmiConnection,
    parse_datetime,
)

_CURRENT_VERSION = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"


# Fixed-width Windows fields preserve the native ABI on both architectures.
class _MemoryStatus(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("length", ctypes.c_uint32), ("load", ctypes.c_uint32)] + [
        (name, ctypes.c_uint64)
        for name in (
            "total",
            "available",
            "total_page",
            "available_page",
            "total_virtual",
            "available_virtual",
            "extended_virtual",
        )
        # pylint: enable=import-error
    ]


class _DomainInfo(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("role", ctypes.c_int32),
        ("flags", ctypes.c_uint32),
        ("flat", ctypes.c_wchar_p),
        ("dns", ctypes.c_wchar_p),
        ("forest", ctypes.c_wchar_p),
        ("guid", ctypes.c_byte * 16),
    ]


class _WorkstationInfo(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("platform", ctypes.c_uint32),
        ("computer", ctypes.c_wchar_p),
        ("group", ctypes.c_wchar_p),
        ("major", ctypes.c_uint32),
        ("minor", ctypes.c_uint32),
    ]


class _SystemInfo(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("architecture", ctypes.c_uint16),
        ("reserved", ctypes.c_uint16),
        ("page_size", ctypes.c_uint32),
        ("minimum", ctypes.c_void_p),
        ("maximum", ctypes.c_void_p),
        ("mask", ctypes.c_size_t),
        ("processors", ctypes.c_uint32),
        ("processor_type", ctypes.c_uint32),
        ("allocation", ctypes.c_uint32),
        ("level", ctypes.c_uint16),
        ("revision", ctypes.c_uint16),
    ]


class _OsVersion(ctypes.Structure):  # pylint: disable=too-few-public-methods
    # Repeat the fixed Windows record layout without adding a staging dependency.
    # pylint: disable=duplicate-code
    _fields_ = [
        ("size", ctypes.c_uint32),
        ("major", ctypes.c_uint32),
        ("minor", ctypes.c_uint32),
        ("build", ctypes.c_uint32),
        ("platform", ctypes.c_uint32),
        ("service_pack", ctypes.c_uint16 * 128),
        ("service_pack_major", ctypes.c_uint16),
        ("service_pack_minor", ctypes.c_uint16),
        ("suite", ctypes.c_uint16),
        ("product_type", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8),
    ]
    # pylint: enable=duplicate-code


def windows_version():
    """Read the native OS version independently of Python's executable manifest.

    :returns: Native version, service-pack words and product type.
    :rtype: ctypes.Structure
    :raises OSError: RtlGetVersion cannot read the running operating system.
    """
    library = ctypes.WinDLL("ntdll", use_last_error=True)
    library.RtlGetVersion.argtypes = [ctypes.POINTER(_OsVersion)]
    library.RtlGetVersion.restype = ctypes.c_int32
    version = _OsVersion(size=ctypes.sizeof(_OsVersion))
    status = library.RtlGetVersion(ctypes.byref(version))
    if status < 0:
        raise OSError(
            "RtlGetVersion failed (NTSTATUS 0x{0:08X}).".format(status & 0xFFFFFFFF)
        )
    return version


class _JobLimits(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("process_time", ctypes.c_int64),
        ("job_time", ctypes.c_int64),
        ("flags", ctypes.c_uint32),
        ("minimum", ctypes.c_size_t),
        ("maximum", ctypes.c_size_t),
        ("active_processes", ctypes.c_uint32),
        ("affinity", ctypes.c_size_t),
        ("priority", ctypes.c_uint32),
        ("scheduling", ctypes.c_uint32),
    ]


class _ExtendedJobLimits(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("basic", _JobLimits),
        ("io_counters", ctypes.c_uint64 * 6),
        ("process_memory", ctypes.c_size_t),
        ("job_memory", ctypes.c_size_t),
        ("peak_process", ctypes.c_size_t),
        ("peak_job", ctypes.c_size_t),
    ]


@contextlib.contextmanager
# Pylint's Sphinx parser has no yield fields; returns documents this context.
# pylint: disable-next=missing-yield-doc,missing-yield-type-doc
def owned_job(process_handle):
    """Own a fact worker and its descendants until the collector finishes.

    :param process_handle: Windows Popen handle for the owned waiting worker.
    :type process_handle: int
    :returns: Context yielding None after successful assignment.
    :rtype: context manager
    :raises OSError: Windows cannot create, configure or assign the job.
    """
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    kernel.CreateJobObjectW.restype = ctypes.c_void_p
    kernel.SetInformationJobObject.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
    ]
    kernel.SetInformationJobObject.restype = ctypes.c_int
    kernel.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    kernel.AssignProcessToJobObject.restype = ctypes.c_int
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    handle = kernel.CreateJobObjectW(None, None)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        limits = _ExtendedJobLimits(_JobLimits(flags=0x2000))
        if not kernel.SetInformationJobObject(
            handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel.AssignProcessToJobObject(handle, process_handle):
            raise ctypes.WinError(ctypes.get_last_error())
        yield
    finally:
        # KILL_ON_JOB_CLOSE also closes any explicit custom script or Facter
        # descendants if the worker timed out or returned before they exited.
        if not kernel.CloseHandle(handle):
            raise ctypes.WinError(ctypes.get_last_error())


def collector_needs_detached():
    """Check whether the caller's job forbids an independently owned collector.

    :returns: True when legacy child creation cannot break away from its job.
    :rtype: bool
    :raises OSError: The native job policy cannot be queried.
    """
    # Both workflows use the maintained launcher's native job-policy query.
    # pylint: disable-next=protected-access
    return not async_native._can_break_away(async_native.kernel_api())


def _collector_kernel():
    kernel = async_native.kernel_api()
    declarations = {
        "CreateEventW": (
            [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p],
            ctypes.c_void_p,
        ),
        "OpenEventW": (
            [ctypes.c_uint32, ctypes.c_int, ctypes.c_wchar_p],
            ctypes.c_void_p,
        ),
        "SetEvent": ([ctypes.c_void_p], ctypes.c_int),
        "GetProcessTimes": (
            [ctypes.c_void_p] + [ctypes.POINTER(ctypes.c_uint64)] * 4,
            ctypes.c_int,
        ),
        "LocalFree": ([ctypes.c_void_p], ctypes.c_void_p),
    }
    for name, (arguments, result) in declarations.items():
        function = getattr(kernel, name)
        function.argtypes, function.restype = arguments, result
    return kernel


def _private_collector_directory(directory, kernel):
    facts = {}
    _user(facts)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    # This independently staged helper owns the fixed native descriptor ABI;
    # sharing four parameter declarations would add an unrelated dependency.
    # pylint: disable=duplicate-code
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = ctypes.c_int
    # pylint: enable=duplicate-code
    security.SetFileSecurityW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    security.SetFileSecurityW.restype = ctypes.c_int
    descriptor = ctypes.c_void_p()
    # IPC belongs to the effective caller, which may differ from the connection
    # account. Files inherit only this SID and SYSTEM, not the shared TEMP ACL.
    sddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{0})".format(facts["ansible_user_sid"])
    if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not security.SetFileSecurityW(directory, 0x80000004, descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.LocalFree(descriptor)


def _process_birth(kernel, handle):
    clocks = [ctypes.c_uint64() for _ in range(4)]
    if not kernel.GetProcessTimes(handle, *[ctypes.byref(clock) for clock in clocks]):
        raise ctypes.WinError(ctypes.get_last_error())
    return clocks[0].value


def _collector_handle(kernel, launched_handle, pid):
    # The launcher's handle pins the original process. Add SET_QUOTA for job
    # assignment, then check birth identity before using the replacement handle.
    handle = kernel.OpenProcess(0x100501, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if _process_birth(kernel, handle) != _process_birth(kernel, launched_handle):
            raise OSError("The detached fact collector's process identity changed.")
    except Exception:
        kernel.CloseHandle(handle)
        raise
    return handle


def await_collector_activation(event_name):
    """Wait a finite interval without collecting before parent job assignment.

    :param event_name: Uniquely named native event created by the owning parent.
    :type event_name: str
    :raises OSError: The parent is absent, activation expires or the wait fails.
    """
    kernel = _collector_kernel()
    event = kernel.OpenEventW(0x100000, False, event_name)
    if not event:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        status = kernel.WaitForSingleObject(event, 5000)
        if status == 258:
            raise OSError("The fact collector was not activated within 5 seconds.")
        if status != 0:
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.CloseHandle(event)


def collect_detached(arguments, request, timeout):
    """Run one gated fact collector with private files and owned descendants.

    :param arguments: Python executable and staged collector helper arguments.
    :type arguments: list[str]
    :param request: UTF-8 JSON request, read by the worker only after assignment.
    :type request: bytes
    :param timeout: Per-collector execution limit in seconds, including zero.
    :type timeout: int
    :returns: Standard output/error bytes, signed return code and timeout flag.
    :rtype: tuple[bytes, bytes, int, bool]
    :raises OSError: Private IPC, process creation, ownership or waiting fails.
    """
    kernel = _collector_kernel()
    with tempfile.TemporaryDirectory(
        prefix="legacy-windows-fact-collector-"
    ) as directory:
        _private_collector_directory(directory, kernel)
        paths = [
            os.path.join(directory, name)
            for name in ("request.json", "output.json", "errors.txt")
        ]
        with open(paths[0], "xb") as stream:
            stream.write(request)
        event_name = "Local\\LegacyWindowsFacts-" + uuid.uuid4().hex
        event = kernel.CreateEventW(None, False, False, event_name)
        if not event:
            raise ctypes.WinError(ctypes.get_last_error())
        with contextlib.ExitStack() as handles:
            handles.callback(kernel.CloseHandle, event)
            with _detached_collector(
                kernel, arguments + [event_name] + paths
            ) as handle:
                with owned_job(handle):
                    if not kernel.SetEvent(event):
                        raise ctypes.WinError(ctypes.get_last_error())
                    timed_out = _wait_collector(kernel, handle, timeout)
                # Close the descendant job before reading/removing private IPC:
                # explicit local facts and Facter may have spawned children.
                if kernel.WaitForSingleObject(handle, 5000) != 0:
                    raise OSError(
                        "The owned fact collector did not exit after job cleanup."
                    )
                code = ctypes.c_uint32()
                if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)):
                    raise ctypes.WinError(ctypes.get_last_error())
                output, errors = _collector_output(paths[1:])
                return output, errors, ctypes.c_int32(code.value).value, timed_out


@contextlib.contextmanager
def _detached_collector(kernel, arguments):
    command = subprocess.list2cmdline(arguments)
    # Private IPC paths are absolute. Preserve the caller's directory just as
    # ordinary Popen collectors do, including relative facts and script reads.
    _, launched_handle, pid = async_native.launch_watchdog(
        command, os.getcwd(), dict(os.environ)
    )
    with contextlib.ExitStack() as handles:
        handles.callback(kernel.CloseHandle, launched_handle)
        try:
            handle = _collector_handle(kernel, launched_handle, pid)
            handles.callback(kernel.CloseHandle, handle)
            yield handle
        finally:
            # Stop by the exact pinned handle even if assignment failed;
            # the ExitStack closes both handles even if this stop itself fails.
            status = kernel.WaitForSingleObject(launched_handle, 0)
            if status == 258:
                if not kernel.TerminateProcess(launched_handle, 1):
                    raise ctypes.WinError(ctypes.get_last_error())
                if kernel.WaitForSingleObject(launched_handle, 5000) != 0:
                    raise OSError("Could not stop the unarmed fact collector.")
            elif status != 0:
                raise ctypes.WinError(ctypes.get_last_error())


def _wait_collector(kernel, handle, timeout):
    deadline = time.monotonic() + timeout
    while True:
        remaining = max(0, deadline - time.monotonic())
        status = kernel.WaitForSingleObject(
            handle, min(math.ceil(remaining * 1000), 0xFFFFFFFE)
        )
        if status != 258 or time.monotonic() >= deadline:
            break
    if status not in (0, 258):
        raise ctypes.WinError(ctypes.get_last_error())
    return status == 258


def _collector_output(paths):
    streams = []
    for path in paths:
        if os.path.exists(path):
            with open(path, "rb") as stream:
                streams.append(stream.read())
        else:
            streams.append(b"")
    return streams[0], streams[1]


def _registry(path, name):
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as key:
            value, kind = winreg.QueryValueEx(key, name)
            # Python 3.4's winreg returns REG_QWORD as raw bytes. Decode only
            # that native type, never an unrelated eight-byte binary value.
            if kind == 11 and isinstance(value, bytes):
                if len(value) != 8:
                    raise ValueError("Invalid registry QWORD length for " + name + ".")
                return struct.unpack("<Q", value)[0]
            return value
    except OSError as error:
        if getattr(error, "winerror", None) not in (2, 3):
            raise
        return None


def _key_exists(path):
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ):
            return True
    except OSError as error:
        if getattr(error, "winerror", None) not in (2, 3):
            raise
        return False


def _query(class_name, properties):
    with WmiConnection() as connection:
        return connection.query(
            "SELECT {0} FROM {1}".format(",".join(properties), class_name), properties
        )


def _one(class_name, properties):
    rows = _query(class_name, properties)
    if not rows:
        raise OSError("WMI returned no {0} instance.".format(class_name))
    return rows[0]


def _version_string(version):
    # Framework Environment.OSVersion packs the two service-pack words into
    # Version.Revision rather than omitting the fourth component.
    revision = (version.service_pack_major << 16) | version.service_pack_minor
    return "{0}.{1}.{2}.{3}".format(
        version.major, version.minor, version.build, revision
    )


def _json_number(value):
    # The released Framework serializer emits integral Double values without
    # a decimal token. Preserve that observable JSON type for these ratios.
    return int(value) if value == int(value) else value


def _administrator():
    # Query current membership locally without staging the token-facts helper.
    # pylint: disable=duplicate-code
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    security.CheckTokenMembership.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int),
    ]
    security.CheckTokenMembership.restype = ctypes.c_int
    sid = ctypes.create_string_buffer(account.sid_bytes("S-1-5-32-544"))
    member = ctypes.c_int()
    if not security.CheckTokenMembership(None, sid, ctypes.byref(member)):
        raise ctypes.WinError(ctypes.get_last_error())
    return bool(member.value)
    # pylint: enable=duplicate-code


def _domain():
    net = ctypes.WinDLL("netapi32", use_last_error=True)
    net.DsRoleGetPrimaryDomainInformation.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    net.DsRoleGetPrimaryDomainInformation.restype = ctypes.c_uint32
    net.DsRoleFreeMemory.argtypes = [ctypes.c_void_p]
    net.DsRoleFreeMemory.restype = None
    net.NetWkstaGetInfo.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    net.NetWkstaGetInfo.restype = ctypes.c_uint32
    net.NetApiBufferFree.argtypes = [ctypes.c_void_p]
    net.NetApiBufferFree.restype = ctypes.c_uint32
    pointer = ctypes.c_void_p()
    code = net.DsRoleGetPrimaryDomainInformation(None, 1, ctypes.byref(pointer))
    if code:
        raise ctypes.WinError(code)
    try:
        info = ctypes.cast(pointer, ctypes.POINTER(_DomainInfo)).contents
        result = {"role": info.role, "member": bool(info.dns), "domain": info.dns}
    finally:
        net.DsRoleFreeMemory(pointer)
    if not result["member"]:
        pointer = ctypes.c_void_p()
        code = net.NetWkstaGetInfo(None, 100, ctypes.byref(pointer))
        if code == 2138:
            result["domain"] = (
                _registry(
                    r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
                    "Workgroup",
                )
                or ""
            )
        elif code:
            raise ctypes.WinError(code)
        else:
            try:
                info = ctypes.cast(pointer, ctypes.POINTER(_WorkstationInfo)).contents
                result["domain"] = info.group
            finally:
                net.NetApiBufferFree(pointer)
    return result


def _system_info():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetNativeSystemInfo.argtypes = [ctypes.POINTER(_SystemInfo)]
    kernel.GetNativeSystemInfo.restype = None
    result = _SystemInfo()
    kernel.GetNativeSystemInfo(ctypes.byref(result))
    kernel.GetComputerNameExW.argtypes = [
        ctypes.c_int,
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    kernel.GetComputerNameExW.restype = ctypes.c_int
    size = ctypes.c_uint32()
    kernel.GetComputerNameExW(0, None, ctypes.byref(size))
    buffer = ctypes.create_unicode_buffer(size.value)
    if not kernel.GetComputerNameExW(0, buffer, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    return result, buffer.value


def parse_smbios(raw):
    """Read BIOS, system and populated processor records from a raw RSMB table.

    :param raw: GetSystemFirmwareTable RSMB bytes, including its eight-byte header.
    :type raw: bytes
    :returns: BIOS/system fields and processor core/thread counts.
    :rtype: dict
    :raises ValueError: The firmware buffer has invalid lengths or string indexes.
    """
    if len(raw) < 8 or struct.unpack_from("<I", raw, 4)[0] != len(raw) - 8:
        raise ValueError("Invalid raw SMBIOS table length.")
    result = {"processors": [], "counts_found": False}
    offset = 8
    while offset < len(raw):
        if offset + 4 > len(raw):
            raise ValueError("Truncated SMBIOS record header.")
        kind, length = raw[offset], raw[offset + 1]
        end = offset + length
        terminator = raw.find(b"\0\0", end)
        if length < 4 or end > len(raw) or terminator < 0:
            raise ValueError("Invalid SMBIOS record length or string table.")
        strings = raw[end:terminator].split(b"\0") if terminator != end else []

        def _text(index):
            if not index:
                return None
            if index > len(strings):
                raise ValueError("Invalid SMBIOS string index.")
            return strings[index - 1].decode("mbcs", "replace").strip()

        data = raw[offset:end]
        if kind == 0 and length >= 9:
            result.update(version=_text(data[5]), release_date=_text(data[8]))
        elif kind == 1 and length >= 24:
            result.update(
                manufacturer=_text(data[4]),
                model=_text(data[5]),
                serial=_text(data[7]),
                uuid=str(uuid.UUID(bytes_le=data[8:24])).upper(),
            )
        elif kind == 4 and length >= 25 and data[24] & 0x40 and data[24] & 7 == 1:
            cores, threads = 0, 0
            # Retain the released collector's version condition, including its
            # fallback for SMBIOS 3.x, instead of changing public CPU facts.
            if raw[1] > 3 or (raw[1] == 2 and raw[2] > 4):
                if length >= 38:
                    result["counts_found"] = True
                    cores, threads = data[35], data[37]
                if length >= 48:
                    result["counts_found"] = True
                    cores = struct.unpack_from("<H", data, 42)[0] or cores
                    threads = struct.unpack_from("<H", data, 46)[0] or threads
            result["processors"].append((cores, threads))
        offset = terminator + 2
    return result


def _bios():
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        read = kernel.GetSystemFirmwareTable
        read.argtypes = [
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        read.restype = ctypes.c_uint32
        size = read(0x52534D42, 0, None, 0)
        if not size:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_string_buffer(size)
        written = read(0x52534D42, 0, buffer, size)
        if written != size:
            raise OSError("Windows returned an incomplete SMBIOS table.")
        return parse_smbios(buffer.raw)
    except (AttributeError, OSError):
        system = _one(
            "Win32_ComputerSystem", ["Model", "Manufacturer", "NumberOfProcessors"]
        )
        bios = _one("Win32_BIOS", ["ReleaseDate", "SMBIOSBIOSVersion", "SerialNumber"])
        product = _one("Win32_ComputerSystemProduct", ["UUID"])
        release = parse_datetime(bios["ReleaseDate"], "ReleaseDate")
        return {
            "model": system["Model"].strip(),
            "manufacturer": system["Manufacturer"],
            "version": bios["SMBIOSBIOSVersion"],
            "serial": bios["SerialNumber"],
            "uuid": product["UUID"],
            "release_date": release.strftime("%m/%d/%Y") if release else None,
            "processors": [None] * system["NumberOfProcessors"],
            "counts_found": False,
        }


def _bios_facts(facts):
    bios = _bios()
    release = bios.get("release_date")
    if release:
        try:
            release = datetime.datetime.strptime(
                release, "%m/%d/%Y" if len(release) == 10 else "%m/%d/%y"
            ).strftime("%m/%d/%Y")
        except ValueError:
            release = None
    facts.update(
        ansible_bios_date=release,
        ansible_bios_version=bios.get("version"),
        ansible_product_name=bios.get("model"),
        ansible_product_serial=bios.get("serial"),
        ansible_product_uuid=bios.get("uuid"),
    )


def _distribution(facts):
    version = windows_version()
    install = _registry(_CURRENT_VERSION, "InstallTime")
    facts.update(
        ansible_distribution=None,
        ansible_os_name=None,
        ansible_distribution_version=_version_string(version),
        ansible_distribution_major_version=str(version.major),
        ansible_os_family="Windows",
        ansible_os_product_type={
            1: "workstation",
            2: "domain_controller",
            3: "server",
        }.get(version.product_type, "unknown"),
        ansible_os_installation_type=_registry(_CURRENT_VERSION, "InstallationType"),
        ansible_os_install_date=(
            (
                datetime.datetime(1601, 1, 1)
                + datetime.timedelta(microseconds=install // 10)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            if install
            else None
        ),
    )
    if _administrator():
        system = _one("Win32_OperatingSystem", ["Caption", "Name"])
        facts["ansible_distribution"] = system["Caption"]
        facts["ansible_os_name"] = system["Name"].split("|")[0].strip()


def _memory(facts):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(_MemoryStatus)]
    kernel.GlobalMemoryStatusEx.restype = ctypes.c_int
    memory = _MemoryStatus(length=ctypes.sizeof(_MemoryStatus))
    if not kernel.GlobalMemoryStatusEx(ctypes.byref(memory)):
        raise ctypes.WinError(ctypes.get_last_error())
    facts.update(
        ansible_memtotal_mb=math.ceil(memory.total / 1048576),
        ansible_memfree_mb=math.ceil(memory.available / 1048576),
        ansible_swaptotal_mb=0,
        ansible_pagefiletotal_mb=None,
        ansible_pagefilefree_mb=None,
    )
    if _administrator():
        paging = _one(
            "Win32_OperatingSystem",
            ["SizeStoredInPagingFiles", "FreeSpaceInPagingFiles"],
        )
        facts["ansible_pagefiletotal_mb"] = round(
            int(paging["SizeStoredInPagingFiles"]) / 1024
        )
        facts["ansible_pagefilefree_mb"] = round(
            int(paging["FreeSpaceInPagingFiles"]) / 1024
        )


def _platform(facts, warnings):
    bios, domain = _bios(), _domain()
    system, netbios = _system_info()
    hostname, suffix = network.host_information()
    fqdn = hostname + ("." + suffix if suffix else "")
    version = windows_version()
    machine_sid = None
    try:
        administrators = account.sid_to_name("S-1-5-32-544").split("\\", 1)[-1]
        machine_sid = next(
            (
                sid.rsplit("-", 1)[0]
                for sid in group.member_sids(administrators)
                if sid.endswith("-500")
            ),
            None,
        )
    except OSError as error:
        warnings.append("Error during machine sid retrieval: {0}".format(error))
    facts.update(
        ansible_domain=domain["domain"] if domain["member"] else suffix,
        ansible_fqdn=fqdn,
        ansible_hostname=hostname,
        ansible_netbios_name=netbios,
        ansible_kernel=_version_string(version),
        ansible_nodename=fqdn,
        ansible_machine_id=machine_sid,
        ansible_owner_name=_registry(_CURRENT_VERSION, "RegisteredOwner") or "",
        ansible_system="Win32NT",
        ansible_system_description=_registry(
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "srvcomment"
        )
        or "",
        ansible_system_vendor=bios.get("manufacturer"),
        ansible_architecture=None,
        ansible_owner_contact="",
        ansible_architecture2={
            0: "i386",
            5: "arm",
            6: "ia64",
            9: "x86_64",
            12: "arm64",
        }.get(system.architecture, "unknown"),
        ansible_reboot_pending=bool(
            _registry(
                r"SYSTEM\CurrentControlSet\Control\Session Manager",
                "PendingFileRenameOperations",
            )
            or _key_exists(
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
            )
            or _registry(
                r"SOFTWARE\Microsoft\ServerManager\ServicingStorage\ServerComponentCache",
                "RestartRequired",
            )
        ),
    )
    if _administrator():
        if version.major < 6:
            # XP/2003 lack OSArchitecture; native system info still reports
            # the OS architecture, including a 32-bit process on 64-bit Windows.
            facts["ansible_architecture"] = (
                "64-bit" if system.architecture in (6, 9, 12) else "32-bit"
            )
        else:
            facts["ansible_architecture"] = _one(
                "Win32_OperatingSystem", ["OSArchitecture"]
            )["OSArchitecture"]
        facts["ansible_owner_contact"] = (
            _one("Win32_ComputerSystem", ["PrimaryOwnerContact"])["PrimaryOwnerContact"]
            or ""
        )


def _processor(facts):
    bios = _bios()
    system, _ = _system_info()
    processors = []
    path = r"HARDWARE\DESCRIPTION\System\CentralProcessor"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
        names = [
            winreg.EnumKey(key, index) for index in range(winreg.QueryInfoKey(key)[0])
        ]
    for name in sorted(names, key=int):
        processors.extend(
            [
                name,
                _registry(path + "\\" + name, "VendorIdentifier"),
                _registry(path + "\\" + name, "ProcessorNameString"),
            ]
        )
    facts.update(
        ansible_processor=processors,
        ansible_processor_count=len(bios["processors"]),
        ansible_processor_vcpus=system.processors,
    )
    cores, threads = None, None
    if bios["counts_found"]:
        cores, threads = bios["processors"][0]
    elif _administrator():
        processor = _one(
            "Win32_Processor", ["NumberOfCores", "NumberOfLogicalProcessors"]
        )
        cores, threads = (
            processor["NumberOfCores"],
            processor["NumberOfLogicalProcessors"],
        )
    facts["ansible_processor_cores"] = cores
    facts["ansible_processor_threads_per_core"] = (
        _json_number(threads / cores) if cores else None
    )


def _uptime(facts):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    try:
        read = kernel.GetTickCount64
        read.argtypes, read.restype = [], ctypes.c_uint64
        milliseconds = read()
    except AttributeError:
        boot = _one("Win32_OperatingSystem", ["LastBootUpTime"])["LastBootUpTime"]
        milliseconds = (
            datetime.datetime.now(datetime.timezone.utc)
            - parse_datetime(boot, "LastBootUpTime")
        ).total_seconds() * 1000
    facts["ansible_lastboot"] = (
        datetime.datetime.now() - datetime.timedelta(milliseconds=milliseconds)
    ).strftime("%Y-%m-%d %H:%M:%SZ")
    facts["ansible_uptime_seconds"] = round(milliseconds / 1000)


def _user(facts):
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    # Keep this independently staged wrapper's native ABI declarations local.
    # pylint: disable=duplicate-code
    kernel.GetCurrentProcess.argtypes, kernel.GetCurrentProcess.restype = (
        [],
        ctypes.c_void_p,
    )
    kernel.CloseHandle.argtypes, kernel.CloseHandle.restype = [
        ctypes.c_void_p
    ], ctypes.c_int
    security.OpenProcessToken.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    security.OpenProcessToken.restype = ctypes.c_int
    security.GetTokenInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    security.GetTokenInformation.restype = ctypes.c_int
    # pylint: enable=duplicate-code
    token = ctypes.c_void_p()
    # The facts query owns the process token until its local cleanup.
    # pylint: disable=duplicate-code
    if not security.OpenProcessToken(
        kernel.GetCurrentProcess(), 8, ctypes.byref(token)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    # pylint: enable=duplicate-code
    try:
        needed = ctypes.c_uint32()
        security.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        buffer = ctypes.create_string_buffer(needed.value)
        if not security.GetTokenInformation(
            token, 1, buffer, len(buffer), ctypes.byref(needed)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        sid = account.sid_to_string(ctypes.c_void_p.from_buffer(buffer).value)
    finally:
        kernel.CloseHandle(token)
    facts.update(
        ansible_user_dir=os.environ.get("USERPROFILE"),
        ansible_user_gecos="",
        ansible_user_id=os.environ.get("USERNAME"),
        ansible_user_sid=sid,
    )


def _local(path, facts, warnings):
    if not path:
        return
    if not os.path.exists(path):
        warnings.append("Non existing path was set for local facts - " + path)
        return
    for filename in sorted(glob.glob(os.path.join(path, "*")), key=str.lower):
        suffix = os.path.splitext(filename)[1]
        if not os.path.isfile(filename) or suffix not in (".json", ".ps1"):
            continue
        if suffix == ".json":
            with open(filename, "r", encoding="utf-8-sig") as stream:
                value = json.load(stream)
            # The released PowerShell JSON reader exposes a root array as a
            # Count/value object. Nested arrays remain ordinary JSON arrays.
            if isinstance(value, list):
                value = {"Count": len(value), "value": value}
        else:
            executable = shutil.which("powershell.exe")
            if not executable:
                raise OSError(
                    "PowerShell is required to execute explicitly supplied .ps1 local facts."
                )
            script = (
                "[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false); & '"
                + filename.replace("'", "''")
                + "' | ConvertTo-Json -Depth 99 -Compress"
            )
            encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
            with subprocess.Popen(
                [
                    executable,
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Unrestricted",
                    "-EncodedCommand",
                    encoded,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as process:
                output, errors = process.communicate()
                if process.returncode:
                    raise OSError(errors.decode("utf-8", "replace"))
            value = json.loads(output.decode("utf-8-sig")) if output.strip() else None
        if value is not None:
            facts["ansible_" + os.path.splitext(os.path.basename(filename))[0]] = value


def _facter(facts):
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        if not directory.strip() or any(
            character in directory for character in '\0<>"|'
        ):
            continue
        executable = os.path.join(directory, "facter.exe")
        if not os.path.isfile(executable):
            continue
        with subprocess.Popen(
            [executable, "-j"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ) as process:
            output, _ = process.communicate()
        facts.update(
            ("facter_" + name, value)
            for name, value in json.loads(output.decode("utf-8-sig")).items()
        )
        return


def _virtual(facts):
    bios = _bios()
    model = bios.get("model") or ""
    models = (
        ("kvm", ("KVM", "KVM Server", "Bochs", "AHV", "CloudStack KVM Hypervisor")),
        ("RHEV", ("RHEV Hypervisor",)),
        ("VMware", ("VMWare*",)),
        ("openstack", ("OpenStack Compute", "OpenStack Nova")),
        ("xen", ("xen", "HVM domU")),
        ("Hyper-V", ("Virtual Machine",)),
        ("VirtualBox", ("VirtualBox",)),
    )
    manufacturers = (
        (
            "kvm",
            (
                "QEMU",
                "oVirt",
                "Amazon EC2",
                "DigitalOcean",
                "Google",
                "Scaleway",
                "Nutanix",
            ),
        ),
        ("KubeVirt", ("KubVirt",)),
        ("parallels", ("Parallels Software International Inc.",)),
        ("openstack", ("OpenStack Foundation",)),
    )
    selected = next(
        (
            name
            for name, patterns in models
            if any(
                fnmatch.fnmatchcase(model.lower(), pattern.lower())
                for pattern in patterns
            )
        ),
        None,
    )
    if selected is None:
        manufacturer = (bios.get("manufacturer") or "").lower()
        selected = next(
            (
                name
                for name, values in manufacturers
                if manufacturer in [value.lower() for value in values]
            ),
            None,
        )
    facts.update(
        ansible_virtualization_type=selected or "NA",
        ansible_virtualization_role="guest" if selected else "NA",
    )


def _environment(trim_trailing_backslashes=True):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetEnvironmentStringsW.argtypes = []
    kernel.GetEnvironmentStringsW.restype = ctypes.c_void_p
    kernel.FreeEnvironmentStringsW.argtypes = [ctypes.c_void_p]
    kernel.FreeEnvironmentStringsW.restype = ctypes.c_int
    block = kernel.GetEnvironmentStringsW()
    if not block:
        raise ctypes.WinError(ctypes.get_last_error())
    values = {}
    try:
        pointer = block
        while True:
            text = ctypes.wstring_at(pointer)
            if not text:
                return values
            if not text.startswith("="):
                name, value = text.split("=", 1)
                values[name] = (
                    value.rstrip("\\") if trim_trailing_backslashes else value
                )
            pointer += (len(text.encode("utf-16-le")) // 2 + 1) * 2
    finally:
        if not kernel.FreeEnvironmentStringsW(block):
            raise ctypes.WinError(ctypes.get_last_error())


def _user_module_path():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
            return winreg.QueryValueEx(key, "PSModulePath")[0]
    except OSError as error:
        if getattr(error, "winerror", None) not in (2, 3):
            raise
        return None


def _documents_directory():
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    shell.SHGetFolderPathW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
    ]
    shell.SHGetFolderPathW.restype = ctypes.c_int32
    buffer = ctypes.create_unicode_buffer(260)
    status = shell.SHGetFolderPathW(None, 5, None, 0, buffer)
    if status < 0:
        raise OSError(
            "SHGetFolderPathW failed (HRESULT 0x{0:08X}).".format(status & 0xFFFFFFFF)
        )
    return buffer.value


def _startup_module_path(environment, home):
    # Microsoft's Windows PowerShell startup contract inserts AllUsers before
    # PSHOME and prefixes CurrentUser only without a user-scoped registry value.
    # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath
    values = {name.upper(): value for name, value in environment.items()}
    system = os.path.join(home, "Modules")
    all_users = os.path.join(values["PROGRAMFILES"], "WindowsPowerShell", "Modules")
    raw = values.get("PSMODULEPATH")
    paths = (
        winreg.ExpandEnvironmentStrings(raw).split(";")
        if raw is not None
        else [all_users, system]
    )
    comparable = [os.path.normcase(path.rstrip("\\")) for path in paths]
    system_index = next(
        (
            index
            for index, path in enumerate(comparable)
            if path == os.path.normcase(system)
        ),
        None,
    )
    if system_index is not None and os.path.normcase(all_users) not in comparable:
        paths.insert(system_index, all_users)
    if _user_module_path() is None:
        current_user = os.path.join(
            _documents_directory(), "WindowsPowerShell", "Modules"
        )
        if os.path.normcase(current_user) not in comparable:
            paths.insert(0, current_user)
    return ";".join(paths)


def initialize_environment(overrides):
    """Initialize the reference process environment, then literal task overrides.

    :param overrides: Validated task environment names and string values.
    :type overrides: dict[str, str]
    :raises OSError: Native environment, registry or folder reads fail.
    """
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.SetEnvironmentVariableW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p]
    kernel.SetEnvironmentVariableW.restype = ctypes.c_int
    # Legacy hosts without the modern default Windows PowerShell engine retain
    # native environment availability, not an invented source startup process.
    home = _registry(
        r"SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine", "ApplicationBase"
    )
    if home:
        environment = _environment(trim_trailing_backslashes=False)
        values = {name.upper(): value for name, value in environment.items()}
        extension = values.get("PATHEXT", "")
        changes = {
            "PSExecutionPolicyPreference": "Unrestricted",
            "PSModulePath": _startup_module_path(environment, home),
        }
        if ".cpl" not in [part.lower() for part in extension.split(";")]:
            changes["PATHEXT"] = extension + ";.CPL" if extension else ".CPL"
        for name, value in changes.items():
            if not kernel.SetEnvironmentVariableW(name, value):
                raise ctypes.WinError(ctypes.get_last_error())
    for name, value in overrides.items():
        if not kernel.SetEnvironmentVariableW(name, value):
            raise ctypes.WinError(ctypes.get_last_error())


# The released module has one fixed collector per subset. Keeping that public
# dispatch visible is clearer than a registry of otherwise-private callbacks.
def collect(name, parameters, facts, warnings):  # pylint: disable=too-many-branches
    """Populate one released setup collector's fact dictionary.

    :param name: Fixed collector name, including the combined IP-address subset.
    :type name: str
    :param parameters: Bound setup arguments.
    :type parameters: dict
    :param facts: Receives collected facts, retaining partial values on failure.
    :type facts: dict
    :param warnings: Receives nonfatal collector diagnostics.
    :type warnings: list[str]
    :raises OSError: A required native operation fails.
    :raises ValueError: Native or custom fact data is malformed.
    :raises NotImplementedError: A selected feature is not implemented.
    """
    if name == "all_ipv4_addresses, all_ipv6_addresses":
        facts["ansible_ip_addresses"] = network.read_addresses()
    elif name == "interfaces":
        facts["ansible_interfaces"] = network.read_interfaces()
    elif name == "bios":
        _bios_facts(facts)
    elif name == "date_time":
        facts["ansible_date_time"] = date_time.read_date_time()
    elif name == "distribution":
        _distribution(facts)
    elif name == "env":
        facts["ansible_env"] = _environment()
    elif name == "facter":
        _facter(facts)
    elif name == "local":
        _local(parameters["fact_path"], facts, warnings)
    elif name == "memory":
        _memory(facts)
    elif name == "platform":
        _platform(facts, warnings)
    elif name == "powershell_version":
        versions = [
            _registry(
                r"SOFTWARE\Microsoft\PowerShell\{0}\PowerShellEngine".format(branch),
                "PowerShellVersion",
            )
            for branch in ("1", "3")
        ]
        installed = [int(value.split(".")[0]) for value in versions if value]
        facts["ansible_powershell_version"] = max(installed) if installed else None
    elif name == "processor":
        _processor(facts)
    elif name == "uptime":
        _uptime(facts)
    elif name == "user":
        _user(facts)
    elif name == "windows_domain":
        domain = _domain()
        roles = (
            "Stand-alone workstation",
            "Member workstation",
            "Stand-alone server",
            "Member server",
            "Backup domain controller",
            "Primary domain controller",
        )
        facts.update(
            ansible_windows_domain=domain["domain"],
            ansible_windows_domain_member=domain["member"],
            ansible_windows_domain_role=(
                roles[domain["role"]]
                if 0 <= domain["role"] < len(roles)
                else "Unknown DomainRole {0}".format(domain["role"])
            ),
        )
    elif name == "virtual":
        _virtual(facts)
    elif name == "winrm":
        winrm.read_facts(facts, warnings)
    else:
        raise ValueError("Unknown setup collector: " + name)
