"""Witness public Setup environment identities and protect one owned workspace."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Calibration deliberately uses an independent Win32 block read, not Setup's
# reader: sharing that implementation would hide the same error in both sides.
# pylint: disable=duplicate-code

import ctypes
import json
import os
import re
import struct
import sys
import time

_JOURNAL = "environment-journal.json"
_SENTINEL = "protected.bin"
_TOKEN = re.compile(r"[0-9A-F]{8}(?:-[0-9A-F]{8}){3}\Z")


class _Entry(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("size", ctypes.c_uint32),
        ("usage", ctypes.c_uint32),
        ("pid", ctypes.c_uint32),
        ("heap", ctypes.c_size_t),
        ("module", ctypes.c_uint32),
        ("threads", ctypes.c_uint32),
        ("parent", ctypes.c_uint32),
        ("priority", ctypes.c_int32),
        ("flags", ctypes.c_uint32),
        ("name", ctypes.c_wchar * 260),
    ]


class _Basic(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("status", ctypes.c_int32),
        ("peb", ctypes.c_void_p),
        ("affinity", ctypes.c_size_t),
        ("priority", ctypes.c_int32),
        ("pid", ctypes.c_size_t),
        ("parent", ctypes.c_size_t),
    ]


class _Region(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("base", ctypes.c_void_p),
        ("allocation", ctypes.c_void_p),
        ("allocation_protect", ctypes.c_uint32),
        ("partition", ctypes.c_uint16),
        ("size", ctypes.c_size_t),
        ("state", ctypes.c_uint32),
        ("protect", ctypes.c_uint32),
        ("kind", ctypes.c_uint32),
    ]


def _decode_environment(data):
    # Decode only the true UTF-16 block, not unrelated memory after its terminator.
    end = next(
        (
            index
            for index in range(0, len(data) - 3, 2)
            if data[index : index + 4] == b"\0\0\0\0"
        ),
        None,
    )
    if end is None:
        raise ValueError("The native environment block has no aligned terminator.")
    values = {}
    for item in data[:end].decode("utf-16-le").split("\0"):
        if not item.startswith("="):
            name, value = item.split("=", 1)
            values[name] = value
    return values


class _ProcessReader:
    """Read same-caller process environment without writing or changing privileges."""

    def __init__(self):
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.nt = ctypes.WinDLL("ntdll", use_last_error=True)
        signatures = {
            "OpenProcess": (
                [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32],
                ctypes.c_void_p,
            ),
            "CloseHandle": ([ctypes.c_void_p], ctypes.c_int),
            "GetProcessTimes": (
                [ctypes.c_void_p] + [ctypes.POINTER(ctypes.c_uint64)] * 4,
                ctypes.c_int,
            ),
            "ReadProcessMemory": (
                [
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.c_size_t,
                    ctypes.POINTER(ctypes.c_size_t),
                ],
                ctypes.c_int,
            ),
            "VirtualQueryEx": (
                [
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.POINTER(_Region),
                    ctypes.c_size_t,
                ],
                ctypes.c_size_t,
            ),
            "IsWow64Process": (
                [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)],
                ctypes.c_int,
            ),
            "CreateToolhelp32Snapshot": (
                [ctypes.c_uint32, ctypes.c_uint32],
                ctypes.c_void_p,
            ),
            "Process32FirstW": (
                [ctypes.c_void_p, ctypes.POINTER(_Entry)],
                ctypes.c_int,
            ),
            "Process32NextW": ([ctypes.c_void_p, ctypes.POINTER(_Entry)], ctypes.c_int),
            "GetEnvironmentStringsW": ([], ctypes.c_void_p),
            "FreeEnvironmentStringsW": ([ctypes.c_void_p], ctypes.c_int),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.api, name)
            function.argtypes, function.restype = arguments, result
        self.nt.NtQueryInformationProcess.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        self.nt.NtQueryInformationProcess.restype = ctypes.c_int32

    def processes(self):
        """Read one complete Toolhelp process catalogue.

        :returns: Process names and actual PID/parent mappings.
        :rtype: dict
        :raises OSError: A snapshot or native handle cannot be read or released.
        """
        snapshot = self.api.CreateToolhelp32Snapshot(2, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        rows = {}
        try:
            entry = _Entry(size=ctypes.sizeof(_Entry))
            found = self.api.Process32FirstW(snapshot, ctypes.byref(entry))
            while found:
                rows[entry.pid] = {
                    "pid": entry.pid,
                    "parent_pid": entry.parent,
                    "name": entry.name,
                }
                found = self.api.Process32NextW(snapshot, ctypes.byref(entry))
            if ctypes.get_last_error() != 18:
                raise ctypes.WinError(ctypes.get_last_error())
            return rows
        finally:
            if not self.api.CloseHandle(snapshot):
                raise ctypes.WinError(ctypes.get_last_error())

    def read(self, pid):
        """Read a live same-bitness process block with birth identity.

        :param pid: Independently enumerated process ID.
        :type pid: int
        :returns: Literal environment and native process birth/parent fields.
        :rtype: dict
        :raises OSError: The process exits or cannot be read.
        :raises ValueError: Its environment block or architecture is invalid.
        """
        handle = self.api.OpenProcess(0x410, False, pid)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            wow = ctypes.c_int()
            if not self.api.IsWow64Process(handle, ctypes.byref(wow)):
                raise ctypes.WinError(ctypes.get_last_error())
            if ctypes.sizeof(ctypes.c_void_p) != 8 or wow.value:
                raise ValueError(
                    "This measured environment witness requires AMD64 processes."
                )
            info = _Basic()
            returned = ctypes.c_uint32()
            status = self.nt.NtQueryInformationProcess(
                handle,
                0,
                ctypes.byref(info),
                ctypes.sizeof(info),
                ctypes.byref(returned),
            )
            if status < 0:
                raise OSError(
                    "NtQueryInformationProcess failed: 0x{0:08X}".format(
                        status & 0xFFFFFFFF
                    )
                )
            if info.pid != pid:
                raise ValueError(
                    "Native process identity differs from the observed PID."
                )
            # Microsoft's PEB ABI exposes ProcessParameters. Its internal
            # Environment pointer follows the two documented UNICODE_STRINGs.
            # This diagnostic offset is calibrated against our independent
            # GetEnvironmentStringsW block on this exact host before watching.
            # It is never used by production Setup and claims no other ABI.
            parameters = int.from_bytes(
                self._memory(handle, info.peb + 32, 8), "little"
            )
            pointer = int.from_bytes(
                self._memory(handle, parameters + 128, 8), "little"
            )
            region = _Region()
            if not self.api.VirtualQueryEx(
                handle, pointer, ctypes.byref(region), ctypes.sizeof(region)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            size = min(region.base + region.size - pointer, 1048576)
            environment = _decode_environment(self._memory(handle, pointer, size))
            times = [ctypes.c_uint64() for _ in range(4)]
            if not self.api.GetProcessTimes(
                handle, *[ctypes.byref(value) for value in times]
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            return {
                "pid": pid,
                "parent_pid": info.parent,
                "created": times[0].value,
                "environment": environment,
                "observed": time.time(),
            }
        finally:
            if not self.api.CloseHandle(handle):
                raise ctypes.WinError(ctypes.get_last_error())

    def _memory(self, handle, address, size):
        data = ctypes.create_string_buffer(size)
        actual = ctypes.c_size_t()
        if not self.api.ReadProcessMemory(
            handle, address, data, size, ctypes.byref(actual)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if actual.value != size:
            raise ValueError("Partial environment-memory read.")
        return data.raw

    def calibrate(self):
        """Compare the internal diagnostic ABI to an independent Win32 environment.

        :returns: This witness's actual PID and native birth identity.
        :rtype: dict
        :raises OSError: A native environment operation fails.
        :raises ValueError: The complete literal blocks differ.
        """
        block = self.api.GetEnvironmentStringsW()
        if not block:
            raise ctypes.WinError(ctypes.get_last_error())
        values = {}
        try:
            pointer = block
            while True:
                text = ctypes.wstring_at(pointer)
                if not text:
                    break
                if not text.startswith("="):
                    name, value = text.split("=", 1)
                    values[name] = value
                pointer += len(text.encode("utf-16-le")) + 2
        finally:
            if not self.api.FreeEnvironmentStringsW(block):
                raise ctypes.WinError(ctypes.get_last_error())
        actual = self.read(os.getpid())
        if actual["environment"] != values:
            raise ValueError("Independent environment-block calibration failed.")
        return {"pid": actual["pid"], "created": actual["created"], "calibrated": True}


def _write(root, name, value):
    with open(os.path.join(root, name), "x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True)


def _journal(root):
    with open(os.path.join(root, _JOURNAL), encoding="utf-8") as stream:
        value = json.load(stream)
    if value["workspace"] != root:
        raise ValueError("The environment journal does not own this literal workspace.")
    return value


def _observe(root, protection):
    journal = _journal(root)
    state = protection["_protected_state"]()
    sentinel = protection["_file"](os.path.join(root, _SENTINEL))
    if journal["before"] != state or journal["sentinel"] != sentinel:
        raise ValueError(
            "Setup changed protected registry values or sentinel bytes/security/time."
        )
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetTickCount64.argtypes, kernel.GetTickCount64.restype = [], ctypes.c_uint64
    kernel.GlobalMemoryStatusEx.argtypes = [ctypes.c_void_p]
    kernel.GlobalMemoryStatusEx.restype = ctypes.c_int
    memory = ctypes.create_string_buffer(struct.pack("<II7Q", 64, *([0] * 8)), 64)
    if not kernel.GlobalMemoryStatusEx(memory):
        raise ctypes.WinError(ctypes.get_last_error())
    return {
        "configuration": state,
        "protected": sentinel,
        "epoch": time.time(),
        "tick_milliseconds": kernel.GetTickCount64(),
        "physical_total_bytes": struct.unpack("<II7Q", memory.raw)[2],
    }


def _watch(root):
    _journal(root)
    reader = _ProcessReader()
    identity = reader.calibrate()
    initial = reader.processes()
    witnesses, errors = {}, {}
    _write(root, "witness-ready.json", identity)
    failure = None
    try:
        _watch_processes(root, reader, initial, witnesses, errors)
    except (OSError, ValueError) as error:
        failure = str(error)
        raise
    finally:
        # Even a failed witness retains every partial read before owned recovery.
        _write(
            root,
            "witnesses.json",
            {
                "identity": identity,
                "witnesses": list(witnesses.values()),
                "read_errors": errors,
                "python": sys.version,
                "failure": failure,
            },
        )
    return {"witness_stopped": True, "identity": identity, "count": len(witnesses)}


def _watch_processes(root, reader, initial, witnesses, errors):
    deadline = time.monotonic() + 300
    while not os.path.isfile(os.path.join(root, "witness-stop.json")):
        if time.monotonic() > deadline:
            raise ValueError(
                "The owned environment witness reached its bounded deadline."
            )
        rows = reader.processes()
        for pid, row in rows.items():
            if pid in initial or row["name"].lower() not in (
                "python.exe",
                "powershell.exe",
            ):
                continue
            try:
                actual = reader.read(pid)
                token = next(
                    (
                        value
                        for name, value in actual["environment"].items()
                        if name.lower() == "bitvisesfsdll"
                    ),
                    None,
                )
                if not isinstance(token, str) or not _TOKEN.match(token):
                    continue
                ancestry = []
                current = rows.get(pid)
                while current and current not in ancestry:
                    ancestry.append(current)
                    current = rows.get(current["parent_pid"])
                if not any(
                    value["pid"] == int(token[:8], 16)
                    and value["name"].lower() == "execs.exe"
                    for value in ancestry
                ):
                    continue
                actual.update(name=row["name"], token=token, ancestry=ancestry)
                # PowerShell startup and task overrides mutate this same live
                # process block. Retain each distinct complete observation,
                # including the final block, rather than pinning its first read.
                key = (
                    pid,
                    actual["created"],
                    json.dumps(actual["environment"], sort_keys=True),
                )
                if key not in witnesses:
                    witnesses[key] = actual
            except (OSError, ValueError, StopIteration) as error:
                # Exit/access races stay raw; only an independently read matching
                # witness can qualify a later public value. No field is dropped.
                errors[pid] = {"name": row["name"], "error": str(error)}
        time.sleep(0.005)


def _closed(reader, processes, actual):
    if actual["pid"] not in processes:
        return True
    return reader.read(actual["pid"])["created"] != actual["created"]


def main(protection, arguments):
    """Run one explicitly owned environment-fixture operation.

    :param protection: Existing Setup fixture's native protection helpers.
    :type protection: dict
    :param arguments: Operation and uniquely allocated workspace path.
    :type arguments: list[str]
    :returns: Raw observation or owned-witness control result.
    :rtype: dict
    :raises ValueError: Ownership, protection or witness validation fails.
    :raises OSError: A native/file operation fails.
    """
    assert sys.version_info[:3] == (3, 4, 4)
    operation, path = arguments
    root = protection["_root"](path)
    if operation == "prepare":
        if os.listdir(root):
            raise ValueError("Environment preparation requires a new empty workspace.")
        before = protection["_protected_state"]()
        with open(os.path.join(root, _SENTINEL), "xb") as stream:
            stream.write(b"owned Setup environment sibling\x00\xff")
        sentinel = protection["_file"](os.path.join(root, _SENTINEL))
        _write(
            root, _JOURNAL, {"workspace": root, "before": before, "sentinel": sentinel}
        )
        return _observe(root, protection)
    if operation == "observe":
        return _observe(root, protection)
    if operation == "watch":
        return _watch(root)
    if operation == "ready":
        _journal(root)
        return {"ready": os.path.isfile(os.path.join(root, "witness-ready.json"))}
    if operation == "stop":
        _journal(root)
        _write(root, "witness-stop.json", {"workspace": root})
        return {"stop_requested": True}
    if operation == "finish":
        observed = _observe(root, protection)
        with open(os.path.join(root, "witnesses.json"), encoding="utf-8") as stream:
            witness = json.load(stream)
        reader = _ProcessReader()
        processes = reader.processes()
        witness["identity"]["closed"] = _closed(reader, processes, witness["identity"])
        for actual in witness["witnesses"]:
            try:
                actual["natural_exit"] = _closed(reader, processes, actual)
            except (OSError, ValueError) as error:
                actual["natural_exit"] = None
                actual["exit_observation_error"] = str(error)
        expected = {
            _JOURNAL,
            _SENTINEL,
            "witness-ready.json",
            "witness-stop.json",
            "witnesses.json",
            "cache",
        }
        if set(os.listdir(root)) != expected or os.listdir(os.path.join(root, "cache")):
            raise ValueError("Unexpected workspace entries or an async cache remain.")
        return {
            "restored": True,
            "observation": observed,
            "witness": witness,
            "owned_entries": sorted(expected),
        }
    raise ValueError("Unknown environment-fixture operation: " + operation)
