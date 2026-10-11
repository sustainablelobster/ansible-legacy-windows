# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
"""Prepare, inspect and restore only owned mixed security descriptors."""

import base64
import ctypes
import json
import os
import struct
import sys
import uuid

# Windows' registry standard library is absent on the developer controller.
import winreg  # pylint: disable=import-error
from contextlib import contextmanager

WORKSPACE, OPERATION = sys.argv[1:3]
JOURNAL = os.path.join(WORKSPACE, "mixed-acl-journal.json")
CONTENT = b"Owned mixed ACL fixture\x00\xff\r\n"
SECURITY = ctypes.WinDLL("advapi32", use_last_error=True)
KERNEL = ctypes.WinDLL("kernel32", use_last_error=True)
POINTER, DWORD = ctypes.c_void_p, ctypes.c_uint32


def _bind(library, name, result, arguments):
    function = getattr(library, name)
    function.restype, function.argtypes = result, arguments
    return function


GET_SECURITY = _bind(
    SECURITY,
    "GetSecurityInfo",
    DWORD,
    [POINTER, ctypes.c_int, DWORD] + [POINTER] * 5,
)
SET_SECURITY = _bind(
    SECURITY,
    "SetSecurityInfo",
    DWORD,
    [POINTER, ctypes.c_int, DWORD] + [POINTER] * 4,
)
GET_CONTROL = _bind(
    SECURITY,
    "GetSecurityDescriptorControl",
    ctypes.c_int,
    [POINTER, POINTER, POINTER],
)
SID_LENGTH = _bind(SECURITY, "GetLengthSid", DWORD, [POINTER])
LOOKUP_SID = _bind(
    SECURITY,
    "LookupAccountSidW",
    ctypes.c_int,
    [ctypes.c_wchar_p, POINTER, POINTER, POINTER, POINTER, POINTER, POINTER],
)
LOCAL_FREE = _bind(KERNEL, "LocalFree", POINTER, [POINTER])
CREATE_FILE = _bind(
    KERNEL,
    "CreateFileW",
    POINTER,
    [ctypes.c_wchar_p, DWORD, DWORD, POINTER, DWORD, DWORD, POINTER],
)
CLOSE_HANDLE = _bind(KERNEL, "CloseHandle", ctypes.c_int, [POINTER])
OPEN_TOKEN = _bind(
    SECURITY, "OpenProcessToken", ctypes.c_int, [POINTER, DWORD, POINTER]
)
LOOKUP_PRIVILEGE = _bind(
    SECURITY,
    "LookupPrivilegeValueW",
    ctypes.c_int,
    [ctypes.c_wchar_p, ctypes.c_wchar_p, POINTER],
)
ADJUST_PRIVILEGE = _bind(
    SECURITY,
    "AdjustTokenPrivileges",
    ctypes.c_int,
    [POINTER, ctypes.c_int, POINTER, DWORD, POINTER, POINTER],
)


# These native records have fields, not public methods.
class Luid(ctypes.Structure):  # pylint: disable=too-few-public-methods
    """Native privilege identifier."""

    _fields_ = [("low", DWORD), ("high", ctypes.c_int32)]


class Privilege(ctypes.Structure):  # pylint: disable=too-few-public-methods
    """Native identifier and privilege attributes."""

    _fields_ = [("luid", Luid), ("attributes", DWORD)]


class Privileges(ctypes.Structure):  # pylint: disable=too-few-public-methods
    """Single-privilege adjustment record."""

    _fields_ = [("count", DWORD), ("entries", Privilege * 1)]


def _require(result):
    if not result:
        raise ctypes.WinError(ctypes.get_last_error())


def _check(error):
    if error:
        raise ctypes.WinError(error)


def _encode(value):
    return base64.b64encode(value).decode("ascii") if value is not None else None


def _decode(value):
    return base64.b64decode(value) if value is not None else None


def _sid(authority, *subauthorities):
    return (
        bytes([1, len(subauthorities)])
        + authority.to_bytes(6, "big")
        + struct.pack("<" + "I" * len(subauthorities), *subauthorities)
    )


def _principal_name(identity):
    name, domain = ctypes.create_unicode_buffer(256), ctypes.create_unicode_buffer(256)
    name_size, domain_size, use = DWORD(len(name)), DWORD(len(domain)), DWORD()
    _require(
        LOOKUP_SID(
            None,
            ctypes.create_string_buffer(identity),
            name,
            ctypes.byref(name_size),
            domain,
            ctypes.byref(domain_size),
            ctypes.byref(use),
        )
    )
    return domain.value + "\\" + name.value if domain.value else name.value


@contextmanager
def _audit_privilege():
    token = POINTER()
    _require(OPEN_TOKEN(POINTER(-1), 0x28, ctypes.byref(token)))
    requested, previous, needed = Privileges(1), Privileges(), DWORD()
    requested.entries[0].attributes = 2
    _require(
        LOOKUP_PRIVILEGE(
            None,
            "SeSecurityPrivilege",
            ctypes.byref(requested.entries[0].luid),
        )
    )
    try:
        ctypes.set_last_error(0)
        # This standalone target fixture binds its own fixed privilege ABI;
        # importing a production runas helper would couple recovery to it.
        # pylint: disable=duplicate-code
        _require(
            ADJUST_PRIVILEGE(
                token,
                False,
                ctypes.byref(requested),
                ctypes.sizeof(previous),
                ctypes.byref(previous),
                ctypes.byref(needed),
            )
        )
        # pylint: enable=duplicate-code
        _check(ctypes.get_last_error())
        yield
    finally:
        if previous.count:
            ctypes.set_last_error(0)
            _require(
                ADJUST_PRIVILEGE(token, False, ctypes.byref(previous), 0, None, None)
            )
            _check(ctypes.get_last_error())
        _require(CLOSE_HANDLE(token))


def _write_journal(record):
    with open(JOURNAL + ".new", "w", encoding="utf-8") as stream:
        json.dump(record, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(JOURNAL + ".new", JOURNAL)


def _read_journal():
    with open(JOURNAL, encoding="utf-8") as stream:
        record = json.load(stream)
    assert record["workspace"] == WORKSPACE
    assert len(record["suffix"]) == 32
    assert all(character in "0123456789abcdef" for character in record["suffix"])
    assert record["paths"] == _paths(record["suffix"])
    return record


def _paths(suffix):
    return {
        "workspace": WORKSPACE,
        "file": os.path.join(WORKSPACE, "mixed-" + suffix + ".txt"),
        "registry": "Software\\LegacyWindowsMixedAcl-" + suffix,
    }


@contextmanager
def _object_handle(role, path, access):
    if role == "registry":
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, access) as handle:
            yield int(handle), 4
    else:
        handle = CREATE_FILE(path, access, 7, None, 3, 0x02000000, None)
        if handle == POINTER(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            yield handle, 1
        finally:
            _require(CLOSE_HANDLE(handle))


def _acl_bytes(pointer):
    if not pointer:
        return None
    size = ctypes.c_uint16.from_address(pointer.value + 2).value
    return ctypes.string_at(pointer, size)


def _entries(raw):
    result = []
    if raw is not None:
        offset = 8
        for _ in range(struct.unpack_from("<H", raw, 4)[0]):
            size = struct.unpack_from("<H", raw, offset + 2)[0]
            assert size >= 4 and offset + size <= len(raw)
            result.append(raw[offset : offset + size])
            offset += size
    return result


def _pack_acl(aces, revision=4):
    body = b"".join(aces)
    return struct.pack("<BBHHH", revision, 0, len(body) + 8, len(aces), 0) + body


def _snapshot(role, path):
    descriptor, owner, group, dacl, sacl = [POINTER() for _ in range(5)]
    with _object_handle(role, path, 0x01020000) as opened:
        try:
            _check(
                GET_SECURITY(
                    opened[0],
                    opened[1],
                    15,
                    ctypes.byref(owner),
                    ctypes.byref(group),
                    ctypes.byref(dacl),
                    ctypes.byref(sacl),
                    ctypes.byref(descriptor),
                )
            )
            control, revision = ctypes.c_uint16(), DWORD()
            _require(
                GET_CONTROL(descriptor, ctypes.byref(control), ctypes.byref(revision))
            )
            return {
                "owner": _encode(ctypes.string_at(owner, SID_LENGTH(owner))),
                "group": _encode(ctypes.string_at(group, SID_LENGTH(group))),
                "dacl": _encode(_acl_bytes(dacl)),
                "sacl": _encode(_acl_bytes(sacl)),
                "control": control.value,
            }
        finally:
            if descriptor:
                LOCAL_FREE(descriptor)


def _apply_snapshot(role, path, value):
    buffers = [
        (
            ctypes.create_string_buffer(_decode(value[name]))
            if value[name] is not None
            else None
        )
        for name in ("owner", "group", "dacl", "sacl")
    ]
    protection = (0x80000000 if value["control"] & 0x1000 else 0x20000000) | (
        0x40000000 if value["control"] & 0x2000 else 0x10000000
    )
    with _object_handle(role, path, 0x010E0000) as opened:
        _check(SET_SECURITY(opened[0], opened[1], 15 | protection, *buffers))


def _protected_baseline(role, path, original):
    # These newly created objects use explicit, protected access and an empty
    # audit ACL. Capture the native result only after proving its roundtrip.
    desired = dict(original)
    desired["control"] |= 0x3000
    access = _decode(original["dacl"])
    assert access is not None
    desired["dacl"] = _encode(
        _pack_acl(
            [ace[:1] + bytes([ace[1] & ~16]) + ace[2:] for ace in _entries(access)],
            access[0],
        )
    )
    desired["sacl"] = _encode(_pack_acl([], 2))
    _apply_snapshot(role, path, desired)
    baseline = _snapshot(role, path)
    _apply_snapshot(role, path, baseline)
    actual = _snapshot(role, path)
    assert actual == baseline, (role, actual, baseline)
    return baseline


def _conditional_ace(kind, mask, condition):
    convert = _bind(
        SECURITY,
        "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        ctypes.c_int,
        [ctypes.c_wchar_p, DWORD, POINTER, POINTER],
    )
    get_dacl = _bind(
        SECURITY,
        "GetSecurityDescriptorDacl",
        ctypes.c_int,
        [POINTER, POINTER, POINTER, POINTER],
    )
    descriptor, dacl, present, defaulted = POINTER(), POINTER(), DWORD(), DWORD()
    sddl = "D:({0};;0x{1:x};;;S-1-5-20;({2}))".format(
        "XA" if kind == 9 else "XD", mask, condition
    )
    try:
        _require(convert(sddl, 1, ctypes.byref(descriptor), None))
        _require(
            get_dacl(
                descriptor,
                ctypes.byref(present),
                ctypes.byref(dacl),
                ctypes.byref(defaulted),
            )
        )
        entries = _entries(_acl_bytes(dacl))
        assert len(entries) == 1 and entries[0][0] == kind
        assert entries[0][20:24] == b"artx"
        return entries[0]
    finally:
        if descriptor:
            LOCAL_FREE(descriptor)


def _unusual_ace(kind, inherited=False, mask=1, condition=None):
    if condition is not None:
        assert kind in (9, 10)
        ace = _conditional_ace(kind, mask, condition)
        return ace[:1] + bytes([16 if inherited else 0]) + ace[2:]
    identity = _sid(5, 20)
    flags = (64 if kind in (2, 7, 13, 15) else 0) | (16 if inherited else 0)
    body = struct.pack("<I", mask)
    if kind in (5, 6, 7, 11, 12, 15):
        body += struct.pack("<I", 0)
    body += identity
    if kind in (9, 10, 11, 12, 13, 15):
        body += b"\x00\x00\x00\x00"
    return struct.pack("<BBH", kind, flags, 4 + len(body)) + body


def _setup():
    assert not os.path.exists(JOURNAL)
    assert not os.listdir(WORKSPACE)
    record = {
        "workspace": WORKSPACE,
        "suffix": uuid.uuid4().hex,
        "baseline": {},
        "created_snapshots": {},
    }
    record["paths"] = _paths(record["suffix"])
    assert not os.path.exists(record["paths"]["file"])
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, record["paths"]["registry"]):
            raise AssertionError("Do not adopt an existing registry key")
    except FileNotFoundError:
        pass
    _write_journal(record)
    record["baseline"]["workspace"] = _snapshot("workspace", WORKSPACE)
    _write_journal(record)
    record["created_snapshots"]["workspace"] = record["baseline"]["workspace"]
    record["baseline"]["workspace"] = _protected_baseline(
        "workspace", WORKSPACE, record["baseline"]["workspace"]
    )
    _write_journal(record)
    with open(record["paths"]["file"], "wb") as stream:
        stream.write(CONTENT)
    record["baseline"]["file"] = _snapshot("file", record["paths"]["file"])
    _write_journal(record)
    record["created_snapshots"]["file"] = record["baseline"]["file"]
    record["baseline"]["file"] = _protected_baseline(
        "file", record["paths"]["file"], record["baseline"]["file"]
    )
    _write_journal(record)
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, record["paths"]["registry"]):
        pass
    record["baseline"]["registry"] = _snapshot("registry", record["paths"]["registry"])
    _write_journal(record)
    record["created_snapshots"]["registry"] = record["baseline"]["registry"]
    record["baseline"]["registry"] = _protected_baseline(
        "registry", record["paths"]["registry"], record["baseline"]["registry"]
    )
    _write_journal(record)
    return {
        "paths": {
            "file": record["paths"]["file"],
            "registry": "HKCU:\\" + record["paths"]["registry"],
        },
        "baseline": record["baseline"],
        "created_snapshots": record["created_snapshots"],
        "suffix": record["suffix"],
        "runtime": list(sys.version_info[:3]),
        "principal": _principal_name(_sid(5, 32, 546)),
        "unusual_principal": _principal_name(_sid(5, 20)),
    }


def _prepare():
    record = _read_journal()
    specification = json.loads(sys.argv[3])
    role, kind = specification["role"], specification["ace_type"]
    assert role in record["baseline"]
    assert kind in (5, 6, 7, 9, 10, 11, 12, 13, 15)
    parent = record["baseline"]["workspace"]
    _apply_snapshot("workspace", WORKSPACE, parent)
    assert _snapshot("workspace", WORKSPACE) == parent
    original = record["baseline"][role]
    _apply_snapshot(role, record["paths"][role], original)
    mixed = dict(_snapshot(role, record["paths"][role]))
    assert mixed == original, (role, mixed, original)
    unusual = _unusual_ace(
        kind,
        specification.get("inherited", False),
        specification.get("mask", 1),
        specification.get("condition"),
    )
    field = "sacl" if kind in (7, 13, 15) else "dacl"
    stored = _entries(_decode(mixed[field]))
    if specification.get("inherited", False):
        # Windows supplies the inherited flag. A direct protected-ACL write
        # normalizes a fabricated inherited ACE into an explicit one.
        assert role == "file" and kind == 9
        inheritable = _unusual_ace(
            kind,
            mask=specification.get("mask", 1),
            condition=specification.get("condition"),
        )
        inheritable = inheritable[:1] + bytes([1]) + inheritable[2:]
        parent = dict(parent)
        parent["dacl"] = _encode(
            _pack_acl(_entries(_decode(parent["dacl"])) + [inheritable])
        )
        _apply_snapshot("workspace", WORKSPACE, parent)
        mixed["control"] &= ~0x1000
        _apply_snapshot(role, record["paths"][role], mixed)
        actual = _snapshot(role, record["paths"][role])
        assert unusual in _entries(_decode(actual[field])), (unusual, actual)
        return {"snapshot": actual, "unusual": _encode(unusual)}
    if specification.get("seed_common"):
        ordinary = 2 if field == "sacl" else int(kind == 10)
        stored.append(
            _unusual_ace(
                ordinary,
                mask=specification.get(
                    "seed_common_mask", specification.get("mask", 1)
                ),
            )
        )
    mixed[field] = _encode(_pack_acl([unusual] + stored))
    mixed["control"] |= 0x2000 if field == "sacl" else 0x1000
    _apply_snapshot(role, record["paths"][role], mixed)
    actual = _snapshot(role, record["paths"][role])
    assert unusual in _entries(_decode(actual[field]))
    return {"snapshot": actual, "unusual": _encode(unusual)}


def _observe():
    record = _read_journal()
    with open(record["paths"]["file"], "rb") as stream:
        assert stream.read() == CONTENT
    return {role: _snapshot(role, path) for role, path in record["paths"].items()}


def _restore():
    record = _read_journal()
    restored = {}
    # Restore the parent first; inheritance may update an unprotected child.
    for role in ("workspace", "file", "registry"):
        if role not in record["baseline"]:
            continue
        baseline = record["baseline"][role]
        path = record["paths"][role]
        _apply_snapshot(role, path, baseline)
        actual = _snapshot(role, path)
        assert actual == baseline, (role, actual, baseline)
        restored[role] = actual
    return {"restored": True, "snapshots": restored}


def _cleanup():
    if not os.path.exists(JOURNAL):
        assert not os.listdir(WORKSPACE)
        return {"restored": True, "journal_absent": True}
    restored = _restore()
    record = _read_journal()
    if "registry" in record["baseline"]:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, record["paths"]["registry"])
    if "file" in record["baseline"]:
        with open(record["paths"]["file"], "rb") as stream:
            assert stream.read() == CONTENT
        os.remove(record["paths"]["file"])
    os.remove(JOURNAL)
    assert not os.listdir(WORKSPACE)
    restored["journal_absent"] = True
    return restored


def _absence():
    suffix = sys.argv[3]
    assert len(suffix) == 32
    assert all(character in "0123456789abcdef" for character in suffix)
    paths = _paths(suffix)
    assert not os.path.exists(paths["file"])
    assert not os.path.exists(JOURNAL)
    assert not os.listdir(WORKSPACE)
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, paths["registry"]):
            raise AssertionError("The owned registry key still exists")
    except FileNotFoundError:
        pass
    return {
        "file_absent": True,
        "registry_absent": True,
        "journal_absent": True,
        "workspace_empty": True,
    }


if __name__ == "__main__":
    assert sys.version_info[:3] == (3, 4, 4), sys.version
    assert os.path.basename(WORKSPACE).startswith("legacy-windows-mixed-acl-")
    assert not os.path.islink(WORKSPACE)
    with _audit_privilege():
        print(
            json.dumps(
                {
                    "setup": _setup,
                    "prepare": _prepare,
                    "observe": _observe,
                    "restore": _restore,
                    "cleanup": _cleanup,
                    "absence": _absence,
                }[OPERATION](),
                sort_keys=True,
            )
        )
