"""Verify NetShare buffers, flag updates, and share security boundaries."""

# SPDX-License-Identifier: GPL-3.0-or-later

# These tests inspect the native ABI and packed security data at its boundary.
# pylint: disable=protected-access

import base64
import ctypes
import gc
import struct
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import load_module, native_error

SOURCE = (
    Path(__file__).resolve().parents[2] / "plugins/module_utils/legacy_windows_share.py"
)
EMPTY_ACL = struct.pack("<BBHHH", 2, 0, 8, 0, 0)
EVERYONE = bytes.fromhex("010100000000000100000000")
ADMINISTRATORS = bytes.fromhex("01020000000000052000000020020000")
SYSTEM = bytes.fromhex("010100000000000512000000")
# Exact initial New-SmbShare descriptor independently observed on Server 2025.
INITIAL_DESCRIPTOR = base64.b64decode(
    "AQAEgDAAAAA8AAAAAAAAABQAAAACABwAAQAAAAAAFACpABIAAQEAAAAAAAEAAAAA"
    "AQEAAAAAAAUSAAAAAQEAAAAAAAUSAAAA"
)


@pytest.fixture(name="share")
def share_fixture(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load target-compatible native code with a portable WinError substitute.

    :param monkeypatch: Scoped imports and error factory.
    :returns: Native share module without opening Windows libraries.
    """
    monkeypatch.syspath_prepend(str(SOURCE.parent))
    monkeypatch.setattr(ctypes, "WinError", native_error, raising=False)
    return load_module(SOURCE, "tested_native_share")


def _set_pointer(destination: Any, pointer: ctypes.c_void_p) -> None:
    ctypes.cast(destination, ctypes.POINTER(ctypes.c_void_p))[0] = pointer


def _security_snapshot() -> dict[str, Any]:
    return {
        "control": 0x8004,
        "owner": ADMINISTRATORS,
        "group": EVERYONE,
        "sacl": None,
        "dacl": EMPTY_ACL,
    }


def test_get_share_copies_properties_and_frees_both_pages(
    share: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = Mock()
    info = share._ShareInfo502(
        "Owned", 0, "Original", 0, 99, 0, "C:\\Owned", None, 0, 123
    )
    flags = share._ShareInfo1005(0x8000 | 0x800 | 0x20 | 0x400)
    pages = {502: info, 1005: flags}

    def _get(_server: None, _name: str, level: int, output: Any) -> int:
        _set_pointer(output, ctypes.cast(ctypes.pointer(pages[level]), ctypes.c_void_p))
        return 0

    library.NetShareGetInfo.side_effect = _get
    monkeypatch.setattr(share, "_netapi", lambda: library)
    monkeypatch.setattr(
        share, "_copy_descriptor", lambda _pointer: _security_snapshot()
    )
    result = share.get_share("Owned")
    info.remark = "Reused page"
    assert result["description"] == "Original"
    assert result["caching_mode"] == "Programs"
    assert not result["list"] and result["encrypt"]
    assert result["scope_name"] == "*"
    assert library.NetApiBufferFree.call_count == 2


@pytest.mark.parametrize("status", [5, 2310])
def test_failed_read_frees_an_allocated_page(
    share: ModuleType, monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    library = Mock()

    def _get(_server: None, _name: str, _level: int, output: Any) -> int:
        _set_pointer(output, ctypes.c_void_p(123))
        return status

    library.NetShareGetInfo.side_effect = _get
    monkeypatch.setattr(share, "_netapi", lambda: library)
    if status == 2310:
        assert share.get_share("Absent") is None
    else:
        with pytest.raises(OSError) as error:
            share.get_share("Owned")
        assert error.value.errno == 5
    assert library.NetApiBufferFree.call_count == 1


def test_security_copy_failure_still_frees_page(
    share: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = Mock()
    info = share._ShareInfo502("Owned", 0, "", 0, 99, 0, "C:\\Owned", None, 0, 123)

    def _get(_server: None, _name: str, _level: int, output: Any) -> int:
        _set_pointer(output, ctypes.cast(ctypes.pointer(info), ctypes.c_void_p))
        return 0

    library.NetShareGetInfo.side_effect = _get
    monkeypatch.setattr(share, "_netapi", lambda: library)
    monkeypatch.setattr(
        share, "_copy_descriptor", Mock(side_effect=ValueError("bad descriptor"))
    )
    with pytest.raises(ValueError, match="bad descriptor"):
        share.get_share("Owned")
    assert library.NetApiBufferFree.call_count == 1


def test_null_security_descriptor_is_rejected_without_native_dereference(
    share: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = Mock()
    monkeypatch.setattr(share, "_security", library)
    with pytest.raises(ValueError, match="did not provide a security descriptor"):
        share._copy_descriptor(None)
    library.assert_not_called()


def test_share_records_match_pointer_width_abi(share: ModuleType) -> None:
    pointer_size = ctypes.sizeof(ctypes.c_void_p)
    offsets = (
        (0, 4, 8, 12, 16, 20, 24, 28)
        if pointer_size == 4
        else (0, 8, 16, 24, 28, 32, 40, 48)
    )
    for (name, _kind), offset in zip(share._ShareInfo502._fields_[:8], offsets):
        assert getattr(share._ShareInfo502, name).offset == offset
    assert share._ShareInfo502.reserved.offset == (32 if pointer_size == 4 else 56)
    assert share._ShareInfo502.descriptor.offset == (36 if pointer_size == 4 else 64)
    assert ctypes.sizeof(share._ShareInfo502) == (40 if pointer_size == 4 else 72)


def test_descriptor_offsets_and_unrelated_security_survive(share: ModuleType) -> None:
    snapshot = _security_snapshot()
    packed = share._pack_descriptor(snapshot)
    revision, unused, control, owner, group, sacl, dacl = struct.unpack_from(
        "<BBHLLLL", packed
    )
    assert (revision, unused, control, sacl) == (1, 0, 0x8004, 0)
    assert all(offset % 4 == 0 for offset in (owner, group, dacl))
    assert packed[owner : owner + len(ADMINISTRATORS)] == ADMINISTRATORS
    assert packed[group : group + len(EVERYONE)] == EVERYONE
    assert dacl == 20
    assert packed[dacl : dacl + len(EMPTY_ACL)] == EMPTY_ACL
    assert snapshot == _security_snapshot()


def test_descriptor_copy_owns_all_native_components(
    share: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = Mock()
    buffers = {
        "Owner": ctypes.create_string_buffer(ADMINISTRATORS),
        "Group": ctypes.create_string_buffer(EVERYONE),
        "Dacl": ctypes.create_string_buffer(EMPTY_ACL),
    }

    def _control(_descriptor: int, control: Any, revision: Any) -> int:
        ctypes.cast(control, ctypes.POINTER(ctypes.c_uint16))[0] = 0x8004
        ctypes.cast(revision, ctypes.POINTER(ctypes.c_uint32))[0] = 1
        return 1

    library.GetSecurityDescriptorControl.side_effect = _control

    def _reader(kind: str) -> Any:
        def _read(_descriptor: int, *outputs: Any) -> int:
            if kind.endswith("acl"):
                ctypes.cast(outputs[0], ctypes.POINTER(ctypes.c_int))[0] = int(
                    kind in buffers
                )
                pointer = outputs[1]
            else:
                pointer = outputs[0]
            _set_pointer(
                pointer,
                (
                    ctypes.cast(buffers[kind], ctypes.c_void_p)
                    if kind in buffers
                    else ctypes.c_void_p()
                ),
            )
            return 1

        return _read

    for kind in ("Owner", "Group", "Dacl", "Sacl"):
        getattr(library, "GetSecurityDescriptor" + kind).side_effect = _reader(kind)
    library.GetLengthSid.side_effect = lambda pointer: (
        len(ADMINISTRATORS)
        if pointer.value == ctypes.addressof(buffers["Owner"])
        else len(EVERYONE)
    )
    monkeypatch.setattr(share, "_security", lambda: library)
    copied = share._copy_descriptor(123)
    assert copied == _security_snapshot()
    for buffer in buffers.values():
        ctypes.memset(buffer, 0, ctypes.sizeof(buffer))
    assert copied == _security_snapshot()


def test_invalid_access_contract_does_not_read_or_write(
    share: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    read = Mock()
    monkeypatch.setattr(share, "get_share", read)
    with pytest.raises(ValueError, match="right or control"):
        share.change_access("Owned", "Everyone", "Unknown", "Allow")
    read.assert_not_called()


def test_create_uses_exact_measured_security_and_keeps_descriptor_alive(
    share: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = Mock()
    sid_bytes = Mock(
        side_effect=lambda sid: {"S-1-5-18": SYSTEM, "S-1-1-0": EVERYONE}[sid]
    )
    monkeypatch.setattr(share.account, "sid_bytes", sid_bytes)

    def _add(server: None, level: int, pointer: Any, errors: None) -> int:
        assert server is None and errors is None and level == 502
        info = ctypes.cast(pointer, ctypes.POINTER(share._ShareInfo502)).contents
        assert (info.name, info.path, info.remark, info.type, info.max_uses) == (
            "Owned",
            "C:\\Owned",
            "",
            0,
            0xFFFFFFFF,
        )
        gc.collect()
        assert info.reserved == 0 and info.descriptor is not None
        assert (
            ctypes.string_at(info.descriptor, len(INITIAL_DESCRIPTOR))
            == INITIAL_DESCRIPTOR
        )
        return 0

    library.NetShareAdd.side_effect = _add
    monkeypatch.setattr(share, "_netapi", lambda: library)
    share.create_share("Owned", "C:\\Owned")
    library.NetShareAdd.assert_called_once()
    assert sid_bytes.mock_calls == [call("S-1-5-18"), call("S-1-1-0")]


def test_create_sid_failure_does_not_create_a_share(
    share: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = Mock()
    monkeypatch.setattr(share, "_netapi", lambda: library)
    monkeypatch.setattr(
        share.account, "sid_bytes", Mock(side_effect=OSError("SID failed"))
    )
    with pytest.raises(OSError, match="SID failed"):
        share.create_share("Owned", "C:\\Owned")
    library.NetShareAdd.assert_not_called()


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("list", False, 0x400 | 0x800 | 0x20),
        ("list", True, 0x400 | 0x20),
        ("encrypt", True, 0x400 | 0x8000 | 0x20),
        ("encrypt", False, 0x400 | 0x20),
        ("caching_mode", "documents", 0x400 | 0x10),
        ("caching_mode", "BranchCache", 0x400 | 0x2000),
    ],
)
def test_property_update_preserves_other_flags(
    share: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
    expected: int,
) -> None:
    monkeypatch.setattr(share, "get_share", lambda _name: {"flags": 0x400 | 0x20})
    writes = Mock()
    monkeypatch.setattr(share, "_set_info", writes)
    share.set_property("Owned", field, value)
    name, level, info = writes.call_args.args
    assert (name, level, info.flags) == ("Owned", 1005, expected)


def test_unsupported_scope_and_caching_do_not_write(
    share: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    writes = Mock()
    monkeypatch.setattr(share, "_set_info", writes)
    monkeypatch.setattr(share, "get_share", lambda _name: {"flags": 0})
    with pytest.raises(ValueError, match="ScopeName = 'Cluster'"):
        share.set_property("Owned", "scope_name", "Cluster")
    with pytest.raises(ValueError, match="caching mode"):
        share.set_property("Owned", "caching_mode", "Unknown")
    writes.assert_not_called()


@pytest.mark.parametrize(
    "acl",
    [b"", EMPTY_ACL[:6], struct.pack("<BBHHH", 2, 0, 8, 1, 0), EMPTY_ACL + b"garbage"],
)
def test_acl_reader_handles_declared_empty_and_rejects_truncation(
    share: ModuleType, acl: bytes
) -> None:
    if acl.startswith(EMPTY_ACL):
        assert share._aces(acl) == []
    else:
        with pytest.raises(ValueError, match="Malformed"):
            share._aces(acl)


def test_empty_acl_reports_provider_synthetic_deny(
    share: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(share.account, "sid_to_name", lambda _sid: "Everyone")
    assert share.access_entries({"security": _security_snapshot()}) == [
        {"account": "Everyone", "sid": "S-1-1-0", "control": "Deny", "right": "Full"}
    ]


def test_access_change_preserves_owner_group_and_opposite_control(
    share: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    snapshot = _security_snapshot()
    denied = struct.pack("<BBHL", 1, 0, 8 + len(EVERYONE), 0x1F01FF) + EVERYONE
    allowed = struct.pack("<BBHL", 0, 0, 8 + len(EVERYONE), 0x1200A9) + EVERYONE
    snapshot["dacl"] = (
        struct.pack("<BBHHH", 2, 0, 8 + len(denied) + len(allowed), 2, 0)
        + denied
        + allowed
    )
    monkeypatch.setattr(share, "get_share", lambda _name: {"security": snapshot})
    monkeypatch.setattr(share.owner, "resolve_owner", lambda _name: "S-1-1-0")
    monkeypatch.setattr(share.account, "sid_bytes", lambda _sid: EVERYONE)
    written: list[bytes] = []

    def capture(name: str, descriptor: Any) -> None:
        assert name == "Owned"
        pointer = ctypes.cast(descriptor, ctypes.c_void_p).value
        assert pointer is not None
        prefix = ctypes.string_at(pointer, 20)
        dacl = struct.unpack_from("<L", prefix, 16)[0]
        size = struct.unpack("<H", ctypes.string_at(pointer + dacl + 2, 2))[0]
        written.append(ctypes.string_at(pointer, dacl + size))

    monkeypatch.setattr(share, "_set_security", capture)
    share.change_access("Owned", "Everyone", "Change", "Allow")
    assert share._aces(snapshot["dacl"])[0] == denied
    assert struct.unpack_from("<L", share._aces(snapshot["dacl"])[1], 4)[0] == 0x1301BF
    assert snapshot["owner"] == ADMINISTRATORS and snapshot["group"] == EVERYONE
    share.change_access("Owned", "Everyone", "Full", "Deny", True)
    assert len(share._aces(snapshot["dacl"])) == 1
    assert len(written) == 2


@pytest.mark.parametrize("status", [0, 5])
def test_security_write_keeps_metadata_and_frees_borrowed_page(
    share: ModuleType, monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    library = Mock()
    original = share._ShareInfo502(
        "Owned", 0, "Owned description", 7, 19, 3, "C:\\Owned", "unused", 0, 123
    )
    packed = share._pack_descriptor(_security_snapshot())
    descriptor = ctypes.create_string_buffer(packed)

    def _get(server: None, name: str, level: int, output: Any) -> int:
        assert (server, name, level) == (None, "Owned", 502)
        _set_pointer(output, ctypes.cast(ctypes.pointer(original), ctypes.c_void_p))
        return 0

    def _write(server: None, name: str, level: int, pointer: Any, errors: None) -> int:
        assert (server, name, level, errors) == (None, "Owned", 502, None)
        info = ctypes.cast(pointer, ctypes.POINTER(share._ShareInfo502)).contents
        assert (
            info.name,
            info.type,
            info.remark,
            info.permissions,
            info.max_uses,
            info.current_uses,
            info.path,
            info.password,
            info.reserved,
        ) == ("Owned", 0, "Owned description", 7, 19, 3, "C:\\Owned", "unused", 0)
        gc.collect()
        assert ctypes.string_at(info.descriptor, len(packed)) == packed
        assert original.descriptor == 123
        library.NetApiBufferFree.assert_not_called()
        return status

    library.NetShareGetInfo.side_effect = _get
    library.NetShareSetInfo.side_effect = _write
    monkeypatch.setattr(share, "_netapi", lambda: library)
    if status:
        with pytest.raises(OSError) as error:
            share._set_security("Owned", descriptor)
        assert error.value.errno == status
    else:
        share._set_security("Owned", descriptor)
    library.NetApiBufferFree.assert_called_once()
    library.NetShareSetInfo.assert_called_once()


def test_security_write_does_not_recreate_a_disappeared_share(
    share: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = Mock()
    library.NetShareGetInfo.return_value = 2310
    monkeypatch.setattr(share, "_netapi", lambda: library)
    with pytest.raises(OSError) as error:
        share._set_security("Owned", ctypes.create_string_buffer(b"unused"))
    assert error.value.errno == 2310
    library.NetShareSetInfo.assert_not_called()
    library.NetApiBufferFree.assert_not_called()


def test_native_delete_error_is_not_hidden(
    share: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = Mock()
    library.NetShareDel.return_value = 5
    monkeypatch.setattr(share, "_netapi", lambda: library)
    with pytest.raises(OSError) as error:
        share.delete_share("Owned")
    assert error.value.errno == 5
    library.NetShareDel.assert_called_once_with(None, "Owned", 0)
