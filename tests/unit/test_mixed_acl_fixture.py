"""Check owned mixed-descriptor preparation, inspection and exact recovery."""

# SPDX-License-Identifier: GPL-3.0-or-later
# The fixture's command protocol is tested through its private implementation.
# pylint: disable=protected-access

import base64
import copy
import ctypes
import json
import struct
import sys
from contextlib import nullcontext
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module, native_error

SOURCE = ROOT / "tests/integration/fixtures/mixed_acl.py"


# The ctypes test double only needs dynamic native-function lookup.
class _Library:  # pylint: disable=too-few-public-methods
    def __init__(self) -> None:
        self.functions: dict[str, Mock] = {}

    def __getattr__(self, name: str) -> Mock:
        if name not in self.functions:
            self.functions[name] = Mock(name=name)
        return self.functions[name]


@pytest.fixture(name="fixture")
def mixed_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load the target-compatible fixture without contacting Windows.

    :param tmp_path: Private fixture journal directory.
    :param monkeypatch: Scoped native imports and process arguments.
    :returns: Fixture module with native library call recorders.
    """
    registry = ModuleType("winreg")
    registry.HKEY_CURRENT_USER = 0x80000001  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "winreg", registry)
    libraries = {name: _Library() for name in ("advapi32", "kernel32")}
    monkeypatch.setattr(
        ctypes, "WinDLL", lambda name, **_kw: libraries[name], raising=False
    )
    monkeypatch.setattr(sys, "argv", [str(SOURCE), str(tmp_path), "observe"])
    fixture = load_module(SOURCE, "tested_mixed_acl_fixture")
    return fixture


def _snapshot(fixture: Any) -> dict[str, Any]:
    return {
        "owner": fixture._encode(fixture._sid(5, 18)),
        "group": fixture._encode(fixture._sid(5, 32, 544)),
        "dacl": fixture._encode(fixture._pack_acl([])),
        "sacl": None,
        "control": 0x8004,
    }


def _journal(fixture: Any) -> dict[str, Any]:
    suffix = "0123456789abcdef" * 2
    value = {
        "workspace": fixture.WORKSPACE,
        "suffix": suffix,
        "paths": fixture._paths(suffix),
        "baseline": {
            role: _snapshot(fixture) for role in ("workspace", "file", "registry")
        },
    }
    fixture._write_journal(value)
    return value


@pytest.mark.parametrize("kind", [5, 6, 7, 9, 10, 11, 12, 13, 15])
@pytest.mark.parametrize("inherited", [False, True])
def test_fixture_aces_have_exact_sid_offsets_lengths_and_opaque_payload(
    fixture: Any, kind: int, inherited: bool
) -> None:
    ace = fixture._unusual_ace(kind, inherited)
    sid_offset = 12 if kind in (5, 6, 7, 11, 12, 15) else 8
    identity = fixture._sid(5, 20)
    assert ace[sid_offset : sid_offset + len(identity)] == identity
    assert struct.unpack_from("<H", ace, 2)[0] == len(ace)
    assert struct.unpack_from("<I", ace, 4)[0] == 1
    assert ace[0] == kind
    assert ace[1] == (64 if kind in (7, 13, 15) else 0) | (16 if inherited else 0)
    if kind in (9, 10, 11, 12, 13, 15):
        assert ace[sid_offset + len(identity) :] == b"\x00" * 4
    else:
        assert len(ace) == sid_offset + len(identity)
    assert fixture._entries(fixture._pack_acl([ace])) == [ace]


def test_native_sid_builder_uses_big_endian_authority_and_little_endian_subauthorities(
    fixture: Any,
) -> None:
    assert fixture._sid(5, 32, 546) == (
        b"\x01\x02\x00\x00\x00\x00\x00\x05" + struct.pack("<II", 32, 546)
    )


@pytest.mark.parametrize("kind", [9, 10])
def test_conditional_fixture_compiles_sddl_copies_native_bytes_and_frees_descriptor(
    fixture: Any, kind: int
) -> None:
    identity = fixture._sid(5, 20)
    body = struct.pack("<I", 1048577) + identity + b"artx\x01\x02\x03\x04"
    ace = struct.pack("<BBH", kind, 0, len(body) + 4) + body
    acl = ctypes.create_string_buffer(fixture._pack_acl([ace]))

    def _convert(_sddl: str, _revision: int, descriptor: Any, _size: Any) -> int:
        descriptor._obj.value = 42
        return 1

    def _dacl(_descriptor: Any, _present: Any, pointer: Any, _defaulted: Any) -> int:
        pointer._obj.value = ctypes.addressof(acl)
        return 1

    convert = fixture.SECURITY.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.side_effect = _convert
    fixture.SECURITY.GetSecurityDescriptorDacl.side_effect = _dacl
    assert fixture._unusual_ace(kind, mask=1048577, condition="1 == 1") == ace
    access_type = "XA" if kind == 9 else "XD"
    assert convert.call_args.args[:2] == (
        f"D:({access_type};;0x100001;;;S-1-5-20;(1 == 1))",
        1,
    )
    assert fixture.LOCAL_FREE.call_args.args[0].value == 42


def test_conditional_fixture_parse_failure_frees_partial_native_descriptor(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _fail(_sddl: str, _revision: int, descriptor: Any, _size: Any) -> int:
        descriptor._obj.value = 42
        return 0

    fixture.SECURITY.ConvertStringSecurityDescriptorToSecurityDescriptorW.side_effect = (
        _fail
    )
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 1337, raising=False)
    monkeypatch.setattr(ctypes, "WinError", native_error, raising=False)
    with pytest.raises(OSError, match="native failure"):
        fixture._conditional_ace(9, 1, "invalid")
    assert fixture.LOCAL_FREE.call_args.args[0].value == 42


@pytest.mark.parametrize("field", ["workspace", "suffix", "paths"])
def test_journal_rejects_foreign_workspace_or_paths(fixture: Any, field: str) -> None:
    value = _journal(fixture)
    value[field] = "unrelated"
    fixture._write_journal(value)
    with pytest.raises(AssertionError):
        fixture._read_journal()


def test_restore_replays_all_descriptor_fields_and_protection(fixture: Any) -> None:
    value = _snapshot(fixture)
    value["sacl"] = fixture._encode(fixture._pack_acl([fixture._unusual_ace(7)]))
    value["control"] |= 0x3000
    fixture._object_handle = lambda *_args: nullcontext((43, 1))
    fixture.SET_SECURITY.return_value = 0
    fixture._apply_snapshot("file", "owned", value)
    arguments = fixture.SET_SECURITY.call_args.args
    assert arguments[:3] == (43, 1, 15 | 0x80000000 | 0x40000000)
    for argument, name in zip(arguments[3:], ("owner", "group", "dacl", "sacl")):
        raw = base64.b64decode(value[name])
        assert ctypes.string_at(argument, len(raw)) == raw


def test_protected_baseline_uses_explicit_rules_and_proves_native_roundtrip(
    fixture: Any,
) -> None:
    original = _snapshot(fixture)
    inherited = fixture._unusual_ace(9, inherited=True)
    original["dacl"] = fixture._encode(fixture._pack_acl([inherited]))
    native = dict(original, control=0xBC14)
    native["dacl"] = fixture._encode(fixture._pack_acl([fixture._unusual_ace(9)]))
    native["sacl"] = fixture._encode(fixture._pack_acl([], 2))
    fixture._apply_snapshot = Mock()
    fixture._snapshot = Mock(side_effect=[copy.deepcopy(native), copy.deepcopy(native)])
    result = fixture._protected_baseline("file", "owned", original)
    assert result == native
    desired = fixture._apply_snapshot.call_args_list[0].args[2]
    assert desired["control"] == original["control"] | 0x3000
    assert desired["sacl"] == native["sacl"]
    assert fixture._entries(fixture._decode(desired["dacl"])) == [
        fixture._unusual_ace(9)
    ]
    assert fixture._apply_snapshot.call_args_list[1].args == ("file", "owned", native)
    assert original["sacl"] is None
    assert fixture._entries(fixture._decode(original["dacl"])) == [inherited]


@pytest.mark.parametrize("field", ["owner", "group", "dacl", "sacl", "control"])
def test_baseline_is_not_accepted_when_native_roundtrip_changes_any_field(
    fixture: Any, field: str
) -> None:
    original = _snapshot(fixture)
    normalized = dict(original, control=0xBC14)
    actual = dict(normalized)
    actual[field] = "different"
    fixture._apply_snapshot = Mock()
    fixture._snapshot = Mock(side_effect=[normalized, actual])
    with pytest.raises(AssertionError):
        fixture._protected_baseline("file", "owned", original)


def test_native_read_error_frees_returned_descriptor(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture._object_handle = lambda *_args: nullcontext((43, 1))

    def _fail(*arguments: Any) -> int:
        arguments[-1]._obj.value = 1234
        return 5

    fixture.GET_SECURITY.side_effect = _fail
    monkeypatch.setattr(ctypes, "WinError", native_error, raising=False)
    with pytest.raises(OSError, match="native failure"):
        fixture._snapshot("file", "owned")
    assert fixture.LOCAL_FREE.call_count == 1
    assert fixture.LOCAL_FREE.call_args.args[0].value == 1234


@pytest.mark.parametrize("kind", [5, 9, 7, 13, 15])
def test_prepare_retains_original_descriptor_and_inserts_opaque_bytes(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, kind: int
) -> None:
    record = _journal(fixture)
    current = copy.deepcopy(record["baseline"]["file"])
    applied = []

    def _apply(_role: str, _path: str, value: dict[str, Any]) -> None:
        applied.append(copy.deepcopy(value))
        current.clear()
        current.update(value)

    fixture._apply_snapshot = _apply
    fixture._snapshot = lambda *_args: copy.deepcopy(current)
    specification = {"role": "file", "ace_type": kind}
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SOURCE), fixture.WORKSPACE, "prepare", json.dumps(specification)],
    )
    result = fixture._prepare()
    assert applied[0] == record["baseline"]["workspace"]
    assert applied[1] == record["baseline"]["file"]
    field = "sacl" if kind in (7, 13, 15) else "dacl"
    assert fixture._entries(fixture._decode(result["snapshot"][field])) == [
        fixture._unusual_ace(kind)
    ]
    assert fixture._read_journal() == record


def test_inherited_callback_is_supplied_by_parent_not_written_into_child(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = _journal(fixture)
    for baseline in record["baseline"].values():
        baseline["control"] |= 0x3000
    fixture._write_journal(record)
    current = copy.deepcopy(record["baseline"])
    applied = []

    def _apply(role: str, _path: str, value: dict[str, Any]) -> None:
        applied.append((role, copy.deepcopy(value)))
        current[role] = copy.deepcopy(value)
        if role == "file" and not value["control"] & 0x1000:
            entries = fixture._entries(fixture._decode(value["dacl"]))
            current[role]["dacl"] = fixture._encode(
                fixture._pack_acl(entries + [fixture._unusual_ace(9, True)])
            )

    fixture._apply_snapshot = _apply
    fixture._snapshot = lambda role, _path: copy.deepcopy(current[role])
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SOURCE),
            fixture.WORKSPACE,
            "prepare",
            json.dumps({"role": "file", "ace_type": 9, "inherited": True}),
        ],
    )
    result = fixture._prepare()
    assert [role for role, _value in applied] == [
        "workspace",
        "file",
        "workspace",
        "file",
    ]
    parent_ace = fixture._entries(fixture._decode(applied[2][1]["dacl"]))[-1]
    assert parent_ace[1] == 1
    assert parent_ace[:1] + bytes([0]) + parent_ace[2:] == fixture._unusual_ace(9)
    assert applied[3][1]["control"] & 0x1000 == 0
    assert fixture._entries(fixture._decode(applied[3][1]["dacl"])) == []
    assert fixture._decode(result["unusual"]) == fixture._unusual_ace(9, True)
    assert fixture._entries(fixture._decode(result["snapshot"]["dacl"])) == [
        fixture._unusual_ace(9, True)
    ]
    assert fixture._read_journal() == record


@pytest.mark.parametrize("field", ["owner", "group", "dacl", "sacl", "control"])
def test_cleanup_refuses_incomplete_descriptor_restoration(
    fixture: Any, field: str
) -> None:
    record = _journal(fixture)
    actual = copy.deepcopy(record["baseline"]["file"])
    actual[field] = "different"
    fixture._apply_snapshot = Mock()
    fixture._snapshot = lambda *_args: actual
    fixture.winreg.DeleteKey = Mock()
    with pytest.raises(AssertionError):
        fixture._cleanup()
    fixture.winreg.DeleteKey.assert_not_called()
    assert Path(fixture.JOURNAL).exists()


def test_restore_keeps_owned_objects_and_journal_for_independent_readback(
    fixture: Any,
) -> None:
    record = _journal(fixture)
    fixture._apply_snapshot = Mock()
    fixture._snapshot = lambda role, _path: copy.deepcopy(record["baseline"][role])
    fixture.winreg.DeleteKey = Mock()
    result = fixture._restore()
    assert result == {"restored": True, "snapshots": record["baseline"]}
    assert [call.args[0] for call in fixture._apply_snapshot.call_args_list] == [
        "workspace",
        "file",
        "registry",
    ]
    fixture.winreg.DeleteKey.assert_not_called()
    assert fixture._read_journal() == record
