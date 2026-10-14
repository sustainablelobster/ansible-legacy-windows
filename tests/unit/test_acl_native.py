"""Exercise explicit ACL semantics and native boundaries without Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Binary ACL and native-lifetime assertions intentionally inspect private helpers.
# pylint: disable=protected-access

import ctypes
import struct
import sys
from contextlib import contextmanager
from types import ModuleType, SimpleNamespace
from typing import Any, Iterator
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module, native_error


def _ace(kind: int = 0, flags: int = 0, mask: int = 1, sid: int = 18) -> bytes:
    identity = b"\x01\x01\x00\x00\x00\x00\x00\x05" + struct.pack("<I", sid)
    return struct.pack("<BBHI", kind, flags, 20, mask) + identity


def _callback(kind: int = 9, flags: int = 0, mask: int = 1, sid: int = 18) -> bytes:
    ordinary = _ace(kind, flags, mask, sid)
    condition = b"artx\x01\x02\x03\x04"
    return (
        ordinary[:2]
        + struct.pack("<H", len(ordinary) + len(condition))
        + ordinary[4:]
        + condition
    )


def _acl(*entries: bytes) -> bytes:
    body = b"".join(entries)
    revision = 4 if any(entry[0] in (5, 6, 11, 12) for entry in entries) else 2
    return struct.pack("<BBHHH", revision, 0, len(body) + 8, len(entries), 0) + body


def _unsupported_ace(kind: int, flags: int = 0) -> bytes:
    ordinary = _ace(kind=kind, flags=flags, sid=19)
    if kind in (5, 6, 11, 12):
        # Object ACEs include an object-flags field before their SID.
        body = ordinary[4:8] + struct.pack("<I", 0) + ordinary[8:]
        return struct.pack("<BBH", kind, flags, len(body) + 4) + body
    return ordinary


def _snapshot(*entries: bytes, container: bool = True) -> dict[str, Any]:
    return {
        "dacl": _acl(*entries),
        "protected": False,
        "container": container,
        "registry": False,
        "kind": "file",
    }


def _windows_error(code: int) -> OSError:
    error = native_error(code)
    setattr(error, "winerror", code)
    return error


@pytest.fixture(name="helper")
def acl_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the payload helper with adjacent dependencies and a native SID.

    :param monkeypatch: Scoped import and SID replacements.
    :returns: Independently loaded ACL helper.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    helper = load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_acl.py",
        "tested_acl_native",
    )
    monkeypatch.setattr(helper.account, "sid_bytes", Mock(return_value=_ace()[8:]))
    return helper


@pytest.mark.parametrize(
    "kind,rights,rule_type,mask",
    [
        ("file", "Read", "allow", 0x120089),
        ("file", "Read", "deny", 0x20089),
        ("file", "Write", "allow", 0x100116),
        ("file", "ReadAndExecute", "allow", 0x1200A9),
        ("file", "Modify", "allow", 0x1301BF),
        ("file", "FullControl", "deny", 0x1F01FF),
        ("file", "2032063", "deny", 0x1F01BF),
        ("file", "Read, Synchronize", "deny", 0x20089),
        ("file", " readdata, writedata ", "allow", 0x100003),
        ("file", "ListDirectory,CreateDirectories,Traverse", "deny", 0x25),
        ("file", "0", "allow", 0x100000),
        # This abbreviation is an observed accepted upstream enum prefix.
        ("file", "ReadD", "allow", 0x100001),  # codespell:ignore readd
        ("registry", "ReadKey", "allow", 0x20019),
        ("registry", "WriteKey", "deny", 0x20006),
        ("registry", "FullControl", "allow", 0xF003F),
        ("registry", "EnumerateSubKeys,Notify", "allow", 0x18),
        ("registry", "8", "allow", 8),
        ("certificate", "Read", "allow", 0x120089),
        ("certificate", "FullControl", "deny", 0x1F01FF),
        ("certificate", "Read,FullControl", "allow", 0x1F01FF),
        ("certificate", "-2146303863", "allow", 0x120089),
    ],
)
def test_rule_rights_match_native_enum_masks(
    helper: ModuleType, kind: str, rights: str | None, rule_type: str, mask: int
) -> None:
    target = {"kind": kind, "container": False}
    result = helper.make_rule(target, "S-1-5-18", rights, rule_type)
    assert result == _ace(int(rule_type == "deny"), 0, mask)
    helper.account.sid_bytes.assert_called_once_with("S-1-5-18")


def test_certificate_matching_requires_requested_rights_type_flags_and_sid(
    helper: ModuleType,
) -> None:
    snapshot = dict(_snapshot(_ace(mask=0x80000000)), kind="certificate")
    assert helper.has_rule(snapshot, _ace(mask=0x120089))
    assert not helper.has_rule(snapshot, _ace(mask=0x1F01FF))
    for rule in (_ace(kind=1), _ace(flags=1), _ace(sid=19)):
        assert not helper.has_rule(snapshot, rule)
    inherited = dict(_snapshot(_ace(flags=16)), kind="certificate")
    assert not helper.has_rule(inherited, _ace())


def test_ordinary_certificate_read_can_upgrade_to_full_and_repeat(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "legacy_windows_acl", helper)
    payload = load_module(
        ROOT / "legacy_windows/plugins/modules/win_acl.py", "tested_key_upgrade"
    )
    snapshot = dict(_snapshot(_ace(mask=0x80000000)), kind="certificate")
    writer = Mock(side_effect=snapshot.update)
    full = _ace(mask=0x1F01FF)
    assert payload._change_rule({"state": "present"}, snapshot, writer, full, True) == {
        "changed": True
    }
    writer.assert_not_called()
    assert payload._change_rule(
        {"state": "present"}, snapshot, writer, full, False
    ) == {"changed": True}
    assert payload._change_rule(
        {"state": "present"}, snapshot, writer, full, False
    ) == {"changed": False}
    assert helper.has_rule(snapshot, _ace(mask=0x120089))
    writer.assert_called_once()


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize(
    "entry",
    [
        (kind, target)
        for kind in (5, 6, 11, 12)
        for target in ("file", "registry", "certificate")
    ]
    + [(kind, "certificate") for kind in (9, 10)],
)
def test_public_insertion_rejects_bypassing_same_principal_restrictions(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    entry: tuple[int, str],
    check_mode: bool,
) -> None:
    kind, target = entry
    restricted = _callback(kind) if kind in (9, 10) else _unsupported_ace(kind)
    sid = 18 if kind in (9, 10) else 19
    snapshot = dict(_snapshot(restricted), kind=target)
    monkeypatch.setitem(sys.modules, "legacy_windows_acl", helper)
    payload = load_module(
        ROOT / "legacy_windows/plugins/modules/win_acl.py", "tested_restricted_key"
    )
    writer = Mock()
    deny = kind in (6, 10, 12)
    result = payload._change_rule(
        {"state": "present"},
        snapshot,
        writer,
        _ace(int(deny), mask=3, sid=sid),
        check_mode,
    )
    assert result["failed"] and not result["changed"]
    assert "could bypass" in result["msg"]
    assert snapshot["dacl"] == _acl(restricted)
    writer.assert_not_called()


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("kind", [0, 1, 9, 10])
def test_capi_partial_removal_fails_before_public_mutation_or_prediction(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, kind: int, check_mode: bool
) -> None:
    entry = (
        _callback(kind, mask=0x90000000) if kind >= 9 else _ace(kind, mask=0x90000000)
    )
    snapshot = dict(_snapshot(entry), kind="certificate", certificate_provider="capi")
    monkeypatch.setitem(sys.modules, "legacy_windows_acl", helper)
    payload = load_module(
        ROOT / "legacy_windows/plugins/modules/win_acl.py", "tested_capi_partial"
    )
    writer = Mock()
    result = payload._change_rule(
        {"state": "absent"}, snapshot, writer, _ace(kind % 9, mask=0x120089), check_mode
    )
    assert result["failed"] and not result["changed"]
    assert "cannot represent this partial rights removal" in result["msg"]
    assert snapshot["dacl"] == _acl(entry)
    writer.assert_not_called()


@pytest.mark.parametrize("kind", [9, 10])
def test_cng_partial_removal_retains_complete_condition_and_unrelated_entries(
    helper: ModuleType, kind: int
) -> None:
    conditional = _callback(kind, mask=0xD01F01FF)
    inherited = _callback(kind, flags=16, mask=0xD01F01FF)
    snapshot = dict(
        _snapshot(conditional, inherited),
        kind="certificate",
        certificate_provider="cng",
    )
    result = helper.remove_rule(snapshot, _ace(kind - 9, mask=0x120089))
    assert result["dacl"] == _acl(_callback(kind, mask=0xD0176), inherited)
    assert not helper.has_rule(result, _ace(kind - 9, mask=0x120089))
    assert snapshot["dacl"] == _acl(conditional, inherited)


@pytest.mark.parametrize("kind", [9, 10])
@pytest.mark.parametrize("target_kind", ["file", "registry"])
def test_callback_matching_uses_exact_ordinary_fields_and_keeps_condition(
    helper: ModuleType, kind: int, target_kind: str
) -> None:
    callback = _callback(kind, flags=3, mask=3)
    snapshot = dict(_snapshot(callback), kind=target_kind)
    requested = _ace(kind - 9, flags=3, mask=3)
    assert helper.has_rule(snapshot, requested)
    for different in (
        _ace(10 - kind, flags=3, mask=3),
        _ace(kind - 9, flags=1, mask=3),
        _ace(kind - 9, flags=7, mask=3),
        _ace(kind - 9, flags=3, mask=1),
        _ace(kind - 9, flags=3, mask=3, sid=20),
    ):
        assert not helper.has_rule(snapshot, different)
    assert snapshot["dacl"] == _acl(callback)
    assert not helper.has_rule(
        dict(_snapshot(_callback(kind, flags=19, mask=3)), kind=target_kind), requested
    )


@pytest.mark.parametrize("kind", [9, 10])
def test_certificate_callback_match_requires_rights_without_changing_conditions(
    helper: ModuleType, kind: int
) -> None:
    callback = _callback(kind, mask=0x80000000)
    snapshot = dict(_snapshot(callback), kind="certificate")
    assert helper.has_rule(snapshot, _ace(kind - 9, mask=0x120089))
    assert not helper.has_rule(snapshot, _ace(kind - 9, mask=0x1F01FF))
    for different in (_ace(10 - kind), _ace(kind - 9, flags=1), _ace(kind - 9, sid=19)):
        assert not helper.has_rule(snapshot, different)
    assert snapshot["dacl"] == _acl(callback)


@pytest.mark.parametrize("kind", [9, 10])
def test_callback_removal_subtracts_rights_preserving_condition_scope_and_inheritance(
    helper: ModuleType, kind: int
) -> None:
    callback, inherited = _callback(kind, flags=3, mask=3), _callback(kind, flags=16)
    requested = _ace(kind - 9)
    original = _snapshot(_callback(kind), callback, inherited)
    result = helper.remove_rule(original, requested)
    assert result["dacl"] == _acl(
        _callback(kind, flags=3, mask=2), _callback(kind, flags=11), inherited
    )
    assert original["dacl"] == _acl(_callback(kind), callback, inherited)
    assert not helper.has_rule(result, requested)


@pytest.mark.parametrize(
    "entry", [(kind, target) for kind in (9, 10) for target in ("file", "certificate")]
)
@pytest.mark.parametrize("state", ["present", "absent"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_public_callback_request_repeat_and_check_mode_never_adds_unconditional_access(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    entry: tuple[int, str],
    state: str,
    check_mode: bool,
) -> None:
    kind, target_kind = entry
    monkeypatch.setitem(sys.modules, "legacy_windows_acl", helper)
    payload = load_module(
        ROOT / "legacy_windows/plugins/modules/win_acl.py", "tested_callback_acl"
    )
    snapshot = dict(_snapshot(_callback(kind)), kind=target_kind)
    writer = Mock(side_effect=snapshot.update)
    result = payload._change_rule(
        {"state": state}, snapshot, writer, _ace(kind - 9), check_mode
    )
    changed = state == "absent"
    assert result == {"changed": changed}
    assert writer.call_count == int(changed and not check_mode)
    assert snapshot["dacl"] == (
        _acl() if changed and not check_mode else _acl(_callback(kind))
    )
    repeat = payload._change_rule(
        {"state": state}, snapshot, writer, _ace(kind - 9), check_mode
    )
    assert repeat == {"changed": changed and check_mode}


@pytest.mark.parametrize("problem", ["truncated", "revision", "count"])
def test_malformed_callback_sid_fails_before_matching_or_writing(
    helper: ModuleType, problem: str
) -> None:
    callback = bytearray(_callback())
    if problem == "truncated":
        callback = bytearray(struct.pack("<BBH", 9, 0, 4))
    elif problem == "revision":
        callback[8] = 0
    else:
        callback[9] = 15
    snapshot = _snapshot(bytes(callback))
    before = dict(snapshot)
    for operation in (helper.has_rule, helper.add_rule, helper.remove_rule):
        with pytest.raises(ValueError, match="malformed ACE SID"):
            operation(snapshot, _ace(sid=20))
        assert snapshot == before


def test_unrepresentable_callback_scope_rolls_back_ordinary_and_conditional_removal(
    helper: ModuleType,
) -> None:
    snapshot = _snapshot(_ace(mask=3), _callback(flags=3, mask=3))
    assert helper.remove_rule(snapshot, _ace(flags=5)) == snapshot


def test_removing_last_callback_orders_remaining_ordinary_entries_by_sid(
    helper: ModuleType,
) -> None:
    snapshot = _snapshot(_callback(), _ace(sid=22), _ace(sid=19))
    assert helper.remove_rule(snapshot, _ace())["dacl"] == _acl(
        _ace(sid=19), _ace(sid=22)
    )
    assert snapshot["dacl"] == _acl(_callback(), _ace(sid=22), _ace(sid=19))


def test_partial_callback_removal_orders_survivors_without_changing_condition(
    helper: ModuleType,
) -> None:
    snapshot = _snapshot(_callback(mask=3, sid=20), _ace(sid=18), _ace(sid=22))
    assert helper.remove_rule(snapshot, _ace(sid=20))["dacl"] == _acl(
        _ace(sid=18), _callback(mask=2, sid=20), _ace(sid=22)
    )


@pytest.mark.parametrize(
    "stored,requested", [(0x80000000, 0x120089), (0x90000000, 0x1F01FF)]
)
@pytest.mark.parametrize("kind", [0, 9])
def test_certificate_generic_rights_remove_through_native_semantics(
    helper: ModuleType, stored: int, requested: int, kind: int
) -> None:
    entry = _callback(mask=stored) if kind == 9 else _ace(mask=stored)
    snapshot = dict(_snapshot(entry), kind="certificate")
    assert helper.remove_rule(snapshot, _ace(mask=requested))["dacl"] == _acl()
    assert snapshot["dacl"] == _acl(entry)


@pytest.mark.parametrize("mask", [0x120089, 0x1F01FF])
@pytest.mark.parametrize("kind", [0, 1, 9, 10])
def test_certificate_exact_rights_removal_accepts_negative_enum_masks(
    helper: ModuleType, mask: int, kind: int
) -> None:
    entry = _callback(kind, mask=mask) if kind >= 9 else _ace(kind, mask=mask)
    snapshot = dict(_snapshot(entry), kind="certificate")
    assert helper.remove_rule(snapshot, _ace(kind % 9, mask=mask))["dacl"] == _acl()


@pytest.mark.parametrize(
    "inherit,propagation,flags",
    [
        (None, "None", 3),
        ("ContainerInherit", "None", 2),
        ("ObjectInherit", "NoPropagateInherit", 5),
        ("ContainerInherit,ObjectInherit", "InheritOnly", 11),
        ("None", "InheritOnly", 0),
        ("3", "3", 15),
        ("1", "2", 10),
    ],
)
def test_inheritance_enum_values_translate_to_native_ace_flags(
    helper: ModuleType, inherit: str | None, propagation: str, flags: int
) -> None:
    rule = helper.make_rule(
        {"kind": "file", "container": True},
        "S-1-5-18",
        "Read",
        "allow",
        inherit,
        propagation,
    )
    assert rule == _ace(flags=flags, mask=0x120089)


def test_file_leaf_discards_inherit_even_when_invalid(helper: ModuleType) -> None:
    rule = helper.make_rule(
        {"kind": "file", "container": False},
        "S-1-5-18",
        "Read",
        "allow",
        "not a valid inheritance flag",
        "InheritOnly",
    )
    assert rule[1] == 0


@pytest.mark.parametrize("rights", [None, "", "invalid", "Re", "512", "2147483648"])
def test_enum_errors_preserve_measured_upstream_messages(
    helper: ModuleType, rights: str | None
) -> None:
    names = (
        "ListDirectory,ReadData,WriteData,CreateFiles,CreateDirectories,AppendData,"
        "ReadExtendedAttributes,WriteExtendedAttributes,Traverse,ExecuteFile,"
        "DeleteSubdirectoriesAndFiles,ReadAttributes,WriteAttributes,Write,Delete,"
        "ReadPermissions,Read,ReadAndExecute,Modify,ChangePermissions,TakeOwnership,"
        "Synchronize,FullControl"
    )
    type_name = "System.Security.AccessControl.FileSystemRights"
    prefix = f'Cannot convert value "{rights}" to type "{type_name}"'
    if rights is None or rights == "512":
        if rights is None:
            prefix = f'Cannot convert null to type "{type_name}"'
        expected = prefix + (
            " due to enumeration values that are not valid. Specify one of the "
            "following enumeration values and try again. The possible enumeration "
            f'values are "{names}".'
        )
    elif rights == "invalid":
        expected = prefix + (
            '. Error: "Unable to match the identifier name invalid to a valid '
            "enumerator name. Specify one of the following enumerator names and "
            f'try again:\r\n{names.replace(",", ", ")}"'
        )
    elif rights == "2147483648":
        expected = (
            prefix + '. Error: "Value was either too large or too small for an Int32."'
        )
    else:
        matches = (
            names.replace(",", ", ")
            if not rights
            else (
                "ReadData, ReadExtendedAttributes, ReadAttributes, ReadPermissions, "
                "Read, ReadAndExecute"
            )
        )
        expected = prefix + (
            f'. Error: "The identifier name {rights} cannot be processed because it is '
            "either too similar or identical to the following enumerator names: "
            f'{matches}. Use a more specific identifier name."'
        )
    with pytest.raises(ValueError) as raised:
        helper.make_rule(
            {"kind": "file", "container": True}, "S-1-5-18", rights, "allow"
        )
    assert str(raised.value) == expected


def test_registry_zero_matches_upstream_constructor_error(helper: ModuleType) -> None:
    with pytest.raises(ValueError) as raised:
        helper.make_rule(
            {"kind": "registry", "container": True}, "S-1-5-18", "0", "allow"
        )
    assert str(raised.value) == (
        'Exception calling ".ctor" with "5" argument(s): "Argument cannot be zero.\r\n'
        'Parameter name: accessMask"'
    )


@pytest.mark.parametrize(
    "arguments",
    [
        ("file", "FullControll", "allow", None, "None"),
        ("file", "Read,", "allow", None, "None"),
        ("file", "-1", "allow", None, "None"),
        ("file", "2032128", "allow", None, "None"),
        ("file", "2147483648", "allow", None, "None"),
        ("file", "0", "deny", None, "None"),
        ("file", "Synchronize", "deny", None, "None"),
        ("file", "Read", "invalid", None, "None"),
        ("file", "Read", "allow", "4", "None"),
        ("file", "Read", "allow", None, "4"),
        ("registry", "Read", "allow", None, "None"),
        ("registry", "0", "allow", None, "None"),
        ("certificate", "Write", "allow", None, "None"),
        ("certificate", "0", "allow", None, "None"),
    ],
)
def test_invalid_rule_rejected_before_native_sid_conversion(
    helper: ModuleType,
    arguments: tuple[str, str, str, str | None, str],
) -> None:
    kind, rights, rule_type, inherit, propagation = arguments
    with pytest.raises(ValueError):
        helper.make_rule(
            {"kind": kind, "container": True},
            "S-1-5-18",
            rights,
            rule_type,
            inherit,
            propagation,
        )
    helper.account.sid_bytes.assert_not_called()


@pytest.mark.parametrize(
    "other",
    [
        _ace(mask=3),
        _ace(kind=1),
        _ace(flags=16),
        _ace(flags=3),
        _ace(flags=11),
        _ace(sid=19),
    ],
)
def test_presence_requires_exact_explicit_rule(
    helper: ModuleType, other: bytes
) -> None:
    assert not helper.has_rule(_snapshot(other), _ace())
    assert helper.has_rule(_snapshot(other, _ace()), _ace())


def test_add_merges_first_compatible_rule_without_changing_input(
    helper: ModuleType,
) -> None:
    initial = _snapshot(_ace(mask=1), _ace(flags=3, mask=4), _ace(flags=16, mask=2))
    result = helper.add_rule(initial, _ace(mask=2))
    assert result["dacl"] == _acl(
        _ace(mask=3), _ace(flags=3, mask=4), _ace(flags=16, mask=2)
    )
    assert initial["dacl"] == _acl(
        _ace(mask=1), _ace(flags=3, mask=4), _ace(flags=16, mask=2)
    )
    assert not helper.has_rule(result, _ace(mask=2))


def test_add_coalesces_compatible_inheritance_scopes(helper: ModuleType) -> None:
    result = helper.add_rule(_snapshot(_ace(flags=2)), _ace(flags=1))
    assert result["dacl"] == _acl(_ace(flags=3))


def test_add_orders_deny_before_allow_and_preserves_inherited_order(
    helper: ModuleType,
) -> None:
    original = _snapshot(_ace(sid=20), _ace(flags=16, sid=20), _ace(flags=16, sid=18))
    result = helper.add_rule(original, _ace(kind=1))
    assert result["dacl"] == _acl(
        _ace(kind=1), _ace(sid=20), _ace(flags=16, sid=20), _ace(flags=16, sid=18)
    )
    result = helper.add_rule(result, _ace(sid=18))
    assert result["dacl"] == _acl(
        _ace(kind=1),
        _ace(sid=18),
        _ace(sid=20),
        _ace(flags=16, sid=20),
        _ace(flags=16, sid=18),
    )


@pytest.mark.parametrize(
    "kind,new_kind,order",
    [
        (5, 0, [0, 2, 1]),
        (5, 1, [2, 0, 1]),
        (6, 0, [1, 0, 2]),
        (6, 1, [2, 1, 0]),
        (9, 0, [0, 1, 2]),
        (9, 1, [2, 0, 1]),
        (10, 0, [1, 0, 2]),
        (10, 1, [1, 2, 0]),
        (11, 0, [0, 2, 1]),
        (11, 1, [2, 0, 1]),
        (12, 0, [1, 0, 2]),
        (12, 1, [2, 1, 0]),
    ],
)
def test_insertion_preserves_mixed_explicit_entries_in_canonical_order(
    helper: ModuleType, kind: int, new_kind: int, order: list[int]
) -> None:
    unusual, current, requested = (
        _unsupported_ace(kind),
        _ace(),
        _ace(kind=new_kind, sid=20),
    )
    original = _snapshot(unusual, current)
    before = dict(original)
    assert helper.inheritance._canonical(helper.inheritance._aces(original["dacl"]))
    result = helper.add_rule(original, requested)
    choices = [current, unusual, requested]
    assert result["dacl"] == _acl(*(choices[index] for index in order))
    assert original == before


@pytest.mark.parametrize("object_flags", [0, 1, 2, 3])
@pytest.mark.parametrize("kind", [5, 6, 11, 12])
def test_object_guid_and_callback_data_remain_byte_exact_when_inserting(
    helper: ModuleType, object_flags: int, kind: int
) -> None:
    body = struct.pack("<II", 1, object_flags)
    if object_flags & 1:
        body += bytes(range(16))
    if object_flags & 2:
        body += bytes(range(16, 32))
    body += _ace(sid=19)[8:]
    if kind in (11, 12):
        body += b"\xde\xad\xbe\xef"
    unusual = struct.pack("<BBH", kind, 0, len(body) + 4) + body
    original = _snapshot(unusual, _ace())
    result = helper.add_rule(original, _ace(sid=20))
    assert unusual in helper.inheritance._aces(result["dacl"])
    assert helper.inheritance._ace_sid(unusual) == _ace(sid=19)[8:]
    assert original["dacl"] == _acl(unusual, _ace())


@pytest.mark.parametrize(
    "problem", ["object_flags", "missing_guid", "sid_revision", "sid_count"]
)
def test_malformed_mixed_entry_refuses_insertion_without_changing_input(
    helper: ModuleType, problem: str
) -> None:
    unusual = bytearray(_unsupported_ace(5))
    if problem == "object_flags":
        struct.pack_into("<I", unusual, 8, 4)
    elif problem == "missing_guid":
        struct.pack_into("<I", unusual, 8, 1)
    elif problem == "sid_revision":
        unusual[12] = 0
    else:
        unusual[13] = 15
    original = _snapshot(bytes(unusual), _ace())
    before = dict(original)
    with pytest.raises(ValueError):
        helper.add_rule(original, _ace(sid=20))
    assert original == before


@pytest.mark.parametrize("kind", [5, 6, 9, 10, 11, 12])
def test_compatible_merge_preserves_unsupported_explicit_entries(
    helper: ModuleType, kind: int
) -> None:
    existing = _unsupported_ace(kind)
    original = _snapshot(existing, _ace())
    result = helper.add_rule(original, _ace(mask=2))
    assert result["dacl"] == _acl(existing, _ace(mask=3))
    assert original["dacl"] == _acl(existing, _ace())


@pytest.mark.parametrize("kind", [5, 6, 9, 10, 11, 12])
def test_insertion_preserves_unsupported_inherited_entries(
    helper: ModuleType, kind: int
) -> None:
    inherited = _unsupported_ace(kind, flags=16)
    result = helper.add_rule(_snapshot(_ace(), inherited), _ace(kind=1, sid=20))
    assert result["dacl"] == _acl(_ace(kind=1, sid=20), _ace(), inherited)


@pytest.mark.parametrize("operation", ["add_rule", "remove_rule"])
def test_modification_rejects_noncanonical_acl(
    helper: ModuleType, operation: str
) -> None:
    snapshot = _snapshot(_ace(), _ace(kind=1))
    assert helper.has_rule(snapshot, _ace())
    with pytest.raises(ValueError, match="noncanonical"):
        getattr(helper, operation)(snapshot, _ace())


def test_remove_subtracts_from_all_matching_scopes_and_keeps_inherited(
    helper: ModuleType,
) -> None:
    snapshot = _snapshot(_ace(), _ace(flags=3, mask=3), _ace(flags=16))
    result = helper.remove_rule(snapshot, _ace())
    assert result["dacl"] == _acl(_ace(flags=3, mask=2), _ace(flags=11), _ace(flags=16))


def test_unrepresentable_scope_subtraction_rolls_back_all_removals(
    helper: ModuleType,
) -> None:
    snapshot = _snapshot(_ace(flags=7), _ace(flags=3, mask=3))
    result = helper.remove_rule(snapshot, _ace(flags=7))
    assert result == snapshot


def test_empty_dacl_and_null_dacl_remain_distinct(helper: ModuleType) -> None:
    empty = _snapshot()
    null = dict(empty, dacl=None)
    added_empty = helper.add_rule(empty, _ace())
    added_null = helper.add_rule(null, _ace())
    assert added_empty["dacl"] == _acl(_ace())
    null_entries = helper.inheritance._aces(added_null["dacl"])
    assert len(null_entries) == 2
    assert struct.unpack_from("<I", null_entries[0], 4)[0] == 0xFFFFFFFF
    assert null_entries[0][8:] == b"\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00"
    assert null_entries[1] == _ace()
    assert helper.remove_rule(added_empty, _ace())["dacl"] == _acl()


@pytest.fixture(name="native")
def acl_native(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Provide API calls with real ctypes buffers and observable ownership.

    :param helper: Loaded ACL helper.
    :param monkeypatch: Scoped library and Windows-error replacements.
    :returns: Configurable native stand-in.
    """
    state = SimpleNamespace(
        security=Mock(),
        kernel=Mock(),
        error=0,
        member=False,
        descriptor=ctypes.create_string_buffer(b"descriptor"),
        dacl=ctypes.create_string_buffer(_acl(_ace())),
    )
    state.kernel.GetFileAttributesW.return_value = 0x410
    state.kernel.CreateFileW.return_value = 0x1234567887654321
    state.security.SetSecurityInfo.return_value = 0

    def _get_security(*args: Any) -> int:
        args[5]._obj.value = ctypes.addressof(state.dacl)
        args[7]._obj.value = ctypes.addressof(state.descriptor)
        return 0

    def _control(_descriptor: Any, control: Any, revision: Any) -> int:
        control._obj.value = 0x1004
        revision._obj.value = 1
        return 1

    def _registry(*args: Any) -> int:
        if args[3] == 0:
            return 5
        args[4]._obj.value = 0x1234567887654322
        return 0

    def _member(_token: Any, _sid: Any, member: Any) -> int:
        member._obj.value = state.member
        return 1

    state.security.GetSecurityInfo.side_effect = _get_security
    state.security.GetSecurityDescriptorControl.side_effect = _control
    state.security.RegOpenKeyExW.side_effect = _registry
    state.security.CheckTokenMembership.side_effect = _member
    monkeypatch.setattr(
        helper.inheritance, "_libraries", lambda: (state.security, state.kernel)
    )
    monkeypatch.setattr(ctypes, "WinError", _windows_error, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: state.error, raising=False)
    return state


def test_literal_path_keeps_percent_variables_and_does_not_follow_by_default(
    helper: ModuleType, native: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    inspect = Mock()
    monkeypatch.setattr(helper.links, "get_link_info", inspect)
    target = helper.resolve_target(r"C:\%TEMP%\literal[1]")
    assert target == {
        "path": r"C:\%TEMP%\literal[1]",
        "kind": "file",
        "container": True,
    }
    native.kernel.GetFileAttributesW.assert_called_once_with(target["path"])
    inspect.assert_not_called()
    native.kernel.ExpandEnvironmentStringsW.assert_not_called()


def test_follow_resolves_nested_relative_link_and_absolute_junction(
    helper: ModuleType, native: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    inspect = Mock(
        side_effect=[
            {"type": "symbolic", "target": "..\\junction", "relative": True},
            {"type": "junction", "target": "C:\\target", "relative": False},
            None,
        ]
    )
    monkeypatch.setattr(helper.links, "get_link_info", inspect)
    target = helper.resolve_target(r"C:\base\link", True)
    assert target["path"] == r"\\?\C:\target"
    assert [call.args[0] for call in inspect.call_args_list] == [
        r"C:\base\link",
        r"C:\junction",
        r"\\?\C:\target",
    ]
    native.kernel.GetFileAttributesW.assert_called_once_with(target["path"])


def test_follow_cycle_fails_without_hanging(
    helper: ModuleType, native: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        helper.links,
        "get_link_info",
        Mock(
            return_value={
                "type": "symbolic",
                "target": "link",
                "relative": True,
            }
        ),
    )
    with pytest.raises(ValueError, match="cycle"):
        helper.resolve_target(r"C:\link", True)
    native.kernel.GetFileAttributesW.assert_not_called()


@pytest.mark.parametrize("error", [2, 3, 123, 5])
@pytest.mark.parametrize("registry", [False, True])
def test_target_absence_is_distinct_from_access_failure(
    helper: ModuleType, native: Any, error: int, registry: bool
) -> None:
    path = "HKCU:\\missing" if registry else "C:\\missing"
    native.error = error
    if registry:
        native.security.RegOpenKeyExW.side_effect = None
        native.security.RegOpenKeyExW.return_value = error
    else:
        native.kernel.GetFileAttributesW.return_value = 0xFFFFFFFF
    if error == 5:
        with pytest.raises(OSError) as raised:
            helper.resolve_target(path)
        assert getattr(raised.value, "winerror") == 5
    else:
        assert helper.resolve_target(path) is None
    native.kernel.CloseHandle.assert_not_called()
    native.security.RegCloseKey.assert_not_called()


def test_registry_existence_requests_provider_read_access_and_closes_handle(
    helper: ModuleType, native: Any
) -> None:
    target = helper.resolve_target(r"HKCU:\Software\literal[1]")
    assert target == {
        "path": r"HKCU:\Software\literal[1]",
        "kind": "registry",
        "container": True,
    }
    args = native.security.RegOpenKeyExW.call_args.args
    assert args[1:4] == (r"Software\literal[1]", 0, 0x20019)
    native.security.RegCloseKey.assert_called_once()
    assert native.security.RegCloseKey.call_args.args[0].value == 0x1234567887654322
    native.security.GetSecurityInfo.assert_not_called()
    native.security.SetSecurityInfo.assert_not_called()


@pytest.mark.parametrize("write", [False, True])
@pytest.mark.parametrize("registry", [False, True])
def test_acl_handles_request_write_only_on_change_and_always_close(
    helper: ModuleType, native: Any, write: bool, registry: bool
) -> None:
    path = "HKCU:\\key" if registry else "C:\\link"
    target = helper.resolve_target(path)
    native.security.RegOpenKeyExW.reset_mock()
    native.security.RegCloseKey.reset_mock()
    with helper.open_acl(target) as (snapshot, writer):
        assert snapshot["dacl"] == _acl(_ace())
        assert snapshot["protected"] is True
        if write:
            writer(helper.add_rule(snapshot, _ace(kind=1, mask=2)))
    if registry:
        accesses = [
            call.args[3] for call in native.security.RegOpenKeyExW.call_args_list
        ]
        assert native.security.RegCloseKey.call_count == 1 + write
        native.kernel.CreateFileW.assert_not_called()
    else:
        calls = native.kernel.CreateFileW.call_args_list
        accesses = [call.args[1] for call in calls]
        assert all(call.args[5] == 0x02200000 for call in calls)
        assert native.kernel.CloseHandle.call_count == 1 + write
    assert accesses == ([0x20000, 0x60000] if write else [0x20000])
    native.kernel.LocalFree.assert_called_once()
    if write:
        args = native.security.SetSecurityInfo.call_args.args
        assert args[1:5] == (4 if registry else 1, 0x80000004, None, None)
        assert args[6] is None
    else:
        native.security.SetSecurityInfo.assert_not_called()


def test_failed_write_closes_handle_and_does_not_prevent_recovery(
    helper: ModuleType, native: Any
) -> None:
    target = helper.resolve_target("C:\\file")
    native.security.SetSecurityInfo.return_value = 5
    with pytest.raises(OSError):
        with helper.open_acl(target) as (snapshot, writer):
            writer(snapshot)
    assert native.kernel.CloseHandle.call_count == 2
    native.security.SetSecurityInfo.return_value = 0
    with helper.open_acl(target) as (snapshot, writer):
        writer(snapshot)
    assert native.kernel.CloseHandle.call_count == 4
    assert native.kernel.LocalFree.call_count == 2


@pytest.mark.parametrize("administrator", [False, True])
@pytest.mark.parametrize("body_failure", [False, True])
def test_privileges_enable_exact_three_only_for_administrator_and_restore(
    helper: ModuleType,
    native: Any,
    monkeypatch: pytest.MonkeyPatch,
    administrator: bool,
    body_failure: bool,
) -> None:
    native.member = administrator
    events: list[Any] = []

    @contextmanager
    def _privileges(names: tuple[str, ...]) -> Iterator[None]:
        events.append(names)
        try:
            yield
        finally:
            events.append("restored")

    monkeypatch.setattr(helper.owner, "ownership_privileges", _privileges)
    try:
        with helper.acl_privileges():
            events.append("operation")
            if body_failure:
                raise RuntimeError("operation failed")
    except RuntimeError:
        assert body_failure
    assert events == (
        [
            ("SeRestorePrivilege", "SeBackupPrivilege", "SeTakeOwnershipPrivilege"),
            "operation",
            "restored",
        ]
        if administrator
        else ["operation"]
    )
    assert native.security.CheckTokenMembership.call_args.args[0] is None
    helper.account.sid_bytes.assert_called_once_with("S-1-5-32-544")
