"""Exercise native audit-ACE bytes, merging, matching, and write boundaries."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These controller-only tests deliberately inspect binary/native boundaries.
# pylint: disable=protected-access

import ctypes
import struct
import sys
from contextlib import contextmanager
from types import ModuleType, SimpleNamespace
from typing import Any, Iterator
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


def _ace(flags: int = 64, mask: int = 131209, sid: int = 18, kind: int = 2) -> bytes:
    identity = b"\x01\x01\x00\x00\x00\x00\x00\x05" + struct.pack("<I", sid)
    return struct.pack("<BBHI", kind, flags, 20, mask) + identity


def _snapshot(*entries: bytes, container: bool = True) -> dict[str, Any]:
    body = b"".join(entries)
    return {
        "path": r"C:\owned",
        "kind": "file",
        "container": container,
        "protected": False,
        "sacl": struct.pack("<BBHHH", 2, 0, len(body) + 8, len(entries), 0) + body,
    }


def _mixed_ace(kind: int, sid: int = 20, flags: int = 64) -> bytes:
    identity = _ace(sid=sid)[8:]
    body = struct.pack("<I", 1)
    if kind in (7, 15):
        body += struct.pack("<I", 0)
    body += identity
    if kind in (13, 15):
        body += b"\xde\xad\xbe\xef"
    return struct.pack("<BBH", kind, flags, 4 + len(body)) + body


@pytest.fixture(name="helper")
def audit_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the real native helper with deterministic SID boundaries.

    :param monkeypatch: Scoped import and native identity replacements.
    :returns: Independent helper using real byte operations and enum metadata.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    helper = load_module(
        ROOT / "plugins/module_utils/legacy_windows_audit_rule.py",
        "tested_audit_rule_native",
    )
    monkeypatch.setattr(helper.filenames, "_current_lower", lambda: str.lower)
    monkeypatch.setattr(helper.account, "sid_bytes", Mock(return_value=_ace()[8:]))
    monkeypatch.setattr(helper.account, "sid_to_string", Mock(return_value="S-1-5-18"))
    monkeypatch.setattr(
        helper.account, "sid_to_name", Mock(return_value=r"NT AUTHORITY\SYSTEM")
    )
    return helper


@pytest.mark.parametrize(
    "pattern,name,matched",
    [
        ("owned_[literal]", "owned_l", True),
        ("owned_[literal]", "owned_[literal]", False),
        ("[a-c]", "B", True),
        ("[Ö-Ø]", "÷", True),
        ("[Ö-Ø]", "ö", True),
        ("[Ö-Ø]", "ø", True),
        ("[Ö-Ø]", "ù", False),
        ("[!a]", "!", True),
        ("[!a]", "a", True),
        ("[!a]", "b", False),
        ("[^a]", "^", True),
        ("[[]", "[", True),
        ("[]]", "]", True),
        ("[a`-c]", "-", True),
        ("[a`-c]", "b", False),
        ("literal`[name`]*", "literal[name]more", True),
        ("a?b", "ab", False),
        ("a?b", "acb", True),
        ("a*b", "ab", True),
        ("[\U0001f63a]", "\U0001f63a", False),
        ("??", "\U0001f63a", True),
    ],
)
def test_provider_patterns_use_positive_sets_and_windows_code_units(
    helper: ModuleType, pattern: str, name: str, matched: bool
) -> None:
    assert helper.filenames.matches(name, [pattern]) == matched


@pytest.mark.parametrize("pattern", ["owned[", "[]", "[z-a]"])
def test_invalid_pattern_reports_the_provider_leaf(
    helper: ModuleType, pattern: str
) -> None:
    with pytest.raises(ValueError) as failure:
        helper.filenames.matches("owned", [pattern])
    assert str(failure.value) == (
        "The specified wildcard character pattern is not valid: " + pattern
    )


def test_provider_range_ending_at_bracket_fails_before_acl_resolution(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolve = Mock()
    monkeypatch.setattr(helper.acl, "resolve_target", resolve)
    monkeypatch.setattr(helper.os, "listdir", lambda _path: ["owned_A", "owned_[@-[]"])
    with pytest.raises(ValueError, match="Unterminated"):
        helper.audit_targets({"path": r"C:\owned_[@-[]", "kind": "file"})
    resolve.assert_not_called()


def test_provider_range_selects_upstream_division_sign_sibling(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper.os, "listdir", lambda _path: ["owned_[Ö-Ø]", "owned_÷"])
    monkeypatch.setattr(
        helper.acl,
        "resolve_target",
        lambda path, _follow: {"path": path, "kind": "file"},
    )
    assert helper.audit_targets({"path": r"C:\owned_[Ö-Ø]", "kind": "file"}) == [
        {"path": r"C:\owned_÷", "kind": "file"}
    ]


def test_plain_audit_target_does_not_enumerate_or_request_parent_permissions(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    listing, resolve = Mock(), Mock()
    monkeypatch.setattr(helper.os, "listdir", listing)
    monkeypatch.setattr(helper.acl, "resolve_target", resolve)
    target = {"path": r"C:\plain_name", "kind": "file", "container": False}
    assert helper.audit_targets(target) == [target]
    listing.assert_not_called()
    resolve.assert_not_called()


def test_filesystem_audit_pattern_selects_sorted_siblings_without_writes(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    listing = Mock(return_value=["owned_l.txt", "owned_[literal].txt", "owned_i.txt"])
    resolve = Mock(
        side_effect=lambda path, _follow: {
            "path": path,
            "kind": "file",
            "container": False,
        }
    )
    monkeypatch.setattr(helper.os, "listdir", listing)
    monkeypatch.setattr(helper.acl, "resolve_target", resolve)
    assert [
        item["path"]
        for item in helper.audit_targets(
            {"path": r"C:\private\owned_[literal].txt", "kind": "file"}
        )
    ] == [r"C:\private\owned_i.txt", r"C:\private\owned_l.txt"]
    listing.assert_called_once_with("C:\\private")
    assert all(call.args[1] is False for call in resolve.call_args_list)


@pytest.mark.parametrize("kind", ["file", "registry"])
@pytest.mark.parametrize("escapes", [1, 2])
def test_provider_escape_conversion_and_distinct_getter_setter_selection(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    escapes: int,
) -> None:
    root = "HKCU:\\Software" if kind == "registry" else "C:\\private"
    names = ["owned_[literal]", "owned_l", "owned_`l", "owned_`[literal]"]
    listing = Mock(return_value=names)
    monkeypatch.setattr(helper.os, "listdir", listing)
    monkeypatch.setattr(helper, "_registry_children", listing)
    monkeypatch.setattr(
        helper.acl,
        "resolve_target",
        Mock(side_effect=lambda path, _follow: {"path": path, "kind": kind}),
    )
    target = {"path": root + "\\owned_" + "`" * escapes + "[literal]", "kind": kind}
    assert [item["path"] for item in helper.audit_targets(target)] == (
        [root + "\\owned_[literal]"] if escapes == 2 else []
    )
    assert [item["path"] for item in helper.audit_write_targets(target)] == (
        [root + "\\owned_l"] if escapes == 2 else []
    )


def test_escaped_getter_checks_second_resolution_before_reading_literal_acl(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper.os, "listdir", Mock(return_value=["owned_[literal]"]))
    monkeypatch.setattr(
        helper.acl,
        "resolve_target",
        Mock(side_effect=lambda path, _follow: {"path": path, "kind": "file"}),
    )
    assert helper.audit_targets({"path": r"C:\owned_``[literal]", "kind": "file"}) == []


def test_plain_backtick_before_nonwildcard_name_is_not_removed(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    listing = Mock()
    monkeypatch.setattr(helper.os, "listdir", listing)
    monkeypatch.setattr(
        helper.acl,
        "resolve_target",
        Mock(side_effect=lambda path, _follow: {"path": path, "kind": "file"}),
    )
    target = {"path": r"C:\owned_`l", "kind": "file"}
    assert helper.audit_targets(target) == [target]
    assert helper.audit_write_targets(target) == [target]
    listing.assert_not_called()


def test_registry_patterns_use_read_only_stdlib_enumeration(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry, key = Mock(), Mock()
    registry.OpenKey.return_value.__enter__ = Mock(return_value=key)
    registry.OpenKey.return_value.__exit__ = Mock(return_value=False)
    registry.QueryInfoKey.return_value = (2, 0, 0)
    registry.EnumKey.side_effect = ["owned_l", "owned_i"]
    monkeypatch.setitem(sys.modules, "winreg", registry)
    monkeypatch.setattr(
        helper.acl,
        "resolve_target",
        Mock(
            side_effect=lambda path, _follow: {
                "path": path,
                "kind": "registry",
                "container": True,
            }
        ),
    )
    assert [
        item["path"]
        for item in helper.audit_targets(
            {"path": r"HKCU:\Software\owned_[literal]", "kind": "registry"}
        )
    ] == [r"HKCU:\Software\owned_i", r"HKCU:\Software\owned_l"]
    assert registry.OpenKey.call_args.args[1:] == ("Software", 0, 0x20019)
    registry.CreateKeyEx.assert_not_called()
    registry.SetValueEx.assert_not_called()


def test_file_match_rejects_literal_directory_inheritance_before_writing(
    helper: ModuleType,
) -> None:
    with pytest.raises(ValueError) as failure:
        helper.add_rule(_snapshot(container=False), _ace(67))
    assert str(failure.value) == (
        'Exception calling "AddAuditRule" with "1" argument(s): '
        '"No flags can be set.\r\nParameter name: inheritanceFlags"'
    )


@pytest.mark.parametrize(
    "kind,rights,mask",
    [
        ("file", ["Read"], 131209),
        ("file", ["read", "WRITE"], 131487),
        ("file", ["FullControl"], 2032127),
        ("registry", ["ReadKey"], 131097),
        ("registry", ["QueryValues", "SetValue"], 3),
    ],
)
@pytest.mark.parametrize(
    "inherit,propagation,flags",
    [
        (["None"], "InheritOnly", 0),
        (["ContainerInherit", "ObjectInherit"], "None", 3),
        (["ObjectInherit"], "NoPropagateInherit", 5),
        (["ContainerInherit"], "InheritOnly", 10),
    ],
)
# Named rights and inheritance dimensions explain each expected native ACE.
def test_constructor_preserves_native_masks(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    helper: ModuleType,
    kind: str,
    rights: list[str],
    mask: int,
    inherit: list[str],
    propagation: str,
    flags: int,
) -> None:
    target = {"kind": kind, "container": True}
    assert helper.make_rule(
        target, "S-1-5-18", rights, inherit, propagation, ["success", "failure"]
    ) == _ace(flags | 192, mask)


@pytest.mark.parametrize(
    "kind,right,label",
    [
        ("file", "ReadKey", "FILE SYSTEM"),
        ("registry", "Read", "REGISTRY"),
        ("file", "ReadData"[:-1], "FILE SYSTEM"),
        ("file", "1", "FILE SYSTEM"),
    ],
)
def test_rights_accept_names_only(
    helper: ModuleType, kind: str, right: str, label: str
) -> None:
    with pytest.raises(
        ValueError, match=right + " does not seem to be a valid " + label + " right"
    ):
        helper.validate_rights({"kind": kind}, [right])


@pytest.mark.parametrize(
    "field,value,message",
    [
        (
            "rights",
            [],
            'Cannot convert value "" to type "System.Security.AccessControl.'
            'FileSystemRights". Error: "The identifier name  cannot be processed '
            "because it is either too similar or identical to the following "
            "enumerator names: ListDirectory, ReadData, WriteData, CreateFiles, "
            "CreateDirectories, AppendData, ReadExtendedAttributes, "
            "WriteExtendedAttributes, Traverse, ExecuteFile, "
            "DeleteSubdirectoriesAndFiles, ReadAttributes, WriteAttributes, "
            "Write, Delete, ReadPermissions, Read, ReadAndExecute, Modify, "
            "ChangePermissions, TakeOwnership, Synchronize, FullControl. "
            'Use a more specific identifier name."',
        ),
        (
            "audit_flags",
            [],
            'Cannot convert value "" to type "System.Security.AccessControl.'
            'AuditFlags". Error: "The identifier name  cannot be processed '
            "because it is either too similar or identical to the following "
            "enumerator names: None, Success, Failure. "
            'Use a more specific identifier name."',
        ),
        (
            "rights",
            None,
            'Cannot find an overload for "FileSystemAuditRule" '
            'and the argument count: "5".',
        ),
        (
            "propagation",
            None,
            'Cannot find an overload for "FileSystemAuditRule" '
            'and the argument count: "5".',
        ),
    ],
)
def test_measured_constructor_failures(
    helper: ModuleType, field: str, value: Any, message: str
) -> None:
    arguments = {
        "rights": ["Read"],
        "inherit": ["ContainerInherit", "ObjectInherit"],
        "propagation": "None",
        "audit_flags": ["success"],
        field: value,
    }
    with pytest.raises(ValueError) as failure:
        helper.make_rule({"kind": "file", "container": True}, "S-1-5-18", **arguments)
    assert str(failure.value) == message


@pytest.mark.parametrize(
    "left,right,expected",
    [
        (_ace(mask=1), _ace(mask=2), _ace(mask=3)),
        (_ace(flags=64), _ace(flags=128), _ace(flags=192)),
        (_ace(flags=65), _ace(flags=66), _ace(flags=67)),
        (_ace(flags=80), _ace(flags=64), None),
        (_ace(), _ace(sid=19), None),
        (_ace(flags=65, mask=1), _ace(flags=66, mask=2), None),
    ],
)
def test_merging_matches_audit_flag_and_inheritance_dimensions(
    helper: ModuleType, left: bytes, right: bytes, expected: bytes | None
) -> None:
    assert helper._merge(left, right) == expected


def test_displayed_rights_match_is_not_numeric_containment(helper: ModuleType) -> None:
    full = _snapshot(_ace(mask=2032127))
    assert not helper.has_rule(full, _ace(mask=131209))
    assert helper.has_rule(full, _ace(mask=2032127))
    combined = _snapshot(_ace(mask=131487, flags=195))
    assert helper.has_rule(combined, _ace(mask=131209, flags=67))
    assert not helper.has_rule(_snapshot(_ace(flags=80)), _ace())


def test_remove_user_purges_explicit_rules_and_preserves_other_and_inherited(
    helper: ModuleType,
) -> None:
    snapshot = _snapshot(
        _ace(mask=1), _ace(mask=2, flags=128), _ace(sid=19), _ace(flags=80)
    )
    updated = helper.remove_user(snapshot, "S-1-5-18")
    assert helper.inheritance._aces(updated["sacl"]) == [_ace(sid=19), _ace(flags=80)]
    assert len(helper.inheritance._aces(snapshot["sacl"])) == 4
    assert not helper.has_user(_snapshot(_ace(flags=80)), "S-1-5-18")


@pytest.mark.parametrize("entries", [(_ace(flags=80), _ace()), (_ace(kind=7),)])
def test_unsupported_or_noncanonical_sacl_fails_before_mutation(
    helper: ModuleType, entries: tuple[bytes, ...]
) -> None:
    snapshot = _snapshot(*entries)
    with pytest.raises(ValueError):
        helper.add_rule(snapshot, _ace(sid=19))
    with pytest.raises(ValueError):
        helper.remove_user(snapshot, "S-1-5-18")
    assert snapshot == _snapshot(*entries)


def test_return_shape_strings_and_enum_names(helper: ModuleType) -> None:
    assert helper.current_rules(_snapshot()) == {}
    single = helper.current_rules(_snapshot(_ace(flags=195)))
    assert single == {
        "user": r"NT AUTHORITY\SYSTEM",
        "rights": "Read",
        "audit_flags": "Success, Failure",
        "is_inherited": "False",
        "inheritance_flags": "ContainerInherit, ObjectInherit",
        "propagation_flags": "None",
    }
    multiple = helper.current_rules(_snapshot(_ace(), _ace(flags=80)))
    assert isinstance(multiple, list) and len(multiple) == 2
    assert multiple[1]["is_inherited"] == "True"


@pytest.mark.parametrize("kind", [7, 13, 15])
@pytest.mark.parametrize("inherited", [False, True])
def test_mixed_audit_projection_matches_common_callback_and_object_visibility(
    helper: ModuleType, kind: int, inherited: bool
) -> None:
    unusual = _mixed_ace(kind, flags=80 if inherited else 64)
    snapshot = _snapshot(unusual, container=False)
    original = dict(snapshot)
    result = helper.current_rules(snapshot)
    if kind == 13:
        assert result == {
            "user": r"NT AUTHORITY\SYSTEM",
            "rights": "ReadData",
            "audit_flags": "Success",
            "is_inherited": str(inherited),
            "inheritance_flags": "None",
            "propagation_flags": "None",
        }
    else:
        assert result == {}
    assert snapshot == original


@pytest.mark.parametrize("kind", [7, 13, 15])
def test_ordinary_audit_insertion_preserves_opaque_entries_and_inherited_order(
    helper: ModuleType, kind: int
) -> None:
    unusual = _mixed_ace(kind)
    inherited = [_mixed_ace(15, sid=19, flags=80), _mixed_ace(13, sid=18, flags=80)]
    snapshot = _snapshot(unusual, *inherited)
    snapshot["sacl"] = b"\x04" + snapshot["sacl"][1:]
    original = dict(snapshot)
    requested = _ace(mask=1)
    updated = helper.add_rule(snapshot, requested)
    assert helper.inheritance._aces(updated["sacl"]) == [requested, unusual, *inherited]
    assert snapshot == original


def test_callback_projection_matches_explicit_requests_without_merging_conditions(
    helper: ModuleType,
) -> None:
    unusual = _mixed_ace(13, sid=18)
    snapshot = _snapshot(unusual)
    assert helper.has_rule(snapshot, _ace(mask=1))
    assert helper.has_user(snapshot, "S-1-5-18")
    assert not helper.has_rule(
        _snapshot(_mixed_ace(13, sid=18, flags=80)), _ace(mask=1)
    )
    updated = helper.add_rule(snapshot, _ace(mask=2))
    assert helper.inheritance._aces(updated["sacl"]) == [unusual, _ace(mask=2)]


@pytest.mark.parametrize("kind", [7, 13, 15])
def test_audit_purge_removes_explicit_sid_without_rebuilding_opaque_aces(
    helper: ModuleType, kind: int
) -> None:
    unusual = _mixed_ace(kind, sid=18)
    other = _mixed_ace(kind, sid=19)
    inherited = _mixed_ace(kind, sid=18, flags=80)
    snapshot = _snapshot(_ace(mask=1), unusual, other, inherited)
    snapshot["sacl"] = b"\x04" + snapshot["sacl"][1:]
    original = dict(snapshot)
    updated = helper.remove_user(snapshot, "S-1-5-18")
    assert helper.inheritance._aces(updated["sacl"]) == [other, inherited]
    assert snapshot == original


@pytest.mark.parametrize("kind", [4, 17, 19])
def test_unknown_explicit_sacl_entries_fail_before_changes(
    helper: ModuleType, kind: int
) -> None:
    snapshot = _snapshot(_ace(kind=kind))
    original = dict(snapshot)
    with pytest.raises(ValueError, match="unsupported explicit"):
        helper.add_rule(snapshot, _ace())
    with pytest.raises(ValueError, match="unsupported explicit"):
        helper.remove_user(snapshot, "S-1-5-18")
    assert snapshot == original


@pytest.mark.parametrize("protected", [False, True])
@pytest.mark.parametrize("raw", [None, _snapshot(_ace())["sacl"]])
def test_writer_changes_only_sacl_and_uses_access_system_security(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    protected: bool,
    raw: bytes | None,
) -> None:
    security, kernel = Mock(), Mock()
    security.SetSecurityInfo.return_value = 0
    events: list[Any] = []

    @contextmanager
    def _handle(
        _security: Any, _kernel: Any, path: str, access: int
    ) -> Iterator[tuple[int, int]]:
        events.append((path, access))
        try:
            yield 37, 4
        finally:
            events.append("closed")

    monkeypatch.setattr(helper.inheritance, "_libraries", lambda: (security, kernel))
    monkeypatch.setattr(helper.inheritance, "_object_handle", _handle)
    snapshot = dict(_snapshot(), kind="registry", protected=protected, sacl=raw)
    helper.write_sacl(snapshot)
    args = security.SetSecurityInfo.call_args.args
    assert args[:6] == (
        37,
        4,
        8 | (0x40000000 if protected else 0x10000000),
        None,
        None,
        None,
    )
    assert ctypes.string_at(args[6], len(raw)) == raw if raw else args[6] is None
    assert events == [(snapshot["path"], 0x01020000), "closed"]


@pytest.mark.parametrize("dacl_protected", [False, True])
@pytest.mark.parametrize("raw", [None, _snapshot(_ace())["sacl"]])
def test_filesystem_setter_reapplies_exact_dacl_and_protection(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    dacl_protected: bool,
    raw: bytes | None,
) -> None:
    security, kernel = Mock(), Mock()
    security.SetNamedSecurityInfoW.return_value = 0
    monkeypatch.setattr(helper.inheritance, "_libraries", lambda: (security, kernel))
    dacl = _snapshot(_ace(kind=0))["sacl"]
    snapshot = dict(
        _snapshot(), sacl=raw, protected=True, dacl=dacl, dacl_protected=dacl_protected
    )
    helper.write_sacl(snapshot)
    args = security.SetNamedSecurityInfoW.call_args.args
    assert args[:5] == (
        snapshot["path"],
        1,
        12 | 0x40000000 | (0x80000000 if dacl_protected else 0x20000000),
        None,
        None,
    )
    assert ctypes.string_at(args[5], len(dacl)) == dacl
    assert ctypes.string_at(args[6], len(raw)) == raw if raw else args[6] is None
    security.SetSecurityInfo.assert_not_called()


@pytest.mark.parametrize("dacl_protected", [False, True])
@pytest.mark.parametrize("raw", [None, _snapshot(_ace())["sacl"]])
def test_legacy_registry_setter_reapplies_dacl_with_write_dac_access(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    dacl_protected: bool,
    raw: bytes | None,
) -> None:
    security, kernel = Mock(), Mock()
    security.SetSecurityInfo.return_value = 0
    opened: list[int] = []

    @contextmanager
    def _handle(*arguments: Any) -> Iterator[tuple[int, int]]:
        opened.append(arguments[3])
        yield 37, 4

    monkeypatch.setattr(helper.inheritance, "_libraries", lambda: (security, kernel))
    monkeypatch.setattr(helper.inheritance, "_object_handle", _handle)
    dacl = _snapshot(_ace(kind=0, flags=16))["sacl"]
    snapshot = dict(
        _snapshot(),
        kind="registry",
        protected=False,
        sacl=raw,
        dacl=dacl,
        dacl_protected=dacl_protected,
    )
    helper.write_sacl(snapshot)
    arguments = security.SetSecurityInfo.call_args.args
    assert arguments[:5] == (
        37,
        4,
        12 | 0x10000000 | (0x80000000 if dacl_protected else 0x20000000),
        None,
        None,
    )
    assert ctypes.string_at(arguments[5], len(dacl)) == dacl
    assert (
        ctypes.string_at(arguments[6], len(raw)) == raw if raw else arguments[6] is None
    )
    assert opened == [0x01060000]
    security.SetNamedSecurityInfoW.assert_not_called()


@pytest.mark.parametrize("version", [(5, 1), (5, 2), (6, 0), (10, 0)])
@pytest.mark.parametrize("failure", [False, True])
def test_registry_reader_keeps_sacl_only_protection_and_frees_every_descriptor(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    version: tuple[int, int],
    failure: bool,
) -> None:
    security, kernel = Mock(), Mock()
    buffer = ctypes.create_string_buffer(_snapshot(_ace(kind=0, flags=16))["sacl"])
    queries: list[int] = []
    events: list[str] = []
    legacy = version in ((5, 1), (5, 2))

    def _read(*arguments: Any) -> int:
        query = arguments[2]
        queries.append(query)
        arguments[7]._obj.value = query
        if query == 4:
            arguments[5]._obj.value = ctypes.addressof(buffer)
        return 5 if failure and query == 4 else 0

    def _control(descriptor: Any, control: Any, _revision: Any) -> bool:
        control._obj.value = 0xA004 if descriptor.value == 4 else 0x8000
        return True

    @contextmanager
    def _handle(*_arguments: Any) -> Iterator[tuple[int, int]]:
        try:
            yield 37, 4
        finally:
            events.append("closed")

    security.GetSecurityInfo.side_effect = _read
    security.GetSecurityDescriptorControl.side_effect = _control
    monkeypatch.setattr(helper.inheritance, "_libraries", lambda: (security, kernel))
    monkeypatch.setattr(helper.inheritance, "_object_handle", _handle)
    monkeypatch.setattr(
        helper.sys,
        "getwindowsversion",
        lambda: SimpleNamespace(major=version[0], minor=version[1]),
        raising=False,
    )
    monkeypatch.setattr(
        helper.ctypes, "WinError", lambda code: OSError(code, "native"), raising=False
    )
    target = {"path": r"HKCU:\Software\owned", "kind": "registry", "container": True}
    if legacy and failure:
        with pytest.raises(OSError, match=r"^\[Errno 5\] native$"):
            helper.read_sacl(target)
    else:
        actual = helper.read_sacl(target)
        assert actual["sacl"] is None and actual["protected"] is False
        assert ("dacl" in actual) is legacy
        if legacy:
            assert (
                actual["dacl"] == buffer.raw[:-1] and actual["dacl_protected"] is False
            )
    assert queries == ([8, 4] if legacy else [8])
    assert [call.args[0].value for call in kernel.LocalFree.call_args_list] == (
        [4, 8] if legacy else [8]
    )
    assert events == ["closed"]
