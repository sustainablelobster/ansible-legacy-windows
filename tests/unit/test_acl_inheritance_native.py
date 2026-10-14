"""Exercise DACL transformations and native boundaries without a Windows host."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native boundary tests deliberately inspect pointer lifetimes and API signatures.
# pylint: disable=protected-access

import ctypes
import struct
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module, native_error


def _ace(
    kind: int = 0,
    flags: int = 0,
    mask: int = 1,
    sid: int | tuple[int, ...] = 18,
) -> bytes:
    subauthorities = (sid,) if isinstance(sid, int) else sid
    identity = bytes((1, len(subauthorities))) + b"\x00\x00\x00\x00\x00\x05"
    identity += struct.pack("<" + "I" * len(subauthorities), *subauthorities)
    return struct.pack("<BBHI", kind, flags, 8 + len(identity), mask) + identity


def _acl(*entries: bytes, revision: int = 2) -> bytes:
    body = b"".join(entries)
    return struct.pack("<BBHHH", revision, 0, len(body) + 8, len(entries), 0) + body


def _snapshot(*entries: bytes, protected: bool = False) -> dict[str, Any]:
    return {
        "protected": protected,
        "dacl": _acl(*entries),
        "registry": False,
        "container": True,
    }


@pytest.fixture(name="helper")
def inheritance_helper() -> ModuleType:
    """Load the target's dependency-free inheritance helper.

    :returns: Independently loaded target helper.
    """
    return load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_acl_inheritance.py",
        "tested_acl_inheritance_native",
    )


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.fixture(name="native")
def inheritance_native(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Provide native buffers and calls with explicit allocation ownership.

    :param helper: Loaded target helper.
    :param monkeypatch: Scoped native API replacements.
    :returns: Configurable stand-in for Windows native calls.
    """
    state = SimpleNamespace(
        security=Mock(),
        kernel=Mock(),
        control=0x8004,
        error=5,
        descriptor=ctypes.create_string_buffer(b"descriptor"),
        dacl=ctypes.create_string_buffer(_acl(_ace(flags=3), _ace(flags=19, sid=20))),
        written=[],
    )
    state.kernel.CreateFileW.return_value = 0x1234567887654321
    state.security.RegCloseKey.return_value = 0

    def _get_security(*args: Any) -> int:
        args[5]._obj.value = ctypes.addressof(state.dacl) if state.dacl else None
        args[7]._obj.value = ctypes.addressof(state.descriptor)
        return 0

    def _get_control(_descriptor: Any, control: Any, revision: Any) -> int:
        control._obj.value = state.control
        revision._obj.value = 1
        return 1

    def _open_registry(*args: Any) -> int:
        args[4]._obj.value = 0x1234567887654322
        return 0

    def _set_security(*args: Any) -> int:
        state.written.append(args[5].raw[:-1] if args[5] is not None else None)
        return 0

    state.security.GetSecurityInfo.side_effect = _get_security
    state.security.GetSecurityDescriptorControl.side_effect = _get_control
    state.security.RegOpenKeyExW.side_effect = _open_registry
    state.security.SetSecurityInfo.side_effect = _set_security
    monkeypatch.setattr(helper, "_libraries", lambda: (state.security, state.kernel))
    monkeypatch.setattr(ctypes, "WinError", native_error, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: state.error, raising=False)
    monkeypatch.setattr(helper.os.path, "isdir", lambda _path: True)
    return state


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def test_signatures_preserve_pointer_sized_handles_and_fixed_dwords(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    libraries = {"advapi32": Mock(), "kernel32": Mock()}
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    loader = Mock(side_effect=lambda name, **_kwargs: libraries[name])
    monkeypatch.setattr(ctypes, "WinDLL", loader, raising=False)
    security, kernel = helper._libraries()
    assert kernel.CreateFileW.restype is ctypes.c_void_p
    assert kernel.CloseHandle.argtypes == [ctypes.c_void_p]
    assert kernel.LocalFree.argtypes == [ctypes.c_void_p]
    assert security.RegOpenKeyExW.argtypes == [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    assert security.RegOpenKeyExW.restype is ctypes.c_int32
    assert security.RegCloseKey.argtypes == [ctypes.c_void_p]
    assert (
        security.GetSecurityInfo.argtypes[3:] == [ctypes.POINTER(ctypes.c_void_p)] * 5
    )
    assert security.GetSecurityInfo.restype is ctypes.c_uint32
    assert security.SetSecurityInfo.restype is ctypes.c_uint32
    assert security.SetSecurityInfo.argtypes[0] is ctypes.c_void_p
    assert loader.call_args_list[0].kwargs == {"use_last_error": True}


# pylint: enable=duplicate-code


def test_non_windows_fails_before_loading_libraries(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="posix"))
    with pytest.raises(ValueError, match="Windows target"):
        helper._libraries()


@pytest.mark.parametrize(
    "prefix",
    [
        "HKLM:",
        "hklm",
        "HKEY_LOCAL_MACHINE",
        "Registry::HKEY_LOCAL_MACHINE",
        "Microsoft.PowerShell.Core\\Registry::HKEY_LOCAL_MACHINE",
    ],
)
def test_registry_path_provider_forms(helper: ModuleType, prefix: str) -> None:
    root, subkey = helper._registry_path(prefix + "\\SOFTWARE\\literal[1]")
    assert root == ctypes.c_void_p(ctypes.c_int32(0x80000002).value).value
    assert subkey == "SOFTWARE\\literal[1]"


@pytest.mark.parametrize(
    "hive,number", [("HKCR", 0), ("HKCU", 1), ("HKLM", 2), ("HKU", 3), ("HKCC", 5)]
)
def test_registry_roots_keep_default_process_view(
    helper: ModuleType, native: Any, hive: str, number: int
) -> None:
    result = helper.read_acl(hive + ":\\")
    assert result["registry"] is True
    assert result["container"] is True
    args = native.security.RegOpenKeyExW.call_args.args
    assert args[0] == ctypes.c_void_p(ctypes.c_int32(0x80000000 + number).value).value
    assert args[1:4] == ("", 0, 0x20000)
    native.security.RegCloseKey.assert_called_once()
    native.kernel.CreateFileW.assert_not_called()
    native.kernel.CloseHandle.assert_not_called()
    assert native.security.GetSecurityInfo.call_args.args[1:3] == (4, 4)


@pytest.mark.parametrize(
    "path", [r"C:\literal[1]", r"\\server\share\file", r"\\?\C:\%TEMP%"]
)
def test_file_paths_are_not_registry_paths(helper: ModuleType, path: str) -> None:
    assert helper._registry_path(path) is None


def test_extended_path_bypasses_environment_expansion(
    helper: ModuleType, native: Any
) -> None:
    path = r"\\?\C:\%TEMP%\file"
    assert helper.normalize_path(path) == path
    native.kernel.ExpandEnvironmentStringsW.assert_not_called()


def test_environment_expansion_retries_and_preserves_literal_characters(
    helper: ModuleType, native: Any
) -> None:
    expanded = "C:\\" + "x" * 260 + "\\literal[1]\\%UNKNOWN%"

    def _expand(path: str, buffer: Any, capacity: int) -> int:
        assert path == r"%ROOT%\literal[1]\%UNKNOWN%"
        if capacity > len(expanded):
            buffer.value = expanded
        return len(expanded) + 1

    native.kernel.ExpandEnvironmentStringsW.side_effect = _expand
    assert helper.normalize_path(r"%ROOT%\literal[1]\%UNKNOWN%") == expanded
    assert native.kernel.ExpandEnvironmentStringsW.call_count == 2


def test_read_frees_descriptor_and_closes_handle_without_privileges(
    helper: ModuleType, native: Any
) -> None:
    result = helper.read_acl(r"C:\target")
    assert result == _snapshot(_ace(flags=3), _ace(flags=19, sid=20))
    native.kernel.CreateFileW.assert_called_once_with(
        r"C:\target", 0x20000, 7, None, 3, 0x02000000, None
    )
    native.kernel.CloseHandle.assert_called_once_with(0x1234567887654321)
    native.kernel.LocalFree.assert_called_once()
    native.security.OpenProcessToken.assert_not_called()
    args = native.security.GetSecurityInfo.call_args.args
    assert args[1:5] == (1, 4, None, None)
    assert args[6] is None


@pytest.mark.parametrize("dacl", [None, _acl()])
def test_read_preserves_null_and_empty_distinction(
    helper: ModuleType, native: Any, dacl: bytes | None
) -> None:
    native.dacl = ctypes.create_string_buffer(dacl) if dacl is not None else None
    assert helper.read_acl(r"C:\target")["dacl"] == dacl


@pytest.mark.parametrize(
    "operation", ["GetSecurityInfo", "GetSecurityDescriptorControl"]
)
def test_read_failure_cleans_descriptor_and_handle(
    helper: ModuleType, native: Any, operation: str
) -> None:
    if operation == "GetSecurityInfo":
        native.security.GetSecurityInfo.side_effect = None
        native.security.GetSecurityInfo.return_value = 5
    else:
        native.security.GetSecurityDescriptorControl.side_effect = None
        native.security.GetSecurityDescriptorControl.return_value = 0
    with pytest.raises(OSError):
        helper.read_acl(r"C:\target")
    native.kernel.CloseHandle.assert_called_once()
    assert native.kernel.LocalFree.call_count == int(operation != "GetSecurityInfo")


@pytest.mark.parametrize("registry", [False, True])
def test_missing_path_errors_do_not_close_unopened_handles(
    helper: ModuleType, native: Any, registry: bool
) -> None:
    native.error = 3
    native.kernel.CreateFileW.return_value = ctypes.c_void_p(-1).value
    native.security.RegOpenKeyExW.side_effect = None
    native.security.RegOpenKeyExW.return_value = 2
    with pytest.raises(OSError) as error:
        helper.read_acl(r"HKLM:\missing" if registry else r"C:\missing")
    assert error.value.errno == (2 if registry else 3)
    native.kernel.CloseHandle.assert_not_called()
    native.security.RegCloseKey.assert_not_called()


@pytest.mark.parametrize("registry", [False, True])
@pytest.mark.parametrize("protected", [False, True])
def test_write_changes_only_dacl_and_protection_and_does_not_reread(
    helper: ModuleType, native: Any, registry: bool, protected: bool
) -> None:
    snapshot = _snapshot(_ace(flags=19), protected=protected)
    path = r"HKLM:\Software\target" if registry else r"C:\target"
    helper.write_acl(path, snapshot)
    args = native.security.SetSecurityInfo.call_args.args
    assert args[1] == (4 if registry else 1)
    assert args[2] == 4 | (0x80000000 if protected else 0x20000000)
    assert args[3:5] == (None, None)
    assert args[6] is None
    assert native.written == [snapshot["dacl"]]
    native.security.GetSecurityInfo.assert_not_called()
    if registry:
        assert native.security.RegOpenKeyExW.call_args.args[3] == 0x60000
        native.security.RegCloseKey.assert_called_once()
    else:
        assert native.kernel.CreateFileW.call_args.args[1] == 0x60000
        native.kernel.CloseHandle.assert_called_once()


def test_failed_write_closes_handle_and_does_not_mutate_snapshot(
    helper: ModuleType, native: Any
) -> None:
    snapshot = _snapshot(_ace())
    native.security.SetSecurityInfo.side_effect = None
    native.security.SetSecurityInfo.return_value = 5
    with pytest.raises(OSError):
        helper.write_acl(r"C:\target", snapshot)
    native.kernel.CloseHandle.assert_called_once()
    assert snapshot == _snapshot(_ace())


def test_protection_removes_inherited_allow_and_deny_without_changing_explicit_rules(
    helper: ModuleType,
) -> None:
    explicit = _ace(mask=3)
    snapshot = _snapshot(explicit, _ace(1, 19), _ace(flags=19))
    result = helper.set_protection(snapshot, True)
    assert result["dacl"] == _acl(explicit)
    assert result["protected"] is True
    assert snapshot["protected"] is False


def test_preserving_inheritance_keeps_native_flags_for_windows_to_persist(
    helper: ModuleType,
) -> None:
    snapshot = _snapshot(_ace(), _ace(1, 19))
    result = helper.set_protection(snapshot, True, True)
    assert result["dacl"] == snapshot["dacl"]
    assert result["protected"] is True


def test_enabling_inheritance_changes_no_aces(helper: ModuleType) -> None:
    snapshot = _snapshot(_ace(), protected=True)
    assert helper.set_protection(snapshot, False) == _snapshot(_ace())


@pytest.mark.parametrize("preserve", [False, True])
def test_empty_dacl_remains_empty_when_protected(
    helper: ModuleType, preserve: bool
) -> None:
    assert helper.set_protection(_snapshot(), True, preserve)["dacl"] == _acl()


@pytest.mark.parametrize("container", [False, True])
def test_null_dacl_materializes_everyone_full_access_like_upstream(
    helper: ModuleType, container: bool
) -> None:
    snapshot = {
        "dacl": None,
        "protected": False,
        "registry": False,
        "container": container,
    }
    result = helper.set_protection(snapshot, True)
    ace = helper._aces(result["dacl"])[0]
    assert ace[:8] == struct.pack("<BBHI", 0, 3 if container else 0, 20, 0xFFFFFFFF)
    assert ace[8:] == b"\x01\x01\0\0\0\0\0\x01\0\0\0\0"
    assert snapshot["dacl"] is None


def test_noncanonical_removal_fails_but_flag_only_transitions_work(
    helper: ModuleType,
) -> None:
    snapshot = _snapshot(_ace(), _ace(1), _ace(flags=19))
    with pytest.raises(ValueError, match="noncanonical"):
        helper.set_protection(snapshot, True)
    assert helper.set_protection(snapshot, True, True)["protected"] is True
    assert helper.set_protection(snapshot, False)["dacl"] == snapshot["dacl"]


def test_duplicate_removal_requires_same_sid_mask_flags_and_type(
    helper: ModuleType,
) -> None:
    duplicate = _ace(flags=3, mask=3)
    different_sid = _ace(flags=3, mask=3, sid=20)
    different_mask = _ace(flags=3, mask=8)
    different_type = _ace(1, 3, 3)
    inherited = _ace(flags=19, mask=3)
    snapshot = _snapshot(
        different_type, duplicate, different_sid, different_mask, inherited
    )
    result = helper.remove_explicit_duplicates(snapshot)
    assert result["dacl"] == _acl(
        different_type, different_sid, different_mask, inherited
    )
    assert snapshot["dacl"] == _acl(
        different_type, duplicate, different_sid, different_mask, inherited
    )


def test_duplicate_removal_subtracts_permissions_from_overlapping_explicit_rules(
    helper: ModuleType,
) -> None:
    # The exact duplicate triggers RemoveAccessRule; its rights also overlap
    # the broader explicit rule, which retains rights outside the removed scope.
    snapshot = _snapshot(_ace(mask=1), _ace(flags=3, mask=3), _ace(flags=16, mask=1))
    result = helper.remove_explicit_duplicates(snapshot)
    assert result["dacl"] == _acl(
        _ace(flags=3, mask=2), _ace(flags=11, mask=1), _ace(flags=16, mask=1)
    )


def test_duplicate_removal_rolls_back_unrepresentable_propagation_subtraction(
    helper: ModuleType,
) -> None:
    snapshot = _snapshot(_ace(flags=5), _ace(flags=1), _ace(flags=21))
    assert helper.remove_explicit_duplicates(snapshot)["dacl"] == snapshot["dacl"]


def test_no_existing_inherited_duplicate_means_no_explicit_removal(
    helper: ModuleType,
) -> None:
    snapshot = _snapshot(_ace(flags=3), protected=True)
    enabled = helper.set_protection(snapshot, False)
    assert helper.remove_explicit_duplicates(enabled)["dacl"] == snapshot["dacl"]


def test_read_normalization_merges_rights_and_preserves_inherited_order(
    helper: ModuleType,
) -> None:
    dacl = _acl(
        _ace(mask=1), _ace(mask=2), _ace(flags=19, sid=25), _ace(flags=19, sid=20)
    )
    assert helper._normalize_acl(dacl, True) == _acl(
        _ace(mask=3), _ace(flags=19, sid=25), _ace(flags=19, sid=20)
    )


def test_read_compaction_advances_after_merging_an_adjacent_pair(
    helper: ModuleType,
) -> None:
    assert helper._normalize_acl(
        _acl(_ace(mask=1), _ace(mask=2), _ace(mask=4)), True
    ) == _acl(_ace(mask=3), _ace(mask=4))


@pytest.mark.parametrize("kind", [0, 1])
@pytest.mark.parametrize("reverse", [False, True])
def test_explicit_rule_order_compares_sid_subauthority_count_before_values(
    helper: ModuleType, kind: int, reverse: bool
) -> None:
    builtin = _ace(kind=kind, sid=(32, 544))
    local = _ace(kind=kind, sid=(21, 1, 2, 3, 1001))
    entries = [local, builtin] if reverse else [builtin, local]
    assert helper._normalize_acl(_acl(*entries), True) == _acl(builtin, local)


def test_leaf_normalization_removes_meaningless_rules_and_flags(
    helper: ModuleType,
) -> None:
    dacl = _acl(
        _ace(flags=11), _ace(mask=0), _ace(flags=0x43, mask=3), _ace(flags=19, sid=20)
    )
    assert helper._normalize_acl(dacl, False) == _acl(
        _ace(mask=3), _ace(flags=16, sid=20)
    )


@pytest.mark.parametrize(
    "dacl",
    [
        b"",
        b"\x02\0\x04\0\0\0\0\0",
        _acl()[:4],
        struct.pack("<BBHHH", 2, 0, 8, 1, 0),
        _acl(b"\0\0\x02\0"),
    ],
)
def test_malformed_acl_fails_before_any_write(helper: ModuleType, dacl: bytes) -> None:
    with pytest.raises(ValueError):
        helper.set_protection(
            {"protected": False, "dacl": dacl, "registry": False}, True
        )
