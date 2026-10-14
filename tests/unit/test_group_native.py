"""Exercise local-group NetAPI boundaries without contacting Windows hosts."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes expose structures, borrowed pointers, and buffer ownership.
# pylint: disable=protected-access

import ctypes
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module, native_error


@pytest.fixture(name="helper")
def group_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Import the native helper without loading Windows libraries.

    :param monkeypatch: Scoped source-import path.
    :returns: Imported target helper.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    return load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_group.py",
        "tested_group_native",
    )


@pytest.fixture(name="native")
def native_boundary(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Mock:
    """Replace Windows libraries and SID conversions with observable calls.

    :param helper: Imported group helper.
    :param monkeypatch: Scoped Windows substitutions.
    :returns: Parent mock with the NetAPI library and SID conversions.
    """
    native = Mock()
    for operation in (
        "NetLocalGroupEnum",
        "NetLocalGroupGetMembers",
        "NetApiBufferFree",
        "NetLocalGroupAdd",
        "NetLocalGroupSetInfo",
        "NetLocalGroupDel",
        "NetLocalGroupAddMembers",
        "NetLocalGroupDelMembers",
    ):
        getattr(native.library, operation).return_value = 0
    native.load.return_value = native.library
    native.sid_bytes.return_value = bytes.fromhex("01020000000000052000000021020000")
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(ctypes, "WinDLL", native.load, raising=False)
    monkeypatch.setattr(ctypes, "WinError", native_error, raising=False)
    monkeypatch.setattr(helper, "sid_bytes", native.sid_bytes)
    monkeypatch.setattr(helper, "sid_to_string", native.sid_to_string)
    return native


def _set_page(arguments: tuple[Any, ...], entries: Any, resume: int) -> None:
    buffer, _preferred, count, total, context = arguments[-5:]
    ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(entries)
    ctypes.cast(count, ctypes.POINTER(ctypes.c_uint32))[0] = len(entries)
    # An approximate total must not stop pagination or determine array length.
    ctypes.cast(total, ctypes.POINTER(ctypes.c_uint32))[0] = 1
    ctypes.cast(context, ctypes.POINTER(ctypes.c_size_t))[0] = resume


def test_native_structures_preserve_pointer_width(helper: ModuleType) -> None:
    pointer_size = ctypes.sizeof(ctypes.c_void_p)
    assert ctypes.sizeof(helper._LocalGroupInfo1) == 2 * pointer_size
    assert helper._LocalGroupInfo1.comment.offset == pointer_size
    assert ctypes.sizeof(helper._LocalGroupInfo1002) == pointer_size
    assert ctypes.sizeof(helper._LocalGroupMemberInfo0) == pointer_size


def test_native_signatures_use_dword_counts_and_pointer_sized_resume(
    helper: ModuleType, native: Mock
) -> None:
    library = helper._netapi()
    native.load.assert_called_once_with("netapi32")
    wide = ctypes.c_wchar_p
    dword = ctypes.c_uint32
    pointer = ctypes.c_void_p
    enumeration = [
        wide,
        dword,
        ctypes.POINTER(pointer),
        dword,
        ctypes.POINTER(dword),
        ctypes.POINTER(dword),
        ctypes.POINTER(ctypes.c_size_t),
    ]
    assert library.NetLocalGroupEnum.argtypes == enumeration
    assert library.NetLocalGroupGetMembers.argtypes == [wide] + enumeration
    assert library.NetLocalGroupAdd.argtypes == [
        wide,
        dword,
        pointer,
        ctypes.POINTER(dword),
    ]
    assert library.NetLocalGroupSetInfo.argtypes == [
        wide,
        wide,
        dword,
        pointer,
        ctypes.POINTER(dword),
    ]
    assert library.NetLocalGroupDel.argtypes == [wide, wide]
    assert library.NetLocalGroupAddMembers.argtypes == [
        wide,
        wide,
        dword,
        pointer,
        dword,
    ]
    assert library.NetLocalGroupDelMembers.argtypes == [
        wide,
        wide,
        dword,
        pointer,
        dword,
    ]
    assert library.NetApiBufferFree.argtypes == [pointer]
    assert all(
        operation.restype is dword for operation in library._mock_children.values()
    )


def test_groups_drain_pages_and_copy_unicode_before_free(
    helper: ModuleType, native: Mock
) -> None:
    name = ctypes.create_unicode_buffer("Owned_雪")
    description = ctypes.create_unicode_buffer("description 雪")
    pages = [
        (helper._LocalGroupInfo1 * 2)(
            (
                ctypes.cast(name, ctypes.c_wchar_p),
                ctypes.cast(description, ctypes.c_wchar_p),
            ),
            ("Empty", None),
        ),
        (helper._LocalGroupInfo1 * 1)(("Last", "last description")),
    ]
    observed = []
    resume = (1 << (ctypes.sizeof(ctypes.c_size_t) * 8 - 1)) + 7

    def _enumerate(*arguments: Any) -> int:
        assert arguments[:2] == (None, 1)
        assert arguments[3] == 0xFFFFFFFF
        observed.append(ctypes.cast(arguments[-1], ctypes.POINTER(ctypes.c_size_t))[0])
        index = len(observed) - 1
        _set_page(arguments, pages[index], resume)
        return 234 if index == 0 else 0

    def _free(buffer: Any) -> int:
        if buffer.value == ctypes.addressof(pages[0]):
            name.value = "freed"
            description.value = "freed"
        return 0

    native.library.NetLocalGroupEnum.side_effect = _enumerate
    native.library.NetApiBufferFree.side_effect = _free
    assert helper.list_groups() == [
        {"name": "Owned_雪", "description": "description 雪"},
        {"name": "Empty", "description": ""},
        {"name": "Last", "description": "last description"},
    ]
    assert observed == [0, resume]
    assert [
        entry.args[0].value for entry in native.library.NetApiBufferFree.call_args_list
    ] == [ctypes.addressof(page) for page in pages]


def test_members_drain_pages_and_convert_borrowed_sids_before_free(
    helper: ModuleType, native: Mock
) -> None:
    pages = [
        (helper._LocalGroupMemberInfo0 * 2)((101,), (102,)),
        (helper._LocalGroupMemberInfo0 * 1)((103,)),
    ]
    observed = []
    converted = []
    resume = (1 << (ctypes.sizeof(ctypes.c_size_t) * 8 - 1)) + 3

    def _members(*arguments: Any) -> int:
        assert arguments[:3] == (None, "Owned_雪", 0)
        assert arguments[4] == 0xFFFFFFFF
        observed.append(ctypes.cast(arguments[-1], ctypes.POINTER(ctypes.c_size_t))[0])
        index = len(observed) - 1
        _set_page(arguments, pages[index], resume)
        return 234 if index == 0 else 0

    def _convert(pointer: int) -> str:
        assert native.library.NetApiBufferFree.call_count == (
            1 if pointer == 103 else 0
        )
        converted.append(pointer)
        return "S-1-5-" + str(pointer)

    native.library.NetLocalGroupGetMembers.side_effect = _members
    native.sid_to_string.side_effect = _convert
    assert helper.member_sids("Owned_雪") == ["S-1-5-101", "S-1-5-102", "S-1-5-103"]
    assert observed == [0, resume]
    assert converted == [101, 102, 103]
    assert native.library.NetApiBufferFree.call_count == 2


@pytest.mark.parametrize("members", [False, True])
def test_empty_enumeration_uses_no_buffer(
    helper: ModuleType, native: Mock, members: bool
) -> None:
    assert (helper.member_sids("Empty") if members else helper.list_groups()) == []
    native.library.NetApiBufferFree.assert_not_called()


@pytest.mark.parametrize("members", [False, True])
@pytest.mark.parametrize("code", [5, 1376, 2220])
@pytest.mark.parametrize("allocated", [False, True])
def test_enumeration_errors_propagate_and_free_any_returned_buffer(
    helper: ModuleType, native: Mock, members: bool, code: int, allocated: bool
) -> None:
    allocation = ctypes.create_string_buffer(b"owned allocation")

    def _fail(*arguments: Any) -> int:
        if allocated:
            ctypes.cast(arguments[-5], ctypes.POINTER(ctypes.c_void_p))[0] = (
                ctypes.addressof(allocation)
            )
        return code

    operation = (
        native.library.NetLocalGroupGetMembers
        if members
        else native.library.NetLocalGroupEnum
    )
    operation.side_effect = _fail
    with pytest.raises(OSError) as caught:
        if members:
            helper.member_sids("Missing")
        else:
            helper.list_groups()
    assert caught.value.errno == code
    assert native.library.NetApiBufferFree.call_count == int(allocated)
    native.sid_to_string.assert_not_called()


def test_member_conversion_failure_frees_and_drains_remaining_pages(
    helper: ModuleType, native: Mock
) -> None:
    pages = [
        (helper._LocalGroupMemberInfo0 * 1)(
            (index,),
        )
        for index in (101, 102, 103)
    ]
    calls = []
    failure = native_error(1337)

    def _members(*arguments: Any) -> int:
        calls.append(ctypes.cast(arguments[-1], ctypes.POINTER(ctypes.c_size_t))[0])
        index = len(calls) - 1
        _set_page(arguments, pages[index], index + 1)
        return 234 if index < 2 else 0

    native.library.NetLocalGroupGetMembers.side_effect = _members
    native.sid_to_string.side_effect = failure
    with pytest.raises(OSError) as caught:
        helper.member_sids("Owned")
    assert caught.value is failure
    assert calls == [0, 1, 2]
    native.sid_to_string.assert_called_once_with(101)
    assert native.library.NetApiBufferFree.call_count == 3


def test_creation_uses_empty_description_and_unicode_name(
    helper: ModuleType, native: Mock
) -> None:
    def _create(server: Any, level: int, buffer: Any, parameter: Any) -> int:
        assert (server, level, parameter) == (None, 1, None)
        information = ctypes.cast(
            buffer, ctypes.POINTER(helper._LocalGroupInfo1)
        ).contents
        assert information.name == "Owned_雪"
        assert information.comment == ""
        return 0

    native.library.NetLocalGroupAdd.side_effect = _create
    helper.create_group("Owned_雪")
    native.library.NetLocalGroupAdd.assert_called_once()
    native.library.NetLocalGroupSetInfo.assert_not_called()


@pytest.mark.parametrize(
    "description,expected",
    [("", ""), ("literal %VALUE% 雪", "literal %VALUE% 雪"), ("nul\0tail", "nul")],
)
def test_description_changes_only_level_1002(
    helper: ModuleType, native: Mock, description: str, expected: str
) -> None:
    def _set(*arguments: Any) -> int:
        assert arguments[:3] == (None, "Owned_雪", 1002)
        assert arguments[-1] is None
        information = ctypes.cast(
            arguments[3], ctypes.POINTER(helper._LocalGroupInfo1002)
        ).contents
        assert information.comment == expected
        return 0

    native.library.NetLocalGroupSetInfo.side_effect = _set
    helper.set_description("Owned_雪", description)
    native.library.NetLocalGroupSetInfo.assert_called_once()


def test_deletion_passes_exact_name_without_enumeration(
    helper: ModuleType, native: Mock
) -> None:
    helper.delete_group("OwNeD_雪")
    native.library.NetLocalGroupDel.assert_called_once_with(None, "OwNeD_雪")
    native.library.NetLocalGroupEnum.assert_not_called()


@pytest.mark.parametrize("remove", [False, True])
def test_membership_changes_one_binary_sid_per_call(
    helper: ModuleType, native: Mock, remove: bool
) -> None:
    captured = []

    def _change(*arguments: Any) -> int:
        assert arguments[:3] == (None, "Owned_雪", 0)
        assert arguments[-1] == 1
        information = ctypes.cast(
            arguments[3], ctypes.POINTER(helper._LocalGroupMemberInfo0)
        ).contents
        captured.append(
            ctypes.string_at(information.sid, len(native.sid_bytes.return_value))
        )
        return 0

    operation = (
        native.library.NetLocalGroupDelMembers
        if remove
        else native.library.NetLocalGroupAddMembers
    )
    operation.side_effect = _change
    change = helper.remove_member if remove else helper.add_member
    change("Owned_雪", "S-1-5-32-545")
    assert captured == [native.sid_bytes.return_value]
    operation.assert_called_once()
    native.sid_bytes.assert_called_once_with("S-1-5-32-545")
    native.library.NetApiBufferFree.assert_not_called()


@pytest.mark.parametrize(
    "mutation",
    [
        ("create_group", ("Owned",), "NetLocalGroupAdd"),
        ("set_description", ("Owned", "value"), "NetLocalGroupSetInfo"),
        ("delete_group", ("Owned",), "NetLocalGroupDel"),
        ("add_member", ("Owned", "S-1-5-32-545"), "NetLocalGroupAddMembers"),
        ("remove_member", ("Owned", "S-1-5-32-545"), "NetLocalGroupDelMembers"),
    ],
)
@pytest.mark.parametrize("code", [5, 87, 1376, 1378, 2220])
def test_mutations_propagate_native_errors_without_retry(
    helper: ModuleType,
    native: Mock,
    mutation: tuple[str, tuple[str, ...], str],
    code: int,
) -> None:
    function, arguments, operation = mutation
    boundary = getattr(native.library, operation)
    boundary.return_value = code
    with pytest.raises(OSError) as caught:
        getattr(helper, function)(*arguments)
    assert caught.value.errno == code
    boundary.assert_called_once()


def test_later_member_failure_preserves_earlier_native_change(
    helper: ModuleType, native: Mock
) -> None:
    native.library.NetLocalGroupAddMembers.side_effect = [0, 1387]
    helper.add_member("Owned", "S-1-5-18")
    with pytest.raises(OSError) as caught:
        helper.add_member("Owned", "S-1-5-19")
    assert caught.value.errno == 1387
    assert native.sid_bytes.call_args_list == [call("S-1-5-18"), call("S-1-5-19")]
    assert native.library.NetLocalGroupAddMembers.call_count == 2
    native.library.NetLocalGroupDelMembers.assert_not_called()


@pytest.mark.parametrize("remove", [False, True])
def test_sid_conversion_failure_prevents_membership_change(
    helper: ModuleType, native: Mock, remove: bool
) -> None:
    native.sid_bytes.side_effect = native_error(1337)
    with pytest.raises(OSError) as caught:
        if remove:
            helper.remove_member("Owned", "invalid SID")
        else:
            helper.add_member("Owned", "invalid SID")
    assert caught.value.errno == 1337
    native.library.NetLocalGroupAddMembers.assert_not_called()
    native.library.NetLocalGroupDelMembers.assert_not_called()


@pytest.mark.parametrize("name", [None, 1, True, b"Owned"])
def test_group_name_requires_a_unicode_string(
    helper: ModuleType, native: Mock, name: Any
) -> None:
    with pytest.raises(ValueError, match="name must be a string"):
        helper.delete_group(name)
    native.library.NetLocalGroupDel.assert_not_called()


def test_description_requires_a_unicode_string(
    helper: ModuleType, native: Mock
) -> None:
    with pytest.raises(ValueError, match="description must be a string"):
        helper.set_description("Owned", None)
    native.library.NetLocalGroupSetInfo.assert_not_called()


def test_non_windows_target_is_rejected(helper: ModuleType) -> None:
    with pytest.raises(ValueError, match="Windows target"):
        helper.list_groups()
