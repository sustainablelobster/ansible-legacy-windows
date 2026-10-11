# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Translate Windows accounts and sort their display names with native APIs."""

import ctypes
import functools
import os

_ERROR_INSUFFICIENT_BUFFER = 122
_ERROR_MORE_DATA = 234
_ERROR_NONE_MAPPED = 1332
_ERROR_INVALID_SID = 1337
_FILTER_NORMAL_ACCOUNT = 2
_MAX_PREFERRED_LENGTH = 0xFFFFFFFF
# Framework NTAccount translation accepts users, groups, aliases, well-known
# groups, and computers; domains and the remaining SID types stay unmapped.
_ACCOUNT_SID_TYPES = (1, 2, 4, 5, 9)
_SID_TYPE_NAMES = (
    "User",
    "Group",
    "Domain",
    "Alias",
    "WellKnownGroup",
    "DeletedAccount",
    "Invalid",
    "Unknown",
    "Computer",
    "Label",
    "Logon",
)


# USER_INFO_0 owns no Python state; its string belongs to the NetAPI page.
class _UserInfo0(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("name", ctypes.c_wchar_p)]


def _netapi():
    if os.name != "nt":
        raise ValueError("Account operations require a Windows target.")
    library = ctypes.WinDLL("netapi32")
    # This fixed NetUserEnum ABI belongs here; sharing the similar share-list
    # signature would couple unrelated account and filesystem operations.
    # pylint: disable=duplicate-code
    library.NetUserEnum.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.NetUserEnum.restype = ctypes.c_uint32
    # pylint: enable=duplicate-code
    library.NetApiBufferFree.argtypes = [ctypes.c_void_p]
    library.NetApiBufferFree.restype = ctypes.c_uint32
    return library


def local_user_names():
    """Read normal user accounts from the local computer's account database.

    :returns: Copied account names in native enumeration order, across all pages.
    :rtype: list[str]
    :raises ValueError: If called outside Windows.
    :raises OSError: If Windows cannot enumerate the accounts.
    """
    library = _netapi()
    resume = ctypes.c_uint32()
    names = []
    # Keep this paging call beside its user-record copying and buffer cleanup.
    # The group API has similar arguments but a pointer-sized resume handle.
    # pylint: disable=duplicate-code
    while True:
        buffer = ctypes.c_void_p()
        count = ctypes.c_uint32()
        total = ctypes.c_uint32()
        try:
            status = library.NetUserEnum(
                None,
                0,
                _FILTER_NORMAL_ACCOUNT,
                ctypes.byref(buffer),
                _MAX_PREFERRED_LENGTH,
                ctypes.byref(count),
                ctypes.byref(total),
                ctypes.byref(resume),
            )
            if status not in (0, _ERROR_MORE_DATA):
                raise ctypes.WinError(status)
            # pylint: enable=duplicate-code
            entries = ctypes.cast(buffer, ctypes.POINTER(_UserInfo0))
            names.extend(entries[index].name for index in range(count.value))
        finally:
            if buffer:
                library.NetApiBufferFree(buffer)
        if status != _ERROR_MORE_DATA:
            return names


def _security():
    if os.name != "nt":
        raise ValueError("Account operations require a Windows target.")
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.ConvertStringSidToSidW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi.ConvertStringSidToSidW.restype = ctypes.c_int
    advapi.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_wchar_p),
    ]
    advapi.ConvertSidToStringSidW.restype = ctypes.c_int
    advapi.LookupAccountNameW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_int),
    ]
    advapi.LookupAccountNameW.restype = ctypes.c_int
    # Keep this fixed ABI local rather than coupling account operations to the
    # separately staged filesystem metadata helper that uses the same API.
    # pylint: disable=duplicate-code
    advapi.LookupAccountSidW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_int),
    ]
    advapi.LookupAccountSidW.restype = ctypes.c_int
    # pylint: enable=duplicate-code
    advapi.GetLengthSid.argtypes = [ctypes.c_void_p]
    advapi.GetLengthSid.restype = ctypes.c_uint32
    advapi.IsValidSid.argtypes = [ctypes.c_void_p]
    advapi.IsValidSid.restype = ctypes.c_int
    return advapi


def _kernel():
    if os.name != "nt":
        raise ValueError("Account operations require a Windows target.")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    # The fixed collation signature also serves filename matching. Declaring
    # it here keeps account sorting independent of that helper's match rules.
    # pylint: disable=duplicate-code
    kernel.CompareStringW.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    kernel.CompareStringW.restype = ctypes.c_int
    # pylint: enable=duplicate-code
    return kernel


def _sid_text(advapi, kernel, sid):
    text = ctypes.c_wchar_p()
    try:
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise ctypes.WinError(ctypes.get_last_error())
        parts = ctypes.wstring_at(text).split("-")
        # Windows formats large authorities in hexadecimal; Framework SID.Value
        # uses decimal for the authority as well as the subauthorities.
        if parts[2].lower().startswith("0x"):
            parts[2] = str(int(parts[2], 16))
        return "-".join(parts)
    finally:
        if text:
            kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))


def _lookup_sid(advapi, name):
    sid_size = ctypes.c_uint32()
    domain_size = ctypes.c_uint32()
    kind = ctypes.c_int()
    sid, domain = None, None
    while True:
        if advapi.LookupAccountNameW(
            None,
            name,
            sid,
            ctypes.byref(sid_size),
            domain,
            ctypes.byref(domain_size),
            ctypes.byref(kind),
        ):
            if kind.value not in _ACCOUNT_SID_TYPES:
                raise ctypes.WinError(_ERROR_NONE_MAPPED)
            return sid
        error = ctypes.get_last_error()
        if error != _ERROR_INSUFFICIENT_BUFFER:
            raise ctypes.WinError(error)
        sid = ctypes.create_string_buffer(sid_size.value)
        domain_size.value = max(1, domain_size.value)
        domain = ctypes.create_unicode_buffer(domain_size.value)


def _utf16_length(value):
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _account_name(name):
    domain, account = "", name
    if "\\" in name:
        domain, account = name.split("\\", 1)
        if domain == ".":
            domain = os.environ.get("COMPUTERNAME", "")
    if not account:
        raise ValueError("Account name must not be empty.")
    limit = 256 if domain else 512
    if _utf16_length(account) > limit:
        raise ValueError("Account name must not exceed {0} UTF-16 units.".format(limit))
    if _utf16_length(domain) > 255:
        raise ValueError("Account domain must not exceed 255 UTF-16 units.")
    if "\0" in domain or "\0" in account:
        # LookupAccountNameW would silently translate only the prefix, unlike
        # the reference's counted account-name lookup, which rejects this input.
        raise ctypes.WinError(87)
    return domain + "\\" + account if domain else account


def account_name_to_sid(name):
    """Resolve an account name without interpreting SID text or SDDL aliases.

    A ``.`` domain means the current ``COMPUTERNAME``; an empty domain means
    an unqualified account. A name such as ``BA`` is looked up as an account.

    :param name: Account name, optionally qualified by a domain.
    :type name: str
    :returns: Canonical SID string with a decimal authority.
    :rtype: str
    :raises ValueError: If the account name is empty or too long, the domain is
        too long, or this function is called outside Windows.
    :raises OSError: If the account name contains NUL, or native account lookup
        or SID conversion fails.
    """
    advapi, kernel = _security(), _kernel()
    return _sid_text(advapi, kernel, _lookup_sid(advapi, _account_name(name)))


def local_group_sid(name):
    """Resolve the identity of a group already found in the local database.

    :param name: Canonical name returned by local group enumeration.
    :type name: str
    :returns: The local or built-in group's canonical SID string.
    :rtype: str
    :raises OSError: If lookup fails or its legacy fallback is not a built-in
        group. Unrelated domain and well-known accounts are not accepted.
    :raises ValueError: If the name is invalid or called outside Windows.
    """
    try:
        return account_name_to_sid(os.environ["COMPUTERNAME"] + "\\" + name)
    except OSError as error:
        if getattr(error, "winerror", None) != _ERROR_NONE_MAPPED:
            raise
        # XP does not resolve built-in groups under the computer's domain.
        # Only a built-in SID is a valid unqualified fallback for this lookup.
        sid = account_name_to_sid(name)
        if not sid.startswith("S-1-5-32-"):
            raise error
        return sid


def parse_sid(name):
    """Parse SID text or an SDDL alias without looking up account names.

    :param name: Numeric SID string or SDDL alias.
    :type name: str
    :returns: Canonical SID string with a decimal authority.
    :rtype: str
    :raises ValueError: If called outside Windows.
    :raises OSError: If parsing, binary SID validation, or text conversion fails.
    """
    advapi, kernel = _security(), _kernel()
    sid = ctypes.c_void_p()
    try:
        if not advapi.ConvertStringSidToSidW(name, ctypes.byref(sid)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not advapi.IsValidSid(sid):
            raise ctypes.WinError(_ERROR_INVALID_SID)
        return _sid_text(advapi, kernel, sid)
    finally:
        if sid:
            kernel.LocalFree(sid)


def name_to_sid(name):
    """Resolve an account name, SID string, or SDDL alias to canonical SID text.

    Invalid SID text is looked up as an account name. A ``.`` domain means the
    current ``COMPUTERNAME``; an empty domain means an unqualified account.

    :param name: Account name, numeric SID string, or SDDL alias.
    :type name: str
    :returns: Canonical SID string with a decimal authority.
    :rtype: str
    :raises ValueError: If the account name is empty or too long, the domain is
        too long, or this function is called outside Windows.
    :raises OSError: If the account name contains NUL, or SID conversion or
        account lookup fails.
    """
    advapi, kernel = _security(), _kernel()
    sid = ctypes.c_void_p()
    try:
        if advapi.ConvertStringSidToSidW(name, ctypes.byref(sid)):
            if advapi.IsValidSid(sid):
                return _sid_text(advapi, kernel, sid)
            error = _ERROR_INVALID_SID
        else:
            error = ctypes.get_last_error()
        if error != _ERROR_INVALID_SID:
            raise ctypes.WinError(error)
    finally:
        if sid:
            kernel.LocalFree(sid)
    return _sid_text(advapi, kernel, _lookup_sid(advapi, _account_name(name)))


def _lookup_name(advapi, sid):
    name_size = ctypes.c_uint32()
    domain_size = ctypes.c_uint32()
    kind = ctypes.c_int()
    name, domain = None, None
    while True:
        # Keep this lookup next to its SID-type filtering and buffer ownership;
        # the stat helper makes the same ABI call with different fallback rules.
        # pylint: disable=duplicate-code
        if advapi.LookupAccountSidW(
            None,
            sid,
            name,
            ctypes.byref(name_size),
            domain,
            ctypes.byref(domain_size),
            ctypes.byref(kind),
        ):
            # pylint: enable=duplicate-code
            if kind.value not in _ACCOUNT_SID_TYPES:
                return None
            return domain.value + "\\" + name.value if domain.value else name.value
        error = ctypes.get_last_error()
        if error == _ERROR_NONE_MAPPED:
            return None
        if error != _ERROR_INSUFFICIENT_BUFFER:
            raise ctypes.WinError(error)
        name = ctypes.create_unicode_buffer(name_size.value)
        domain_size.value = max(1, domain_size.value)
        domain = ctypes.create_unicode_buffer(domain_size.value)


def sid_to_name(sid):
    """Resolve SID text to an account name, retaining canonical unmapped SIDs.

    :param sid: Numeric SID string or SDDL alias.
    :type sid: str
    :returns: ``DOMAIN\\account``, an account with no domain, or canonical SID
        text when Windows reports ERROR_NONE_MAPPED or the resolved SID type
        does not represent an account (for example, a domain SID).
    :rtype: str
    :raises ValueError: If called outside Windows.
    :raises OSError: If parsing fails or lookup reports another native error.
    """
    advapi, kernel = _security(), _kernel()
    pointer = ctypes.c_void_p()
    try:
        if not advapi.ConvertStringSidToSidW(sid, ctypes.byref(pointer)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not advapi.IsValidSid(pointer):
            raise ctypes.WinError(_ERROR_INVALID_SID)
        name = _lookup_name(advapi, pointer)
        return _sid_text(advapi, kernel, pointer) if name is None else name
    finally:
        if pointer:
            kernel.LocalFree(pointer)


def sid_to_string(pointer):
    """Convert a borrowed SID pointer to canonical text without freeing the SID.

    :param pointer: Pointer to a valid native SID owned by the caller.
    :type pointer: ctypes.c_void_p or int
    :returns: Canonical SID string with a decimal authority.
    :rtype: str
    :raises ValueError: If called outside Windows.
    :raises OSError: If native SID conversion fails.
    """
    return _sid_text(_security(), _kernel(), pointer)


def describe_sid(pointer):
    """Resolve a borrowed SID to its separate identity fields for ``win_whoami``.

    All native SID types are retained, including labels and domains. Unmapped
    SIDs and failed trust lookups have null names; logon SIDs instead receive
    the pinned upstream's synthetic ``NT AUTHORITY`` logon-session name.

    :param pointer: Pointer to a valid SID whose memory remains caller-owned.
    :type pointer: ctypes.c_void_p or int
    :returns: SID text, account name, domain name, and SID type name.
    :rtype: dict
    :raises ValueError: If called outside Windows.
    :raises OSError: SID conversion or account lookup fails unexpectedly.
    """
    advapi = _security()
    sid = _sid_text(advapi, _kernel(), pointer)
    name_size, domain_size = ctypes.c_uint32(), ctypes.c_uint32()
    kind = ctypes.c_int()
    name, domain = None, None
    while True:
        if advapi.LookupAccountSidW(
            None,
            pointer,
            name,
            ctypes.byref(name_size),
            domain,
            ctypes.byref(domain_size),
            ctypes.byref(kind),
        ):
            return {
                "sid": sid,
                "account_name": name.value if name is not None else "",
                "domain_name": domain.value if domain is not None else "",
                "type": (
                    _SID_TYPE_NAMES[kind.value - 1]
                    if 1 <= kind.value <= len(_SID_TYPE_NAMES)
                    else str(kind.value)
                ),
            }
        error = ctypes.get_last_error()
        if error in (1332, 1789):
            logon = sid.startswith("S-1-5-5-")
            return {
                "sid": sid,
                "account_name": "LogonSessionId_" + sid[8:] if logon else None,
                "domain_name": "NT AUTHORITY" if logon else None,
                "type": "Logon" if logon else "Unknown",
            }
        if error != _ERROR_INSUFFICIENT_BUFFER:
            raise ctypes.WinError(error)
        name_size.value = max(1, name_size.value)
        domain_size.value = max(1, domain_size.value)
        name = ctypes.create_unicode_buffer(name_size.value)
        domain = ctypes.create_unicode_buffer(domain_size.value)


def sid_bytes(sid):
    """Copy a parsed SID into Python-owned bytes for native membership calls.

    :param sid: Numeric SID string or SDDL alias.
    :type sid: str
    :returns: Complete binary SID, independent of the temporary native buffer.
    :rtype: bytes
    :raises ValueError: If called outside Windows.
    :raises OSError: If native SID parsing fails.
    """
    advapi, kernel = _security(), _kernel()
    pointer = ctypes.c_void_p()
    try:
        if not advapi.ConvertStringSidToSidW(sid, ctypes.byref(pointer)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not advapi.IsValidSid(pointer):
            raise ctypes.WinError(_ERROR_INVALID_SID)
        return ctypes.string_at(pointer, advapi.GetLengthSid(pointer))
    finally:
        if pointer:
            kernel.LocalFree(pointer)


def sort_names(names, unique=False):
    """Sort account names with case-insensitive Windows user-culture collation.

    XP and Server 2003 reject linguistic casing flags. Those systems use their
    available case-insensitive collation; sorting tables and casing behavior
    remain dependent on the target Windows version and user locale.

    :param names: Names to sort without modifying the caller's sequence.
    :type names: list[str]
    :param unique: Keep only the first spelling of collation-equivalent names.
    :type unique: bool
    :returns: Sorted names, optionally deduplicated by the same comparison.
    :rtype: list[str]
    :raises ValueError: If called outside Windows.
    :raises OSError: If native collation fails.
    """
    kernel = _kernel()
    flags = 0x08000001

    def _compare(left, right):
        nonlocal flags
        while True:
            result = kernel.CompareStringW(
                0x400, flags, left, _utf16_length(left), right, _utf16_length(right)
            )
            if result:
                return result - 2
            error = ctypes.get_last_error()
            if error != 1004 or flags == 1:
                raise ctypes.WinError(error)
            flags = 1

    result = sorted(names, key=functools.cmp_to_key(_compare))
    if not unique:
        return result
    deduplicated = []
    for name in result:
        if not deduplicated or _compare(deduplicated[-1], name):
            deduplicated.append(name)
    return deduplicated
