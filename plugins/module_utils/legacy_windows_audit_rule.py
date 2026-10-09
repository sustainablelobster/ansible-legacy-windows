# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read and modify filesystem and registry system audit ACLs natively."""

import ctypes
import ntpath
import os
import re
import struct
import sys
from collections import OrderedDict

# The established native helpers provide enum metadata, scoped object handles,
# and binary ACL operations; duplicating them would obscure the SACL differences.
# pylint: disable=import-error,protected-access
import legacy_windows_account as account
import legacy_windows_acl as acl
import legacy_windows_acl_inheritance as inheritance
import legacy_windows_find_match as filenames
import legacy_windows_owner as owner

_AUDIT_FLAGS = OrderedDict([("None", 0), ("Success", 1), ("Failure", 2)])


def _unescape_path(text):
    return re.sub(r"`([*?\[\]`])", r"\1", text)


def _registry_children(path):
    # winreg is Windows' standard library; defer its import for binary ACL tests
    # on non-Windows controllers, not as an alternative target implementation.
    import winreg  # pylint: disable=import-error,import-outside-toplevel

    root, key_path = inheritance._registry_path(path)
    with winreg.OpenKey(root, key_path, 0, 0x20019) as key:
        return [
            winreg.EnumKey(key, index) for index in range(winreg.QueryInfoKey(key)[0])
        ]


def _contains_pattern(path):
    return re.search(r"(?<!`)(?:``)*[*?\[\]]", path) is not None


def _provider_targets(target):
    path = target["path"]
    if not any(character in path for character in "*?[]`"):
        return [target]
    registry = target["kind"] == "registry"
    if registry:
        path = re.sub(
            r"^(?:Microsoft\.PowerShell\.Core\\)?Registry::", "", path, flags=re.I
        )
        root, _, tail = path.replace("/", "\\").partition("\\")
    else:
        root, tail = ntpath.splitdrive(path.replace("/", "\\"))
        if tail.startswith("\\"):
            root += "\\"
        root = root or "."
    paths = [root]
    parts = list(filter(None, tail.split("\\")))
    expand = _contains_pattern(path)
    for index, part in enumerate(parts):
        if not expand or (not _contains_pattern(part) and index != len(parts) - 1):
            paths = [ntpath.join(parent, _unescape_path(part)) for parent in paths]
            continue
        # The pinned provider converts escapes before its wildcard matcher:
        # a pair becomes one backtick, while a single becomes a backslash.
        converted = re.sub(
            r"``|`", lambda match: "`" if len(match.group(0)) == 2 else "\\", part
        )
        selected = []
        for parent in paths:
            names = _registry_children(parent) if registry else os.listdir(parent)
            selected.extend(
                ntpath.join(parent, name)
                for name in sorted(names, key=str.lower)
                if filenames.matches(name, [converted])
            )
        paths = selected
    return [
        resolved
        for resolved in (acl.resolve_target(path, False) for path in paths)
        if resolved is not None
    ]


def audit_targets(target):
    """Select the security objects read by the pinned provider-path getter.

    The caller first validates the original literal path. The getter resolves
    provider patterns, then checks each resolved name through the provider
    again before reading that name literally.

    :param target: Literal target with path and kind fields.
    :type target: dict
    :returns: Selected native targets in provider name order.
    :rtype: list
    :raises OSError: If enumeration or target inspection fails.
    :raises ValueError: If a wildcard character range is invalid.
    """
    return [
        selected
        for selected in _provider_targets(target)
        if _provider_targets(selected)
    ]


def audit_write_targets(target):
    """Select the objects receiving the pinned provider-path setter's ACL.

    Unlike the getter's existence check, the setter applies its descriptor to
    the second resolution's objects. Escaped bracket names can consequently
    read one object's ACL and write it to different siblings.

    :param target: Literal target with path and kind fields.
    :type target: dict
    :returns: Write targets in provider order, without performing writes.
    :rtype: list
    :raises OSError: If enumeration or target inspection fails.
    :raises ValueError: If a wildcard character range is invalid.
    """
    return [
        destination
        for selected in _provider_targets(target)
        for destination in _provider_targets(selected)
    ]


def audit_privileges():
    """Temporarily enable the held privilege needed to read and write a SACL.

    :returns: Context manager restoring the previous token state on exit.
    :rtype: context manager
    :raises OSError: If native privilege adjustment or restoration fails.
    """
    return owner.ownership_privileges(("SeSecurityPrivilege",))


def _acl_bytes(pointer):
    if not pointer:
        return None
    size = ctypes.c_uint16.from_address(pointer.value + 2).value
    return ctypes.string_at(pointer, size)


def _legacy_registry_dacl(security, kernel, handle, kind):
    descriptor, dacl = ctypes.c_void_p(), ctypes.c_void_p()
    try:
        status = security.GetSecurityInfo(
            handle,
            kind,
            4,
            None,
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(descriptor),
        )
        if status:
            raise ctypes.WinError(status)
        control, revision = ctypes.c_uint16(), ctypes.c_uint32()
        if not security.GetSecurityDescriptorControl(
            descriptor, ctypes.byref(control), ctypes.byref(revision)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return {
            "dacl": _acl_bytes(dacl),
            "dacl_protected": bool(control.value & 0x1000),
        }
    finally:
        if descriptor:
            kernel.LocalFree(descriptor)


def read_sacl(target):
    """Read the raw SACL and its protection state without changing the object.

    :param target: Resolved filesystem or registry target.
    :type target: dict
    :returns: Target fields, raw SACL and protection, plus the filesystem DACL
        and its protection for the unchanged copy used by the upstream setter.
        XP and Server 2003 registry targets also include their unchanged DACL.
    :rtype: dict
    :raises OSError: If opening or inspecting the object fails.
    :raises ValueError: If called outside Windows.
    """
    security, kernel = inheritance._libraries()
    with inheritance._object_handle(
        security, kernel, target["path"], 0x01020000
    ) as opened:
        handle, kind = opened
        descriptor, sacl, dacl = [ctypes.c_void_p() for _ in range(3)]
        filesystem = target["kind"] == "file"
        try:
            status = security.GetSecurityInfo(
                handle,
                kind,
                12 if filesystem else 8,
                None,
                None,
                ctypes.byref(dacl) if filesystem else None,
                ctypes.byref(sacl),
                ctypes.byref(descriptor),
            )
            if status:
                raise ctypes.WinError(status)
            control, revision = ctypes.c_uint16(), ctypes.c_uint32()
            if not security.GetSecurityDescriptorControl(
                descriptor, ctypes.byref(control), ctypes.byref(revision)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            result = dict(
                target, sacl=_acl_bytes(sacl), protected=bool(control.value & 0x2000)
            )
            if filesystem:
                result.update(
                    dacl=_acl_bytes(dacl), dacl_protected=bool(control.value & 0x1000)
                )
            else:
                version = getattr(sys, "getwindowsversion")()
                if (version.major, version.minor) in ((5, 1), (5, 2)):
                    # Reading the DACL separately keeps the SACL-only query's
                    # null-ACL protection behavior; a combined query differs.
                    result.update(_legacy_registry_dacl(security, kernel, handle, kind))
            return result
        finally:
            if descriptor:
                kernel.LocalFree(descriptor)


def write_sacl(snapshot):
    """Persist audit changes with the pinned filesystem/registry setter effects.

    The filesystem provider reapplies its read DACL too. A SACL-only native
    write clears inherited DACL flags on the verified target, so passing the
    unchanged DACL and protection is necessary to retain the upstream state.
    XP and Server 2003 registry writes need the same unchanged DACL copy to
    preserve inherited access entries and protected child keys.

    :param snapshot: Snapshot with prepared SACL bytes and protection state.
    :type snapshot: dict
    :raises OSError: If opening or writing the SACL fails.
    :raises ValueError: If called outside Windows.
    """
    security, kernel = inheritance._libraries()
    raw = snapshot["sacl"]
    buffer = ctypes.create_string_buffer(raw) if raw is not None else None
    protection = 0x40000000 if snapshot["protected"] else 0x10000000
    if snapshot["kind"] == "file":
        setter = security.SetNamedSecurityInfoW
        setter.argtypes = [ctypes.c_wchar_p, ctypes.c_int, ctypes.c_uint32] + [
            ctypes.c_void_p
        ] * 4
        setter.restype = ctypes.c_uint32
        dacl = snapshot["dacl"]
        access = ctypes.create_string_buffer(dacl) if dacl is not None else None
        dacl_protection = 0x80000000 if snapshot["dacl_protected"] else 0x20000000
        status = setter(
            snapshot["path"],
            1,
            12 | protection | dacl_protection,
            None,
            None,
            access,
            buffer,
        )
        if status:
            raise ctypes.WinError(status)
        return
    _write_registry_sacl(security, kernel, snapshot, buffer, protection)


def _write_registry_sacl(security, kernel, snapshot, buffer, protection):
    copy_dacl = "dacl" in snapshot
    access = (
        ctypes.create_string_buffer(snapshot["dacl"])
        if copy_dacl and snapshot["dacl"] is not None
        else None
    )
    information = 8 | protection
    if copy_dacl:
        information |= 4 | (0x80000000 if snapshot["dacl_protected"] else 0x20000000)
    with inheritance._object_handle(
        security, kernel, snapshot["path"], 0x01060000 if copy_dacl else 0x01020000
    ) as opened:
        handle, kind = opened
        status = security.SetSecurityInfo(
            handle, kind, information, None, None, access, buffer
        )
        if status:
            raise ctypes.WinError(status)


def _display(value, names):
    if not value:
        return "None"
    labels = []
    remaining = value
    for name, mask in reversed(list(names.items())):
        if mask and remaining & mask == mask:
            labels.append(name)
            remaining &= ~mask
    return str(value) if remaining else ", ".join(reversed(labels))


def _rights(kind):
    return acl._REGISTRY_RIGHTS if kind == "registry" else acl._FILE_RIGHTS


def validate_rights(target, rights):
    """Validate names before the upstream file-inheritance check.

    :param target: Resolved target with its kind field.
    :type target: dict
    :param rights: Requested enum names.
    :type rights: list or None
    :returns: Combined mask, including zero for an empty list.
    :rtype: int
    :raises ValueError: If a name is not in the target's rights enumeration.
    """
    lookup = {name.lower(): mask for name, mask in _rights(target["kind"]).items()}
    mask = 0
    for right in rights or []:
        if right.lower() not in lookup:
            raise ValueError(
                "{0} does not seem to be a valid {1} right".format(
                    right, "REGISTRY" if target["kind"] == "registry" else "FILE SYSTEM"
                )
            )
        mask |= lookup[right.lower()]
    return mask


# Audit constructors do not add Synchronize to filesystem rights, unlike allow
# access-rule constructors. Keep all requested rule fields visible here.
def make_rule(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    target, sid, rights, inherit, propagation, audit_flags
):
    """Construct a common system-audit ACE from the public named options.

    :param target: Resolved target including kind and container fields.
    :type target: dict
    :param sid: Canonical SID string.
    :type sid: str
    :param rights: Named filesystem or registry rights.
    :type rights: list
    :param inherit: Named inheritance flags.
    :type inherit: list
    :param propagation: Named propagation flag.
    :type propagation: str
    :param audit_flags: Success, failure, or both.
    :type audit_flags: list
    :returns: Explicit system-audit ACE bytes.
    :rtype: bytes
    :raises ValueError: If names are invalid or the constructor cannot bind
        null or empty enum arguments.
    :raises OSError: If native SID conversion fails.
    """
    if any(value is None for value in (rights, inherit, propagation, audit_flags)):
        raise ValueError(
            'Cannot find an overload for "{0}AuditRule" and the argument count: "5".'.format(
                "Registry" if target["kind"] == "registry" else "FileSystem"
            )
        )
    mask = validate_rights(target, rights)
    if not rights:
        acl._enum(
            "",
            _rights(target["kind"]),
            "RegistryRights" if target["kind"] == "registry" else "FileSystemRights",
        )
    if not inherit:
        acl._enum("", acl._INHERITANCE, "InheritanceFlags")
    if not audit_flags:
        acl._enum("", _AUDIT_FLAGS, "AuditFlags")
    flags = 0
    for name in inherit or []:
        flags |= {"none": 0, "containerinherit": 2, "objectinherit": 1}[name.lower()]
    if flags:
        flags |= {"none": 0, "nopropagateinherit": 4, "inheritonly": 8}[
            propagation.lower()
        ]
    for name in audit_flags or []:
        flags |= {"success": 64, "failure": 128}[name.lower()]
    identity = account.sid_bytes(sid)
    return struct.pack("<BBHI", 2, flags, 8 + len(identity), mask) + identity


def translate_rule_user(rule, user):
    """Translate the string constructor's account identity for an actual add.

    Matching uses the separately resolved SID. The string rule constructor,
    however, stores an account name, translated only at AddAuditRule.

    :param rule: Requested common audit ACE.
    :type rule: bytes
    :param user: Original account-name argument.
    :type user: str
    :returns: Common audit ACE using the constructor's translated identity.
    :rtype: bytes
    :raises OSError: If native account translation fails.
    :raises ValueError: If the account name is invalid.
    """
    identity = account.sid_bytes(account.account_name_to_sid(user))
    flags, mask, _ = _common(rule)
    return struct.pack("<BBHI", 2, flags, 8 + len(identity), mask) + identity


def _common(ace):
    if ace[0] != 2 or len(ace) < 16:
        return None
    size = 8 + 4 * ace[9]
    if ace[8] != 1 or len(ace) != size + 8:
        return None
    return ace[1], struct.unpack_from("<I", ace, 4)[0], ace[8:]


def _projected_rule(ace):
    if ace[0] not in (2, 13):
        return None
    return ace[1], struct.unpack_from("<I", ace, 4)[0], inheritance._ace_sid(ace)


def _merge(left, right):
    first, second = _common(left), _common(right)
    if (
        first is None
        or second is None
        or first[2] != second[2]
        or (first[0] | second[0]) & 16
    ):
        return None
    flags1, flags2 = first[0], second[0]
    if flags1 == flags2:
        return inheritance._replace_ace(left, mask=first[1] | second[1])
    if first[1] != second[1]:
        return None
    if flags1 & 15 == flags2 & 15:
        return inheritance._replace_ace(left, flags=flags1 | flags2)
    if flags1 & 192 == flags2 & 192:
        coverage = inheritance._scope(flags1 & 15) | inheritance._scope(flags2 & 15)
        flags = inheritance._SCOPE_FLAGS.get(coverage)
        if flags is not None:
            return inheritance._replace_ace(left, flags=flags | (flags1 & 192))
    return None


def _canonical(entries):
    inherited = False
    for ace in entries:
        if ace[1] & 16:
            inherited = True
        elif inherited:
            return False
    return True


def _sort(entries):
    def _order(pair):
        index, ace = pair
        if ace[1] & 16:
            return (2, index, ())
        if ace[0] not in (2, 7, 13, 15):
            raise ValueError("Cannot order an unsupported explicit audit entry.")
        sid = inheritance._ace_sid(ace)
        return (
            1 if ace[0] in (7, 15) else 0,
            0,
            (sid[2:8], sid[1], struct.unpack("<" + "I" * sid[1], sid[8:])),
        )

    return [ace for _, ace in sorted(enumerate(entries), key=_order)]


def _entries(snapshot):
    entries = []
    for ace in inheritance._aces(snapshot["sacl"]) if snapshot["sacl"] else []:
        rule = _common(ace)
        if rule is None:
            entries.append(ace)
            continue
        flags, mask, _ = rule
        if (
            not mask
            or not flags & 192
            or flags & 8
            and (not snapshot["container"] or not flags & 3)
        ):
            continue
        if not snapshot["container"]:
            flags &= ~15
        elif not flags & 3:
            flags &= ~4
        entries.append(inheritance._replace_ace(ace, flags=flags))
    if _canonical(entries) and all(ace[1] & 16 or _common(ace) for ace in entries):
        entries = _sort(entries)
        index = 0
        while index + 1 < len(entries):
            merged = _merge(entries[index], entries[index + 1])
            if merged is not None:
                entries[index : index + 2] = [merged]
            index += 1
    return entries


def _public_rule(snapshot, ace):
    flags, mask, sid = _projected_rule(ace)
    return {
        "user": account.sid_to_name(
            account.sid_to_string(ctypes.create_string_buffer(sid))
        ),
        "rights": _display(mask, _rights(snapshot["kind"])),
        "audit_flags": _display(flags >> 6 & 3, _AUDIT_FLAGS),
        "is_inherited": str(bool(flags & 16)),
        "inheritance_flags": _display(
            (flags & 2) >> 1 | (flags & 1) << 1, acl._INHERITANCE
        ),
        "propagation_flags": _display(flags >> 2 & 3, acl._PROPAGATION),
    }


def current_rules(snapshot):
    """Return stored audit rules with the upstream zero/one/many result shape.

    Common and callback audit ACEs are projected into named rule fields. As in
    the upstream public getter, object and callback-object ACEs are not exposed
    as audit rules; their raw bytes remain in the descriptor.

    :param snapshot: Current target SACL snapshot.
    :type snapshot: dict
    :returns: Empty dict, one rule dict, or a list of rule dicts.
    :rtype: dict or list
    :raises OSError: If native SID translation fails.
    :raises ValueError: If the ACL or a projected rule is malformed.
    """
    results = []
    for ace in _entries(snapshot):
        if _projected_rule(ace) is not None:
            results.append(_public_rule(snapshot, ace))
        elif ace[0] in (7, 15):
            inheritance._ace_sid(ace)
    return results[0] if len(results) == 1 else results or {}


def has_rule(snapshot, requested):
    """Match displayed enum tokens, excluding inherited entries.

    :param snapshot: Current target SACL snapshot.
    :type snapshot: dict
    :param requested: Common audit ACE to match.
    :type requested: bytes
    :returns: Whether an explicit rule contains the requested displayed fields.
    :rtype: bool
    :raises ValueError: If the SACL is malformed.
    """
    flags, mask, sid = _common(requested)
    desired = (
        _display(mask, _rights(snapshot["kind"])),
        _display(flags >> 6 & 3, _AUDIT_FLAGS),
        _display((flags & 2) >> 1 | (flags & 1) << 1, acl._INHERITANCE),
    )
    for ace in _entries(snapshot):
        candidate = _projected_rule(ace)
        if candidate is None or ace[1] & 16 or candidate[2] != sid:
            continue
        other_flags, other_mask, _ = candidate
        actual = (
            _display(other_mask, _rights(snapshot["kind"])),
            _display(other_flags >> 6 & 3, _AUDIT_FLAGS),
            _display((other_flags & 2) >> 1 | (other_flags & 1) << 1, acl._INHERITANCE),
        )
        if flags & 12 == other_flags & 12 and all(
            set(wanted.split(", ")).issubset(stored.split(", "))
            for wanted, stored in zip(desired, actual)
        ):
            return True
    return False


def _updated(snapshot, entries):
    revision = snapshot["sacl"][0] if snapshot["sacl"] else 2
    # NativeObjectSecurity persists a null SACL when its managed ACL has no
    # entries. Windows then determines protection and descendant propagation.
    raw = inheritance._pack_acl(entries, revision) if entries else None
    return dict(snapshot, sacl=raw)


def _editable(snapshot):
    entries = _entries(snapshot)
    if not _canonical(entries):
        raise ValueError("Audit rules cannot be changed in a noncanonical SACL.")
    for ace in entries:
        if ace[1] & 16:
            continue
        if ace[0] not in (2, 7, 13, 15):
            raise ValueError(
                "Cannot change a SACL containing unsupported explicit entries."
            )
        inheritance._ace_sid(ace)
    return entries


def add_rule(snapshot, requested):
    """Merge an explicit audit ACE without removing unrelated or inherited ACEs.

    :param snapshot: Current target SACL snapshot; the input is unchanged.
    :type snapshot: dict
    :param requested: Common audit ACE to add.
    :type requested: bytes
    :returns: Prepared snapshot for write_sacl.
    :rtype: dict
    :raises ValueError: If the SACL cannot be safely edited.
    """
    if not snapshot["container"] and requested[1] & 3:
        raise ValueError(
            'Exception calling "AddAuditRule" with "1" argument(s): '
            '"No flags can be set.\r\nParameter name: inheritanceFlags"'
        )
    entries = _editable(snapshot)
    for index, ace in enumerate(entries):
        merged = _merge(ace, requested)
        if merged is not None:
            entries[index] = merged
            return _updated(snapshot, entries)
    entries.append(requested)
    return _updated(snapshot, _sort(entries))


def remove_user(snapshot, sid):
    """Remove explicit audit ACEs for one SID without changing inherited ACEs.

    :param snapshot: Current target SACL snapshot; the input is unchanged.
    :type snapshot: dict
    :param sid: Canonical SID string identifying rules to purge.
    :type sid: str
    :returns: Prepared snapshot for write_sacl.
    :rtype: dict
    :raises ValueError: If the SACL cannot be safely edited.
    :raises OSError: If native SID conversion fails.
    """
    identity = account.sid_bytes(sid)
    return _updated(
        snapshot,
        [
            ace
            for ace in _editable(snapshot)
            if ace[1] & 16 or inheritance._ace_sid(ace) != identity
        ],
    )


def has_user(snapshot, sid):
    """Check whether any projected explicit audit ACE belongs to a SID.

    :param snapshot: Current target SACL snapshot.
    :type snapshot: dict
    :param sid: Canonical SID string.
    :type sid: str
    :returns: Whether removal would find an explicit entry.
    :rtype: bool
    :raises OSError: If native SID conversion fails.
    :raises ValueError: If the SACL is malformed.
    """
    identity = account.sid_bytes(sid)
    return any(
        not ace[1] & 16
        and _projected_rule(ace) is not None
        and _projected_rule(ace)[2] == identity
        for ace in _entries(snapshot)
    )
