# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage explicit filesystem, registry, and certificate access rules."""

import ctypes
import ntpath
import struct
from collections import OrderedDict
from contextlib import contextmanager

# The target action stages these native helpers beside this module.
# Reuse the inheritance engine's byte operations to keep both ACL modules aligned.
# pylint: disable=import-error,protected-access
import legacy_windows_account as account
import legacy_windows_acl_inheritance as inheritance
import legacy_windows_link as links
import legacy_windows_owner as owner

# Preserve the upstream enum display order, including aliases with equal values.
_FILE_RIGHTS = OrderedDict(
    [
        ("ListDirectory", 1),
        ("ReadData", 1),
        ("WriteData", 2),
        ("CreateFiles", 2),
        ("CreateDirectories", 4),
        ("AppendData", 4),
        ("ReadExtendedAttributes", 8),
        ("WriteExtendedAttributes", 16),
        ("Traverse", 32),
        ("ExecuteFile", 32),
        ("DeleteSubdirectoriesAndFiles", 64),
        ("ReadAttributes", 128),
        ("WriteAttributes", 256),
        ("Write", 278),
        ("Delete", 65536),
        ("ReadPermissions", 131072),
        ("Read", 131209),
        ("ReadAndExecute", 131241),
        ("Modify", 197055),
        ("ChangePermissions", 262144),
        ("TakeOwnership", 524288),
        ("Synchronize", 1048576),
        ("FullControl", 2032127),
    ]
)
_REGISTRY_RIGHTS = OrderedDict(
    [
        ("QueryValues", 1),
        ("SetValue", 2),
        ("CreateSubKey", 4),
        ("EnumerateSubKeys", 8),
        ("Notify", 16),
        ("CreateLink", 32),
        ("Delete", 65536),
        ("ReadPermissions", 131072),
        ("WriteKey", 131078),
        ("ExecuteKey", 131097),
        ("ReadKey", 131097),
        ("ChangePermissions", 262144),
        ("TakeOwnership", 524288),
        ("FullControl", 983103),
    ]
)
_CERTIFICATE_RIGHTS = OrderedDict([("Read", -2146303863), ("FullControl", -803274241)])
_INHERITANCE = OrderedDict([("None", 0), ("ContainerInherit", 1), ("ObjectInherit", 2)])
_PROPAGATION = OrderedDict([("None", 0), ("NoPropagateInherit", 1), ("InheritOnly", 2)])
_PRIVILEGES = ("SeRestorePrivilege", "SeBackupPrivilege", "SeTakeOwnershipPrivilege")


def _key_mask(mask):
    # CryptoAPI key-container security uses file access rights. Compare generic
    # and specific representations by their Windows GENERIC_MAPPING, not by a
    # managed AccessMask property that is absent on upstream's access rules.
    rights = mask & 0x0FFFFFFF
    for generic, specific in (
        (0x80000000, 0x120089),
        (0x40000000, 0x120116),
        (0x20000000, 0x1200A0),
        (0x10000000, 0x1F01FF),
    ):
        if mask & generic:
            rights |= specific
    return rights


def _enum(value, names, label):
    type_name = "System.Security.AccessControl." + label
    if label == "CertAccessRights":
        type_name = "Ansible.Windows._CertAclHelper.CertAccessRights"
    if value is None:
        raise ValueError(
            'Cannot convert null to type "{0}" due to enumeration values that are '
            "not valid. Specify one of the following enumeration values and try "
            'again. The possible enumeration values are "{1}".'.format(
                type_name, ",".join(names)
            )
        )
    text = str(value).strip()
    try:
        numeric = int(text, 10)
    except ValueError:
        return _named_enum(str(value), names, type_name)
    if numeric < -2147483648 or numeric > 2147483647:
        raise ValueError(
            'Cannot convert value "{0}" to type "{1}". Error: "Value was either '
            'too large or too small for an Int32."'.format(value, type_name)
        )
    allowed = 0
    for mask in names.values():
        allowed |= mask
    if allowed >= 0 and (numeric < 0 or numeric & ~allowed):
        raise ValueError(
            'Cannot convert value "{0}" to type "{1}" due to enumeration values '
            "that are not valid. Specify one of the following enumeration values "
            'and try again. The possible enumeration values are "{2}".'.format(
                value, type_name, ",".join(names)
            )
        )
    return numeric


def _named_enum(value, names, type_name):
    lookup = {name.lower(): mask for name, mask in names.items()}
    parts = [part.strip().lower() for part in value.split(",")]
    if all(part in lookup for part in parts):
        result = 0
        for part in parts:
            result |= lookup[part]
        return result
    matches = [name for name in names if name.lower().startswith(value.lower())]
    if len(matches) == 1:
        return names[matches[0]]
    if matches:
        detail = (
            "The identifier name {0} cannot be processed because it is either too "
            "similar or identical to the following enumerator names: {1}. "
            "Use a more specific identifier name."
        ).format(value, ", ".join(matches))
    else:
        detail = (
            "Unable to match the identifier name {0} to a valid enumerator name. "
            "Specify one of the following enumerator names and try again:\r\n{1}"
        ).format(value, ", ".join(names))
    raise ValueError(
        'Cannot convert value "{0}" to type "{1}". Error: "{2}"'.format(
            value, type_name, detail
        )
    )


# Keep the public rule fields explicit instead of hiding them in an options map.
def make_rule(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    target, sid, rights, rule_type, inherit=None, propagation="None"
):
    """Build the explicit access rule used for matching and modification.

    :param target: Target or ACL snapshot with kind and container fields.
    :type target: dict
    :param sid: Canonical SID string for the requested principal.
    :type sid: str
    :param rights: Comma-separated rights or a signed decimal mask.
    :type rights: str or None
    :param rule_type: Either allow or deny.
    :type rule_type: str
    :param inherit: Inheritance names or decimal flags; None uses defaults.
    :type inherit: str or None
    :param propagation: Propagation flag names or decimal flags.
    :type propagation: str or None
    :returns: A native, explicit common ACE.
    :rtype: bytes
    :raises ValueError: If rights, flags, or rule type are invalid.
    :raises OSError: If the SID cannot be converted to native bytes.
    """
    kind = target["kind"]
    names, label = {
        "file": (_FILE_RIGHTS, "FileSystemRights"),
        "registry": (_REGISTRY_RIGHTS, "RegistryRights"),
        "certificate": (_CERTIFICATE_RIGHTS, "CertAccessRights"),
    }[kind]
    mask = _enum(rights, names, label)
    if kind == "certificate":
        mask = _key_mask(mask & 0xFFFFFFFF)
        if target.get("certificate_provider") == "capi" and mask not in (
            0x120089,
            0x1F01FF,
        ):
            raise ValueError(
                "The CAPI key provider supports Read or FullControl rights."
            )
    if not target["container"]:
        inherit = "None"
    elif inherit is None:
        inherit = "ContainerInherit, ObjectInherit"
    inherit_flags = _enum(inherit, _INHERITANCE, "InheritanceFlags")
    propagate_flags = _enum(propagation, _PROPAGATION, "PropagationFlags")
    if rule_type not in ("allow", "deny"):
        raise ValueError("Access rule type must be allow or deny.")
    if kind == "file":
        if mask < 0 or mask > _FILE_RIGHTS["FullControl"]:
            raise ValueError("FileSystemRights is outside its permitted range.")
        if rule_type == "allow":
            mask |= 0x100000
        elif mask not in (0x1F01FF, 0x1F01BF):
            mask &= ~0x100000
    if not mask:
        operation = (
            '"AccessRuleFactory" with "6"'
            if kind == "certificate"
            else '".ctor" with "5"'
        )
        raise ValueError(
            'Exception calling {0} argument(s): "Argument cannot be zero.\r\n'
            'Parameter name: accessMask"'.format(operation)
        )
    if not 0 <= inherit_flags <= 3 or not 0 <= propagate_flags <= 3:
        raise ValueError("Inheritance and propagation flags must be between 0 and 3.")
    flags = ((inherit_flags & 1) << 1) | ((inherit_flags & 2) >> 1)
    if flags:
        flags |= propagate_flags << 2
    identity = account.sid_bytes(sid)
    return (
        struct.pack(
            "<BBHI",
            int(rule_type == "deny"),
            flags,
            8 + len(identity),
            mask & 0xFFFFFFFF,
        )
        + identity
    )


def _entries(snapshot):
    if snapshot["dacl"] is not None:
        return inheritance._aces(snapshot["dacl"])
    # Managed discretionary ACLs represent a null DACL as Everyone/full access.
    identity = b"\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00"
    flags = 3 if snapshot["container"] else 0
    return [struct.pack("<BBHI", 0, flags, 20, 0xFFFFFFFF) + identity]


def _access_rule(ace):
    if ace[0] in (9, 10):
        # GetAccessRules projects common callback ACEs into ordinary rules;
        # their condition is opaque and is not part of the matching fields.
        identity = inheritance._ace_sid(ace)
        return (
            ace[0] - 9,
            ace[1] & 15,
            struct.unpack_from("<I", ace, 4)[0],
            identity,
        )
    return inheritance._common_rule(ace)


def _key_rule(ace):
    current = _access_rule(ace)
    if current is None:
        return None
    return current[:2] + (_key_mask(current[2]),) + current[3:]


def has_rule(snapshot, rule):
    """Check explicit access fields, excluding inherited permission entries.

    File and registry rules require exact rights. Certificate entries must
    contain the requested native rights; a read grant cannot satisfy full control.

    :param snapshot: Normalized ACL snapshot.
    :type snapshot: dict
    :param rule: Explicit common ACE returned by make_rule.
    :type rule: bytes
    :returns: Whether the requested fields identify a sufficient explicit entry.
    :rtype: bool
    :raises ValueError: If the DACL is malformed.
    """
    requested = inheritance._common_rule(rule)
    certificate = snapshot.get("kind") == "certificate"
    for ace in _entries(snapshot):
        candidate = _access_rule(ace)
        if certificate and candidate is not None:
            if (
                candidate[:2] + candidate[3:] == requested[:2] + requested[3:]
                and _key_mask(candidate[2]) & requested[2] == requested[2]
                and not ace[1] & 16
            ):
                return True
            continue
        if not ace[1] & 16 and candidate == requested:
            return True
    return False


def validate_addition(snapshot, rule):
    """Reject an ordinary insertion that bypasses an existing restriction.

    :param dict snapshot: Existing ACL snapshot.
    :param bytes rule: Requested explicit common rule.
    :raises ValueError: Matching object restrictions or certificate conditions
        cannot safely be expressed by this module's ordinary-rule interface.
    """
    requested = inheritance._common_rule(rule)
    for ace in _entries(snapshot):
        object_rule = ace[0] in (5, 6, 11, 12)
        conditional_key = snapshot.get("kind") == "certificate" and ace[0] in (9, 10)
        if not object_rule and not conditional_key:
            continue
        allow = ace[0] in (5, 9, 11)
        if int(not allow) == requested[0] and inheritance._ace_sid(ace) == requested[3]:
            raise ValueError(
                "An existing rule for this principal has object restrictions or "
                "certificate conditions. Adding an unconditional rule could bypass "
                "them; manage that restricted rule with a condition-aware tool."
            )


def _updated(snapshot, entries):
    result = dict(snapshot)
    revision = snapshot["dacl"][0] if snapshot["dacl"] is not None else 2
    result["dacl"] = inheritance._pack_acl(entries, revision)
    return result


def add_rule(snapshot, rule):
    """Merge an explicit rule or insert it into canonical SID order.

    :param snapshot: Normalized ACL snapshot; the input is unchanged.
    :type snapshot: dict
    :param rule: Explicit common ACE returned by make_rule.
    :type rule: bytes
    :returns: Updated ACL snapshot.
    :rtype: dict
    :raises ValueError: If the ACL is noncanonical, malformed, too large, or
        contains an unrecognized explicit ACE type or object flag.
    """
    entries = _entries(snapshot)
    if not inheritance._canonical(entries):
        raise ValueError("Access rules cannot be added to a noncanonical DACL.")
    for index, ace in enumerate(entries):
        merged = inheritance._merge_common(ace, rule)
        if merged is not None:
            entries[index] = merged
            return _updated(snapshot, entries)
    entries.append(rule)
    return _updated(snapshot, inheritance._sort_aces(entries))


def remove_rule(snapshot, rule):
    """Subtract matched rights without rewriting remaining callback conditions.

    :param snapshot: Normalized ACL snapshot; the input is unchanged.
    :type snapshot: dict
    :param rule: Explicit common ACE returned by make_rule.
    :type rule: bytes
    :returns: Updated ACL snapshot, preserving inherited rules.
    :rtype: dict
    :raises ValueError: If the ACL is noncanonical, malformed, or too large.
    """
    entries = _entries(snapshot)
    requested = inheritance._common_rule(rule)
    if not inheritance._canonical(entries):
        raise ValueError("Access rules cannot be removed from a noncanonical DACL.")
    project = _key_rule if snapshot.get("kind") == "certificate" else _access_rule
    if snapshot.get("kind") == "certificate":
        if snapshot.get("certificate_provider") == "capi":
            for ace in entries:
                current = project(ace)
                if (
                    current is None
                    or ace[1] & 16
                    or current[0] != requested[0]
                    or current[3] != requested[3]
                ):
                    continue
                remaining_mask = current[2] & ~requested[2]
                if current[2] & requested[2] and remaining_mask not in (
                    0,
                    0x120089,
                    0x1F01FF,
                ):
                    raise ValueError(
                        "The CAPI key provider cannot represent this partial rights "
                        "removal. Remove the complete Read or FullControl rule instead."
                    )
    remaining = inheritance._subtract_rule(entries, requested, project)
    callback_changed = any(
        ace[0] in (9, 10) and ace not in remaining for ace in entries
    )
    if callback_changed:
        # Upstream orders the surviving explicit entries by SID after callback
        # removal, including when a condition keeps some of its original rights.
        remaining = inheritance._sort_aces(remaining)
    return _updated(snapshot, remaining)


def resolve_user(user):
    """Resolve SID aliases and local or domain accounts with upstream semantics.

    :param user: User-supplied account, SID string, or SDDL alias.
    :type user: str
    :returns: Canonical SID string.
    :rtype: str
    :raises OSError: If account or native SID lookup fails.
    :raises ValueError: If the identity is malformed.
    """
    return owner.resolve_owner(user)


def _follow_links(path):
    visited = set()
    while path not in visited:
        visited.add(path)
        try:
            info = links.get_link_info(path)
        except (OSError, ValueError, NotImplementedError):
            break
        if not info or info["type"] not in ("symbolic", "junction"):
            break
        if info.get("relative"):
            path = ntpath.normpath(ntpath.join(ntpath.dirname(path), info["target"]))
        else:
            target = info["target"]
            path = target if target.startswith("\\\\?\\") else "\\\\?\\" + target
    else:
        raise ValueError("The path contains a symbolic link or junction cycle.")
    return path


def resolve_target(path, follow=False):
    """Resolve filesystem links when requested and check literal path existence.

    :param path: Literal filesystem or registry provider path.
    :type path: str
    :param follow: Follow symbolic links and junctions to their final target.
    :type follow: bool
    :returns: Target path, kind, and container fields, or None if absent.
    :rtype: dict or None
    :raises OSError: If native path inspection fails for reasons besides absence.
    :raises ValueError: If links form a cycle or the target is not Windows.
    """
    security, kernel = inheritance._libraries()
    if inheritance._registry_path(path) is not None:
        try:
            # The registry provider checks existence with OpenSubKey(read-only),
            # which requests KEY_READ; Windows can reject a zero-access open.
            with inheritance._object_handle(
                security, kernel, path, _REGISTRY_RIGHTS["ReadKey"]
            ):
                pass
        except OSError as error:
            if getattr(error, "winerror", None) in (2, 3, 123):
                return None
            raise
        return {"path": path, "kind": "registry", "container": True}
    if follow:
        path = _follow_links(path)
    kernel.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    kernel.GetFileAttributesW.restype = ctypes.c_uint32
    attributes = kernel.GetFileAttributesW(path)
    if attributes == 0xFFFFFFFF:
        error = ctypes.get_last_error()
        if error in (2, 3, 123):
            return None
        raise ctypes.WinError(error)
    return {"path": path, "kind": "file", "container": bool(attributes & 16)}


@contextmanager
def open_acl(target):
    """Read a filesystem or registry ACL and provide a scoped writer callback.

    Read-only operations never request WRITE_DAC. A requested write opens the
    same literal path with READ_CONTROL and WRITE_DAC; both operations open the
    final reparse point itself because explicit following occurs beforehand.

    :param target: Resolved filesystem or registry target.
    :type target: dict
    :returns: Context manager yielding a snapshot and writer(snapshot).
    :rtype: context manager
    :raises OSError: If native ACL reading or writing fails.
    :raises ValueError: If the ACL is malformed or the target is not Windows.
    """
    snapshot = inheritance.read_acl(target["path"], True, target["container"])
    snapshot["kind"] = target["kind"]

    def _write(updated):
        inheritance.write_acl(target["path"], updated, True)

    yield snapshot, _write


@contextmanager
def acl_privileges():
    """Enable the three held upstream privileges only for an administrator.

    The membership check respects disabled and deny-only groups. Previous token
    state is restored after both successful operations and exceptions.

    :returns: Context manager yielding None while held privileges are enabled.
    :rtype: context manager
    :raises OSError: If token membership, privilege changes, or restoration fails.
    :raises ValueError: If called outside Windows.
    """
    security, _ = inheritance._libraries()
    security.CheckTokenMembership.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int),
    ]
    security.CheckTokenMembership.restype = ctypes.c_int
    administrators = ctypes.create_string_buffer(account.sid_bytes("S-1-5-32-544"))
    member = ctypes.c_int()
    if not security.CheckTokenMembership(None, administrators, ctypes.byref(member)):
        raise ctypes.WinError(ctypes.get_last_error())
    if member.value:
        with owner.ownership_privileges(_PRIVILEGES):
            yield
    else:
        yield
