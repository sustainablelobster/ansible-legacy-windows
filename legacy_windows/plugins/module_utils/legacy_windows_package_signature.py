# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Verify package signatures with the target's native Authenticode policy."""

import ctypes
import ntpath
import os
import re
import uuid
from functools import cmp_to_key

# The action stages the collection's already-maintained wildcard helper.
import legacy_windows_find_match as filenames  # pylint: disable=import-error


# Native ABI records contain fields, not behavioral methods.
class _FileInfo(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("size", ctypes.c_uint32),
        ("path", ctypes.c_wchar_p),
        ("file", ctypes.c_void_p),
        ("subject", ctypes.c_void_p),
    ]


class _TrustData(ctypes.Structure):  # pylint: disable=too-few-public-methods
    # The pre-Windows8 layout is the same one used by the released Windows
    # PowerShell verifier. No newer signature-settings tail is required.
    _fields_ = [
        ("size", ctypes.c_uint32),
        ("policy", ctypes.c_void_p),
        ("sip", ctypes.c_void_p),
        ("ui", ctypes.c_uint32),
        ("revocation", ctypes.c_uint32),
        ("choice", ctypes.c_uint32),
        ("information", ctypes.c_void_p),
        ("action", ctypes.c_uint32),
        ("state", ctypes.c_void_p),
        ("url", ctypes.c_wchar_p),
        ("flags", ctypes.c_uint32),
        ("context", ctypes.c_uint32),
    ]


class _SignatureInfo(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("size", ctypes.c_uint32),
        ("state", ctypes.c_uint32),
        ("kind", ctypes.c_uint32),
        ("signature_availability", ctypes.c_uint32),
        ("availability", ctypes.c_uint32),
        ("display", ctypes.c_void_p),
        ("display_length", ctypes.c_uint32),
        ("publisher", ctypes.c_void_p),
        ("publisher_length", ctypes.c_uint32),
        ("more_info", ctypes.c_void_p),
        ("more_info_length", ctypes.c_uint32),
        ("hash", ctypes.c_void_p),
        ("hash_length", ctypes.c_uint32),
        ("os_binary", ctypes.c_int32),
    ]


def _trust(library, information, choice, action=1, state=None):
    pointer = (
        ctypes.cast(ctypes.pointer(information), ctypes.c_void_p)
        if information is not None
        else None
    )
    value = _TrustData(
        ctypes.sizeof(_TrustData),
        None,
        None,
        2,
        0,
        choice,
        pointer,
        action,
        state,
        None,
        0,
        0,
    )
    identifier = ctypes.create_string_buffer(
        uuid.UUID("00aac56b-cd44-11d0-8cc2-00c04fc295ee").bytes_le, 16
    )
    return library.WinVerifyTrust(None, identifier, ctypes.byref(value)), value


def _catalog_valid(library, path):
    try:
        operation = library.WTGetSignatureInfo
    except AttributeError:
        # XP/2003 expose WinVerifyTrust but not the later catalog convenience
        # API. Probe the function itself rather than infer support from a build.
        return False
    operation.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(_SignatureInfo),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    operation.restype = ctypes.c_int32
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    crypt.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
    crypt.CertFreeCertificateContext.restype = ctypes.c_int32
    information, certificate, state = (
        _SignatureInfo(size=ctypes.sizeof(_SignatureInfo)),
        ctypes.c_void_p(),
        ctypes.c_void_p(),
    )
    # This is the descriptor for the caller's open file, not a new native handle.
    import msvcrt  # pylint: disable=import-outside-toplevel,import-error

    with open(path, "rb") as stream:
        try:
            code = operation(
                path,
                msvcrt.get_osfhandle(stream.fileno()),
                0x3803,
                ctypes.byref(information),
                ctypes.byref(certificate),
                ctypes.byref(state),
            )
            return code >= 0 and information.state in (5, 6)
        finally:
            # The native call populates these initially-null output pointers.
            # pylint: disable-next=using-constant-test
            if state.value:
                _trust(library, None, 3, 2, state.value)
            # pylint: disable-next=using-constant-test
            if certificate.value:
                crypt.CertFreeCertificateContext(certificate)


def status(path):
    """Return the released signature status using native catalog/file verification.

    :param str path: Existing local package file to inspect without modifying it.
    :returns: Windows PowerShell's observable signature-status name.
    :rtype: str
    :raises OSError: Native verification or reading the input file is unavailable.
    """
    library = ctypes.WinDLL("wintrust", use_last_error=True)
    library.WinVerifyTrust.argtypes = [ctypes.c_void_p] * 3
    library.WinVerifyTrust.restype = ctypes.c_int32
    if _catalog_valid(library, path):
        return "Valid"
    information = _FileInfo(ctypes.sizeof(_FileInfo), path, None, None)
    code, state = _trust(library, information, 1)
    try:
        return {
            0: "Valid",
            0x80090008: "Incompatible",
            0x800B0100: "NotSigned",
            0x80096010: "HashMismatch",
            0x8009200D: "HashMismatch",
            0x800B0001: "NotSupportedFileFormat",
            0x800B0111: "NotTrusted",
        }.get(code & 0xFFFFFFFF, "UnknownError")
    finally:
        _trust(library, information, 1, 2, state.state)


def _has_pattern(path):
    return re.search(r"(?<!`)(?:``)*[*?\[\]]", path) is not None


def _visible(path):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    kernel.GetFileAttributesW.restype = ctypes.c_uint32
    attributes = kernel.GetFileAttributesW(path)
    if attributes == 0xFFFFFFFF:
        raise ctypes.WinError(ctypes.get_last_error())
    return not attributes & 2


def _signature_paths(path):
    if not any(character in path for character in "*?[]`"):
        return [path]
    root, tail = ntpath.splitdrive(path.replace("/", "\\"))
    if tail.startswith("\\"):
        root += "\\"
    paths = [root or "."]
    parts = list(filter(None, tail.split("\\")))
    expand = _has_pattern(path)
    for index, part in enumerate(parts):
        if not expand or (not _has_pattern(part) and index != len(parts) - 1):
            literal = re.sub(r"`([*?\[\]`])", r"\1", part)
            paths = [ntpath.join(parent, literal) for parent in paths]
            continue
        # The filesystem provider converts escapes before wildcard matching.
        pattern = re.sub(
            r"``|`", lambda match: "`" if len(match.group(0)) == 2 else "\\", part
        )
        selected = []
        for parent in paths:
            if not os.path.isdir(parent):
                continue
            names = sorted(os.listdir(parent), key=cmp_to_key(filenames.compare_paths))
            selected.extend(
                ntpath.join(parent, name)
                for name in names
                if filenames.matches(name, [pattern])
                and _visible(ntpath.join(parent, name))
            )
        paths = selected
    return [resolved for resolved in paths if os.path.isfile(resolved)]


def verify(path):
    """Require the signature status accepted by the released Package module.

    ``FilePath`` resolves provider wildcards; it is not a literal-path check.
    The installer still receives the caller's original file, as upstream does.

    :param str path: Existing local package file, resolved before verification.
    :raises ValueError: The native signature is not valid or its inspection fails.
    """
    try:
        observed = [status(resolved) for resolved in _signature_paths(path)]
        if not observed:
            raise ValueError("You cannot call a method on a null-valued expression.")
        # The released scalar ToString check also rejects a signature array,
        # including one containing only Valid statuses.
        if observed != ["Valid"]:
            raise ValueError(
                "File '{0}': signature status is '{1}', expected 'Valid'".format(
                    path, " ".join(observed)
                )
            )
    except (OSError, ValueError) as error:
        raise ValueError("Authenticode check failed: " + str(error)) from error
