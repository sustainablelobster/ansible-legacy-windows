# SPDX-License-Identifier: GPL-3.0-or-later
"""Journal and move only the validated Windows Update cache in a VM snapshot."""

import base64
import ctypes
import hashlib
import json
import os
import sys


def _libraries():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetWindowsDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    kernel.GetWindowsDirectoryW.restype = ctypes.c_uint32
    kernel.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    kernel.GetFileAttributesW.restype = ctypes.c_uint32
    # The cache ownership journal needs fixed ABI bindings independent of WUA.
    # pylint: disable=duplicate-code
    kernel.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    kernel.CreateFileW.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    kernel.GetFileInformationByHandle.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    kernel.GetFileInformationByHandle.restype = ctypes.c_int
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    security.GetFileSecurityW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    security.GetFileSecurityW.restype = ctypes.c_int
    # pylint: enable=duplicate-code
    return kernel, security


def _attributes(kernel, path):
    attributes = kernel.GetFileAttributesW(path)
    if attributes == 0xFFFFFFFF:
        error = ctypes.WinError(ctypes.get_last_error())
        error.filename = path
        raise error
    if attributes & 0x400:
        raise OSError("Refusing a reparse point in the cache journal: " + path)
    return attributes


def _security(security, path):
    required = ctypes.c_uint32()
    if security.GetFileSecurityW(path, 7, None, 0, ctypes.byref(required)):
        raise OSError("Unexpected empty cache security descriptor.")
    if ctypes.get_last_error() != 122 or not required.value:
        raise ctypes.WinError(ctypes.get_last_error())
    buffer = ctypes.create_string_buffer(required.value)
    if not security.GetFileSecurityW(
        path, 7, buffer, len(buffer), ctypes.byref(required)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return base64.b64encode(buffer.raw[: required.value]).decode("ascii")


def _identity(kernel, security, path):
    attributes = _attributes(kernel, path)
    if not attributes & 16:
        raise OSError("The journaled cache path is not a directory.")
    handle = kernel.CreateFileW(path, 0, 7, None, 3, 0x02000000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    # BY_HANDLE_FILE_INFORMATION is thirteen consecutive DWORDs, including the
    # three FILETIMEs. Only volume/file IDs and attributes establish this target.
    information = (ctypes.c_uint32 * 13)()
    try:
        if not kernel.GetFileInformationByHandle(handle, information):
            raise ctypes.WinError(ctypes.get_last_error())
        return {
            "path": path,
            "attributes": attributes,
            "volume": information[7],
            "file_id": [information[11], information[12]],
            "security": _security(security, path),
        }
    finally:
        if not kernel.CloseHandle(handle):
            raise ctypes.WinError(ctypes.get_last_error())


def _path(kernel):
    buffer = ctypes.create_unicode_buffer(32768)
    length = kernel.GetWindowsDirectoryW(buffer, len(buffer))
    if not length or length >= len(buffer):
        raise ctypes.WinError(ctypes.get_last_error())
    # Current cumulative-update payloads contain measured paths over MAX_PATH.
    # Python3.4 and native wide APIs accept the established extended local path.
    return "\\\\?\\" + os.path.join(buffer.value, "SoftwareDistribution")


def _file(kernel, root, path):
    attributes = _attributes(kernel, path)
    before = os.stat(path)
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    after = os.stat(path)
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise OSError("The cache file changed during its content journal: " + path)
    return {
        "path": os.path.relpath(path, root),
        "attributes": attributes,
        "length": after.st_size,
        "mtime_ns": after.st_mtime_ns,
        "sha256": digest.hexdigest(),
    }


def observe():
    """Capture literal cache identity, root security and every file's content.

    :returns: Exact file paths, directory attributes, lengths, write times and SHA256s.
    :rtype: dict
    :raises OSError: Native identity/security or stable file reading fails.
    """
    kernel, security = _libraries()
    root = _path(kernel)
    result = {
        "identity": _identity(kernel, security, root),
        "directories": [],
        "files": [],
    }
    for parent, directories, files in os.walk(root):
        directories.sort()
        files.sort()
        # Validate each child before os.walk can descend into it; Python3.4's
        # Windows junction handling must not broaden this literal cache target.
        for name in directories:
            _attributes(kernel, os.path.join(parent, name))
        result["directories"].append(
            {
                "path": os.path.relpath(parent, root),
                "attributes": _attributes(kernel, parent),
            }
        )
        for name in files:
            path = os.path.join(parent, name)
            result["files"].append(_file(kernel, root, path))
    return result


def prepare(expected):
    """Move the exact journaled cache to its uniquely absent sibling.

    :param dict expected: Controller-retained identity and exact owned sibling name.
    :returns: Validated original and backup identities after the same-volume move.
    :rtype: dict
    :raises OSError: Identity differs, a target exists, or the native rename fails.
    """
    kernel, security = _libraries()
    root = _path(kernel)
    if _identity(kernel, security, root) != expected["identity"]:
        raise OSError(
            "The cache directory no longer matches its original identity/security."
        )
    backup = root + ".legacy-updates-public-v2-110"
    if expected["backup"] != backup or os.path.lexists(backup):
        raise OSError(
            "The uniquely owned cache backup is not the exact absent sibling."
        )
    os.rename(root, backup)
    return {
        "original": expected["identity"],
        "backup": _identity(kernel, security, backup),
    }


if __name__ == "__main__":
    if sys.version_info[:3] != (3, 4, 4):
        raise OSError("This cache fixture requires actual Python3.4.4.")
    print(
        json.dumps(
            observe() if sys.argv[1] == "observe" else prepare(json.loads(sys.argv[2]))
        )
    )
