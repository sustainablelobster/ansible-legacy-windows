"""Observe exact owned files and staging without creating task directories."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import ctypes
import glob
import json
import os
import sys
import tempfile


def _attributes(path):
    function = ctypes.windll.kernel32.GetFileAttributesW
    function.argtypes = [ctypes.c_wchar_p]
    function.restype = ctypes.c_ulong
    value = function(path)
    if value == 0xFFFFFFFF:
        raise ctypes.WinError()
    return int(value)


def snapshot(root=None):
    """Read literal protected bytes/metadata and current global staging.

    :param root: Exact owned workspace, or None for initial/final staging.
    :type root: str or None
    :returns: JSON-compatible observation without any file or configuration write.
    :rtype: dict
    :raises OSError: If an owned existing path cannot be observed.
    """
    result = {
        "python": list(sys.version_info[:3]),
        "root": root,
        "staging": sorted(
            glob.glob(os.path.join(tempfile.gettempdir(), "ansible-tmp-*"))
        ),
        "root_exists": root is not None and os.path.exists(root),
        "files": {},
        "directories": [],
    }
    if result["root_exists"]:
        for directory, folders, names in os.walk(root):
            result["directories"].extend(
                sorted(
                    os.path.relpath(os.path.join(directory, name), root)
                    for name in folders
                )
            )
            for name in sorted(names):
                path = os.path.join(directory, name)
                info = os.stat(path)
                with open(path, "rb") as stream:
                    data = stream.read()
                result["files"][os.path.relpath(path, root)] = {
                    "data": base64.b64encode(data).decode("ascii"),
                    "attributes": _attributes(path),
                    "mtime_ns": info.st_mtime_ns,
                    "size": info.st_size,
                }
    return result


if __name__ == "__main__":
    assert sys.version_info[:3] == (3, 4, 4)
    print(
        json.dumps(snapshot(sys.argv[1] if len(sys.argv) > 1 else None), sort_keys=True)
    )
