"""Observe only owned Slurp inputs and the actual Windows runtime."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import ctypes
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile


# ctypes structures declare an ABI rather than a method-bearing object model.
# Keep the fixed OSVERSIONINFOEX layout independent of the tested Slurp payload.
# pylint: disable=duplicate-code
class NativeVersion(ctypes.Structure):  # pylint: disable=too-few-public-methods
    """Native Windows version, independent of the Python executable manifest."""

    _fields_ = [
        ("size", ctypes.c_uint32),
        ("major", ctypes.c_uint32),
        ("minor", ctypes.c_uint32),
        ("build", ctypes.c_uint32),
        ("platform", ctypes.c_uint32),
        ("service_pack", ctypes.c_uint16 * 128),
        ("service_pack_major", ctypes.c_uint16),
        ("service_pack_minor", ctypes.c_uint16),
        ("suite", ctypes.c_uint16),
        ("product_type", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8),
    ]


# pylint: enable=duplicate-code


def _observe():
    native = ctypes.WinDLL("ntdll", use_last_error=True)
    native.RtlGetVersion.argtypes = [ctypes.POINTER(NativeVersion)]
    native.RtlGetVersion.restype = ctypes.c_int32
    version = NativeVersion(size=ctypes.sizeof(NativeVersion))
    status = native.RtlGetVersion(ctypes.byref(version))
    if status < 0:
        raise OSError("RtlGetVersion failed: 0x{0:08X}".format(status & 0xFFFFFFFF))
    return {
        "python": list(sys.version_info[:3]),
        "windows_version": [version.major, version.minor],
        "mac": subprocess.check_output(
            # This literal flag selects CSV formatting in the native command.
            ["getmac", "/fo", "csv", "/nh"]  # codespell:ignore fo
        ).decode("ascii"),
        "staging": sorted(
            glob.glob(os.path.join(tempfile.gettempdir(), "ansible-tmp-*"))
        ),
    }


def _files(root):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    kernel.GetFileAttributesW.restype = ctypes.c_uint32
    result = {}
    for name in ("binary.bin", "binary [literal] \u96ea.bin"):
        path = os.path.join(root, name)
        attributes = kernel.GetFileAttributesW(path)
        if attributes == 0xFFFFFFFF:
            raise ctypes.WinError(ctypes.get_last_error())
        with open(path, "rb") as stream:
            data = stream.read()
        result[name] = {
            "bytes": base64.b64encode(data).decode("ascii"),
            "attributes": attributes,
            "mtime_ns": os.stat(path).st_mtime_ns,
        }
    assert sorted(os.listdir(root)) == sorted(list(result) + ["directory"])
    assert os.path.isdir(os.path.join(root, "directory"))
    return result


def main():
    """Prepare, inspect or remove exclusively owned inputs.

    :raises AssertionError: If runtime, ownership or protected inputs differ.
    """
    operation = sys.argv[1]
    observation = _observe()
    assert observation["python"] == [3, 4, 4]
    assert observation["windows_version"] == json.loads(sys.argv[2])
    assert sys.argv[3].replace(":", "-").upper() in observation["mac"].upper()
    if operation == "prepare":
        root = tempfile.mkdtemp(prefix="legacy-slurp-inputs-")
        os.mkdir(os.path.join(root, "directory"))
        for name in ("binary.bin", "binary [literal] \u96ea.bin"):
            with open(os.path.join(root, name), "wb") as stream:
                stream.write(bytes(bytearray(range(256))) + b"\x00\xff\r\n")
        print(json.dumps({"root": root, "runtime": observation, "files": _files(root)}))
        return
    root = sys.argv[4]
    assert os.path.dirname(root).lower() == tempfile.gettempdir().lower()
    assert os.path.basename(root).startswith("legacy-slurp-inputs-")
    assert os.path.isdir(root) and not os.path.islink(root)
    files = _files(root)
    if operation == "cleanup":
        shutil.rmtree(root)
        assert not os.path.exists(root)
    else:
        assert operation == "inspect"
    print(
        json.dumps(
            {
                "root": root,
                "runtime": observation,
                "files": files,
                "root_absent": not os.path.exists(root),
            }
        )
    )


if __name__ == "__main__":
    main()
