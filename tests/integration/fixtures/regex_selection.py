"""Journal and recover only the Unicode-name files owned by the regex fixture."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ctypes
import hashlib
import json
import os
import sys
import uuid

FILES = (
    "python.txt",
    "É.txt",
    "\u037f.txt",
    "\u08b3.txt",
    "\u0345.txt",
    "upperΙ.txt",
    "lowerι.txt",
    "prosι.txt",
    "1.txt",
    "😀.txt",
)
TEXT = {"mark.txt": "\u0345", "iota.txt": "Ι", "pros.txt": "ι", "astral.txt": "😀"}
STAMP = 1477984205


def _write(path, value):
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True)


def _read(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def _owned(root, nonce):
    assert os.path.basename(root).startswith("legacy-windows-regex-selection-")
    journal = _read(os.path.join(root, "journal.json"))
    assert journal["root"] == root and journal["nonce"] == nonce
    assert journal["files"] == list(FILES) and journal["texts"] == TEXT
    assert set(os.listdir(root)).issubset(
        {"files", "journal.json", "sentinel.bin"} | set(TEXT)
    )
    if os.path.isdir(os.path.join(root, "files")):
        assert set(os.listdir(os.path.join(root, "files"))).issubset(set(FILES))
    return journal


def _kernel():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    # The independent file-time observer must bind this fixed native ABI itself.
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
    # pylint: enable=duplicate-code
    kernel.SetFileTime.argtypes = [ctypes.c_void_p] + [ctypes.c_void_p] * 3
    kernel.SetFileTime.restype = ctypes.c_int
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    kernel.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    kernel.GetFileAttributesW.restype = ctypes.c_uint32
    return kernel


def _reset(root, nonce):
    _owned(root, nonce)
    kernel = _kernel()
    for name in FILES:
        stamp = ctypes.c_uint64(
            (STAMP + 11644473600) * 10000000 + (2500000 if name == "É.txt" else 0)
        )
        path = os.path.join(root, "files", name)
        handle = kernel.CreateFileW(path, 0x100, 7, None, 3, 0, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not kernel.SetFileTime(
                handle, ctypes.byref(stamp), ctypes.byref(stamp), ctypes.byref(stamp)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            assert kernel.CloseHandle(handle)
    return {"reset": True}


def _file(path):
    attributes = _kernel().GetFileAttributesW(path)
    assert attributes != 0xFFFFFFFF
    status = os.stat(path)
    with open(path, "rb") as stream:
        body = stream.read()
    return {
        "sha256": hashlib.sha256(body).hexdigest(),
        "bytes": list(body),
        "attributes": attributes,
        "mtime": status.st_mtime,
    }


def _observe(root, nonce):
    journal = _owned(root, nonce)
    assert sorted(os.listdir(os.path.join(root, "files"))) == sorted(FILES)
    return {
        "root": root,
        "nonce": nonce,
        "files": {name: _file(os.path.join(root, "files", name)) for name in FILES},
        "texts": {name: _file(os.path.join(root, name)) for name in TEXT},
        "sentinel": _file(os.path.join(root, "sentinel.bin")),
        "phase": journal["phase"],
    }


def _prepare(root):
    assert os.path.basename(root).startswith("legacy-windows-regex-selection-")
    assert os.listdir(root) == []
    nonce = uuid.uuid4().hex
    journal = {
        "root": root,
        "nonce": nonce,
        "phase": "preparing",
        "files": list(FILES),
        "texts": TEXT,
    }
    _write(os.path.join(root, "journal.json"), journal)
    os.mkdir(os.path.join(root, "files"))
    for name in FILES:
        with open(os.path.join(root, "files", name), "wb") as stream:
            stream.write(("owned Unicode regex file " + name).encode("utf-8"))
    for name, value in TEXT.items():
        with open(os.path.join(root, name), "wb") as stream:
            stream.write(b"\xef\xbb\xbf" + value.encode("utf-8"))
    with open(os.path.join(root, "sentinel.bin"), "wb") as stream:
        stream.write(b"owned protected regex sentinel\x00\xff")
    _reset(root, nonce)
    baseline = _observe(root, nonce)
    journal["phase"] = "prepared"
    baseline["phase"] = "prepared"
    journal["baseline"] = baseline
    _write(os.path.join(root, "journal.json"), journal)
    return baseline


def _cleanup(root):
    journal = _read(os.path.join(root, "journal.json"))
    nonce = journal["nonce"]
    _owned(root, nonce)
    before = _observe(root, nonce) if journal["phase"] == "prepared" else None
    if before is not None:
        assert before == journal["baseline"]
    # The pre-write journal lists the exact names; no directory-wide deletion.
    for name in FILES:
        path = os.path.join(root, "files", name)
        if os.path.isfile(path):
            os.remove(path)
    if os.path.isdir(os.path.join(root, "files")):
        os.rmdir(os.path.join(root, "files"))
    for name in list(TEXT) + ["sentinel.bin", "journal.json"]:
        path = os.path.join(root, name)
        if os.path.isfile(path):
            os.remove(path)
    os.rmdir(root)
    return {"before": before, "absent": not os.path.exists(root)}


def main():
    """Run one actual Python3.4.4 journal-owned fixture operation."""
    assert sys.version_info[:3] == (3, 4, 4)
    operation, root = sys.argv[1:3]
    if operation == "prepare":
        result = _prepare(root)
    elif operation == "cleanup":
        result = _cleanup(root)
    else:
        assert operation in ("observe", "reset")
        result = {"observe": _observe, "reset": _reset}[operation](root, sys.argv[3])
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
