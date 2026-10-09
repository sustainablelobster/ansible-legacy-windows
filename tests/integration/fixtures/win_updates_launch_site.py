"""Deny execution of only an owned test interpreter after its frontend starts."""

# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later
# This fixture never changes the installed interpreter, WUA, or production code.

import atexit
import binascii
import ctypes
import hashlib
import json
import os
import sys
import time


# Keep the exact native ACL layouts independent of the production launcher;
# sharing them here would preload target helpers before the real payload starts.
# pylint: disable=duplicate-code
class _Trustee(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("multiple", ctypes.c_void_p),
        ("operation", ctypes.c_int),
        ("form", ctypes.c_int),
        ("kind", ctypes.c_int),
        ("name", ctypes.c_void_p),
    ]


class _Access(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("permissions", ctypes.c_uint32),
        ("mode", ctypes.c_int),
        ("inheritance", ctypes.c_uint32),
        ("trustee", _Trustee),
    ]


# pylint: enable=duplicate-code


def _apis():
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.c_void_p
    out = ctypes.POINTER(pointer)
    # These fixed Windows signatures stay independent of production helpers;
    # importing those here could alter the payload's module-import provenance.
    # pylint: disable=duplicate-code
    security.OpenProcessToken.argtypes = [pointer, ctypes.c_uint32, out]
    security.OpenProcessToken.restype = ctypes.c_int
    security.GetTokenInformation.argtypes = [
        pointer,
        ctypes.c_int,
        pointer,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    security.GetTokenInformation.restype = ctypes.c_int
    security.ConvertSidToStringSidW.argtypes = [pointer, out]
    security.ConvertSidToStringSidW.restype = ctypes.c_int
    security.ConvertStringSidToSidW.argtypes = [ctypes.c_wchar_p, out]
    security.ConvertStringSidToSidW.restype = ctypes.c_int
    # pylint: enable=duplicate-code
    security.GetNamedSecurityInfoW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_uint32,
        out,
        out,
        out,
        out,
        out,
    ]
    security.GetNamedSecurityInfoW.restype = ctypes.c_uint32
    security.SetNamedSecurityInfoW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_uint32,
        pointer,
        pointer,
        pointer,
        pointer,
    ]
    security.SetNamedSecurityInfoW.restype = ctypes.c_uint32
    security.SetEntriesInAclW.argtypes = [
        ctypes.c_uint32,
        ctypes.POINTER(_Access),
        pointer,
        out,
    ]
    security.SetEntriesInAclW.restype = ctypes.c_uint32
    kernel.GetCurrentProcess.restype = pointer
    kernel.CloseHandle.argtypes = [pointer]
    kernel.CloseHandle.restype = ctypes.c_int
    kernel.LocalFree.argtypes = [pointer]
    kernel.LocalFree.restype = pointer
    return security, kernel


def _sid():
    security, kernel = _apis()
    token, text, length = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_uint32()
    if not security.OpenProcessToken(
        kernel.GetCurrentProcess(), 8, ctypes.byref(token)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        assert not security.GetTokenInformation(token, 1, None, 0, ctypes.byref(length))
        assert ctypes.get_last_error() == 122
        buffer = ctypes.create_string_buffer(length.value)
        if not security.GetTokenInformation(
            token, 1, buffer, length.value, ctypes.byref(length)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if not security.ConvertSidToStringSidW(
            ctypes.c_void_p.from_buffer(buffer), ctypes.byref(text)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return ctypes.wstring_at(text)
    finally:
        if text:
            kernel.LocalFree(text)
        kernel.CloseHandle(token)


def _acl_bytes(pointer):
    assert pointer
    length = ctypes.c_uint16.from_address(pointer.value + 2).value
    assert 8 <= length <= 0xFFFF
    return ctypes.string_at(pointer, length)


def _dacl(image):
    security, kernel = _apis()
    dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
    status = security.GetNamedSecurityInfoW(
        image, 1, 4, None, None, ctypes.byref(dacl), None, ctypes.byref(descriptor)
    )
    if status:
        raise ctypes.WinError(status)
    try:
        return _acl_bytes(dacl)
    finally:
        kernel.LocalFree(descriptor)


def _set_dacl(image, value):
    security = _apis()[0]
    data = ctypes.create_string_buffer(value)
    # The fixture prepares a protected DACL on this new copied file only.
    status = security.SetNamedSecurityInfoW(
        image, 1, 0x80000004, None, None, data, None
    )
    if status:
        raise ctypes.WinError(status)


def _deny(original, sid):
    security, kernel = _apis()
    native_sid, revised = ctypes.c_void_p(), ctypes.c_void_p()
    if not security.ConvertStringSidToSidW(sid, ctypes.byref(native_sid)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        access = _Access(0x20, 3, 0, _Trustee(None, 0, 0, 1, native_sid.value))
        status = security.SetEntriesInAclW(
            1,
            ctypes.byref(access),
            ctypes.create_string_buffer(original),
            ctypes.byref(revised),
        )
        if status:
            raise ctypes.WinError(status)
        return _acl_bytes(revised)
    finally:
        if revised:
            kernel.LocalFree(revised)
        kernel.LocalFree(native_sid)


def _hash(path):
    with open(path, "rb") as stream:
        return hashlib.sha256(stream.read()).hexdigest()


def _write(path, value):
    with open(path, "x", encoding="utf-8") as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())


def _read(root):
    with open(
        os.path.join(root, "copied-image-security.json"), encoding="utf-8"
    ) as stream:
        return json.load(stream)


def _restore(config):
    original = binascii.unhexlify(config["original"])
    revised = binascii.unhexlify(config["revised"])
    assert _dacl(config["image"]) in (
        original,
        revised,
    ), "The owned image DACL changed outside this fixture."
    _set_dacl(config["image"], original)
    assert _dacl(config["image"]) == original


def _should_deny(executable, script, sid, config):
    return (
        sid == config["sid"] != "S-1-5-18"
        and os.path.normcase(os.path.abspath(executable))
        == os.path.normcase(config["image"])
        and os.path.basename(script).lower()
        in (
            "ansiballz_win_updates.py",
            "win_updates_launch_lifecycle.py",
        )
    )


def _script_argument(arguments):
    for value in arguments[1:]:
        if value in ("-c", "-m", "-") or not value.startswith("-"):
            return value
    return ""


def _startup_script():
    # Python 3.4 imports site before initializing sys.argv. Read the actual
    # process command line through Windows' parser, not a guessed Python argv.
    kernel = _apis()[1]
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    kernel.GetCommandLineW.argtypes = []
    kernel.GetCommandLineW.restype = ctypes.c_wchar_p
    shell.CommandLineToArgvW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
    shell.CommandLineToArgvW.restype = ctypes.POINTER(ctypes.c_wchar_p)
    count = ctypes.c_int()
    arguments = shell.CommandLineToArgvW(kernel.GetCommandLineW(), ctypes.byref(count))
    if not arguments:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return _script_argument([arguments[index] for index in range(count.value)])
    finally:
        if kernel.LocalFree(arguments):
            raise ctypes.WinError(ctypes.get_last_error())


def _event(root, name, config, script):
    with open(
        os.path.join(root, "copied-image-events.jsonl"), "a", encoding="utf-8"
    ) as stream:
        stream.write(
            json.dumps(
                {
                    "event": name,
                    "pid": os.getpid(),
                    "time": time.time(),
                    "script": os.path.basename(script),
                    "sid": config["sid"],
                }
            )
            + "\n"
        )
        stream.flush()
        os.fsync(stream.fileno())


def _activate():
    root = os.path.dirname(os.path.abspath(__file__))
    if not os.path.isfile(os.path.join(root, "deny-owned-image.enabled")):
        return
    config = _read(root)
    script = _startup_script()
    if not _should_deny(sys.executable, script, _sid(), config):
        return
    assert sys.version_info[:3] == (3, 4, 4)
    assert _hash(config["image"]) == config["image_sha256"]
    original, revised = (
        binascii.unhexlify(config[name]) for name in ("original", "revised")
    )
    assert _dacl(config["image"]) == original

    def restore():
        _restore(config)
        _event(root, "restored", config, script)

    # Register recovery before the native write; it accepts only recorded ACLs.
    atexit.register(restore)
    _set_dacl(config["image"], revised)
    assert _dacl(config["image"]) == revised
    _event(root, "denied", config, script)


def main():
    """Prepare, enable, inspect or restore the exclusive copied image fixture.

    :raises AssertionError: Runtime, ownership, image hash or ACL gates fail.
    :raises OSError: A native operation or durable journal operation fails.
    :raises ValueError: The requested operation is unknown.
    """
    root, operation = sys.argv[1:]
    assert os.path.basename(root).startswith("legacy-windows-updates-runas-")
    path = os.path.join(root, "copied-image-security.json")
    marker = os.path.join(root, "deny-owned-image.enabled")
    if operation == "setup":
        image = os.path.join(root, "python.exe")
        original = _dacl(image)
        config = {
            "sid": _sid(),
            "image": image,
            "image_sha256": _hash(image),
            "dll_sha256": _hash(os.path.join(root, "python34.dll")),
            "original": binascii.hexlify(original).decode("ascii"),
        }
        revised = _deny(original, config["sid"])
        config["revised"] = binascii.hexlify(revised).decode("ascii")
        _write(path, config)
        # Establish exact file-DACL roundtrips before enabling any frontend gate.
        _set_dacl(image, revised)
        assert _dacl(image) == revised
        _restore(config)
        result = config
    elif operation == "enable":
        _write(marker, {"enabled": True})
        result = {"enabled": True}
    elif operation in ("observe", "restore"):
        config = _read(root)
        if operation == "restore":
            if os.path.exists(marker):
                os.remove(marker)
            _restore(config)
        events = []
        event_path = os.path.join(root, "copied-image-events.jsonl")
        if os.path.exists(event_path):
            with open(event_path, encoding="utf-8") as stream:
                events = [json.loads(line) for line in stream]
        result = {
            "original_dacl": _dacl(config["image"])
            == binascii.unhexlify(config["original"]),
            "image_hash_unchanged": _hash(config["image"]) == config["image_sha256"],
            "dll_hash_unchanged": _hash(os.path.join(root, "python34.dll"))
            == config["dll_sha256"],
            "events": events,
            "gate_disabled": not os.path.exists(marker),
        }
    else:
        raise ValueError("Unknown copied-image fixture operation")
    print(json.dumps(result))


if __name__ == "sitecustomize":
    _activate()
elif __name__ == "__main__":
    main()
