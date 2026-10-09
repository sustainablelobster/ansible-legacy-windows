# SPDX-License-Identifier: GPL-3.0-or-later
"""Own custom setup inputs and observe protected state without host changes."""

import base64
import ctypes
import hashlib
import json
import os
import struct
import sys
import tempfile
import time
import winreg  # pylint: disable=import-error

_JOURNAL = "setup-journal.json"
_DIRECTORIES = ("json-facts", "script-facts", "timeout-facts")
_REGISTRY = (
    ("user_environment", "HKEY_CURRENT_USER", r"Environment"),
    (
        "machine_environment",
        "HKEY_LOCAL_MACHINE",
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
    ),
    (
        "timezone",
        "HKEY_LOCAL_MACHINE",
        r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation",
    ),
    (
        "computer_name",
        "HKEY_LOCAL_MACHINE",
        r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName",
    ),
)


def _root(path):
    path = os.path.abspath(path)
    if not os.path.basename(path).startswith("legacy-windows-setup-"):
        raise ValueError("Not an allocated setup workspace.")
    # XP/2003 often spell TEMP using 8.3 aliases. Compare the directory's
    # identity, not its spelling; neither a sibling nor a nested path is owned.
    if not os.path.samefile(os.path.dirname(path), tempfile.gettempdir()):
        raise ValueError(
            "The setup workspace is outside the target temporary directory."
        )
    # This workspace guard must observe attributes independently of Setup.
    # pylint: disable=duplicate-code
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    kernel.GetFileAttributesW.restype = ctypes.c_uint32
    attributes = kernel.GetFileAttributesW(path)
    if attributes == 0xFFFFFFFF:
        raise ctypes.WinError(ctypes.get_last_error())
    # pylint: enable=duplicate-code
    if not attributes & 0x10 or attributes & 0x400:
        raise ValueError("The setup workspace must be an ordinary owned directory.")
    return path


def _registry_values(hive, path):
    # Recovery reads real registry values without the tested Setup helper.
    # pylint: disable=duplicate-code
    try:
        key = winreg.OpenKey(
            getattr(winreg, hive), path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        )
    except OSError as error:
        # Registry errors have winerror on Windows; controller type stubs omit it.
        # pylint: disable-next=no-member
        if error.winerror in (2, 3):
            return None
        raise
    # pylint: enable=duplicate-code
    # Keep journal enumeration independent of the Setup payload's registry reads.
    # pylint: disable=duplicate-code
    with key:
        values = []
        for index in range(winreg.QueryInfoKey(key)[1]):
            name, value, kind = winreg.EnumValue(key, index)
            if isinstance(value, bytes):
                value = {"base64": base64.b64encode(value).decode("ascii")}
            values.append({"name": name, "kind": kind, "value": value})
        return sorted(values, key=lambda value: value["name"])
    # pylint: enable=duplicate-code


def _protected_state():
    return {label: _registry_values(hive, path) for label, hive, path in _REGISTRY}


def _file(path):
    with open(path, "rb") as stream:
        digest = hashlib.sha256(stream.read()).hexdigest()
    # These fixed bindings keep the sibling-file oracle independent of Setup.
    # pylint: disable=duplicate-code
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    kernel.GetFileAttributesW.restype = ctypes.c_uint32
    attributes = kernel.GetFileAttributesW(path)
    if attributes == 0xFFFFFFFF:
        raise ctypes.WinError(ctypes.get_last_error())
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
    needed = ctypes.c_uint32()
    security.GetFileSecurityW(path, 7, None, 0, ctypes.byref(needed))
    if not needed.value:
        raise ctypes.WinError(ctypes.get_last_error())
    descriptor = ctypes.create_string_buffer(needed.value)
    if not security.GetFileSecurityW(
        path, 7, descriptor, len(descriptor), ctypes.byref(needed)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return {
        "sha256": digest,
        "attributes": attributes,
        "mtime_ns": os.stat(path).st_mtime_ns,
        "security": base64.b64encode(descriptor.raw[: needed.value]).decode("ascii"),
    }


def _write(path, value, encoding="utf-8"):
    with open(path, "x", encoding=encoding) as stream:
        json.dump(value, stream, ensure_ascii=False)


def _read(root):
    with open(os.path.join(root, _JOURNAL), encoding="utf-8") as stream:
        journal = json.load(stream)
    if journal["workspace"] != root:
        raise ValueError("Setup journal does not own this literal workspace.")
    return journal


def _timeout_process(root):
    path = os.path.join(root, "timeout-identity.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8-sig") as stream:
        identity = json.load(stream)
    # Process-birth validation cannot rely on the custom-fact process itself.
    # pylint: disable=duplicate-code
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    kernel.GetProcessTimes.argtypes = [ctypes.c_void_p] + [
        ctypes.POINTER(ctypes.c_uint64)
    ] * 4
    kernel.GetProcessTimes.restype = ctypes.c_int
    kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel.WaitForSingleObject.restype = ctypes.c_uint32
    # pylint: enable=duplicate-code
    handle = kernel.OpenProcess(0x100400, False, identity["pid"])
    if not handle:
        error = ctypes.get_last_error()
        if error != 87:
            raise ctypes.WinError(error)
        return dict(identity, stopped=True)
    try:
        created, exited, system, user = [ctypes.c_uint64() for _ in range(4)]
        if not kernel.GetProcessTimes(
            handle,
            ctypes.byref(created),
            ctypes.byref(exited),
            ctypes.byref(system),
            ctypes.byref(user),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        # A reused PID belongs to somebody else; never terminate or reject it.
        stopped = (
            created.value != identity["created"]
            or kernel.WaitForSingleObject(handle, 0) == 0
        )
        if not stopped:
            raise ValueError("The literal owned custom-fact process is still running.")
        return dict(identity, stopped=True)
    finally:
        if not kernel.CloseHandle(handle):
            raise ctypes.WinError(ctypes.get_last_error())


def _prepare(root):
    if os.listdir(root):
        raise ValueError("Setup preparation requires a new empty workspace.")
    journal = {"workspace": root, "before": _protected_state()}
    _write(os.path.join(root, _JOURNAL), journal)
    with open(os.path.join(root, "protected.bin"), "xb") as stream:
        stream.write(b"setup protected sibling\x00\xff")
    for name in _DIRECTORIES:
        os.mkdir(os.path.join(root, name))
    inputs = {
        "object": {"message": "Café 雪", "number": 3, "nested": {"null": None}},
        "false": False,
        "zero": 0,
        "null": None,
        "empty": [],
        "single": [{"value": "one"}],
        "array": [1, "two", False, None],
    }
    for name, value in inputs.items():
        _write(os.path.join(root, "json-facts", name + ".json"), value, "utf-8-sig")
    _write(os.path.join(root, "json-facts", "ignored.JSON"), {"ignored": True})
    os.mkdir(os.path.join(root, "json-facts", "ignored-directory.json"))
    with open(
        os.path.join(root, "script-facts", "owned.ps1"), "x", encoding="utf-8-sig"
    ) as stream:
        stream.write("@{message='Café 雪'; count=3; nested=@{nothing=$null}}\n")
    with open(
        os.path.join(root, "timeout-facts", "owned.ps1"), "x", encoding="utf-8"
    ) as stream:
        identity_path = os.path.join(root, "timeout-identity.json").replace("'", "''")
        stream.write(
            "@{pid=$PID; created=[Diagnostics.Process]::GetCurrentProcess()."
            "StartTime.ToFileTimeUtc()} "
            "| ConvertTo-Json -Compress | Set-Content -Encoding UTF8 -LiteralPath '"
            + identity_path
            + "'\nStart-Sleep -Seconds 30\n@{unexpected='late'}\n"
        )
    protected = _file(os.path.join(root, "protected.bin"))
    _write(os.path.join(root, "setup-protected.json"), protected)
    return {"prepared": True, "before": journal["before"], "protected": protected}


def _observe(root):
    journal = _read(root)
    current = _protected_state()
    with open(os.path.join(root, "setup-protected.json"), encoding="utf-8") as stream:
        protected = json.load(stream)
    actual = _file(os.path.join(root, "protected.bin"))
    if current != journal["before"] or actual != protected:
        raise ValueError("Setup changed the protected registry values or sibling file.")
    return {
        "protected": actual,
        "configuration": current,
        "epoch": time.time(),
        "timeout_process": _timeout_process(root),
    }


def _observe_dynamic(root):
    result = _observe(root)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetTickCount64.argtypes, kernel.GetTickCount64.restype = [], ctypes.c_uint64
    kernel.GlobalMemoryStatusEx.argtypes = [ctypes.c_void_p]
    kernel.GlobalMemoryStatusEx.restype = ctypes.c_int
    memory = ctypes.create_string_buffer(struct.pack("<II7Q", 64, *([0] * 8)), 64)
    if not kernel.GlobalMemoryStatusEx(memory):
        raise ctypes.WinError(ctypes.get_last_error())
    fields = struct.unpack("<II7Q", memory.raw)
    result["physical_total_bytes"] = fields[2]
    result["physical_available_bytes"] = fields[3]
    result["tick_milliseconds"] = kernel.GetTickCount64()
    result["epoch"] = time.time()
    return result


def _cleanup(root):
    result = _observe(root)
    expected = {_JOURNAL, "setup-protected.json", "protected.bin"}.union(_DIRECTORIES)
    if os.path.isfile(os.path.join(root, "timeout-identity.json")):
        expected.add("timeout-identity.json")
    if set(os.listdir(root)) != expected:
        raise ValueError("Unexpected entries remain in the setup workspace.")
    expected_inputs = {
        "json-facts": {
            "object.json",
            "false.json",
            "zero.json",
            "null.json",
            "empty.json",
            "single.json",
            "array.json",
            "ignored.JSON",
            "ignored-directory.json",
        },
        "script-facts": {"owned.ps1"},
        "timeout-facts": {"owned.ps1"},
    }
    for name, inputs in expected_inputs.items():
        directory = os.path.join(root, name)
        if set(os.listdir(directory)) != inputs:
            raise ValueError("Unexpected custom-fact entries remain in " + name + ".")
    result["restored"] = True
    result["before"] = _read(root)["before"]
    result["after"] = result.pop("configuration")
    return result


def main():
    """Execute only the declared owned fixture phase.

    :raises ValueError: Fixture ownership or literal protected recovery fails.
    :raises OSError: Native observation or an owned file operation fails.
    """
    if sys.version_info[:3] != (3, 4, 4):
        raise ValueError("Setup fixture requires actual Python 3.4.4.")
    operations = {
        "prepare": _prepare,
        "observe": _observe,
        "observe_dynamic": _observe_dynamic,
        "cleanup": _cleanup,
    }
    root = _root(sys.argv[1])
    result = operations[sys.argv[2]](root)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
