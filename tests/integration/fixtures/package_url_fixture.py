"""Extend the measured owned MSI fixture with exact HTTP process recovery."""

# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import ctypes
import glob
import json
import ntpath
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from urllib.request import urlopen

import package_msp_fixture as base  # pylint: disable=import-error

# Reuse the frozen fixture's exact owned-product and recovery boundary rather
# than duplicate its catalogue, ACL and service observations.
# pylint: disable=protected-access

ROOT, OPERATION = sys.argv[1:3]


def _api():
    library = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer, dword = ctypes.c_void_p, ctypes.c_uint32
    for name, result, arguments in (
        ("OpenProcess", pointer, [dword, ctypes.c_int32, dword]),
        ("GetProcessTimes", ctypes.c_int32, [pointer] * 5),
        ("WaitForSingleObject", dword, [pointer, dword]),
        ("TerminateProcess", ctypes.c_int32, [pointer, dword]),
        ("CloseHandle", ctypes.c_int32, [pointer]),
    ):
        function = getattr(library, name)
        function.restype, function.argtypes = result, arguments
    return library


def _creation(library, handle):
    times = [ctypes.c_uint64() for _index in range(4)]
    assert library.GetProcessTimes(handle, *[ctypes.byref(value) for value in times])
    return times[0].value


def _temporary_directories():
    return sorted(
        glob.glob(os.path.join(tempfile.gettempdir(), "legacy-windows-package-url-*"))
    )


def _requests():
    path = os.path.join(ROOT, "requests.jsonl")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as stream:
        return [json.loads(line) for line in stream]


def _directory_records():
    with open(os.path.join(ROOT, "directories.json"), encoding="utf-8") as stream:
        return json.load(stream)


def _portable_uninstall_keys(snapshot, observed):
    keys = copy.deepcopy(snapshot["uninstall_keys"])
    for values in keys.values():
        for index, value in enumerate(values or []):
            if value[0] != "InstallSource":
                continue
            assert value[2] == 1 and isinstance(value[1], str)
            assert value[1].endswith("\\")
            directory = value[1][:-1]
            if ntpath.normcase(directory) == ntpath.normcase(ROOT):
                continue
            parent, name = ntpath.dirname(directory), ntpath.basename(directory)
            native = ntpath.normcase(parent) == ntpath.normcase(
                tempfile.gettempdir()
            ) and re.match(r"^legacy-windows-package-url-[a-z0-9_]{8}$", name)
            original = ntpath.normcase(parent) == ntpath.normcase(ROOT) and re.match(
                r"^ansible-moduletmp-[0-9]+-[0-9]+-[0-9]+$", name
            )
            assert native or original, directory
            proofs = [
                entry
                for entry in observed
                if ntpath.normcase(entry["path"]) == ntpath.normcase(directory)
            ]
            assert len(proofs) == 1, (directory, proofs)
            assert proofs[0]["attributes"] & 0x10
            assert not proofs[0]["attributes"] & 0x400
            assert proofs[0]["creation"] <= proofs[0]["observed"]
            assert not os.path.exists(directory)
            values[index] = (
                value[0],
                "<owned-downloaded-package-directory>\\",
                value[2],
            )
    return keys


def _server(record):
    with open(os.path.join(ROOT, "server.json"), encoding="utf-8") as stream:
        information = json.load(stream)
    assert {key: information[key] for key in ("pid", "creation", "token")} == {
        key: record["url"][key] for key in ("pid", "creation", "token")
    }
    library = _api()
    handle = library.OpenProcess(0x400 | 0x100000, False, information["pid"])
    assert handle
    try:
        assert _creation(library, handle) == information["creation"]
        assert library.WaitForSingleObject(handle, 0) == 0x102
    finally:
        library.CloseHandle(handle)
    assert base._file_state(os.path.join(ROOT, "server.py")) == record["url"]["script"]
    return information


def _journal():
    observed = base._journal()
    record = base._read()
    record["url"] = {"temporary_directories": _temporary_directories()}
    base._write(record)
    return observed


def _setup():
    observed = base._setup()
    record, library = base._read(), _api()
    record["url"].update(
        token=uuid.uuid4().hex,
        script=base._file_state(os.path.join(ROOT, "server.py")),
    )
    base._write(record)
    # This detached server deliberately outlives the setup call; cleanup owns
    # its exact creation identity. A context manager would wait here for20min.
    # pylint: disable-next=consider-using-with
    child = subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "server.py"), ROOT, record["url"]["token"]],
        creationflags=0x1000000 | 8 | 512,
        close_fds=True,
    )
    try:
        # Windows Popen owns this native handle; Linux's stub has no such field.
        handle = int(child._handle)  # pylint: disable=no-member
        record["url"].update(pid=child.pid, creation=_creation(library, handle))
        base._write(record)
    except BaseException:
        if child.poll() is None:
            child.terminate()
        assert child.wait(timeout=5) is not None
        raise
    for _attempt in range(100):
        if os.path.exists(os.path.join(ROOT, "server.json")):
            information = _server(record)
            address = "http://127.0.0.1:{0}".format(information["port"])
            with urlopen(address + "/health/" + record["url"]["token"]) as response:
                assert response.read().decode("ascii") == record["url"]["token"]
            for _directory_attempt in range(100):
                if os.path.exists(os.path.join(ROOT, "directories.json")):
                    break
                time.sleep(0.01)
            assert os.path.isfile(os.path.join(ROOT, "directories.json"))
            return dict(observed, http=address, server=information)
        assert child.poll() is None
        time.sleep(0.05)
    raise ValueError("Owned package HTTP fixture did not become ready")


def _prepare():
    _server(base._read())
    observed = base._prepare()
    record = base._read()
    record["url"].update(
        offset=len(_requests()),
        started=time.time(),
        directory_offset=len(_directory_records()),
    )
    base._write(record)
    return dict(observed, started=record["url"]["started"])


def _observe():
    record = base._read()
    _server(record)
    assert _temporary_directories() == record["url"]["temporary_directories"]
    snapshot = base._snapshot()
    directories = _directory_records()[record["url"]["directory_offset"] :]
    directories = [
        dict(entry, absent=not os.path.exists(entry["path"])) for entry in directories
    ]
    ended = time.time()
    assert all(
        record["url"]["started"] <= item["creation"] <= item["observed"] <= ended
        for item in directories
    )
    assert all(entry["absent"] for entry in directories)
    return dict(
        snapshot,
        portable_uninstall_keys=_portable_uninstall_keys(snapshot, directories),
        directory_creations=directories,
        requests=_requests()[record["url"]["offset"] :],
        started=record["url"]["started"],
        ended=ended,
        temporary_directories=_temporary_directories(),
    )


def _cleanup():
    if not os.path.exists(base.JOURNAL):
        assert os.listdir(ROOT) == []
        return {"restored": True, "journal_absent": True}
    record, library = base._read(), _api()
    if "pid" in record["url"]:
        handle = library.OpenProcess(0x400 | 1 | 0x100000, False, record["url"]["pid"])
        if handle:
            try:
                assert _creation(library, handle) == record["url"]["creation"]
                status = library.WaitForSingleObject(handle, 0)
                assert status in (0, 0x102)
                if status == 0x102:
                    assert library.TerminateProcess(handle, 0)
                    assert library.WaitForSingleObject(handle, 5000) == 0
            finally:
                library.CloseHandle(handle)
        else:
            assert ctypes.get_last_error() == 87
    metadata = os.path.join(ROOT, "server.json")
    if os.path.exists(metadata):
        with open(metadata, encoding="utf-8") as stream:
            information = json.load(stream)
        assert information["pid"] == record["url"]["pid"]
        assert information["creation"] == record["url"]["creation"]
        assert information["token"] == record["url"]["token"]
        with socket.socket() as connection:
            assert connection.connect_ex(("127.0.0.1", information["port"])) != 0
    assert _temporary_directories() == record["url"]["temporary_directories"]
    if "script" in record["url"]:
        assert (
            base._file_state(os.path.join(ROOT, "server.py")) == record["url"]["script"]
        )
    return dict(
        base._cleanup(), process_stopped=True, temporary_directories_restored=True
    )


def main():
    """Dispatch only owned URL fixture operations on actual Python3.4.4."""
    assert sys.version_info[:3] == (3, 4, 4)
    assert os.path.basename(ROOT).startswith("legacy-windows-package-url-test-")
    library = ctypes.WinDLL("kernel32", use_last_error=True)
    library.GetLongPathNameW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    ]
    library.GetLongPathNameW.restype = ctypes.c_uint32

    def _canonical(path):
        buffer = ctypes.create_unicode_buffer(32768)
        count = library.GetLongPathNameW(path, buffer, len(buffer))
        assert 0 < count < len(buffer)
        return os.path.normcase(buffer.value.rstrip("\\"))

    assert _canonical(os.path.dirname(ROOT)) == _canonical(tempfile.gettempdir())
    assert not os.path.islink(ROOT)
    operation = {
        "journal": _journal,
        "setup": _setup,
        "prepare": _prepare,
        "observe": _observe,
        "cleanup": _cleanup,
        "finalize": base._finalize,
    }[OPERATION]
    print(json.dumps(operation(), default=base._encode, sort_keys=True))


if __name__ == "__main__":
    main()
