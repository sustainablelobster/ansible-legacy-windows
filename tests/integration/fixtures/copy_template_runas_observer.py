"""Observe live Copy/Template workers during one serial, owned public call."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import ctypes
import hashlib
import json
import os
import re
import sys
import time
import traceback

# These identify the literal declared Core become bootstrap, not a copy of it.
SOURCE_BOOTSTRAP_HASHES = (
    "f35a1eda014c65231af5a050dba4abe73c4fb50a46c65c68e109dab7117a841b",
    "ee7ad1251c3ce7626f3faeeda9a6f832f2da1bbf4c16c65e73ecaa13bfaca8c2",
)


def _namespace(source, name):
    namespace = {"__name__": name}
    exec(compile(source, name, "exec"), namespace)  # pylint: disable=exec-used
    return namespace


def _selected(row, workspace, side):
    command = row.get("CommandLine") or ""
    if side == "native":
        return (
            row["Name"].lower() == "python.exe"
            and (workspace + "\\staging\\").lower() in command.lower()
            and "ansiballz_win_copy.py" in command.lower()
        )
    if row["Name"].lower() != "powershell.exe":
        return False
    match = re.search(
        r"\s-noni\s+-nop\s+-ex\s+Bypass\s+-e\s+([A-Za-z0-9+/=]+)\s*$",
        command,
        re.IGNORECASE,
    )
    if match is None:
        return False
    bootstrap = base64.b64decode(match.group(1)).decode("utf-16-le")
    return (
        hashlib.sha256(bootstrap.encode("utf-8")).hexdigest() in SOURCE_BOOTSTRAP_HASHES
    )


def _token_sid(pid, kernel):
    # The token-user ABI is the maintained runas_observer.py observation, using
    # a live worker handle instead of GetCurrentProcess. No token is modified.
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    # Keep this live-worker token observation independent of payload staging.
    # pylint: disable=duplicate-code
    security.OpenProcessToken.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    security.OpenProcessToken.restype = ctypes.c_int
    security.GetTokenInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    security.GetTokenInformation.restype = ctypes.c_int
    security.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    security.ConvertSidToStringSidW.restype = ctypes.c_int
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    handle = kernel.OpenProcess(0x100400, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    token, text = ctypes.c_void_p(), ctypes.c_void_p()
    try:
        if not security.OpenProcessToken(handle, 8, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        needed = ctypes.c_uint32()
        assert not security.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        assert ctypes.get_last_error() == 122 and needed.value
        information = ctypes.create_string_buffer(needed.value)
        assert security.GetTokenInformation(
            token, 1, information, needed.value, ctypes.byref(needed)
        )
        # pylint: enable=duplicate-code
        assert security.ConvertSidToStringSidW(
            ctypes.c_void_p.from_buffer(information), ctypes.byref(text)
        )
        return ctypes.wstring_at(text)
    finally:
        if text:
            kernel.LocalFree(text)
        if token:
            assert kernel.CloseHandle(token)
        assert kernel.CloseHandle(handle)


def _write(path, value):
    temporary = path + ".tmp"
    with open(temporary, "x", encoding="utf-8") as stream:
        json.dump(value, stream)
    os.rename(temporary, path)


def _rows(connection):
    fields = ["Name", "ProcessId", "ParentProcessId", "CommandLine", "ExecutablePath"]
    return connection.query(
        "SELECT " + ",".join(fields) + " FROM Win32_Process WHERE "
        "Name='python.exe' OR Name='powershell.exe' OR Name='cmd.exe'",
        fields,
    )


def _record(row, parents, process):
    identity = process["_process"](row["ProcessId"])
    parent_row = parents.get(row["ParentProcessId"])
    if not identity or not identity["alive"] or parent_row is None:
        return None
    parent = process["_process"](parent_row["ProcessId"])
    if not parent or not parent["alive"]:
        return None
    kernel = process["_kernel"]()
    sid = _token_sid(identity["pid"], kernel)
    parent_sid = _token_sid(parent["pid"], kernel)
    if process["_process"](identity["pid"]) != identity:
        return None
    if process["_process"](parent["pid"]) != parent:
        return None
    return {
        "identity": identity,
        "sid": sid,
        "process": row,
        "parent_identity": parent,
        "parent_sid": parent_sid,
        "parent_process": parent_row,
        "observed_epoch": time.time(),
    }


def _collect(connection, process, ready, prefix):
    result = {
        "ready": ready,
        "records": [],
        "races": [],
        "failure": None,
        "enumerations": [],
    }
    deadline = time.monotonic() + 90
    try:
        while not os.path.exists(prefix + "-release"):
            if time.monotonic() >= deadline:
                raise OSError("Owned Copy/Template observer was not released.")
            started = time.time()
            rows = _rows(connection)
            result["enumerations"].append(
                {
                    "started_epoch": started,
                    "finished_epoch": time.time(),
                    "count": len(rows),
                }
            )
            parents = {row["ProcessId"]: row for row in rows}
            for row in rows:
                if not _selected(row, ready["workspace"], ready["side"]):
                    continue
                identity = process["_process"](row["ProcessId"])
                if identity and any(
                    item["identity"]
                    and item["identity"]["pid"] == identity["pid"]
                    and item["identity"]["created"] == identity["created"]
                    for item in ready["baseline"] + result["records"]
                ):
                    continue
                record = _record(row, parents, process)
                if record is None:
                    result["races"].append({"process": row, "identity": identity})
                else:
                    result["records"].append(record)
            time.sleep(0.01)
    # Keep every observation failure available to the fixture's owned recovery.
    except Exception as error:  # pylint: disable=broad-exception-caught
        result["failure"] = repr(error)
    result["finished_epoch"] = time.time()
    return result


def _debug_state(helper, security, token):
    # Read TOKEN_PRIVILEGES using the maintained Runas helper's native records.
    # No privileges are added; the existing SeDebugPrivilege is the sole change.
    # pylint: disable=protected-access
    information = helper._information(security, token, 3)
    count = helper._DWORD.from_buffer(information).value
    privileges = (helper._Privilege * count).from_buffer(
        information, helper._PrivilegeChange.privilege.offset
    )
    luid = helper._Luid()
    assert security.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid))
    entries = [
        {"luid": [item.luid.low, item.luid.high], "attributes": item.attributes}
        for item in privileges
    ]
    matching = [item for item in entries if item["luid"] == [luid.low, luid.high]]
    assert len(matching) == 1, "Observer has no existing SeDebugPrivilege."
    return {
        "privileges": entries,
        "debug_luid": [luid.low, luid.high],
        "debug_attributes": matching[0]["attributes"],
    }


def _system_collect(connection, process, ready, prefix):
    # Only this ordinary-account test observer temporarily enables its existing
    # privilege. The maintained context restores it even if observation fails.
    # Lazy import keeps the ordinary user observation branch literal.
    # pylint: disable=import-outside-toplevel
    import legacy_windows_runas_token as helper  # pylint: disable=import-error

    # These private native contracts are reused literally, not reimplemented.
    # pylint: disable=protected-access
    security, kernel, _ = helper._libraries()
    token = ctypes.c_void_p()
    assert security.OpenProcessToken(
        kernel.GetCurrentProcess(), 0x28, ctypes.byref(token)
    )
    state = {"token_closed": False}
    try:
        state["before"] = _debug_state(helper, security, token)
        with helper._privilege(security, token, "SeDebugPrivilege"):
            state["enabled"] = _debug_state(helper, security, token)
            assert state["enabled"]["debug_attributes"] & 2
            ready["debug_privilege"] = {
                "before": state["before"],
                "enabled": state["enabled"],
            }
            _write(prefix + "-ready.json", ready)
            result = _collect(connection, process, ready, prefix)
    finally:
        try:
            state["after"] = _debug_state(helper, security, token)
        finally:
            assert kernel.CloseHandle(token)
            state["token_closed"] = True
            _write(prefix + "-privilege.json", state)
    result["debug_privilege"] = state
    return result


def _monitor(workspace, side, tag):
    assert sys.version_info[:3] == (3, 4, 4)
    process = _namespace(globals()["PROCESS_SOURCE"], "owned_copy_process")
    wmi = _namespace(globals()["WMI_SOURCE"], "owned_copy_wmi")
    prefix = os.path.join(workspace, "observer-" + tag)
    with wmi["WmiConnection"]() as connection:
        baseline = []
        for row in _rows(connection):
            if _selected(row, workspace, side):
                baseline.append(
                    {"process": row, "identity": process["_process"](row["ProcessId"])}
                )
        ready = {
            "observer": process["_process"](os.getpid()),
            "baseline": baseline,
            "observer_sid": _token_sid(os.getpid(), process["_kernel"]()),
            "started_epoch": time.time(),
            "side": side,
            "workspace": workspace,
            "python": list(sys.version_info[:3]),
        }
        if int(tag.rsplit("-", 1)[1]) >= 12:
            _write(
                prefix + "-result.json",
                _system_collect(connection, process, ready, prefix),
            )
        else:
            _write(prefix + "-ready.json", ready)
            _write(
                prefix + "-result.json", _collect(connection, process, ready, prefix)
            )


def _main():
    prefix = os.path.join(sys.argv[1], "observer-" + sys.argv[3])
    original = sys.stdout, sys.stderr
    with open(prefix + "-stdout", "x", encoding="utf-8") as output, open(
        prefix + "-stderr", "x", encoding="utf-8"
    ) as errors:
        sys.stdout, sys.stderr = output, errors
        try:
            _monitor(*sys.argv[1:])
        # Retain startup failures without inheriting any launcher pipe handles.
        except Exception:  # pylint: disable=broad-exception-caught
            traceback.print_exc(file=errors)
            return 1
        finally:
            sys.stdout, sys.stderr = original
    return 0


if __name__ == "__main__":
    sys.exit(_main())
