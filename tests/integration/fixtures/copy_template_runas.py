# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later

"""Observe owned Copy/Template content, security and synchronous Runas effects."""

import base64
import ctypes
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time


def _content(workflow):
    if workflow == "file":
        return {"single.bin": bytes(bytearray(range(256))) * 4}
    if workflow == "archive":
        return {
            "nested/payload.bin": bytes(bytearray(range(256))) * 4,
            "Café 雪 [x].txt": b"Public fixture % ! &\r\n",
        }
    assert workflow == "template"
    return {"basic.txt": "Header % ! &\r\nCafé 雪 \\path % ! &\r\n".encode("utf-8")}


def _write_content(directory, workflow):
    os.makedirs(directory)
    if workflow == "archive":
        os.mkdir(os.path.join(directory, "empty"))
    for relative, data in _content(workflow).items():
        path = os.path.join(directory, *relative.split("/"))
        parent = os.path.dirname(path)
        if not os.path.isdir(parent):
            os.makedirs(parent)
        with open(path, "xb") as stream:
            stream.write(data)
        os.utime(path, (946782244, 946782244))
    # Existing directories need the same literal baseline on both preparations.
    for parent, _children, _files in os.walk(directory):
        os.utime(parent, (946782244, 946782244))


def _security(path):
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    api.GetNamedSecurityInfoW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
    ] + [ctypes.POINTER(ctypes.c_void_p)] * 5
    api.GetNamedSecurityInfoW.restype = ctypes.c_uint32
    # This independent ACL observer needs the native signatures, not payload imports.
    # pylint: disable=duplicate-code
    api.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    api.ConvertSidToStringSidW.restype = ctypes.c_int
    api.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
    ]
    api.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = ctypes.c_int
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    owner, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
    sid, text = ctypes.c_void_p(), ctypes.c_void_p()
    try:
        status = api.GetNamedSecurityInfoW(
            path,
            1,
            5,
            ctypes.byref(owner),
            None,
            None,
            None,
            ctypes.byref(descriptor),
        )
        if status:
            raise ctypes.WinError(status)
        # pylint: enable=duplicate-code
        if not api.ConvertSidToStringSidW(owner, ctypes.byref(sid)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not api.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor, 1, 5, ctypes.byref(text), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return {"owner": ctypes.wstring_at(sid), "sddl": ctypes.wstring_at(text)}
    finally:
        for allocation in (text, sid, descriptor):
            if allocation:
                kernel.LocalFree(allocation)


def _entry(path):
    namespace = {"__name__": "owned_copy_template_file_observer"}
    # Reuse the exact maintained metadata ABI, independent of payload staging.
    exec(  # pylint: disable=exec-used
        compile(globals()["FILE_SOURCE"], "owned_file_observer.py", "exec"),
        namespace,
    )
    metadata = namespace["file_info"](path)
    metadata.pop("access_time")
    result = {"metadata": metadata, "security": _security(path)}
    if os.path.isfile(path):
        with open(path, "rb") as stream:
            data = stream.read()
        result["base64"] = base64.b64encode(data).decode("ascii")
    return result


def _profiles():
    # Windows-only registry reads never create a profile or load a hive.
    import winreg  # pylint: disable=import-outside-toplevel,import-error

    loaded, paths = [], {}
    for root, target in (
        (winreg.HKEY_USERS, loaded),
        (winreg.HKEY_LOCAL_MACHINE, paths),
    ):
        name = (
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
            if root == winreg.HKEY_LOCAL_MACHINE
            else ""
        )
        with winreg.OpenKey(root, name) as key:
            for index in range(winreg.QueryInfoKey(key)[0]):
                child = winreg.EnumKey(key, index)
                if isinstance(target, list):
                    target.append(child)
                else:
                    with winreg.OpenKey(key, child) as profile:
                        target[child] = list(
                            winreg.QueryValueEx(profile, "ProfileImagePath")
                        )
    return {"loaded_hives": sorted(loaded), "profile_paths": paths}


def _global():
    with open(sys.executable, "rb") as stream:
        executable = hashlib.sha256(stream.read()).hexdigest()
    return {
        "python": list(sys.version_info[:3]),
        "python_executable": sys.executable,
        "executable_sha256": executable,
        "profiles": _profiles(),
    }


def _process_namespace():
    namespace = {"__name__": "owned_copy_process"}
    exec(  # pylint: disable=exec-used
        compile(globals()["PROCESS_SOURCE"], "owned_copy_process.py", "exec"),
        namespace,
    )
    return namespace


def _start_observer(workspace, side, index):
    process = _process_namespace()
    tag = side + "-" + str(index)
    prefix = os.path.join(workspace, "observer-" + tag)
    script = os.path.join(workspace, "observer.py")
    # Reuse get_url_fixture.yml's detached Python3.4 launch: stdio redirects
    # forbid close_fds=True, and inherited SSH pipes delay the public call.
    # The child opens owned output files; the birth journal owns its lifetime.
    worker = subprocess.Popen(  # pylint: disable=consider-using-with
        [sys.executable, script, workspace, side, tag],
        creationflags=0x1000000 | 8 | 512,
        close_fds=True,
    )
    try:
        identity = process["_process"](worker.pid)
        assert identity and identity["alive"]
        state = {"identity": identity, "prefix": prefix}
        with open(
            os.path.join(workspace, "observer-state.json"), "w", encoding="utf-8"
        ) as stream:
            json.dump(state, stream)
    except BaseException:
        # Before the birth journal exists, Popen owns the exact process handle.
        worker.terminate()
        worker.wait(timeout=10)
        raise
    deadline = time.monotonic() + 10
    while not os.path.isfile(prefix + "-ready.json"):
        assert (
            worker.poll() is None
        ), "Owned observer exited before readiness; stderr retained."
        assert time.monotonic() < deadline, "Owned observer readiness timed out."
        time.sleep(0.01)
    with open(prefix + "-ready.json", encoding="utf-8") as stream:
        return json.load(stream)


def _stop_observer(workspace, recover=False):
    state_path = os.path.join(workspace, "observer-state.json")
    if not os.path.isfile(state_path):
        return None
    process = _process_namespace()
    with open(state_path, encoding="utf-8") as stream:
        state = json.load(stream)
    identity, prefix = state["identity"], state["prefix"]
    if not os.path.exists(prefix + "-release"):
        with open(prefix + "-release", "x", encoding="utf-8"):
            pass
    deadline = time.monotonic() + 10
    while process["_process"](identity["pid"]) == identity:
        if time.monotonic() >= deadline:
            assert recover, "Owned observer did not stop; birth journal retained."
            kernel = process["_kernel"]()
            kernel.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
            kernel.TerminateProcess.restype = ctypes.c_int
            handle = kernel.OpenProcess(0x100401, False, identity["pid"])
            assert handle
            try:
                clocks = [ctypes.c_uint64() for _ in range(4)]
                assert kernel.GetProcessTimes(
                    handle, *[ctypes.byref(clock) for clock in clocks]
                )
                assert clocks[0].value == identity["created"]
                assert kernel.TerminateProcess(handle, 1)
                assert kernel.WaitForSingleObject(handle, 10000) == 0
            finally:
                assert kernel.CloseHandle(handle)
            break
        time.sleep(0.01)
    current = process["_process"](identity["pid"])
    assert (
        current is None
        or current["created"] != identity["created"]
        or not current["alive"]
    )
    result = {"observer": identity, "observer_closed": True, "recovery": recover}
    if os.path.isfile(prefix + "-privilege.json"):
        with open(prefix + "-privilege.json", encoding="utf-8") as stream:
            result["debug_privilege"] = json.load(stream)
    if os.path.isfile(prefix + "-result.json"):
        with open(prefix + "-result.json", encoding="utf-8") as stream:
            result.update(json.load(stream))
    else:
        with open(prefix + "-stderr", "rb") as stream:
            result["stderr_base64"] = base64.b64encode(stream.read()).decode("ascii")
        result["failure"] = "Owned observer exited without a complete observation."
    return result


def _inventory(root):
    entries = {}
    for directory, children, files in os.walk(root):
        for name in sorted(children + files):
            path = os.path.join(directory, name)
            entries[os.path.relpath(path, root).replace("\\", "/")] = _entry(path)
    return entries


def _observe(workspace):
    staging = os.path.join(workspace, "staging")
    return {
        "time": time.time(),
        "output": _inventory(os.path.join(workspace, "output")),
        "sentinel": _entry(os.path.join(workspace, "sentinel.bin")),
        "source": _entry(os.path.join(workspace, "source.bin")),
        "global": _global(),
        "staging": sorted(os.listdir(staging)),
        "staging_inventory": _inventory(staging),
    }


def _setup(workspace):
    assert os.listdir(workspace) == []
    for name in ("source.bin", "sentinel.bin"):
        with open(os.path.join(workspace, name), "xb") as stream:
            stream.write(b"protected copy/template\x00\xff")
        os.utime(os.path.join(workspace, name), (946782244, 946782244))
    os.mkdir(os.path.join(workspace, "staging"))
    script = (
        "".join(
            name + " = " + repr(globals()[name]) + "\n"
            for name in ("PROCESS_SOURCE", "WMI_SOURCE")
        )
        + globals()["OBSERVER_SOURCE"]
    )
    with open(os.path.join(workspace, "observer.py"), "x", encoding="utf-8") as stream:
        stream.write(script)
    for module, source in (
        ("legacy_windows_account", "ACCOUNT_SOURCE"),
        ("legacy_windows_s4u", "S4U_SOURCE"),
        ("legacy_windows_runas_token", "RUNAS_TOKEN_SOURCE"),
    ):
        with open(
            os.path.join(workspace, module + ".py"), "x", encoding="utf-8"
        ) as stream:
            stream.write(globals()[source])
    result = _observe(workspace)
    with open(os.path.join(workspace, "journal.json"), "x", encoding="utf-8") as stream:
        json.dump(result, stream)
    return result


def _target(workspace, mode, workflow=None, phase=None):
    assert sys.version_info[:3] == (3, 4, 4)
    assert os.path.basename(workspace).startswith("legacy-windows-copy-template-runas-")
    journal = os.path.join(workspace, "journal.json")
    if mode == "setup":
        return _setup(workspace)
    if mode == "cleanup" and not os.path.isfile(journal):
        # Failed setup has no accepted protected baseline; retain that fact.
        # The caller still owns this exact tempfile directory and its children.
        _stop_observer(workspace, recover=True)
        shutil.rmtree(workspace)
        return {
            "setup_incomplete": True,
            "workspace_absent": not os.path.exists(workspace),
        }
    with open(journal, encoding="utf-8") as stream:
        initial = json.load(stream)
    if mode == "prepare":
        output = os.path.join(workspace, "output")
        if os.path.isdir(output):
            shutil.rmtree(output)
        if phase in ("repeat", "check_existing"):
            _write_content(output, workflow)
        else:
            assert phase in ("create", "check_new")
            os.mkdir(output)
        return _observe(workspace)
    if mode == "observer_start":
        return _start_observer(workspace, workflow, phase)
    if mode == "observer_stop":
        observation = _stop_observer(workspace)
        records = observation.get("records", [])
        parents = {
            (record["parent_identity"]["pid"], record["parent_identity"]["created"])
            for record in records
        }
        observation["expected_sid"] = workflow
        observation["expected_workers"] = int(phase)
        observation["valid"] = (
            observation.get("failure") is None
            and not observation.get("races")
            and len(records) == len(parents) == int(phase)
            and all(record["sid"] == workflow for record in records)
        )
        return observation
    observer = _stop_observer(workspace, recover=True) if mode == "cleanup" else None
    result = _observe(workspace)
    for field in ("source", "sentinel", "global"):
        assert result[field] == initial[field], (field, result[field], initial[field])
    if mode == "cleanup":
        shutil.rmtree(workspace)
        result["workspace_absent"] = not os.path.exists(workspace)
        result["observer_recovery"] = observer
    else:
        assert mode == "observe"
    return result


def _controller_observe(root):
    observed = {}
    for parent, _children, files in os.walk(root):
        for name in files:
            path = os.path.join(parent, name)
            with open(path, "rb") as fixture:
                data = fixture.read()
            observed[os.path.relpath(path, root)] = {
                "sha256": hashlib.sha256(data).hexdigest(),
                "mtime": os.stat(path).st_mtime,
                "mode": os.stat(path).st_mode,
            }
    return observed


def _main():
    if sys.argv[1] == "controller_observe":
        print(json.dumps(_controller_observe(sys.argv[2])))
    elif sys.argv[1] == "controller":
        _write_content(os.path.join(sys.argv[2], "tree"), "archive")
        with open(os.path.join(sys.argv[2], "single.bin"), "xb") as fixture:
            fixture.write(_content("file")["single.bin"])
        os.utime(os.path.join(sys.argv[2], "single.bin"), (946782244, 946782244))
    else:
        result = _target(*sys.argv[1:])
        print(json.dumps(result))
        if sys.argv[2] == "observer_stop" and not result["valid"]:
            sys.exit(3)


if __name__ == "__main__":
    _main()
