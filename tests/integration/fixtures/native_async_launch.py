"""Exercise real detached watchdogs inside owned permissive and restricted jobs."""

# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

import ctypes
import json
import os
import shutil
import subprocess
import sys
import time

_PAYLOAD = """import json,os,sys,time
with open(sys.argv[1], 'a') as stream:
    stream.write('once\\n')
time.sleep(2)
print(json.dumps({'changed': False, 'marker': os.environ['ASYNC_LAUNCH_MARKER'],
                  'cwd': os.getcwd(), 'argument': sys.argv[2]}))
"""


def _helpers(workspace):
    sys.path.insert(0, os.path.join(workspace, "helpers"))
    import legacy_windows_async_native as native  # pylint: disable=import-outside-toplevel,import-error

    return native


def _child(workspace, case):
    native = _helpers(workspace)
    directory = os.path.join(workspace, case, "ansible-tmp-probe")
    os.mkdir(directory)
    for name in os.listdir(os.path.join(workspace, "helpers")):
        if name.endswith(".py"):
            shutil.copyfile(
                os.path.join(workspace, "helpers", name), os.path.join(directory, name)
            )
    payload = os.path.join(directory, "payload.py")
    with open(payload, "x", encoding="utf-8") as stream:
        stream.write(_PAYLOAD)
    counter = os.path.join(workspace, case, "counter.txt")
    cache = os.path.join(workspace, case, "cache")
    os.mkdir(cache)
    os.environ["ANSIBLE_ASYNC_DIR"] = cache
    os.environ["ASYNC_LAUNCH_MARKER"] = "café λ"
    sys.path.insert(0, directory)
    import legacy_windows_async_wrapper as wrapper  # pylint: disable=import-outside-toplevel,import-error

    calls = []
    original = native._launch_watchdog_wmi  # pylint: disable=protected-access

    def _wmi(*arguments):
        calls.append("wmi")
        if case == "direct":
            raise AssertionError("Direct watchdog attempted WMI fallback")
        return original(*arguments)

    native._launch_watchdog_wmi = _wmi  # pylint: disable=protected-access
    # The wrapper imports the helper normally; this guard observes only this
    # fixture process. The restricted case calls the actual maintained WMI API.
    launch = wrapper.launch(
        ["j1", "30", "false", payload, sys.executable, payload, counter, "Unicode λ"],
        10,
    )
    result = _wait_job(native.kernel_api(), wrapper, launch)
    assert calls == (["wmi"] if case == "restricted" else [])
    assert result["marker"] == "café λ" and result["argument"] == "Unicode λ"
    assert result["cwd"] == workspace
    with open(counter, encoding="ascii") as stream:
        assert stream.read() == "once\n"
    assert not os.path.exists(directory)
    os.remove(launch["results_file"])
    assert os.listdir(cache) == []
    return {"case": case, "wmi_calls": len(calls), "result": result, "executions": 1}


def _wait_job(kernel, wrapper, launch):
    handle = kernel.OpenProcess(0x100401, False, launch["ansible_async_watchdog_pid"])
    assert handle
    try:
        deadline = time.monotonic() + 30
        while True:
            result = wrapper.read_json(launch["results_file"])
            if result["finished"]:
                break
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert not result.get("failed"), result
        assert kernel.WaitForSingleObject(handle, 5000) == 0
    finally:
        if kernel.WaitForSingleObject(handle, 0) == 258:
            assert kernel.TerminateProcess(handle, 1)
            assert kernel.WaitForSingleObject(handle, 5000) == 0
        assert kernel.CloseHandle(handle)
    return result


# Keep the startup streams and job/process handles together so ownership stays visible.
# pylint: disable-next=too-many-locals
def _probe(workspace, case):
    # Keep the caller alive while its child is associated with a real Windows
    # job. Neither the connection's job nor global WMI configuration is changed.
    import msvcrt  # pylint: disable=import-outside-toplevel,import-error

    native = _helpers(workspace)
    kernel = native.kernel_api()
    directory = os.path.join(workspace, case)
    os.mkdir(directory)
    job = kernel.CreateJobObjectW(None, None)
    assert job
    info = native._ProcessInfo()  # pylint: disable=protected-access
    try:
        # The fixture exercises the helper's fixed Windows ABI record layout.
        # pylint: disable=protected-access
        limits = native._ExtendedJobLimits(
            native._JobLimits(
                flags=0x2000 | (0x800 if case == "direct" else 0)
            )  # pylint: disable=protected-access
        )
        assert kernel.SetInformationJobObject(
            job, 9, ctypes.byref(limits), ctypes.sizeof(limits)
        )
        with open(os.devnull, "rb") as stdin, open(
            os.path.join(directory, "stdout"), "xb"
        ) as stdout, open(os.path.join(directory, "stderr"), "xb") as stderr:
            handles = [
                msvcrt.get_osfhandle(stream.fileno())
                for stream in (stdin, stdout, stderr)
            ]
            for handle in handles:
                assert kernel.SetHandleInformation(handle, 1, 1)
            startup = native._StartupInfo(  # pylint: disable=protected-access
                size=ctypes.sizeof(
                    native._StartupInfo
                ),  # pylint: disable=protected-access
                flags=0x100,
                stdin=handles[0],
                stdout=handles[1],
                stderr=handles[2],
            )
            # pylint: enable=protected-access
            command = ctypes.create_unicode_buffer(
                subprocess.list2cmdline(
                    [sys.executable, __file__, workspace, "child", case]
                )
            )
            try:
                assert kernel.CreateProcessW(
                    sys.executable,
                    command,
                    None,
                    None,
                    True,
                    0x09000004,
                    None,
                    workspace,
                    ctypes.byref(startup),
                    ctypes.byref(info),
                )
                assert kernel.AssignProcessToJobObject(job, info.process)
                assert kernel.ResumeThread(info.thread) != 0xFFFFFFFF
                assert kernel.WaitForSingleObject(info.process, 60000) == 0
            finally:
                for handle in handles:
                    assert kernel.SetHandleInformation(handle, 1, 0)
        code = ctypes.c_uint32()
        assert kernel.GetExitCodeProcess(info.process, ctypes.byref(code))
        with open(os.path.join(directory, "stdout"), encoding="utf-8") as stdout, open(
            os.path.join(directory, "stderr"), encoding="utf-8"
        ) as stderr:
            output, errors = stdout.read(), stderr.read()
        assert code.value == 0, (output, errors)
        return json.loads(output)
    finally:
        try:
            if info.process:
                if kernel.WaitForSingleObject(info.process, 0) == 258:
                    assert kernel.TerminateProcess(info.process, 1)
                    assert kernel.WaitForSingleObject(info.process, 5000) == 0
                assert kernel.CloseHandle(info.process)
        finally:
            try:
                if info.thread:
                    assert kernel.CloseHandle(info.thread)
            finally:
                assert kernel.CloseHandle(job)


if __name__ == "__main__":
    assert sys.version_info[:3] == (3, 4, 4)
    _WORKSPACE, _OPERATION, _CASE = sys.argv[1:4]
    assert os.path.basename(_WORKSPACE).startswith(
        "legacy-windows-native-async-launch-"
    )
    assert _CASE in ("direct", "restricted")
    _RESULT = (
        _child(_WORKSPACE, _CASE)
        if _OPERATION == "child"
        else _probe(_WORKSPACE, _CASE)
    )
    sys.stdout.buffer.write(json.dumps(_RESULT, ensure_ascii=False).encode("utf-8"))
