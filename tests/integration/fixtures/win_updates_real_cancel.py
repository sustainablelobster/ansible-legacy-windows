"""Lose only a pinned public caller after a real native WUA download callback."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import ctypes
import glob
import hashlib
import importlib
import json
import os
import re
import sys
import tempfile
import time


def _read(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def _active_download(state):
    return not state["finished"] and any(
        row["task"] == "download"
        and row["result"]["progress"]["TotalBytesDownloaded"] > 0
        for row in state["output"]
    )


# These private contracts validate and pin the exact production-owned process;
# copying their security/identity implementation would weaken this fixture.
# pylint: disable=protected-access
def _find_downloading_worker(progress_path, expected_kb):
    deadline = time.monotonic() + 600
    selected = None
    while selected is None:
        for root in glob.glob(
            os.path.join(tempfile.gettempdir(), "legacy-windows-updates-*")
        ):
            request_path = os.path.join(root, "request.json")
            state_path = os.path.join(root, "state.json")
            if not os.path.isfile(request_path) or not os.path.isfile(state_path):
                continue
            try:
                request, state = _read(request_path), _read(state_path)
            except OSError:
                continue
            options = request["options"]
            if options.get("log_path") != progress_path:
                continue
            if options["state"] != "downloaded" or options["accept_list"] != [
                expected_kb
            ]:
                raise OSError("The observed worker does not match the public download.")
            if state["finished"]:
                raise OSError("The real WUA operation finished before caller loss.")
            if _active_download(state):
                selected = root, request, state
                break
        if selected is None:
            if time.monotonic() >= deadline:
                raise OSError(
                    "No active real WUA download callback appeared within600s."
                )
            time.sleep(0.01)
    return selected


def _pin_worker(root, request, active):
    if not re.match(r"^[0-9a-f]{32}$", request["nonce"]):
        raise OSError("The native worker nonce is not a valid ownership identity.")
    # Import only the exact live worker's immutable helper bytes. Disable Python
    # bytecode writes so observation cannot create unowned files in its root.
    sys.dont_write_bytecode = True
    sys.path.insert(0, root)
    worker = importlib.import_module("legacy_windows_updates_worker")
    worker._validate({"root": root, "nonce": request["nonce"]})
    journal = worker._launched(root, _read(os.path.join(root, "journal.json")))
    frontend, backend = request["supervisor"], journal["worker"]
    if frontend["pid"] == backend["pid"]:
        raise OSError(
            "The public caller and detached servicing worker are not distinct."
        )
    if worker._process(frontend["pid"]) != frontend:
        raise OSError("The caller birth identity is no longer the recorded live owner.")
    if worker._process(backend["pid"]) != backend or backend != active["worker"]:
        raise OSError("The actual downloading backend birth identity changed.")
    return worker, journal, frontend, backend


def _open_pinned_handles(worker, frontend, backend):
    kernel = worker._kernel()
    kernel.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel.TerminateProcess.restype = ctypes.c_int
    caller_handle = kernel.OpenProcess(0x100401, False, frontend["pid"])
    backend_handle = kernel.OpenProcess(0x100400, False, backend["pid"])
    if not caller_handle or not backend_handle:
        error_code = ctypes.get_last_error()
        if caller_handle:
            kernel.CloseHandle(caller_handle)
        if backend_handle:
            kernel.CloseHandle(backend_handle)
        raise ctypes.WinError(error_code)
    try:
        for handle, identity in (
            (caller_handle, frontend),
            (backend_handle, backend),
        ):
            clocks = [ctypes.c_uint64() for _ in range(4)]
            if (
                not kernel.GetProcessTimes(
                    handle, *[ctypes.byref(clock) for clock in clocks]
                )
                or clocks[0].value != identity["created"]
            ):
                raise OSError("The process handle does not match its recorded birth.")
    except Exception:
        kernel.CloseHandle(caller_handle)
        kernel.CloseHandle(backend_handle)
        raise
    return kernel, caller_handle, backend_handle


def _wait_for_backend(kernel, handle, result):
    began = time.monotonic()
    deadline = began + 1800
    last_state = result["actual_download_callback"]
    while True:
        status = kernel.WaitForSingleObject(handle, 0)
        if status == 0:
            break
        if status != 258:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            last_state = _read(os.path.join(result["root"], "state.json"))
        except OSError:
            pass
        if time.monotonic() >= deadline:
            result["last_state"] = last_state
            print(json.dumps(result), flush=True)
            raise OSError(
                "The actual WUA worker is still servicing after30min; retained "
                + result["root"]
                + "; it was not terminated."
            )
        time.sleep(0.02)
    result["backend_natural_exit_confirmed"] = True
    result["closure_seconds"] = time.monotonic() - began
    result["last_state"] = last_state
    result["root_absent"] = not os.path.exists(result["root"])


def _lose_caller_and_wait(worker, result):
    kernel, caller_handle, backend_handle = _open_pinned_handles(
        worker, result["frontend_before"], result["backend_before"]
    )
    try:
        if not kernel.TerminateProcess(caller_handle, 1):
            raise ctypes.WinError(ctypes.get_last_error())
        if kernel.WaitForSingleObject(caller_handle, 5000) != 0:
            raise OSError("The exact owned public caller did not exit.")
        result["caller_exit_confirmed"] = True
        _wait_for_backend(kernel, backend_handle, result)
    finally:
        kernel.CloseHandle(caller_handle)
        kernel.CloseHandle(backend_handle)


def observe(workspace, expected_kb):
    """Pin a real downloading worker, lose its caller, and await native closure.

    :param str workspace: Exact journal-owned public fixture workspace.
    :param str expected_kb: The sole public selected download filter.
    :returns: Full caller/backend identities, real callback and natural closure.
    :rtype: dict
    :raises OSError: No active real download or cooperative closure is observed.
    :raises ValueError: The workspace is outside the exact owned fixture prefix.
    """
    if sys.version_info[:3] != (3, 4, 4):
        raise OSError("The actual WUA cancellation fixture requires Python3.4.4.")
    if not os.path.basename(workspace).startswith(
        "legacy-windows-native-async-updates-"
    ):
        raise ValueError(
            "The cancellation observer requires its exact owned workspace."
        )
    progress_path = os.path.join(workspace, "progress.log")
    root, request, active = _find_downloading_worker(progress_path, expected_kb)
    worker, journal, frontend, backend = _pin_worker(root, request, active)
    result = {
        "python": list(sys.version_info[:3]),
        "root": root,
        "request": request,
        "journal": journal,
        "actual_download_callback": active,
        "frontend_before": frontend,
        "backend_before": backend,
        "backend_was_terminated": False,
    }
    _lose_caller_and_wait(worker, result)
    with open(progress_path, "rb") as stream:
        progress = stream.read()
    result["log_base64"] = base64.b64encode(progress).decode("ascii")
    result["log_sha256"] = hashlib.sha256(progress).hexdigest()
    result["actual_operation_aborted"] = bool(
        re.search(
            r"Download result for [0-9a-f-]+ - ResultCode: 5, HResult:",
            progress.decode("utf-8"),
        )
    ) or any(
        row["task"] == "download_result"
        and any(
            value["result_code"] == 5 or value["hresult"] & 0xFFFFFFFF == 0x8024000B
            for value in row["result"]["info"]
        )
        for row in result["last_state"]["output"]
    )
    if not result["root_absent"]:
        print(json.dumps(result), flush=True)
        raise OSError("The completed real WUA worker retained its owned root: " + root)
    return result


if __name__ == "__main__":
    print(json.dumps(observe(sys.argv[1], sys.argv[2])))
