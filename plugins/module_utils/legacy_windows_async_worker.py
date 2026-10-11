# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Supervise one staged Python payload and publish its standard async cache."""

import ctypes
import json
import os
import sys
import time
import traceback

# These native helpers are staged adjacent to this watchdog by the action.
from legacy_windows_async_native import (  # pylint: disable=import-error
    payload_process,
    remove_staging,
)


def read_json(path):
    """Read an owned UTF-8 JSON protocol file.

    :param path: Literal file path.
    :type path: str
    :returns: Decoded JSON value.
    :rtype: object
    :raises OSError: Reading fails.
    :raises ValueError: The JSON document is invalid.
    """
    with open(path, encoding="utf-8-sig") as stream:
        return json.load(stream)


def atomic_json(path, value):
    """Publish a complete UTF-8 BOM record, tolerating concurrent status reads.

    :param path: Literal destination path.
    :type path: str
    :param value: JSON-serializable record.
    :type value: object
    :raises OSError: Creating or replacing the owned file fails.
    """
    temporary = path + "." + str(os.getpid()) + ".tmp"
    try:
        with open(temporary, "x", encoding="utf-8-sig") as stream:
            json.dump(value, stream, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        deadline = time.monotonic() + 5
        while True:
            try:
                os.replace(temporary, path)
                return
            except PermissionError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)


def module_result(stdout, stderr, returncode):
    """Decode the module's JSON object without discarding public fields.

    :param stdout: Complete UTF-8 module stdout.
    :type stdout: bytes
    :param stderr: Complete UTF-8 module stderr.
    :type stderr: bytes
    :param returncode: Native process exit code.
    :type returncode: int
    :returns: The module result, including any trailing-junk warning.
    :rtype: dict
    :raises ValueError: Output contains no valid JSON object.
    """
    text = stdout.decode("utf-8", "replace")
    first, last = text.find("{"), text.rfind("}")
    if first < 0:
        raise ValueError("No start of json char found in module result")
    if last < first:
        raise ValueError("No end of json char found in module result")
    result = json.loads(text[first : last + 1])
    if not isinstance(result, dict):
        raise ValueError("Module output is not a JSON object")
    trailing = text[last + 1 :].strip()
    if trailing:
        if not result.get("warnings"):
            result["warnings"] = []
        result["warnings"].append(
            "Module invocation had junk after the JSON data: " + trailing
        )
    if returncode and not result.get("failed"):
        result.update(
            failed=True, rc=returncode, stderr=stderr.decode("utf-8", "replace")
        )
    return result


def _wait_payload(kernel, handle, job, timeout):
    # Core's parallel gathering uses zero when the module owns its deadlines.
    # Setup bounds each collector separately; zero is not an immediate timeout.
    deadline = time.monotonic() + timeout if timeout else None
    while True:
        milliseconds = (
            min(int(max(0, deadline - time.monotonic()) * 1000), 0xFFFFFFFE)
            if deadline is not None
            else 0xFFFFFFFF
        )
        status = kernel.WaitForSingleObject(handle, milliseconds)
        if status != 258 or deadline is not None and time.monotonic() >= deadline:
            break
    if status == 258:
        if not kernel.TerminateJobObject(job, 1):
            raise ctypes.WinError(ctypes.get_last_error())
        raise TimeoutError("timed out waiting for module completion")
    if status != 0:
        raise ctypes.WinError(ctypes.get_last_error())
    code = ctypes.c_uint32()
    if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)):
        raise ctypes.WinError(ctypes.get_last_error())
    return code.value


def _run_payload(request, request_path):
    stdout_path = request_path + ".stdout"
    stderr_path = request_path + ".stderr"
    with open(os.devnull, "rb") as stdin, open(stdout_path, "xb") as stdout, open(
        stderr_path, "xb"
    ) as stderr:
        with payload_process(
            request["arguments"], request["cwd"], (stdin, stdout, stderr)
        ) as process:
            atomic_json(request_path + ".started", {"ready": True, "pid": os.getpid()})
            # Even an immediately completed payload must not delete the
            # startup acknowledgment before its frontend has read it.
            deadline = time.monotonic() + request["startup_timeout"]
            while not os.path.exists(request_path + ".accepted"):
                if time.monotonic() >= deadline:
                    raise OSError("Async frontend did not accept startup")
                time.sleep(0.01)
            code = _wait_payload(process[0], process[1], process[2], request["timeout"])
    with open(stdout_path, "rb") as stdout, open(stderr_path, "rb") as stderr:
        return module_result(stdout.read(), stderr.read(), code)


def supervise(request_path):
    """Run the exact staged payload, enforcing its deadline and owning cleanup.

    :param request_path: Owned watchdog request next to the staged payload.
    :type request_path: str
    :raises OSError: Initial request or final cache cannot be accessed.
    :raises ValueError: The initial request is invalid.
    """
    request = read_json(request_path)
    # Launch starts beside the staged helper; Windows cannot remove a process's
    # current directory. Use the caller's original cwd before owning cleanup.
    os.chdir(request["cwd"])
    directory = os.path.dirname(request_path)
    release = request_path + ".release"
    acknowledgment = request_path + ".started"
    # The frontend pins our native handle before publishing our PID/cache record.
    # Do not execute the payload until that handshake has completed.
    deadline = time.monotonic() + request["startup_timeout"] + 5
    while not os.path.exists(release):
        if time.monotonic() >= deadline:
            return
        time.sleep(0.01)
    metadata = read_json(release)
    if metadata["ansible_async_watchdog_pid"] != os.getpid():
        raise ValueError("Async watchdog PID does not match its launch request")
    result = dict(metadata, finished=True)
    try:
        public = _run_payload(request, request_path)
        duplicates = set(public).intersection(metadata)
        if duplicates:
            raise ValueError(
                "Module result contains async metadata: "
                + ", ".join(sorted(duplicates))
            )
        result.update(public)
    # No controller is waiting to catch unexpected module/output exceptions.
    except Exception as error:  # pylint: disable=broad-exception-caught
        result.update(
            failed=True,
            msg="failure during async watchdog: " + str(error),
            stdout=None,
            stderr="",
            exception=traceback.format_exc(),
        )
        if not os.path.exists(acknowledgment):
            atomic_json(
                acknowledgment,
                {"ready": False, "pid": os.getpid(), "msg": result["msg"]},
            )
    finally:
        if not request["preserve_tmp"]:
            try:
                remove_staging(directory)
            except OSError as error:
                result.update(
                    failed=True,
                    msg="failure during async watchdog cleanup: " + str(error),
                    exception=traceback.format_exc(),
                )
        atomic_json(request["cache_path"], result)


if __name__ == "__main__":
    supervise(sys.argv[1])
