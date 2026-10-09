#!/usr/bin/python
# WANT_JSON
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Implement ansible-core's private async-wrapper argv ABI for Windows Python."""

import ctypes
import json
import os
import re
import subprocess
import sys
import time
import traceback

# The action transfers the watchdog and native helpers next to this private CLI.
# pylint: disable=import-error
from legacy_windows_async_native import launch_watchdog  # pylint: disable=import-error
from legacy_windows_async_worker import (  # pylint: disable=import-error
    atomic_json,
    read_json,
)

_STARTUP_TIMEOUT = 5  # Controller-configured startup deadline.


def _request(arguments, startup_timeout):
    if len(arguments) < 6:
        raise ValueError(
            "Async wrapper requires job ID, timeout, ownership and payload arguments"
        )
    # pylint: enable=import-error
    prefix, limit, preserve, module_path = arguments[:4]
    if not re.match(r"^j[0-9]+$", prefix) or preserve not in ("true", "false"):
        raise ValueError("Invalid async wrapper job ID or staging ownership")
    timeout = int(limit)
    # Core parallel gathering uses zero when the module owns its deadlines.
    if timeout < 0 or startup_timeout <= 0:
        raise ValueError(
            "Async execution limit cannot be negative; startup deadline must be positive"
        )
    directory = os.path.dirname(os.path.abspath(__file__))
    if (
        os.path.dirname(os.path.abspath(module_path)) != directory
        or arguments[5] != module_path
    ):
        raise ValueError("Async payload must be staged next to its private wrapper")
    job_id = prefix + "." + str(os.getpid())
    async_dir = os.path.expanduser(os.path.expandvars(os.environ["ANSIBLE_ASYNC_DIR"]))
    if not os.path.isabs(async_dir):
        raise ValueError("ansible_async_dir must resolve to an absolute Windows path")
    os.makedirs(async_dir, exist_ok=True)
    cache_path = os.path.join(async_dir, job_id)
    request_path = os.path.join(directory, ".async-" + job_id + ".json")
    request = {
        "arguments": arguments[4:],
        "cwd": os.getcwd(),
        "timeout": timeout,
        "startup_timeout": startup_timeout,
        "preserve_tmp": preserve == "true",
        "cache_path": cache_path,
    }
    atomic_json(request_path, request)
    return directory, request_path, cache_path, job_id


def _await_startup(kernel, handle, pid, request_path, startup_timeout):
    deadline = time.monotonic() + startup_timeout
    while not os.path.exists(request_path + ".started"):
        if kernel.WaitForSingleObject(handle, 0) != 258:
            raise OSError("Async watchdog exited before acknowledging startup")
        if time.monotonic() >= deadline:
            raise OSError(
                "Async watchdog did not start within {0} seconds; "
                "increase ansible_win_async_startup_timeout".format(startup_timeout)
            )
        time.sleep(0.01)
    acknowledgment = read_json(request_path + ".started")
    if acknowledgment.get("pid") != pid or not acknowledgment.get("ready"):
        raise OSError(
            acknowledgment.get("msg", "Invalid async watchdog startup acknowledgment")
        )
    atomic_json(request_path + ".accepted", {"pid": pid})


def launch(arguments, startup_timeout):
    """Launch one watchdog using core's job prefix/limit/preserve/payload ABI.

    :param arguments: Core async-wrapper arguments, without this executable.
    :type arguments: list
    :param startup_timeout: Configured watchdog startup deadline in seconds.
    :type startup_timeout: int
    :returns: Standard asynchronous launch metadata.
    :rtype: dict
    :raises OSError: Creating or starting the watchdog fails.
    :raises ValueError: Core arguments or target staging paths are invalid.
    :raises Exception: Startup fails after stopping the exact owned watchdog.
    """
    directory, request_path, cache_path, job_id = _request(arguments, startup_timeout)
    command = subprocess.list2cmdline(
        [
            sys.executable,
            os.path.join(directory, "legacy_windows_async_worker.py"),
            request_path,
        ]
    )
    kernel, handle, pid = launch_watchdog(command, directory, dict(os.environ))
    metadata = {
        "started": True,
        "finished": False,
        "results_file": cache_path,
        "ansible_job_id": job_id,
        "ansible_async_watchdog_pid": pid,
    }
    try:
        atomic_json(cache_path, metadata)
        atomic_json(request_path + ".release", metadata)
        _await_startup(kernel, handle, pid, request_path, startup_timeout)
    except Exception as error:
        # The retained handle identifies precisely this worker, not a recycled PID.
        if kernel.WaitForSingleObject(handle, 0) == 258:
            if not kernel.TerminateProcess(handle, 1):
                raise ctypes.WinError(ctypes.get_last_error()) from error
            if kernel.WaitForSingleObject(handle, 5000) != 0:
                raise OSError("Failed to stop the owned async watchdog") from error
        try:
            os.remove(cache_path)
        except FileNotFoundError:
            pass
        raise
    finally:
        kernel.CloseHandle(handle)
    # This core-only flag transfers staging ownership to the watchdog. Do not
    # persist it in the cache: later async_status tasks own their own directories.
    return dict(metadata, _ansible_suppress_tmpdir_delete=True)


if __name__ == "__main__":
    try:
        _RESULT = launch(sys.argv[1:], _STARTUP_TIMEOUT)
    # The core command must receive a JSON failure even for an unexpected native
    # exception; it cannot inspect a detached worker through Python exceptions.
    except Exception as _ERROR:  # pylint: disable=broad-exception-caught
        _RESULT = {
            "failed": True,
            "msg": "failed to launch async task: " + str(_ERROR),
            "exception": traceback.format_exc(),
        }
    sys.stdout.buffer.write(json.dumps(_RESULT, ensure_ascii=False).encode("utf-8"))
