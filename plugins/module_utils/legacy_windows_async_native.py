# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Detach an async watchdog and run its payload in an owned Windows job."""

import ctypes
import os
import subprocess
from contextlib import ExitStack, contextmanager

# The action stages this maintained native helper next to the watchdog.
import legacy_windows_wmi as wmi  # pylint: disable=import-error


# Native ABI records have fields, not Python operations.
# pylint: disable=too-few-public-methods
class _StartupInfo(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_uint32),
        ("reserved", ctypes.c_wchar_p),
        ("desktop", ctypes.c_wchar_p),
        ("title", ctypes.c_wchar_p),
        ("x", ctypes.c_uint32),
        ("y", ctypes.c_uint32),
        ("width", ctypes.c_uint32),
        ("height", ctypes.c_uint32),
        ("columns", ctypes.c_uint32),
        ("rows", ctypes.c_uint32),
        ("fill", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("show", ctypes.c_uint16),
        ("reserved_size", ctypes.c_uint16),
        ("reserved_bytes", ctypes.c_void_p),
        ("stdin", ctypes.c_void_p),
        ("stdout", ctypes.c_void_p),
        ("stderr", ctypes.c_void_p),
    ]


class _ProcessInfo(ctypes.Structure):
    _fields_ = [
        ("process", ctypes.c_void_p),
        ("thread", ctypes.c_void_p),
        ("pid", ctypes.c_uint32),
        ("thread_id", ctypes.c_uint32),
    ]


class _JobLimits(ctypes.Structure):
    # Repeat the fixed Windows record layout without adding a staging dependency.
    # pylint: disable=duplicate-code
    _fields_ = [
        ("process_time", ctypes.c_int64),
        ("job_time", ctypes.c_int64),
        ("flags", ctypes.c_uint32),
        ("minimum", ctypes.c_size_t),
        ("maximum", ctypes.c_size_t),
        ("active_processes", ctypes.c_uint32),
        ("affinity", ctypes.c_size_t),
        ("priority", ctypes.c_uint32),
        ("scheduling", ctypes.c_uint32),
    ]
    # pylint: enable=duplicate-code


class _ExtendedJobLimits(ctypes.Structure):
    # Repeat the fixed Windows record layout without adding a staging dependency.
    # pylint: disable=duplicate-code
    _fields_ = [
        ("basic", _JobLimits),
        ("io", ctypes.c_uint64 * 6),
        ("process_memory", ctypes.c_size_t),
        ("job_memory", ctypes.c_size_t),
        ("peak_process", ctypes.c_size_t),
        ("peak_job", ctypes.c_size_t),
    ]
    # pylint: enable=duplicate-code


# pylint: enable=too-few-public-methods


def kernel_api():
    """Configure the Windows process and job functions used by the watchdog.

    :returns: The configured kernel32 library.
    :rtype: ctypes.WinDLL
    :raises OSError: Windows APIs are unavailable.
    """
    if os.name != "nt":
        raise OSError("Native async execution requires Windows.")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    declarations = {
        "OpenProcess": (
            [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32],
            ctypes.c_void_p,
        ),
        "CloseHandle": ([ctypes.c_void_p], ctypes.c_int),
        "GetCurrentProcess": ([], ctypes.c_void_p),
        "IsProcessInJob": (
            [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)],
            ctypes.c_int,
        ),
        # This job-query ABI stays local; matching registry pointer types do not
        # make the unrelated Windows function signatures interchangeable.
        # pylint: disable=duplicate-code
        "QueryInformationJobObject": (
            [
                ctypes.c_void_p,
                ctypes.c_int,
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_void_p,
            ],
            ctypes.c_int,
        ),
        # pylint: enable=duplicate-code
        "WaitForSingleObject": ([ctypes.c_void_p, ctypes.c_uint32], ctypes.c_uint32),
        "TerminateProcess": ([ctypes.c_void_p, ctypes.c_uint32], ctypes.c_int),
        "CreateJobObjectW": ([ctypes.c_void_p, ctypes.c_wchar_p], ctypes.c_void_p),
        "SetInformationJobObject": (
            [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32],
            ctypes.c_int,
        ),
        "AssignProcessToJobObject": ([ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int),
        "TerminateJobObject": ([ctypes.c_void_p, ctypes.c_uint32], ctypes.c_int),
        "ResumeThread": ([ctypes.c_void_p], ctypes.c_uint32),
        "GetExitCodeProcess": (
            [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)],
            ctypes.c_int,
        ),
        "GetFileAttributesW": ([ctypes.c_wchar_p], ctypes.c_uint32),
        "SetHandleInformation": (
            [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32],
            ctypes.c_int,
        ),
        "CreateProcessW": (
            [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_int,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_wchar_p,
                ctypes.POINTER(_StartupInfo),
                ctypes.POINTER(_ProcessInfo),
            ],
            ctypes.c_int,
        ),
    }
    for name, (arguments, result) in declarations.items():
        function = getattr(kernel, name)
        function.argtypes = arguments
        function.restype = result
    return kernel


def _in_job(kernel, process):
    member = ctypes.c_int()
    if not kernel.IsProcessInJob(process, None, ctypes.byref(member)):
        raise ctypes.WinError(ctypes.get_last_error())
    return bool(member.value)


def _can_break_away(kernel):
    if not _in_job(kernel, kernel.GetCurrentProcess()):
        return True
    limits = _JobLimits()
    if not kernel.QueryInformationJobObject(
        None, 2, ctypes.byref(limits), ctypes.sizeof(limits), None
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    # Match core 2.21.1: explicit breakaway must be permitted by the caller's job.
    return bool(limits.flags & 0x800)


def _stop_watchdog(kernel, handle):
    state = kernel.WaitForSingleObject(handle, 0)
    if state == 258:
        if not kernel.TerminateProcess(handle, 1):
            raise ctypes.WinError(ctypes.get_last_error())
        if kernel.WaitForSingleObject(handle, 5000) != 0:
            raise OSError("Failed to stop the owned async watchdog")
    elif state != 0:
        raise ctypes.WinError(ctypes.get_last_error())


def _launch_watchdog_direct(kernel, command, directory, environment):
    info = _ProcessInfo()
    # Explicit null stdio keeps Windows 7 from inheriting connection pipe handles.
    startup = _StartupInfo(size=ctypes.sizeof(_StartupInfo), flags=0x101, show=0)
    block = ctypes.create_unicode_buffer(
        "\0".join(
            key + "=" + value
            for key, value in sorted(
                environment.items(), key=lambda item: item[0].upper()
            )
        )
        + "\0\0"
    )
    try:
        if not kernel.CreateProcessW(
            None,
            ctypes.create_unicode_buffer(command),
            None,
            None,
            False,
            0x0100040C,
            block,
            directory,
            ctypes.byref(startup),
            ctypes.byref(info),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        # A nested job can prevent full escape despite its nearest job's flags.
        # The child is still suspended, so stop it before choosing WMI instead.
        if _in_job(kernel, info.process):
            _stop_watchdog(kernel, info.process)
            return None
        if kernel.ResumeThread(info.thread) == 0xFFFFFFFF:
            raise ctypes.WinError(ctypes.get_last_error())
        handle = info.process
        # Clearing this ctypes ABI field transfers handle ownership to the caller.
        # pylint: disable-next=attribute-defined-outside-init
        info.process = None
        return handle, info.pid
    finally:
        try:
            if info.process:
                try:
                    _stop_watchdog(kernel, info.process)
                finally:
                    kernel.CloseHandle(info.process)
        finally:
            if info.thread:
                kernel.CloseHandle(info.thread)


def launch_watchdog(command, directory, environment):
    """Launch a watchdog outside the caller's job and retain its process handle.

    :param command: Literal Windows process command line.
    :type command: str
    :param directory: Initial working directory.
    :type directory: str
    :param environment: Complete inherited Windows environment.
    :type environment: dict
    :returns: Kernel API, owned process handle and newly created process identifier.
    :rtype: tuple
    :raises OSError: Job inspection, process creation or watchdog startup fails.
    """
    kernel = kernel_api()
    if _can_break_away(kernel):
        launched = _launch_watchdog_direct(kernel, command, directory, environment)
        if launched is not None:
            return kernel, launched[0], launched[1]
    pid = _launch_watchdog_wmi(command, directory, environment)
    handle = kernel.OpenProcess(0x100401, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    return kernel, handle, pid


def _launch_watchdog_wmi(command, directory, environment):
    # WMI's embedded ProcessStartupInformation must be VT_UNKNOWN, not a
    # dictionary. Reuse the maintained COM lifetime/SAFEARRAY primitives.
    # pylint: disable=protected-access
    with wmi.WmiConnection() as connection, ExitStack() as cleanup:
        # The watchdog launcher owns its native ProcessStartup object.
        # pylint: disable=duplicate-code
        definition = wmi._get_object(
            connection._services,
            connection._automation,
            cleanup,
            "Win32_ProcessStartup",
        )
        startup = ctypes.c_void_p()
        cleanup.callback(wmi._release, startup)
        wmi._check(
            wmi._method(
                definition,
                15,
                ctypes.c_int32,
                [ctypes.c_int32, ctypes.POINTER(ctypes.c_void_p)],
            )(definition, 0, ctypes.byref(startup)),
            "SpawnInstance(ProcessStartup)",
        )
        # pylint: enable=duplicate-code
        # Declare this watchdog's environment and detached-process startup settings.
        # pylint: disable=duplicate-code
        wmi._put_string_array(
            startup,
            connection._automation,
            "EnvironmentVariables",
            [key + "=" + value for key, value in sorted(environment.items())],
        )
        wmi._put_integer(startup, connection._automation, "CreateFlags", 0x01000408)
        wmi._put_integer(startup, connection._automation, "ShowWindow", 0)
        inputs = connection._method_inputs(
            cleanup,
            "Win32_Process",
            "Create",
            {"CommandLine": command, "CurrentDirectory": directory},
        )
        # pylint: enable=duplicate-code
        # Marshal the embedded startup object with its matching COM reference cleanup.
        # pylint: disable=duplicate-code
        value = wmi._Variant(kind=13)
        value.data.bstr = startup
        wmi._method(startup, 1, ctypes.c_uint32, [])(startup)
        # pylint: enable=duplicate-code
        # This launcher owns the native Create output until its result is decoded.
        # pylint: disable=duplicate-code
        try:
            wmi._check(
                wmi._method(
                    inputs,
                    5,
                    ctypes.c_int32,
                    [
                        ctypes.c_wchar_p,
                        ctypes.c_int32,
                        ctypes.POINTER(wmi._Variant),
                        ctypes.c_int32,
                    ],
                )(inputs, "ProcessStartupInformation", 0, ctypes.byref(value), 0),
                "Put(ProcessStartupInformation)",
            )
        finally:
            wmi._check(
                connection._automation.VariantClear(ctypes.byref(value)),
                "VariantClear(ProcessStartupInformation)",
            )
        output = ctypes.c_void_p()
        cleanup.callback(wmi._release, output)
        wmi._check(
            wmi._method(
                connection._services,
                24,
                ctypes.c_int32,
                [
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.c_int32,
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.POINTER(ctypes.c_void_p),
                    ctypes.c_void_p,
                ],
            )(
                connection._services,
                wmi._bstr(connection._automation, cleanup, "Win32_Process"),
                wmi._bstr(connection._automation, cleanup, "Create"),
                0,
                None,
                inputs,
                ctypes.byref(output),
                None,
            ),
            "ExecMethod(Create watchdog)",
        )
        # pylint: enable=duplicate-code
        if not output:
            raise OSError("WMI returned no watchdog creation result.")
        result = connection._properties(output, ["ReturnValue", "ProcessId"])
    # pylint: enable=protected-access
    if result.get("ReturnValue") != 0 or not result.get("ProcessId"):
        raise OSError("WMI could not create the async watchdog: {0}".format(result))
    return int(result["ProcessId"])


@contextmanager
# The context returns a live job/process pair; Sphinx's parser has no yield fields.
# pylint: disable-next=missing-yield-doc,missing-yield-type-doc
def payload_process(arguments, directory, streams):
    """Assign a suspended payload to a kill-on-close job before running it.

    :param arguments: Executable and literal arguments supplied by Ansible.
    :type arguments: list
    :param directory: Payload working directory.
    :type directory: str
    :param streams: Open stdin, stdout and stderr files, in that order.
    :type streams: tuple
    :returns: Context yielding kernel32, process handle, job handle and PID.
    :rtype: context manager
    :raises OSError: Creating, assigning or resuming the payload fails.
    """
    # msvcrt exists only on the target; importing here keeps native ABI unit
    # checks usable on the Linux controller without a fake target dependency.
    import msvcrt  # pylint: disable=import-outside-toplevel,import-error

    kernel = kernel_api()
    info = _ProcessInfo()
    handles = [msvcrt.get_osfhandle(stream.fileno()) for stream in streams]
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        limits = _ExtendedJobLimits(_JobLimits(flags=0x2000))
        if not kernel.SetInformationJobObject(
            job, 9, ctypes.byref(limits), ctypes.sizeof(limits)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        for handle in handles:
            if not kernel.SetHandleInformation(handle, 1, 1):
                raise ctypes.WinError(ctypes.get_last_error())
        startup = _StartupInfo(
            size=ctypes.sizeof(_StartupInfo),
            flags=0x100,
            stdin=handles[0],
            stdout=handles[1],
            stderr=handles[2],
        )
        command = ctypes.create_unicode_buffer(subprocess.list2cmdline(arguments))
        if not kernel.CreateProcessW(
            arguments[0],
            command,
            None,
            None,
            True,
            0x00000004 | 0x08000000,
            None,
            directory,
            ctypes.byref(startup),
            ctypes.byref(info),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel.AssignProcessToJobObject(job, info.process):
            raise ctypes.WinError(ctypes.get_last_error())
        if kernel.ResumeThread(info.thread) == 0xFFFFFFFF:
            raise ctypes.WinError(ctypes.get_last_error())
        yield kernel, info.process, job, info.pid
    finally:
        for handle in handles:
            kernel.SetHandleInformation(handle, 1, 0)
        # A failed assignment still leaves a suspended child; terminate that
        # exact handle before closing it. Closing the job kills descendants.
        if info.process and kernel.WaitForSingleObject(info.process, 0) == 258:
            kernel.TerminateProcess(info.process, 1)
        kernel.CloseHandle(job)
        if info.process:
            kernel.WaitForSingleObject(info.process, 5000)
            kernel.CloseHandle(info.process)
        if info.thread:
            kernel.CloseHandle(info.thread)


def remove_staging(directory):
    """Remove only the owned task directory, without following reparse points.

    :param directory: Exact task directory validated against the staged module.
    :type directory: str
    :raises OSError: A file or directory cannot be removed.
    """
    kernel = kernel_api()

    def remove(path):
        attributes = kernel.GetFileAttributesW(path)
        if attributes == 0xFFFFFFFF:
            code = ctypes.get_last_error()
            if code in (2, 3):
                return
            raise ctypes.WinError(code)
        if attributes & 0x10:
            if not attributes & 0x400:
                for name in os.listdir(path):
                    remove(os.path.join(path, name))
            os.rmdir(path)
        else:
            os.remove(path)

    remove(directory)
