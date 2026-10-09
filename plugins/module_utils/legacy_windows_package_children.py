# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Wait for the installer and its descendants using a native completion job."""

import ctypes
import os
import subprocess
import threading
from contextlib import ExitStack, contextmanager

import legacy_windows_process as processes  # pylint: disable=import-error
import legacy_windows_text as text_codec  # pylint: disable=import-error


# Native ABI records are data fields, not behavioral interfaces.
class _CompletionPort(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("key", ctypes.c_void_p), ("port", ctypes.c_void_p)]


def _kernel():
    library = ctypes.WinDLL("kernel32", use_last_error=True)
    signatures = {
        "CreateJobObjectW": ([ctypes.c_void_p, ctypes.c_wchar_p], ctypes.c_void_p),
        "CreateIoCompletionPort": (
            [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32],
            ctypes.c_void_p,
        ),
        "SetInformationJobObject": (
            [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32],
            ctypes.c_int,
        ),
        "AssignProcessToJobObject": ([ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int),
        "GetQueuedCompletionStatus": (
            [
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_uint32),
                ctypes.POINTER(ctypes.c_size_t),
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.c_uint32,
            ],
            ctypes.c_int,
        ),
        "ResumeThread": ([ctypes.c_void_p], ctypes.c_uint32),
        "WaitForSingleObject": ([ctypes.c_void_p, ctypes.c_uint32], ctypes.c_uint32),
        "GetExitCodeProcess": (
            [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)],
            ctypes.c_int,
        ),
        "TerminateProcess": ([ctypes.c_void_p, ctypes.c_uint32], ctypes.c_int),
        "CloseHandle": ([ctypes.c_void_p], ctypes.c_int),
        "GetConsoleWindow": ([], ctypes.c_void_p),
        "AllocConsole": ([], ctypes.c_int),
        "FreeConsole": ([], ctypes.c_int),
        "SetConsoleCP": ([ctypes.c_uint32], ctypes.c_int),
        "SetConsoleOutputCP": ([ctypes.c_uint32], ctypes.c_int),
    }
    for name, (arguments, result) in signatures.items():
        operation = getattr(library, name)
        operation.argtypes, operation.restype = arguments, result
    return library


def _read_output(stream, output, errors, index):
    try:
        output[index] = stream.read()
    except OSError as error:
        errors.append(error)


@contextmanager
def _job(kernel):
    job, port = None, None
    try:
        job = kernel.CreateJobObjectW(None, None)
        if not job:
            raise ctypes.WinError(ctypes.get_last_error())
        port = kernel.CreateIoCompletionPort(ctypes.c_void_p(-1), None, 0, 1)
        if not port:
            raise ctypes.WinError(ctypes.get_last_error())
        association = _CompletionPort(job, port)
        if not kernel.SetInformationJobObject(
            job, 7, ctypes.byref(association), ctypes.sizeof(association)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        yield job, port
    finally:
        for handle in (port, job):
            if handle:
                kernel.CloseHandle(handle)


def _create_process(kernel, application, command, directory, child_streams):
    # CPython3.4's own Windows CreateProcess binding retains the primary thread
    # handle, which Popen closes too early for race-free job assignment.
    import msvcrt  # pylint: disable=import-outside-toplevel,import-error

    import _winapi  # pylint: disable=import-outside-toplevel,import-error

    startup = subprocess.STARTUPINFO()
    startup.dwFlags = 0x100
    startup.hStdInput, startup.hStdOutput, startup.hStdError = (
        msvcrt.get_osfhandle(stream.fileno()) for stream in child_streams
    )
    allocated = False
    if not kernel.GetConsoleWindow():
        allocated = bool(kernel.AllocConsole())
    kernel.SetConsoleCP(65001)
    kernel.SetConsoleOutputCP(65001)
    try:
        return _winapi.CreateProcess(
            application, command, None, None, True, 0x4, None, directory, startup
        )
    finally:
        if allocated:
            kernel.FreeConsole()


def _wait_process(kernel, process, port, streams):
    output, errors = [b"", b""], []
    readers = [
        threading.Thread(target=_read_output, args=(stream, output, errors, index))
        for index, stream in enumerate(streams)
    ]
    for reader in readers:
        reader.start()
    for reader in readers:
        reader.join()
    if errors:
        raise errors[0]
    if kernel.WaitForSingleObject(process, 0xFFFFFFFF) == 0xFFFFFFFF:
        raise ctypes.WinError(ctypes.get_last_error())
    code = ctypes.c_uint32()
    if not kernel.GetExitCodeProcess(process, ctypes.byref(code)):
        raise ctypes.WinError(ctypes.get_last_error())
    message, key, overlapped = ctypes.c_uint32(), ctypes.c_size_t(), ctypes.c_void_p()
    # The released watcher returns when the queue fails or reports ACTIVE
    # PROCESS ZERO. Other notifications are not descendants' return codes.
    while kernel.GetQueuedCompletionStatus(
        port,
        ctypes.byref(message),
        ctypes.byref(key),
        ctypes.byref(overlapped),
        0xFFFFFFFF,
    ):
        if message.value == 4:
            break
    return code.value, output[0], output[1]


def _pipe(resources):
    reader, writer = os.pipe()
    return (
        resources.enter_context(os.fdopen(reader, "rb")),
        resources.enter_context(os.fdopen(writer, "wb")),
    )


def _execute(application, command, directory):
    kernel = _kernel()
    with _job(kernel) as (job, port), ExitStack() as resources:
        stdin, stdout, stderr = _pipe(resources), _pipe(resources), _pipe(resources)
        child_streams = (stdin[0], stdout[1], stderr[1])
        for stream in child_streams:
            os.set_inheritable(stream.fileno(), True)
        process, primary_thread = _create_process(
            kernel, application, command, directory, child_streams
        )[:2]
        resumed = False
        try:
            if not kernel.AssignProcessToJobObject(job, process):
                raise ctypes.WinError(ctypes.get_last_error())
            # Package stdin is immediate EOF; parent writer copies must close
            # before the readers can see the child's final output EOF.
            for stream in child_streams + (stdin[1],):
                stream.close()
            if kernel.ResumeThread(primary_thread) == 0xFFFFFFFF:
                raise ctypes.WinError(ctypes.get_last_error())
            resumed = True
            return _wait_process(kernel, process, port, (stdout[0], stderr[0]))
        finally:
            # Do not leave our exact unstarted suspended root after a failed
            # assignment/resume; no successfully launched descendants are killed.
            if not resumed:
                kernel.TerminateProcess(process, 1)
                kernel.WaitForSingleObject(process, 5000)
            kernel.CloseHandle(primary_thread)
            kernel.CloseHandle(process)


def run_command(executable, command_line, parameters):
    """Execute a Package command after enrolling its suspended root in a job.

    :param str executable: Explicit executable, or None to resolve the command.
    :param str command_line: Complete released installer command line.
    :param dict parameters: Working directory and output encoding; stdin is EOF.
    :returns: Root return code and captured streams after all descendants exit.
    :rtype: dict
    """
    # These exact parsing/encoding primitives are already shared by win_command;
    # preserve them without adding child-wait behavior to that public module.
    # pylint: disable=protected-access
    try:
        encoding = processes._output_encoding(parameters["output_encoding_override"])
        application = executable or processes._application_from_command(command_line)
        application = processes.resolve_executable(application, parameters["chdir"])
        code, stdout, stderr = _execute(
            application, command_line, parameters["chdir"] or None
        )
    except (OSError, ValueError) as error:
        # Package's child-wait runner returns the same public command failure fields.
        # pylint: disable=duplicate-code
        return {
            "changed": False,
            "failed": True,
            "cmd": command_line,
            "rc": getattr(error, "winerror", None) or 2,
            "msg": "Failed to run: '{0}': {1}".format(command_line, error),
        }
        # pylint: enable=duplicate-code
    return {
        "changed": True,
        "cmd": command_line,
        "rc": code,
        "stdout": text_codec.decode_bytes(stdout, encoding),
        "stderr": text_codec.decode_bytes(stderr, encoding),
    }
