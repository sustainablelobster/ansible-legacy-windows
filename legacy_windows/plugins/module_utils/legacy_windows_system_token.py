# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Acquire a legacy SYSTEM token through one temporary native SCM service."""

import ctypes
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager

_DWORD = ctypes.c_uint32
_HANDLE = ctypes.c_void_p
_BOOL = ctypes.c_int
_INVALID = _HANDLE(-1).value
_PREFIX = "legacy_windows_system_"
_SECONDS = 15


# These records describe Windows ABI storage, not independent Python objects.
class _Attributes(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("length", _DWORD), ("descriptor", _HANDLE), ("inherit", _BOOL)]


class _Status(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("kind", _DWORD),
        ("state", _DWORD),
        ("controls", _DWORD),
        ("error", _DWORD),
        ("specific", _DWORD),
        ("checkpoint", _DWORD),
        ("wait_hint", _DWORD),
        ("pid", _DWORD),
        ("flags", _DWORD),
    ]


def _libraries():
    if os.name != "nt":
        raise ValueError("SYSTEM acquisition requires Windows.")
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.POINTER(_HANDLE)
    count = ctypes.POINTER(_DWORD)
    wide = ctypes.c_wchar_p
    definitions = (
        (security, "OpenProcessToken", [_HANDLE, _DWORD, pointer], _BOOL),
        (security, "OpenThreadToken", [_HANDLE, _DWORD, _BOOL, pointer], _BOOL),
        (
            security,
            "GetTokenInformation",
            [_HANDLE, ctypes.c_int, _HANDLE, _DWORD, count],
            _BOOL,
        ),
        (security, "ConvertSidToStringSidW", [_HANDLE, pointer], _BOOL),
        (
            security,
            "DuplicateTokenEx",
            [_HANDLE, _DWORD, _HANDLE, ctypes.c_int, ctypes.c_int, pointer],
            _BOOL,
        ),
        (
            security,
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            [wide, _DWORD, pointer, count],
            _BOOL,
        ),
        (security, "ImpersonateNamedPipeClient", [_HANDLE], _BOOL),
        (security, "RevertToSelf", [], _BOOL),
        (security, "SetThreadToken", [pointer, _HANDLE], _BOOL),
        (security, "OpenSCManagerW", [wide, wide, _DWORD], _HANDLE),
        (
            security,
            "CreateServiceW",
            [
                _HANDLE,
                wide,
                wide,
                _DWORD,
                _DWORD,
                _DWORD,
                _DWORD,
                wide,
                wide,
                count,
                wide,
                wide,
                wide,
            ],
            _HANDLE,
        ),
        (security, "StartServiceW", [_HANDLE, _DWORD, _HANDLE], _BOOL),
        (
            security,
            "QueryServiceStatusEx",
            [_HANDLE, _DWORD, _HANDLE, _DWORD, count],
            _BOOL,
        ),
        (security, "ControlService", [_HANDLE, _DWORD, _HANDLE], _BOOL),
        (security, "DeleteService", [_HANDLE], _BOOL),
        (security, "CloseServiceHandle", [_HANDLE], _BOOL),
        (kernel, "GetCurrentProcess", [], _HANDLE),
        (kernel, "GetCurrentThread", [], _HANDLE),
        (kernel, "OpenProcess", [_DWORD, _BOOL, _DWORD], _HANDLE),
        (kernel, "CloseHandle", [_HANDLE], _BOOL),
        (kernel, "LocalFree", [_HANDLE], _HANDLE),
        (kernel, "CreateDirectoryW", [wide, _HANDLE], _BOOL),
        (
            kernel,
            "CreateNamedPipeW",
            [wide, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _DWORD, _HANDLE],
            _HANDLE,
        ),
        (kernel, "ConnectNamedPipe", [_HANDLE, _HANDLE], _BOOL),
        (
            kernel,
            "CreateFileW",
            [wide, _DWORD, _DWORD, _HANDLE, _DWORD, _DWORD, _HANDLE],
            _HANDLE,
        ),
        (kernel, "SetNamedPipeHandleState", [_HANDLE, count, count, count], _BOOL),
        (kernel, "ReadFile", [_HANDLE, _HANDLE, _DWORD, count, _HANDLE], _BOOL),
        (kernel, "WriteFile", [_HANDLE, _HANDLE, _DWORD, count, _HANDLE], _BOOL),
        (kernel, "WaitForSingleObject", [_HANDLE, _DWORD], _DWORD),
    )
    for library, name, arguments, result in definitions:
        function = getattr(library, name)
        function.argtypes, function.restype = arguments, result
    return security, kernel


def _sid(security, kernel, token):
    needed = _DWORD()
    security.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
    if ctypes.get_last_error() != 122 or not needed.value:
        raise ctypes.WinError(ctypes.get_last_error())
    buffer = ctypes.create_string_buffer(needed.value)
    if not security.GetTokenInformation(
        token, 1, buffer, len(buffer), ctypes.byref(needed)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    text = _HANDLE()
    if not security.ConvertSidToStringSidW(
        _HANDLE.from_buffer(buffer), ctypes.byref(text)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.wstring_at(text)
    finally:
        kernel.LocalFree(text)


@contextmanager
def _attributes(security, kernel, caller, children=False):
    inheritance = "OICI" if children else ""
    descriptor = _HANDLE()
    sddl = "D:P(A;{0};GA;;;SY)(A;{0};GA;;;{1})".format(inheritance, caller)
    if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        yield _Attributes(ctypes.sizeof(_Attributes), descriptor, False)
    finally:
        kernel.LocalFree(descriptor)


def _status(security, service):
    result, needed = _Status(), _DWORD()
    if not security.QueryServiceStatusEx(
        service, 0, ctypes.byref(result), ctypes.sizeof(result), ctypes.byref(needed)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return result


def _read_message(kernel, pipe, expected, deadline):
    buffer, count = ctypes.create_string_buffer(len(expected) + 1), _DWORD()
    while time.monotonic() < deadline:
        if kernel.ReadFile(pipe, buffer, len(buffer), ctypes.byref(count), None):
            if buffer.raw[: count.value] != expected:
                raise ValueError("Unexpected SYSTEM token handoff message.")
            return
        error = ctypes.get_last_error()
        # A nonblocking server can be read before the SCM child opens its end.
        # ERROR_PIPE_LISTENING is transient, just like an empty pipe, and the
        # same deadline bounds all three states.
        if error not in (232, 233, 536):
            raise ctypes.WinError(error)
        time.sleep(0.02)
    raise ValueError("Timed out waiting for the SYSTEM token handoff.")


def _write_message(kernel, pipe, value):
    count = _DWORD()
    if not kernel.WriteFile(pipe, value, len(value), ctypes.byref(count), None):
        raise ctypes.WinError(ctypes.get_last_error())
    if count.value != len(value):
        raise ValueError("Incomplete SYSTEM token handoff message.")


def _duplicate_client(security, kernel, pipe):
    previous, client, duplicate = _HANDLE(), _HANDLE(), _HANDLE()
    if (
        not security.OpenThreadToken(
            kernel.GetCurrentThread(), 0xC, True, ctypes.byref(previous)
        )
        and ctypes.get_last_error() != 1008
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    impersonated = False
    try:
        if not security.ImpersonateNamedPipeClient(pipe):
            raise ctypes.WinError(ctypes.get_last_error())
        impersonated = True
        # Open as the peer, not the administrative caller: XP protects SYSTEM's
        # token from other identities even when the caller has debug privilege.
        if not security.OpenThreadToken(
            kernel.GetCurrentThread(), 0xF, False, ctypes.byref(client)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if _sid(security, kernel, client) != "S-1-5-18":
            raise ValueError("SYSTEM token handoff peer is not LocalSystem.")
        if not security.DuplicateTokenEx(
            client, 0x02000000, None, 2, 1, ctypes.byref(duplicate)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        restored = True
        if impersonated:
            restored = bool(
                security.SetThreadToken(None, previous)
                if previous
                else security.RevertToSelf()
            )
        if client:
            kernel.CloseHandle(client)
        if previous:
            kernel.CloseHandle(previous)
        if not restored:
            if duplicate:
                kernel.CloseHandle(duplicate)
            raise ctypes.WinError(ctypes.get_last_error())
    return duplicate


def _stop_and_wait(security, kernel, resources):
    service = resources["service"]
    if _status(security, service).state not in (1, 3):
        stopped = _Status()
        if not security.ControlService(service, 1, ctypes.byref(stopped)):
            error = ctypes.get_last_error()
            # This one-shot service can enter shutdown between the status
            # query and STOP. Its rejected control is not proof of shutdown;
            # the bounded loop below still requires SERVICE_STOPPED.
            if error not in (1052, 1061, 1062):
                raise ctypes.WinError(error)
    deadline = time.monotonic() + _SECONDS
    while _status(security, service).state != 1:
        if time.monotonic() >= deadline:
            raise ValueError("Temporary SYSTEM service did not stop.")
        time.sleep(0.02)
    if (
        resources.get("process")
        and kernel.WaitForSingleObject(resources["process"], _SECONDS * 1000) != 0
    ):
        raise ValueError("Temporary SYSTEM service process did not exit.")


def _cleanup(security, kernel, resources):
    failures = []
    if resources.get("pipe"):
        kernel.CloseHandle(resources["pipe"])
    service = resources.get("service")
    if service:
        try:
            _stop_and_wait(security, kernel, resources)
        except (OSError, ValueError) as error:
            failures.append(str(error))
        if not security.DeleteService(service):
            failures.append(str(ctypes.WinError(ctypes.get_last_error())))
        security.CloseServiceHandle(service)
    if resources.get("process"):
        kernel.CloseHandle(resources["process"])
    if resources.get("manager"):
        security.CloseServiceHandle(resources["manager"])
    if resources.get("directory") and not failures:
        try:
            if resources.get("script"):
                os.unlink(resources["script"])
            os.rmdir(resources["directory"])
        except OSError as error:
            failures.append(str(error))
    if failures:
        raise ValueError(
            "Temporary SYSTEM service cleanup failed for {0} at {1}: {2}".format(
                resources.get("name"), resources.get("directory"), "; ".join(failures)
            )
        )


def _caller_sid(security, kernel):
    process_token = _HANDLE()
    if not security.OpenProcessToken(
        kernel.GetCurrentProcess(), 8, ctypes.byref(process_token)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return _sid(security, kernel, process_token)
    finally:
        kernel.CloseHandle(process_token)


def _prepare_service(security, kernel, caller, resources):
    name = resources["name"]
    directory = os.path.join(tempfile.gettempdir(), name)
    with _attributes(security, kernel, caller, children=True) as attributes:
        if not kernel.CreateDirectoryW(directory, ctypes.byref(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())
    resources["directory"] = directory
    script = os.path.join(directory, "system_token.py")
    with open(script, "xb") as output, open(__file__, "rb") as source:
        resources["script"] = script
        shutil.copyfileobj(source, output)
    with _attributes(security, kernel, caller) as attributes:
        pipe = kernel.CreateNamedPipeW(
            "\\\\.\\pipe\\" + name,
            3 | 0x80000,
            4 | 2 | 1,
            1,
            64,
            64,
            0,
            ctypes.byref(attributes),
        )
    if pipe in (None, _INVALID):
        raise ctypes.WinError(ctypes.get_last_error())
    resources["pipe"] = pipe
    if not kernel.ConnectNamedPipe(pipe, None):
        error = ctypes.get_last_error()
        if error not in (535, 536):
            raise ctypes.WinError(error)
    manager = security.OpenSCManagerW(None, None, 2)
    if not manager:
        raise ctypes.WinError(ctypes.get_last_error())
    resources["manager"] = manager
    command = subprocess.list2cmdline(
        [sys.executable, script, name, resources["nonce"]]
    )
    service = security.CreateServiceW(
        manager,
        name,
        name,
        0x10000 | 4 | 0x10 | 0x20,
        0x10,
        3,
        1,
        command,
        None,
        None,
        None,
        None,
        None,
    )
    if not service:
        raise ctypes.WinError(ctypes.get_last_error())
    resources["service"] = service


def acquire_token():
    """Return an owned primary SYSTEM token without changing existing ACLs.

    :returns: Native primary token handle; the caller must close it.
    :rtype: ctypes.c_void_p
    :raises OSError: If native permissions or token acquisition fail.
    :raises ValueError: If identity, deadline, or owned-resource cleanup fails.
        The one-shot service and its private files are removed before return.
    """
    security, kernel = _libraries()
    resources = {"name": _PREFIX + uuid.uuid4().hex, "nonce": uuid.uuid4().hex}
    token, acquired, cleaned = None, False, False
    operation = "preparing the owned service"
    try:
        _prepare_service(security, kernel, _caller_sid(security, kernel), resources)
        service, pipe = resources["service"], resources["pipe"]
        operation = "starting the owned service"
        if not security.StartServiceW(service, 0, None):
            raise ctypes.WinError(ctypes.get_last_error())
        operation = "pinning the owned service process"
        pid = _status(security, service).pid
        process = kernel.OpenProcess(0x100000 | 0x400, False, pid)
        if not process:
            raise ctypes.WinError(ctypes.get_last_error())
        resources["process"] = process
        operation = "reading the authenticated handoff"
        _read_message(
            kernel,
            pipe,
            resources["nonce"].encode("ascii"),
            time.monotonic() + _SECONDS,
        )
        operation = "duplicating the authenticated service token"
        token = _duplicate_client(security, kernel, pipe)
        operation = "acknowledging the completed handoff"
        _write_message(kernel, pipe, b"\x01")
        acquired = True
    except OSError as error:
        raise OSError(
            "SYSTEM acquisition failed while {0}: {1}".format(operation, error)
        ) from error
    finally:
        try:
            _cleanup(security, kernel, resources)
            cleaned = True
        finally:
            if token and not (acquired and cleaned):
                kernel.CloseHandle(token)
    return token


def _client(kernel, name, nonce):
    pipe = kernel.CreateFileW(
        "\\\\.\\pipe\\" + name, 0xC0000000, 0, None, 3, 0x120000, None
    )
    if pipe in (None, _INVALID):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        mode = _DWORD(2 | 1)
        if not kernel.SetNamedPipeHandleState(pipe, ctypes.byref(mode), None, None):
            raise ctypes.WinError(ctypes.get_last_error())
        _write_message(kernel, pipe, nonce.encode("ascii"))
        _read_message(kernel, pipe, b"\x01", time.monotonic() + _SECONDS)
    finally:
        kernel.CloseHandle(pipe)


def _serve(name, nonce):
    if not re.match(r"^legacy_windows_system_[0-9a-f]{32}$", name) or not re.match(
        r"^[0-9a-f]{32}$", nonce
    ):
        raise ValueError("Invalid one-shot SYSTEM service arguments.")
    security, kernel = _libraries()
    main_type = ctypes.WINFUNCTYPE(None, _DWORD, ctypes.POINTER(ctypes.c_wchar_p))
    handler_type = ctypes.WINFUNCTYPE(_DWORD, _DWORD, _DWORD, _HANDLE, _HANDLE)

    # The callbacks and status remain alive until the native dispatcher returns.
    class _Entry(ctypes.Structure):  # pylint: disable=too-few-public-methods
        _fields_ = [("name", ctypes.c_wchar_p), ("main", main_type)]

    security.RegisterServiceCtrlHandlerExW.argtypes = [
        ctypes.c_wchar_p,
        handler_type,
        _HANDLE,
    ]
    security.RegisterServiceCtrlHandlerExW.restype = _HANDLE
    security.SetServiceStatus.argtypes = [_HANDLE, _HANDLE]
    security.SetServiceStatus.restype = _BOOL
    security.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(_Entry)]
    security.StartServiceCtrlDispatcherW.restype = _BOOL
    done = threading.Event()

    @handler_type
    def _handler(control, _event, _data, _context):
        if control == 1:
            done.set()
        return 0

    @main_type
    def _main(_count, _arguments):
        handle = security.RegisterServiceCtrlHandlerExW(name, _handler, None)
        if not handle:
            return
        status = _Status(0x10, 4, 1, 0, 0, 0, 0, 0, 0)
        if not security.SetServiceStatus(handle, ctypes.byref(status)):
            return
        error = 0
        try:
            if not done.is_set():
                _client(kernel, name, nonce)
        except (OSError, ValueError):
            error = 1
        finally:
            status = _Status(0x10, 1, 0, error, 0, 0, 0, 0, 0)
            security.SetServiceStatus(handle, ctypes.byref(status))

    table = (_Entry * 2)(_Entry(name, _main), _Entry(None, main_type()))
    if not security.StartServiceCtrlDispatcherW(table):
        raise ctypes.WinError(ctypes.get_last_error())


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise ValueError("Expected one-shot SYSTEM service name and nonce.")
    _serve(sys.argv[1], sys.argv[2])
