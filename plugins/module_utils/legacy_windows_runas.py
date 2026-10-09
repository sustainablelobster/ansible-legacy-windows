# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Execute a staged task under native runas credentials received through stdin."""

import ctypes
import json

# msvcrt is a Windows standard-library module, absent on the Linux workstation.
import msvcrt  # pylint: disable=import-error
import os
import subprocess
import sys
import threading
from contextlib import contextmanager

import legacy_windows_account as account  # pylint: disable=import-error
import legacy_windows_runas_token as runas_token  # pylint: disable=import-error

_HANDLE = ctypes.c_void_p
_DWORD = ctypes.c_uint32
_BOOL = ctypes.c_int


# Complete native layouts preserve pointer alignment on 32- and 64-bit Windows.
class _SecurityAttributes(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("length", _DWORD), ("descriptor", _HANDLE), ("inherit", _BOOL)]


class _StartupInfo(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("size", _DWORD),
        ("reserved", ctypes.c_wchar_p),
        ("desktop", ctypes.c_wchar_p),
        ("title", ctypes.c_wchar_p),
        ("x", _DWORD),
        ("y", _DWORD),
        ("width", _DWORD),
        ("height", _DWORD),
        ("chars_x", _DWORD),
        ("chars_y", _DWORD),
        ("fill", _DWORD),
        ("flags", _DWORD),
        ("show", ctypes.c_uint16),
        ("reserved_size", ctypes.c_uint16),
        ("reserved_pointer", _HANDLE),
        ("stdin", _HANDLE),
        ("stdout", _HANDLE),
        ("stderr", _HANDLE),
    ]


class _ProcessInfo(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("process", _HANDLE),
        ("thread", _HANDLE),
        ("pid", _DWORD),
        ("tid", _DWORD),
    ]


class _ProfileInfo(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("size", _DWORD),
        ("flags", _DWORD),
        ("username", ctypes.c_wchar_p),
        ("path", ctypes.c_wchar_p),
        ("default_path", ctypes.c_wchar_p),
        ("server", ctypes.c_wchar_p),
        ("policy", ctypes.c_wchar_p),
        ("profile", _HANDLE),
    ]


class _Trustee(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("multiple", _HANDLE),
        ("operation", ctypes.c_int),
        ("form", ctypes.c_int),
        ("kind", ctypes.c_int),
        ("name", _HANDLE),
    ]


class _ExplicitAccess(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("permissions", _DWORD),
        ("mode", ctypes.c_int),
        ("inheritance", _DWORD),
        ("trustee", _Trustee),
    ]


def _libraries():
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreatePipe.argtypes = [
        ctypes.POINTER(_HANDLE),
        ctypes.POINTER(_HANDLE),
        ctypes.POINTER(_SecurityAttributes),
        _DWORD,
    ]
    kernel.CreatePipe.restype = _BOOL
    kernel.SetHandleInformation.argtypes = [_HANDLE, _DWORD, _DWORD]
    kernel.SetHandleInformation.restype = _BOOL
    kernel.CloseHandle.argtypes = [_HANDLE]
    kernel.CloseHandle.restype = _BOOL
    kernel.WaitForSingleObject.argtypes = [_HANDLE, _DWORD]
    kernel.WaitForSingleObject.restype = _DWORD
    kernel.GetExitCodeProcess.argtypes = [_HANDLE, ctypes.POINTER(_DWORD)]
    kernel.GetExitCodeProcess.restype = _BOOL
    kernel.TerminateProcess.argtypes = [_HANDLE, _DWORD]
    kernel.TerminateProcess.restype = _BOOL
    kernel.LocalFree.argtypes = [_HANDLE]
    kernel.LocalFree.restype = _HANDLE
    security.GetNamedSecurityInfoW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_int,
        _DWORD,
        _HANDLE,
        _HANDLE,
        ctypes.POINTER(_HANDLE),
        _HANDLE,
        ctypes.POINTER(_HANDLE),
    ]
    security.GetNamedSecurityInfoW.restype = _DWORD
    security.SetEntriesInAclW.argtypes = [
        _DWORD,
        ctypes.POINTER(_ExplicitAccess),
        _HANDLE,
        ctypes.POINTER(_HANDLE),
    ]
    security.SetEntriesInAclW.restype = _DWORD
    security.SetNamedSecurityInfoW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_int,
        _DWORD,
        _HANDLE,
        _HANDLE,
        _HANDLE,
        _HANDLE,
    ]
    security.SetNamedSecurityInfoW.restype = _DWORD
    startup = ctypes.POINTER(_StartupInfo)
    process = ctypes.POINTER(_ProcessInfo)
    security.CreateProcessWithLogonW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        _DWORD,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        _DWORD,
        _HANDLE,
        ctypes.c_wchar_p,
        startup,
        process,
    ]
    security.CreateProcessWithLogonW.restype = _BOOL
    if hasattr(security, "CreateProcessWithTokenW"):
        security.CreateProcessWithTokenW.argtypes = [
            _HANDLE,
            _DWORD,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            _DWORD,
            _HANDLE,
            ctypes.c_wchar_p,
            startup,
            process,
        ]
        security.CreateProcessWithTokenW.restype = _BOOL
    security.CreateProcessAsUserW.argtypes = [
        _HANDLE,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        _HANDLE,
        _HANDLE,
        _BOOL,
        _DWORD,
        _HANDLE,
        ctypes.c_wchar_p,
        startup,
        process,
    ]
    security.CreateProcessAsUserW.restype = _BOOL
    return security, kernel


def _grant_task_read(security, kernel, directory, sid):
    descriptor, previous, revised = _HANDLE(), _HANDLE(), _HANDLE()
    raw_sid = ctypes.create_string_buffer(account.sid_bytes(sid))
    # Add only read/execute inheritance for the authenticated child account.
    access = _ExplicitAccess(
        0x1200A9, 1, 3, _Trustee(None, 0, 0, 1, ctypes.addressof(raw_sid))
    )
    try:
        status = security.GetNamedSecurityInfoW(
            directory,
            1,
            4,
            None,
            None,
            ctypes.byref(previous),
            None,
            ctypes.byref(descriptor),
        )
        if not status and not previous:
            # A NULL DACL already grants access; replacing it would remove rights.
            return
        if not status:
            status = security.SetEntriesInAclW(
                1, ctypes.byref(access), previous, ctypes.byref(revised)
            )
        if not status:
            status = security.SetNamedSecurityInfoW(
                directory, 1, 4, None, None, revised, None
            )
        if status:
            raise ctypes.WinError(status)
    finally:
        if revised:
            kernel.LocalFree(revised)
        if descriptor:
            kernel.LocalFree(descriptor)


def _pipe(kernel, parent_reads):
    read, write = _HANDLE(), _HANDLE()
    attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), None, True)
    if not kernel.CreatePipe(
        ctypes.byref(read), ctypes.byref(write), ctypes.byref(attributes), 0
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    parent, child = (read, write) if parent_reads else (write, read)
    try:
        if not kernel.SetHandleInformation(parent, 1, 0):
            raise ctypes.WinError(ctypes.get_last_error())
        return parent, child
    except Exception:
        kernel.CloseHandle(read)
        kernel.CloseHandle(write)
        raise


def _logon_flags(value):
    flags = {"None": 0, "WithProfile": 1, "NetCredentialsOnly": 2}
    result = 0
    for flag in value.split(", "):
        if flag not in flags:
            raise ValueError("Invalid runas logon flag: " + flag)
        result |= flags[flag]
    return result


@contextmanager
def _legacy_environment(security, token, request):
    if _has_token_launch(security) or (
        request["password"] is not None and request["logon_type"] == "Interactive"
    ):
        # These process APIs create the requested user's environment themselves.
        yield None
        return
    flags = _logon_flags(request["logon_flags"])
    if flags & 2:
        raise ValueError("Legacy token-only runas cannot use NetCredentialsOnly.")
    userenv = ctypes.WinDLL("userenv", use_last_error=True)
    userenv.LoadUserProfileW.argtypes = [_HANDLE, ctypes.POINTER(_ProfileInfo)]
    userenv.LoadUserProfileW.restype = _BOOL
    userenv.UnloadUserProfile.argtypes = [_HANDLE, _HANDLE]
    userenv.UnloadUserProfile.restype = _BOOL
    userenv.CreateEnvironmentBlock.argtypes = [ctypes.POINTER(_HANDLE), _HANDLE, _BOOL]
    userenv.CreateEnvironmentBlock.restype = _BOOL
    userenv.DestroyEnvironmentBlock.argtypes = [_HANDLE]
    userenv.DestroyEnvironmentBlock.restype = _BOOL
    username = request["username"].split("\\")[-1]
    profile = _ProfileInfo(size=ctypes.sizeof(_ProfileInfo), flags=1, username=username)
    environment = _HANDLE()
    loaded = False
    try:
        if flags & 1:
            if not userenv.LoadUserProfileW(token, ctypes.byref(profile)):
                error = ctypes.WinError(ctypes.get_last_error())
                raise OSError(
                    error.errno, "Cannot load the requested user profile: " + str(error)
                ) from error
            loaded = True
        if not userenv.CreateEnvironmentBlock(ctypes.byref(environment), token, False):
            error = ctypes.WinError(ctypes.get_last_error())
            raise OSError(
                error.errno,
                "Cannot create the requested user environment: " + str(error),
            ) from error
        yield environment
    finally:
        try:
            if environment and not userenv.DestroyEnvironmentBlock(environment):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            if loaded and not userenv.UnloadUserProfile(token, profile.profile):
                raise ctypes.WinError(ctypes.get_last_error())


def _has_token_launch(security):
    # Keep the established Vista-and-later token-launch path. The tested
    # Server 2003 export rejected a valid SYSTEM launch as not implemented,
    # so earlier systems use the working legacy CreateProcessAsUser path.
    return hasattr(security, "CreateProcessWithTokenW") and (
        sys.getwindowsversion().major >= 6  # pylint: disable=no-member
    )


# The arguments are the native launch inputs plus the optional legacy user block.
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def _launch(security, token, request, startup, process, environment=None):
    # Sending the real command through stdin avoids WithTokenW's 1024-char limit.
    worker = os.path.abspath(__file__)
    command = ctypes.create_unicode_buffer(
        subprocess.list2cmdline([sys.executable, worker, "--worker"])
    )
    flags = _logon_flags(request["logon_flags"])
    if _has_token_launch(security):
        return bool(
            security.CreateProcessWithTokenW(
                token,
                flags,
                sys.executable,
                command,
                0x400,
                None,
                os.environ["SystemRoot"],
                ctypes.byref(startup),
                ctypes.byref(process),
            )
        )
    # XP lacks WithTokenW. Its ordinary interactive credential path still has
    # native profile loading and environment creation through WithLogonW.
    if request["password"] is not None and request["logon_type"] == "Interactive":
        username = request["username"]
        domain = None if "@" in username else "."
        if "\\" in username:
            domain, username = username.split("\\", 1)
        return bool(
            security.CreateProcessWithLogonW(
                username,
                domain,
                request["password"],
                flags,
                sys.executable,
                command,
                0x400,
                None,
                os.environ["SystemRoot"],
                ctypes.byref(startup),
                ctypes.byref(process),
            )
        )
    return bool(
        security.CreateProcessAsUserW(
            token,
            sys.executable,
            command,
            None,
            None,
            True,
            0x400,
            environment,
            os.environ["SystemRoot"],
            ctypes.byref(startup),
            ctypes.byref(process),
        )
    )


def _forward(handle, mode, data, errors):
    try:
        # Windows exposes O_BINARY; Linux's os stub does not describe it.
        # pylint: disable-next=no-member
        flags = os.O_BINARY | (os.O_WRONLY if mode == "wb" else os.O_RDONLY)
        descriptor = msvcrt.open_osfhandle(handle.value, flags)
        handle.value = None
        with os.fdopen(descriptor, mode) as stream:
            if mode == "wb":
                stream.write(data)
            else:
                while True:
                    block = stream.read(65536)
                    if not block:
                        break
                    data.write(block)
                    data.flush()
    except OSError as error:
        # A child that exits without reading all input closes its pipe normally.
        if mode != "wb" or getattr(error, "winerror", None) not in (109, 232):
            errors.append(error)


@contextmanager
def _stdio(kernel):
    handles = []
    try:
        for parent_reads in (False, True, True):
            handles.extend(_pipe(kernel, parent_reads))
        yield handles
    finally:
        for handle in handles:
            if handle:
                kernel.CloseHandle(handle)


def _communicate(kernel, process, handles, command_data):
    threads, errors = [], []
    for index in (1, 3, 5):
        kernel.CloseHandle(handles[index])
        handles[index].value = None
    try:
        for handle, mode, data in (
            (handles[2], "rb", sys.stdout.buffer),
            (handles[4], "rb", sys.stderr.buffer),
            (handles[0], "wb", command_data),
        ):
            thread = threading.Thread(
                target=_forward, args=(handle, mode, data, errors)
            )
            thread.start()
            threads.append(thread)
        if kernel.WaitForSingleObject(process.process, 0xFFFFFFFF) == 0xFFFFFFFF:
            raise ctypes.WinError(ctypes.get_last_error())
    except Exception:
        kernel.TerminateProcess(process.process, 1)
        kernel.WaitForSingleObject(process.process, 0xFFFFFFFF)
        raise
    finally:
        for thread in threads:
            thread.join()
    if errors:
        raise errors[0]
    result = _DWORD()
    if not kernel.GetExitCodeProcess(process.process, ctypes.byref(result)):
        raise ctypes.WinError(ctypes.get_last_error())
    return result.value


def execute(request, input_data):
    """Run one task with raw stdio and return the native process exit code.

    :param request: Validated account, password, logon settings and command.
    :type request: dict
    :param input_data: Original task stdin, forwarded after the command header.
    :type input_data: bytes
    :returns: Unsigned Windows process exit code.
    :rtype: int
    :raises OSError: For token, ACL, process, pipe or wait failures.
    :raises ValueError: For a runas mode not yet available on the target.
    """
    security, kernel = _libraries()
    process = _ProcessInfo()
    try:
        with runas_token.logon_tokens(
            request["username"], request["password"], request["logon_type"]
        ) as tokens, _stdio(kernel) as handles:
            startup = _StartupInfo(
                size=ctypes.sizeof(_StartupInfo),
                flags=0x100,
                stdin=handles[1].value,
                stdout=handles[3].value,
                stderr=handles[5].value,
            )
            # All task files are disposable Ansible staging, not user data.
            sid = runas_token.token_sid(tokens[0])
            _grant_task_read(
                security, kernel, os.path.dirname(os.path.abspath(__file__)), sid
            )
            # Legacy profile lifetime extends until the child exits. Otherwise
            # unloading its hive here would change the running task's context.
            with _legacy_environment(security, tokens[0], request) as environment:
                for token in tokens:
                    if _launch(security, token, request, startup, process, environment):
                        break
                else:
                    error = ctypes.WinError(ctypes.get_last_error())
                    raise OSError(
                        error.errno,
                        "Cannot launch the requested user process: " + str(error),
                    ) from error
                command_data = (
                    json.dumps(request["command"]).encode("utf-8") + b"\n" + input_data
                )
                return _communicate(kernel, process, handles, command_data)
    finally:
        if process.thread:
            kernel.CloseHandle(process.thread)
        if process.process:
            kernel.CloseHandle(process.process)


def _main():
    if sys.argv[1:] == ["--worker"]:
        command = json.loads(sys.stdin.buffer.readline().decode("utf-8"))
        # readline can read ahead into Python's buffer. Forward that buffered
        # task input explicitly instead of letting a child inherit only the fd.
        with subprocess.Popen(command, shell=True, stdin=subprocess.PIPE) as child:
            child.communicate(sys.stdin.buffer.read())
            return child.returncode
    request = json.loads(sys.stdin.buffer.readline().decode("utf-8"))
    return execute(request, sys.stdin.buffer.read())


if __name__ == "__main__":
    try:
        sys.exit(_main())
    except (OSError, ValueError, KeyError) as failure:
        sys.stderr.write("Native runas failed: {0}\n".format(failure))
        sys.exit(1)
