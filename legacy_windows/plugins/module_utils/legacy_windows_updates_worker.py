# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Own a detached native update worker and its private progress directory."""

import ctypes
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from contextlib import ExitStack

import legacy_windows_account as account  # pylint: disable=import-error
import legacy_windows_updates as updates  # pylint: disable=import-error
import legacy_windows_wmi as wmi  # pylint: disable=import-error

# Win32_ProcessStartup requires embedded WMI objects, which the shared public
# scalar-input API intentionally does not expose. This fixed native launch ABI
# reuses the existing WMI owner's private primitives without modifying them.
# pylint: disable=protected-access

HELPERS = (
    "legacy_windows_module.py",
    "legacy_windows_wmi.py",
    "legacy_windows_boot.py",
    "legacy_windows_text.py",
    "legacy_windows_process.py",
    "legacy_windows_reboot_request.py",
    "legacy_windows_regex.py",
    "legacy_windows_regex_categories.py",
    "legacy_windows_updates_native.py",
    "legacy_windows_updates.py",
    "legacy_windows_updates_worker.py",
    "legacy_windows_account.py",
    "legacy_windows_s4u.py",
    "legacy_windows_system_token.py",
    "legacy_windows_runas_token.py",
)
_FILES = HELPERS + (
    "worker.py",
    "journal.json",
    "launch.json",
    "request.json",
    "state.json",
    ".state-next.json",
    "cancel.request",
)
_PREFIX = "legacy-windows-updates-"


class _LaunchDenied(OSError):
    """A native launch result proves that no worker process was created."""


def _read(root, name):
    with open(os.path.join(root, name), encoding="utf-8") as stream:
        return json.load(stream)


def _write(root, name, value):
    # This standalone worker owns creation and durable publication of its journal.
    # pylint: disable=duplicate-code
    with open(os.path.join(root, name), "x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=True)
        stream.flush()
        os.fsync(stream.fileno())
    # pylint: enable=duplicate-code


def _atomic(root, value):
    # This worker's journal owns the flush and atomic state-file replacement.
    # pylint: disable=duplicate-code
    with open(os.path.join(root, ".state-next.json"), "w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=True)
        stream.flush()
        os.fsync(stream.fileno())
    deadline = time.monotonic() + 5
    while True:
        try:
            # Keep this worker's owned state paths explicit at atomic replacement.
            os.replace(
                os.path.join(root, ".state-next.json"), os.path.join(root, "state.json")
            )
            return
        except PermissionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.01)
    # pylint: enable=duplicate-code


def _kernel():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    kernel.GetProcessTimes.argtypes = [ctypes.c_void_p] + [
        ctypes.POINTER(ctypes.c_uint64)
    ] * 4
    kernel.GetProcessTimes.restype = ctypes.c_int
    kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel.WaitForSingleObject.restype = ctypes.c_uint32
    kernel.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    kernel.GetFileAttributesW.restype = ctypes.c_uint32
    return kernel


def _process(pid):
    kernel = _kernel()
    # Birth-time queries need only limited information on Vista and newer.
    # Requesting full query rights can reject a SYSTEM worker owned by this
    # caller's journal; XP and Server 2003 require the older query right.
    windows_major = sys.getwindowsversion().major  # pylint: disable=no-member
    query_access = 0x1000 if windows_major >= 6 else 0x400
    handle = kernel.OpenProcess(0x100000 | query_access, False, pid)
    if not handle:
        code = ctypes.get_last_error()
        if code == 87:
            return None
        raise ctypes.WinError(code)
    try:
        times = [ctypes.c_uint64() for _ in range(4)]
        if not kernel.GetProcessTimes(
            handle, *[ctypes.byref(value) for value in times]
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        state = kernel.WaitForSingleObject(handle, 0)
        if state == 0xFFFFFFFF:
            raise ctypes.WinError(ctypes.get_last_error())
        if state not in (0, 258):
            raise OSError("Unexpected native process wait result {0}.".format(state))
        return {"pid": pid, "created": times[0].value, "alive": state == 258}
    finally:
        if not kernel.CloseHandle(handle):
            raise ctypes.WinError(ctypes.get_last_error())


def _sid(pid):
    # Identifying the owner must not depend on WMI method-execution rights:
    # denial of those rights is a legitimate worker-launch fallback trigger.
    kernel, security = _kernel(), ctypes.WinDLL("advapi32", use_last_error=True)
    # Keep these fixed token-query signatures local so ownership checks do not
    # import another management helper just to repeat the Windows ABI.
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
    # pylint: enable=duplicate-code
    process, token = kernel.OpenProcess(0x400, False, pid), ctypes.c_void_p()
    if not process:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not security.OpenProcessToken(process, 8, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        needed = ctypes.c_uint32()
        if (
            security.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
            or ctypes.get_last_error() != 122
        ):
            raise OSError("Cannot size the update owner's native token SID.")
        buffer = ctypes.create_string_buffer(needed.value)
        if not security.GetTokenInformation(
            token, 1, buffer, len(buffer), ctypes.byref(needed)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return account.sid_to_string(ctypes.c_void_p.from_buffer(buffer).value)
    finally:
        if token:
            kernel.CloseHandle(token)
        kernel.CloseHandle(process)


def _directory(root, sid):
    # This structure is the native SECURITY_ATTRIBUTES layout, not an object API.
    class SecurityAttributes(
        ctypes.Structure
    ):  # pylint: disable=too-few-public-methods
        """Native SECURITY_ATTRIBUTES storage for this single directory call."""

        _fields_ = [
            ("length", ctypes.c_uint32),
            ("descriptor", ctypes.c_void_p),
            ("inherit", ctypes.c_int),
        ]

    kernel, security = _kernel(), ctypes.WinDLL("advapi32", use_last_error=True)
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = ctypes.c_int
    kernel.CreateDirectoryW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.POINTER(SecurityAttributes),
    ]
    kernel.CreateDirectoryW.restype = ctypes.c_int
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    descriptor = ctypes.c_void_p()
    if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{0})".format(sid),
        1,
        ctypes.byref(descriptor),
        None,
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        attributes = SecurityAttributes(
            ctypes.sizeof(SecurityAttributes), descriptor, False
        )
        if not kernel.CreateDirectoryW(root, ctypes.byref(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        if kernel.LocalFree(descriptor):
            raise ctypes.WinError(ctypes.get_last_error())


def _launch(command, root, environment, dynamic_cloaking=False):
    # This is the measured Win32_Process.Create/ProcessStartupInformation ABI;
    # WMI's public scalar-input helper deliberately does not accept objects.
    connection_context = (
        wmi.WmiConnection(dynamic_cloaking=True)
        if dynamic_cloaking
        else wmi.WmiConnection()
    )
    with connection_context as connection, ExitStack() as cleanup:
        # This WMI method is callable without general method-execution rights.
        # Its native access mask can conclusively reject launch before dispatch.
        access = connection.call_method(
            "__SystemSecurity=@", "GetCallerAccessRights", ["ReturnValue", "rights"]
        )
        rights = access.get("rights")
        if not isinstance(access.get("ReturnValue"), int) or isinstance(
            access.get("ReturnValue"), bool
        ):
            raise OSError("Malformed WMI worker-launch status: " + repr(access))
        if (
            access["ReturnValue"] != 0
            or not isinstance(rights, int)
            or isinstance(rights, bool)
            or not 0 <= rights <= 0xFFFFFFFF
        ):
            raise OSError("Cannot establish WMI worker-launch rights: " + repr(access))
        if not rights & 2:  # WBEM_METHOD_EXECUTE
            raise _LaunchDenied(
                "The caller lacks WMI method-execution rights; "
                "the update worker was not dispatched."
            )
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
        if not startup:
            raise OSError("Win32_ProcessStartup returned a null instance.")
        wmi._put_string_array(
            startup,
            connection._automation,
            "EnvironmentVariables",
            [key + "=" + value for key, value in sorted(environment.items())],
        )
        # DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT | CREATE_BREAKAWAY_FROM_JOB
        wmi._put_integer(startup, connection._automation, "CreateFlags", 0x01000408)
        wmi._put_integer(startup, connection._automation, "ShowWindow", 0)
        inputs = connection._method_inputs(
            cleanup,
            "Win32_Process",
            "Create",
            {"CommandLine": command, "CurrentDirectory": root},
        )
        value = wmi._Variant(kind=13)
        value.data.bstr = startup
        wmi._method(startup, 1, ctypes.c_uint32, [])(startup)
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
                "VariantClear(startup input)",
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
            "ExecMethod(Create update worker)",
        )
        if not output:
            raise OSError("Win32_Process.Create returned no result.")
        result = connection._properties(output, ["ReturnValue", "ProcessId"])
    return _created_process_id(result)


def _created_process_id(result):
    status, pid = result.get("ReturnValue"), result.get("ProcessId")
    if (
        not isinstance(status, int)
        or isinstance(status, bool)
        or not 0 <= status <= 0xFFFFFFFF
    ):
        raise OSError("Malformed native worker-launch response: " + repr(result))
    if "ProcessId" not in result:
        raise OSError(
            "The native worker-launch response has no ProcessId: " + repr(result)
        )
    if pid is not None:
        if (
            not isinstance(pid, int)
            or isinstance(pid, bool)
            or not 0 <= pid <= 0xFFFFFFFF
        ):
            raise OSError("Malformed native worker-launch ProcessId: " + repr(result))
    if status in (2, 3) and pid in (None, 0):
        raise _LaunchDenied(
            "Win32_Process.Create rejected the worker before process creation "
            "(ReturnValue {0}).".format(result["ReturnValue"])
        )
    if status != 0 or pid in (None, 0):
        raise OSError(
            "Win32_Process.Create could not start the update worker: {0}.".format(
                result
            )
        )
    return pid


def _launch_system(command, root, environment):
    # Use the existing token lifetime and WMI launch ABI. Dynamic cloaking makes
    # the service proxy authenticate this thread's token, not the caller process.
    import legacy_windows_runas_token as tokens  # pylint: disable=import-outside-toplevel,import-error

    dispatch_attempted = False
    try:
        security = tokens._libraries()[0]
        with tokens.logon_tokens("NT AUTHORITY\\SYSTEM", None, "Service") as acquired:
            with tokens._impersonation(security, acquired[0]) as impersonated:
                if not impersonated:
                    raise OSError("Windows could not impersonate the SYSTEM token.")
                # From this boundary onward an error is not proof of no child.
                # Only _launch's explicit native rejection remains conclusive.
                dispatch_attempted = True
                return _launch(command, root, environment, dynamic_cloaking=True)
    except Exception as error:
        if not dispatch_attempted:
            raise _LaunchDenied(
                "SYSTEM worker launch failed before dispatch: " + str(error)
            ) from error
        raise


def _launch_owned(command, root, request, publish):
    try:
        return _launch(command, root, request["environment"])
    except _LaunchDenied:
        if request["sid"] == "S-1-5-18":
            raise
        request["worker_sid"] = "S-1-5-18"
        # No process exists after the conclusive native rejection. Publish the
        # selected identity before any SYSTEM child can read this request.
        publish()
        return _launch_system(command, root, request["environment"])


def _replace_request(root, name, request):
    # This replacement occurs only while no worker exists; competing readers
    # cannot observe a partial request. Flush before native process creation.
    with open(os.path.join(root, name), "w", encoding="utf-8") as stream:
        json.dump(request, stream, ensure_ascii=True)
        stream.flush()
        os.fsync(stream.fileno())


def _validate(options):
    root, nonce = options.get("root"), options.get("nonce")
    if (
        not isinstance(root, str)
        or not isinstance(nonce, str)
        or not re.match(r"^[0-9a-f]{32}$", nonce)
    ):
        raise ValueError("Invalid internal update-worker ownership options.")
    parent, basename = os.path.dirname(root), os.path.basename(root)
    if os.path.normcase(parent) != os.path.normcase(
        tempfile.gettempdir()
    ) or not re.match(r"^" + _PREFIX + r"[0-9a-f]{32}$", basename):
        raise ValueError("Invalid internal update-worker directory.")
    attributes = _kernel().GetFileAttributesW(root)
    if attributes == 0xFFFFFFFF:
        raise ctypes.WinError(ctypes.get_last_error())
    if attributes & 0x400 or not attributes & 0x10:
        raise OSError(
            "Refusing an update-worker directory that is a reparse point or not a directory."
        )
    journal = _read(root, "journal.json")
    if (
        journal["nonce"] != nonce
        or journal["root"] != root
        or journal["sid"] != _sid(os.getpid())
    ):
        raise OSError("The requested update workspace does not belong to this caller.")
    return root, journal


def _alive(journal):
    original = journal.get("worker")
    if original is None:
        return False
    actual = _process(original["pid"])
    return (
        actual is not None
        and actual["created"] == original["created"]
        and actual["alive"]
    )


def _launched(root, journal):
    if os.path.isfile(os.path.join(root, "launch.json")):
        result = _read(root, "launch.json")
        if any(result[name] != journal[name] for name in ("root", "nonce", "sid")):
            raise OSError("The update launch journal does not match its owner.")
        return result
    # A provider failure can occur after Create starts the worker but before
    # the caller receives its PID. The protected worker acknowledgement is
    # retained independently and provides its PID plus native creation time.
    state = _read(root, "state.json")
    if state["nonce"] != journal["nonce"]:
        raise OSError("The update worker acknowledgement does not match its owner.")
    return dict(journal, worker=state["worker"])


def _cleanup(root, journal, own_worker=False):
    if _alive(journal):
        if not own_worker or journal["worker"] != _process(os.getpid()):
            raise OSError(
                "The owned update worker is still running; workspace retained at "
                + root
            )
    names = os.listdir(root)
    unexpected = sorted(set(names).difference(_FILES))
    if unexpected:
        raise OSError(
            "Refusing update cleanup with unowned files: " + ", ".join(unexpected)
        )
    kernel = _kernel()
    for name in names:
        path = os.path.join(root, name)
        attributes = kernel.GetFileAttributesW(path)
        if attributes == 0xFFFFFFFF:
            raise ctypes.WinError(ctypes.get_last_error())
        if attributes & (0x400 | 0x10):
            raise OSError(
                "Refusing an unowned directory or reparse point during update cleanup: "
                + path
            )
    for name in names:
        os.remove(os.path.join(root, name))
    os.rmdir(root)


def start(options, *, supervised=False):
    """Start one owned update round outside the connection's process job.

    :param dict options: Bound public update options for the dedicated worker.
    :param bool supervised: Tie cooperative cancellation to this async frontend's lifetime.
    :returns: Internal polling and cancellation ownership options.
    :rtype: dict
    :raises OSError: Launch/startup fails; the message identifies retained recovery data.
    """
    if supervised:
        return _start_supervised(options)
    root = os.path.join(tempfile.gettempdir(), _PREFIX + uuid.uuid4().hex)
    journal = {
        "root": root,
        "nonce": uuid.uuid4().hex,
        "sid": _sid(os.getpid()),
        "worker": None,
    }
    _directory(root, journal["sid"])
    launch_attempted = False
    try:
        _write(root, "journal.json", journal)
        request = {
            "options": options,
            "environment": dict(os.environ),
            "nonce": journal["nonce"],
            "sid": journal["sid"],
        }
        _write(root, "request.json", request)
        source = os.path.dirname(os.path.abspath(__file__))
        for name in HELPERS:
            shutil.copyfile(os.path.join(source, name), os.path.join(root, name))
        with open(os.path.join(root, "worker.py"), "x", encoding="utf-8") as stream:
            stream.write(
                "import legacy_windows_updates_worker as worker\nworker.main()\n"
            )
        launch_attempted = True
        pid = _launch_owned(
            subprocess.list2cmdline(
                [sys.executable, "-B", os.path.join(root, "worker.py"), root]
            ),
            root,
            request,
            lambda: _replace_request(root, "request.json", request),
        )
        worker_identity = _process(pid)
        if worker_identity is None:
            # A fast worker can finish before the parent opens its process.
            state = _read(root, "state.json")
            worker_identity = state["worker"]
        journal["worker"] = worker_identity
        _write(root, "launch.json", journal)
        deadline = time.monotonic() + 20
        while not os.path.isfile(os.path.join(root, "state.json")):
            if not _alive(journal) or time.monotonic() >= deadline:
                raise OSError(
                    "The update worker did not acknowledge startup within 20 seconds."
                )
            time.sleep(0.1)
        state = _read(root, "state.json")
        if (
            state["worker"]["pid"] != pid
            or state["worker"]["created"] != worker_identity["created"]
        ):
            raise OSError(
                "The update worker startup identity did not match its native launch."
            )
    except Exception as error:
        if isinstance(error, _LaunchDenied):
            launch_attempted = False
        if not launch_attempted:
            try:
                _cleanup(root, journal)
            except Exception as cleanup_error:
                raise OSError(
                    "Update worker startup failed: {0}; recovery retained at {1}: {2}".format(
                        error, root, cleanup_error
                    )
                ) from cleanup_error
            raise OSError(
                (
                    "Update worker startup failed before launch: {0}; "
                    "its owned workspace was removed."
                ).format(error)
            ) from error
        raise OSError(
            "Update worker startup failed: {0}; recovery retained at {1}, nonce {2}".format(
                error, root, journal["nonce"]
            )
        ) from error
    return {
        "changed": False,
        "cancel_options": {"root": root, "nonce": journal["nonce"]},
        "poll_options": {"root": root, "nonce": journal["nonce"], "offset": 0},
    }


def _start_supervised(options):
    nonce = uuid.uuid4().hex
    root = os.path.join(tempfile.gettempdir(), _PREFIX + nonce)
    source = os.path.dirname(os.path.abspath(__file__))
    bootstrap = ".updates-start-" + nonce + ".json"
    journal = {"root": root, "nonce": nonce, "sid": _sid(os.getpid()), "worker": None}
    request = {
        "options": options,
        "environment": dict(os.environ),
        "nonce": nonce,
        "sid": journal["sid"],
        "supervisor": _process(os.getpid()),
    }
    # Only the existing watchdog-owned staging receives a frontend write. The
    # detached worker becomes the cleanup owner BEFORE it creates a separate
    # Updates workspace; frontend death before native launch cannot orphan one.
    _write(source, bootstrap, {"journal": journal, "request": request})
    try:
        pid = _launch_owned(
            subprocess.list2cmdline(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    "import legacy_windows_updates_worker as worker;worker._supervised_main()",
                    os.path.join(source, bootstrap),
                ]
            ),
            source,
            request,
            lambda: _replace_request(
                source, bootstrap, {"journal": journal, "request": request}
            ),
        )
        identity = _process(pid)
        deadline = time.monotonic() + 20
        while not os.path.isfile(os.path.join(root, "state.json")):
            if identity is None or not _alive({"worker": identity}):
                raise OSError("The supervised update worker exited before startup.")
            if time.monotonic() >= deadline:
                raise OSError(
                    "The supervised update worker did not start within20 seconds."
                )
            time.sleep(0.1)
        state = _read(root, "state.json")
        if state["nonce"] != nonce or state["worker"] != identity:
            raise OSError(
                "The supervised update worker startup identity did not match."
            )
    except Exception as error:
        if isinstance(error, _LaunchDenied):
            raise OSError(
                (
                    "Supervised update startup failed before launch: {0}; "
                    "no update workspace was created."
                ).format(error)
            ) from error
        raise OSError(
            "Supervised update startup failed: {0}; recovery retained at {1}, nonce {2}".format(
                error, root, nonce
            )
        ) from error
    finally:
        path = os.path.join(source, bootstrap)
        if os.path.exists(path):
            os.remove(path)
    return {
        "changed": False,
        "cancel_options": {"root": root, "nonce": nonce},
        "poll_options": {"root": root, "nonce": nonce, "offset": 0},
    }


def _supervised_main():
    source = os.path.dirname(os.path.abspath(__file__))
    path = os.path.abspath(sys.argv[1])
    if os.path.dirname(path) != source or not re.match(
        r"^\.updates-start-[0-9a-f]{32}\.json$", os.path.basename(path)
    ):
        raise ValueError("Invalid supervised update startup request path.")
    # WMI's initial cwd is staging; release that directory before its watchdog
    # may remove it. All subsequent source and ownership paths are absolute.
    os.chdir(tempfile.gettempdir())
    bootstrap = _read(source, os.path.basename(path))
    journal, request = bootstrap["journal"], bootstrap["request"]
    nonce = os.path.basename(path)[15:-5]
    root = os.path.join(tempfile.gettempdir(), _PREFIX + nonce)
    if (
        journal["root"] != root
        or journal["nonce"] != nonce
        or request["nonce"] != nonce
    ):
        raise OSError(
            "The supervised update startup ownership does not match its request."
        )
    if (
        journal["sid"] != request["sid"]
        or request.get("worker_sid", request["sid"]) != _sid(os.getpid())
        or request["environment"] != dict(os.environ)
    ):
        raise OSError("The supervised update startup does not belong to this caller.")
    if not _alive({"worker": request["supervisor"]}):
        return
    # Read all staged sources before allocating a new workspace. If its generic
    # watchdog has already removed staging, no separate root has been created.
    sources = {}
    for name in HELPERS:
        with open(os.path.join(source, name), "rb") as stream:
            sources[name] = stream.read()
    journal["worker"] = _process(os.getpid())
    _directory(root, journal["sid"])
    completed = False
    try:
        _write(root, "journal.json", journal)
        _write(root, "request.json", request)
        for name, contents in sources.items():
            with open(os.path.join(root, name), "xb") as stream:
                stream.write(contents)
        _write(root, "launch.json", journal)
        if _alive({"worker": request["supervisor"]}):
            main(root)
        completed = True
    finally:
        # The detached process owns even partial startup. Never depend on a
        # frontend finally block or acknowledgment to recover these exact files.
        if os.path.exists(root) and (
            not completed or not _alive({"worker": request["supervisor"]})
        ):
            os.chdir(tempfile.gettempdir())
            _cleanup(root, journal, own_worker=True)


def poll(options):
    """Read the next owned progress batch, replaying it after connection loss.

    :param dict options: Ownership options and the next unacknowledged packet offset.
    :returns: Progress packets and the following offset.
    :rtype: dict
    :raises OSError: The worker died without a final result or state is inconsistent.
    :raises ValueError: Internal ownership or progress offset is invalid.
    """
    root, journal = _validate(options)
    journal = _launched(root, journal)
    offset = options.get("offset", 0)
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ValueError("Invalid internal update progress offset.")
    received = None
    while True:
        state = _read(root, "state.json")
        if state["nonce"] != journal["nonce"] or offset > len(state["output"]):
            raise OSError("Update worker progress ownership or offset is inconsistent.")
        if len(state["output"]) > offset:
            if received is None:
                received = time.monotonic()
            if state["finished"] or time.monotonic() - received >= 1:
                return {
                    "changed": False,
                    "output": state["output"][offset:],
                    "offset": len(state["output"]),
                }
        if not _alive(journal):
            raise OSError(
                "The owned update worker exited without an unread final result; "
                "recovery retained at " + root
            )
        time.sleep(0.1)


def cancel(options):
    """Request cooperative WUA cancellation and remove only the stopped worker's files.

    :param dict options: Exact internal ownership options returned at startup.
    :returns: An unchanged result after confirmed process death and cleanup.
    :rtype: dict
    :raises OSError: Cancellation has not completed; retained workspace is actionable.
    """
    root, journal = _validate(options)
    journal = _launched(root, journal)
    if not os.path.exists(os.path.join(root, "cancel.request")):
        _write(root, "cancel.request", journal["nonce"])
    elif _read(root, "cancel.request") != journal["nonce"]:
        raise OSError("The update cancellation request does not match its owner.")
    deadline = time.monotonic() + 10
    while _alive(journal):
        if time.monotonic() >= deadline:
            raise OSError(
                (
                    "The update worker has not completed cancellation within 10 seconds; "
                    "recovery retained at {0}, nonce {1}. Retry cancellation after WUA "
                    "finishes; the live worker was not terminated."
                ).format(root, journal["nonce"])
            )
        time.sleep(0.1)
    _cleanup(root, journal)
    return {"changed": False}


def _finish_supervised(root, request, state):
    supervisor = request.get("supervisor")
    if supervisor is None:
        return
    journal = {
        "root": root,
        "nonce": request["nonce"],
        "sid": request["sid"],
        "worker": state["worker"],
    }
    while True:
        if not _alive({"worker": supervisor}):
            # The exact birth-time-pinned frontend died (for example at its
            # generic async deadline). WUA resources are now closed, so this
            # worker may remove only its own validated files, not another PID's.
            os.chdir(tempfile.gettempdir())
            _cleanup(root, journal, own_worker=True)
            return
        path = os.path.join(root, "cancel.request")
        if os.path.exists(path) and _read(root, "cancel.request") == request["nonce"]:
            return
        time.sleep(0.1)


def main(root=None):
    """Run the dedicated worker from its fixed private directory.

    :param root: Already owned directory for supervised startup, or None for the CLI.
    :type root: str or None
    :raises OSError: Ownership, native caller identity or progress persistence fails.
    """
    root = sys.argv[1] if root is None else root
    request = _read(root, "request.json")
    if (
        _sid(os.getpid()) != request.get("worker_sid", request["sid"])
        or dict(os.environ) != request["environment"]
    ):
        raise OSError(
            "The update worker did not inherit its caller identity and environment."
        )
    state = {
        "nonce": request["nonce"],
        "worker": _process(os.getpid()),
        "output": [],
        "finished": False,
    }
    if "worker_sid" in request:
        state["worker_sid"] = request["worker_sid"]
    lock = threading.Lock()
    _atomic(root, state)

    def emit(name, result):
        with lock:
            state["output"].append({"task": name, "result": result})
            if name == "exit":
                state["finished"] = True
            _atomic(root, state)

    def _cancelled():
        path = os.path.join(root, "cancel.request")
        return (
            os.path.exists(path) and _read(root, "cancel.request") == request["nonce"]
        ) or (
            request.get("supervisor") is not None
            and not _alive({"worker": request["supervisor"]})
        )

    with ExitStack() as resources:
        try:
            path = request["options"].get("log_path")
            logger = (
                resources.enter_context(open(path, "a", encoding="utf-8"))
                if path and not request["options"].get("check_mode")
                else None
            )
        except OSError as error:
            emit(
                "exit",
                {
                    "changed": False,
                    "failed": True,
                    "reboot_required": False,
                    "exception": {"message": str(error)},
                },
            )
            _finish_supervised(root, request, state)
            return

        def log(message):
            if logger is not None:
                with lock:
                    logger.write(
                        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%SZ")
                        + " update_task "
                        + message
                        + "\n"
                    )
                    logger.flush()

        updates.run(request["options"], emit, _cancelled, log)
    _finish_supervised(root, request, state)
