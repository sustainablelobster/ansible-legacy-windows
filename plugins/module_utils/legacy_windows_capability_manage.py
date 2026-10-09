# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Service capabilities with native DISM and a same-user scheduled batch task."""

import ctypes
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from xml.sax.saxutils import escape

import legacy_windows_capability as metadata  # pylint: disable=import-error

# Reuse the accepted native record, library bindings and buffer ownership rules.
# Their private names intentionally remain outside the public metadata interface.
# pylint: disable=protected-access


# The native version record bypasses Python 3.4's application-manifest limit.
class _VersionInfo(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("size", ctypes.c_uint32),
        ("major", ctypes.c_uint32),
        ("minor", ctypes.c_uint32),
        ("build", ctypes.c_uint32),
        ("platform", ctypes.c_uint32),
        ("service_pack", ctypes.c_wchar * 128),
    ]


def _windows_version():
    library = ctypes.WinDLL("ntdll")
    library.RtlGetVersion.argtypes = [ctypes.POINTER(_VersionInfo)]
    library.RtlGetVersion.restype = ctypes.c_int32
    version = _VersionInfo(ctypes.sizeof(_VersionInfo))
    status = library.RtlGetVersion(ctypes.byref(version))
    if status:
        raise OSError(
            "RtlGetVersion failed (NTSTATUS 0x{0:08X}).".format(status & 0xFFFFFFFF)
        )
    return version.major, version.minor, version.build


def logging_levels():
    """Return the pinned cmdlet logging enum for the running Windows version.

    The pinned source documents Debug for Windows 11 and Server 2025.
    Native DismInitialize also accepts unnamed values, so it cannot enforce
    the cmdlet's public argument boundary.

    :returns: Named logging levels, indexed by their public integer value.
    :rtype: tuple
    :raises OSError: The native Windows version cannot be read.
    """
    levels = ("Errors", "Warnings", "WarningsInfo")
    # Build 22000 is the Windows 11 boundary inferred from that source contract.
    # Installed enums were verified on 19045 and 26200; other builds remain
    # unverified and are not added to the support record by this selection.
    if _windows_version() >= (10, 0, 22000):
        levels += ("Debug",)
    return levels


def _provider_expression(pattern):
    expression = "^"
    in_class = False
    for character in pattern:
        if character == "[":
            in_class = True
            expression += character
        elif character == "]":
            in_class = False
            expression += character
        elif in_class:
            expression += character
        elif character == "*":
            expression += ".*"
        elif character == "?":
            expression += "."
        else:
            expression += re.escape(character)
    return expression + "$"


def _validate_pattern(pattern):
    expression = _provider_expression(pattern)
    try:
        return re.compile(expression, re.IGNORECASE)
    except re.error as error:
        detail = str(error)
        # Python 3.4 names an unfinished class differently from the developer
        # interpreter; neither spelling is the measured provider diagnostic.
        if (
            "unterminated character set" in detail
            or detail == "unexpected end of regular expression"
        ):
            detail = "Unterminated [] set."
        elif "bad character range" in detail:
            detail = "[x-y] range in reverse order."
        raise ValueError('parsing "' + expression + '" - ' + detail) from error


class CapabilitySession:
    """Own one native online DISM session, without restarting Windows.

    :param int log_level: Optional native logging level; zero uses the default.
    :param str log_path: Optional logging filename.
    """

    def __init__(self, log_level=None, log_path=None):
        self.library = None
        self.session = ctypes.c_uint32()
        self._opened = False
        self.log_level = log_level
        self.log_path = log_path

    def __enter__(self):
        self.library = metadata._library()
        library = self.library
        library.DismAddCapability.argtypes = [
            ctypes.c_uint32,
            ctypes.c_wchar_p,
            ctypes.c_int32,
            ctypes.POINTER(ctypes.c_wchar_p),
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        library.DismAddCapability.restype = ctypes.c_int32
        library.DismRemoveCapability.argtypes = [
            ctypes.c_uint32,
            ctypes.c_wchar_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        library.DismRemoveCapability.restype = ctypes.c_int32
        metadata._check(
            library,
            library.DismInitialize(self.log_level or 2, self.log_path or None, None),
            "DismInitialize",
        )
        try:
            self._open()
        except Exception:
            # Initialization owns shutdown even when opening the image fails.
            metadata._check(library, library.DismShutdown(), "DismShutdown")
            raise
        return self

    def _open(self):
        metadata._check(
            self.library,
            self.library.DismOpenSession(
                metadata._ONLINE_IMAGE, None, None, ctypes.byref(self.session)
            ),
            "DismOpenSession",
        )
        self._opened = True

    def __exit__(self, _exc_type, _exc_value, _traceback):
        try:
            if self._opened:
                metadata._check(
                    self.library,
                    self.library.DismCloseSession(self.session),
                    "DismCloseSession",
                )
                self._opened = False
        finally:
            metadata._check(self.library, self.library.DismShutdown(), "DismShutdown")

    def catalogue(self):
        """Read ordered names and states and release the native array.

        :returns: Capability name and state dictionaries in provider order.
        :rtype: list
        :raises OSError: Native enumeration fails or returns an invalid array.
        """
        values = ctypes.POINTER(metadata._Capability)()
        count = ctypes.c_uint32()
        try:
            metadata._check(
                self.library,
                self.library.DismGetCapabilities(
                    self.session, ctypes.byref(values), ctypes.byref(count)
                ),
                "DismGetCapabilities",
            )
            if count.value and not values:
                raise OSError("DISM returned a count without a capability array.")
            result = []
            for index in range(count.value):
                value = values[index]
                state = value.state
                result.append(
                    {
                        "name": value.name,
                        "state": (
                            metadata._STATES[state]
                            if 0 <= state < len(metadata._STATES)
                            else str(state)
                        ),
                    }
                )
            return result
        finally:
            if values:
                self.library.DismDelete(values)

    def _changed(self, status, operation):
        # Keep DISM's session-reload response explicit in this session owner.
        # pylint: disable=duplicate-code
        if status == 1:
            # DISMAPI_S_RELOAD_IMAGE_SESSION_REQUIRED is successful, not a reboot.
            metadata._check(
                self.library,
                self.library.DismCloseSession(self.session),
                "DismCloseSession",
            )
            self._opened = False
            self._open()
            return False
        # pylint: enable=duplicate-code
        if status == 3010:
            return True
        if status:
            detail = ctypes.POINTER(metadata._DismString)()
            message = ""
            try:
                if (
                    not self.library.DismGetLastErrorMessage(ctypes.byref(detail))
                    and detail
                ):
                    message = detail.contents.value or ""
            finally:
                if detail:
                    self.library.DismDelete(detail)
            # The cmdlet exposes the provider's servicing text verbatim, not
            # the metadata reader's operation/HRESULT diagnostic prefix.
            if message:
                raise OSError(message)
            raise OSError(
                "{0} failed (HRESULT 0x{1:08X}).".format(operation, status & 0xFFFFFFFF)
            )
        return False

    def add(self, name, sources, disable_update):
        """Install one prechecked capability without restarting the host.

        :param str name: Full capability name.
        :param list sources: Source directories in supplied order, or None.
        :param bool disable_update: Prevent Windows Update payload acquisition.
        :returns: Whether servicing requires a reboot.
        :rtype: bool
        :raises OSError: Servicing fails, possibly after partial effects.
        """
        paths = (ctypes.c_wchar_p * len(sources))(*sources) if sources else None
        status = self.library.DismAddCapability(
            self.session,
            name,
            disable_update,
            paths,
            len(sources or []),
            None,
            None,
            None,
        )
        return self._changed(status, "DismAddCapability")

    def remove(self, name):
        """Remove one prechecked capability without restarting the host.

        :param str name: Full capability name.
        :returns: Whether servicing requires a reboot.
        :rtype: bool
        :raises OSError: Servicing fails, possibly after partial effects.
        """
        status = self.library.DismRemoveCapability(self.session, name, None, None, None)
        return self._changed(status, "DismRemoveCapability")


def select(names, state, log_level=None, log_path=None):
    """Precheck every requested pattern, preserving caller order and duplicates.

    :param list names: Capability patterns, in caller order.
    :param str state: Desired present/absent state, or None for no changes.
    :param int log_level: Optional DISM logging level.
    :param str log_path: Optional DISM logging filename.
    :returns: Full capability names selected for servicing.
    :rtype: list
    :raises LookupError: A requested pattern has no capability match.
    :raises ValueError: A reached provider pattern is malformed.
    :raises OSError: Native capability enumeration fails or is unavailable.
    """
    selected = []
    with CapabilitySession(log_level, log_path) as native:
        version = _windows_version()
        for pattern in names:
            if (
                version < (10, 0, 17764)
                and not any(character in pattern for character in "*?[")
                and "~" not in pattern
            ):
                pattern += "~*"
            expression = _validate_pattern(pattern)
            entries = [
                entry
                for entry in native.catalogue()
                if expression.search(entry["name"]) is not None
            ]
            if not entries:
                raise LookupError("Failed to find capability '" + pattern + "'")
            desired = (
                ("Installed", "InstallPending")
                if state == "present"
                else ("NotPresent", "Staged", "Removed", "RemovePending")
            )
            # The source compares an array to scalar states: multiple matches
            # select every entry, including entries already in the desired state.
            if state is not None and (
                len(entries) > 1 or entries[0]["state"] not in desired
            ):
                selected.extend(entry["name"] for entry in entries)
    return selected


def _scheduler():
    root = os.environ["SystemRoot"]
    native = os.path.join(root, "Sysnative", "schtasks.exe")
    if not os.path.isfile(native):
        native = os.path.join(root, "System32", "schtasks.exe")
    return native


def _task_command(arguments):
    with subprocess.Popen(
        [_scheduler()] + arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ) as process:
        output = process.communicate()[0]
    if process.returncode:
        raise OSError(output.decode("mbcs", errors="replace").strip())


def _current_account():
    api = ctypes.WinDLL("secur32", use_last_error=True)
    api.GetUserNameExW.argtypes = [
        ctypes.c_int32,
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    api.GetUserNameExW.restype = ctypes.c_ubyte
    size = ctypes.c_uint32()
    api.GetUserNameExW(2, None, ctypes.byref(size))
    buffer = ctypes.create_unicode_buffer(size.value)
    if not api.GetUserNameExW(2, buffer, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    return buffer.value


def _task_xml(account, request, response, ready):
    logon = "S4U"
    if account.lower() in (
        "nt authority\\system",
        "nt authority\\local service",
        "nt authority\\network service",
    ):
        logon = "ServiceAccount"
    elif account.endswith("$"):
        logon = "Password"
    arguments = subprocess.list2cmdline(
        [os.path.abspath(__file__), "--batch", request, response, ready]
    )
    return (
        '<?xml version="1.0" encoding="UTF-16"?>'
        '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        '<Principals><Principal id="Caller"><UserId>' + escape(account) + "</UserId>"
        "<LogonType>" + logon + "</LogonType><RunLevel>LeastPrivilege</RunLevel>"
        "</Principal></Principals><Settings>"
        "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
        "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"
        "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"
        "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>"
        '<Actions Context="Caller"><Exec><Command>'
        + escape(sys.executable)
        + "</Command>"
        "<Arguments>" + escape(arguments) + "</Arguments></Exec></Actions></Task>"
    )


def _write_json(path, result):
    temporary = path + ".writing"
    with open(temporary, "w", encoding="utf-8") as stream:
        json.dump(result, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _batch_worker(request, response, ready):
    with open(request, encoding="utf-8") as stream:
        options = json.load(stream)
    _write_json(ready, {"pid": os.getpid()})
    result = {"reboot_required": False}
    try:
        if not options["check_mode"]:
            with CapabilitySession(options["log_level"], options["log_path"]) as native:
                for name in options["names"]:
                    try:
                        reboot = native.add(
                            name, options["sources"], options["disable_update"]
                        )
                    except OSError as error:
                        result["failure"] = (
                            "Failed to install capability '" + name + "': " + str(error)
                        )
                        break
                    result["reboot_required"] = result["reboot_required"] or reboot
    except (OSError, ValueError) as error:
        result["failure"] = str(error)
    _write_json(response, result)


def _wait_for_response(directory):
    ready = os.path.join(directory, "ready.json")
    response = os.path.join(directory, "response.json")
    deadline = time.monotonic() + 30
    while not os.path.exists(ready):
        if time.monotonic() >= deadline:
            raise OSError(
                "Timeout waiting for capability batch process to start; "
                "check SeBatchLogonRight"
            )
        time.sleep(0.1)
    with open(ready, encoding="utf-8") as stream:
        pid = json.load(stream)["pid"]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel.WaitForSingleObject.restype = ctypes.c_uint32
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    handle = kernel.OpenProcess(0x100000, False, pid)
    try:
        while not os.path.exists(response):
            if not handle:
                raise ctypes.WinError(ctypes.get_last_error())
            status = kernel.WaitForSingleObject(handle, 100)
            if status == 0 and not os.path.exists(response):
                raise OSError("Capability batch process exited without its result")
            if status == 0xFFFFFFFF:
                raise ctypes.WinError(ctypes.get_last_error())
        with open(response, encoding="utf-8") as stream:
            return json.load(stream)
    finally:
        if handle:
            kernel.CloseHandle(handle)


def _execute_batch(task, directory):
    registered = False
    completed = False
    try:
        _task_command(
            ["/Create", "/TN", task, "/XML", os.path.join(directory, "task.xml")]
        )
        registered = True
        _task_command(["/Run", "/TN", task])
        result = _wait_for_response(directory)
        completed = True
        return result
    finally:
        if registered:
            try:
                try:
                    if not completed:
                        _task_command(["/End", "/TN", task])
                finally:
                    _task_command(["/Delete", "/TN", task, "/F"])
            except OSError as error:
                # Retain the request identifying only this owned task/workspace
                # if native cleanup fails; never erase its recovery evidence.
                raise OSError(
                    "Capability batch cleanup failed for task '"
                    + task
                    + "', workspace '"
                    + directory
                    + "': "
                    + str(error)
                ) from error
        shutil.rmtree(directory)


def add_batch(names, options, check_mode):
    """Install prechecked names as the current account with a batch logon.

    Check mode still starts the scheduled process, validating the source's
    batch-logon prerequisite without servicing anything. No rights are granted.

    :param list names: Full capability names in caller order.
    :param dict options: Bound source, update and logging options.
    :param bool check_mode: Only validate batch process creation.
    :returns: Reboot flag and optional first servicing failure.
    :rtype: dict
    :raises OSError: Task registration, startup, execution or cleanup fails.
    """
    task = "LegacyWindowsCapability-" + str(uuid.uuid4())
    directory = tempfile.mkdtemp(prefix="legacy-windows-capability-batch-")
    prepared = False
    try:
        request = os.path.join(directory, "request.json")
        response = os.path.join(directory, "response.json")
        ready = os.path.join(directory, "ready.json")
        xml = os.path.join(directory, "task.xml")
        _write_json(
            request,
            {
                "names": names,
                "sources": options["sources"],
                "disable_update": options["disable_update"],
                "log_level": options["log_level"],
                "log_path": options["log_path"],
                "check_mode": check_mode,
                "task": task,
            },
        )
        with open(xml, "w", encoding="utf-16") as stream:
            stream.write(_task_xml(_current_account(), request, response, ready))
        prepared = True
    finally:
        # Before registration this directory owns files only, never a task.
        if not prepared:
            shutil.rmtree(directory)
    return _execute_batch(task, directory)


if __name__ == "__main__":
    if len(sys.argv) != 5 or sys.argv[1] != "--batch":
        raise ValueError("Capability helper requires its private batch arguments")
    _batch_worker(*sys.argv[2:])
