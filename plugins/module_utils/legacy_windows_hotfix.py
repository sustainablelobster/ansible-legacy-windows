# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Inspect and service MSU packages through native DISM and Windows utilities."""

import ctypes
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as xml
from contextlib import contextmanager

import legacy_windows_find_match as matching  # pylint: disable=import-error
import legacy_windows_hotfix_command as command  # pylint: disable=import-error
from legacy_windows_wmi import WmiConnection  # pylint: disable=import-error

_ONLINE_IMAGE = "DISM_{53BFAE52-B167-4E2F-A258-0A37B57FF845}"
_STATES = (
    "NotPresent",
    "UninstallPending",
    "Staged",
    "Removed",
    "Installed",
    "InstallPending",
    "Superseded",
    "PartiallyInstalled",
)
_PREREQUISITE = (
    "Hotfix management requires installed native DISM online package "
    "servicing through DismApi.dll or dism.exe."
)


# Native records use four-byte packing on both supported Windows architectures.
class _SystemTime(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _pack_ = 4
    _fields_ = [("parts", ctypes.c_uint16 * 8)]


class _Package(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _pack_ = 4
    _fields_ = [
        ("name", ctypes.c_wchar_p),
        ("state", ctypes.c_int32),
        ("release_type", ctypes.c_int32),
        ("install_time", _SystemTime),
    ]


class _PackageInfo(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _pack_ = 4
    _fields_ = [
        ("name", ctypes.c_wchar_p),
        ("state", ctypes.c_int32),
        ("release_type", ctypes.c_int32),
        ("install_time", _SystemTime),
        ("applicable", ctypes.c_int32),
        ("copyright", ctypes.c_wchar_p),
        ("company", ctypes.c_wchar_p),
        ("creation_time", _SystemTime),
        ("display_name", ctypes.c_wchar_p),
        ("description", ctypes.c_wchar_p),
        ("install_client", ctypes.c_wchar_p),
        ("install_package_name", ctypes.c_wchar_p),
        ("last_update_time", _SystemTime),
        ("product_name", ctypes.c_wchar_p),
        ("product_version", ctypes.c_wchar_p),
        ("restart_required", ctypes.c_int32),
        ("fully_offline", ctypes.c_int32),
        ("support_information", ctypes.c_wchar_p),
        ("custom_properties", ctypes.c_void_p),
        ("custom_property_count", ctypes.c_uint32),
        ("features", ctypes.c_void_p),
        ("feature_count", ctypes.c_uint32),
    ]


class _DismString(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _pack_ = 4
    _fields_ = [("value", ctypes.c_wchar_p)]


def _library():
    if os.name != "nt":
        raise OSError(_PREREQUISITE)
    try:
        library = ctypes.WinDLL(
            os.path.join(os.environ["SystemRoot"], "System32", "DismApi.dll")
        )
        signatures = {
            "DismInitialize": [ctypes.c_int32, ctypes.c_wchar_p, ctypes.c_wchar_p],
            "DismOpenSession": [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.POINTER(ctypes.c_uint32),
            ],
            "DismGetPackages": [
                ctypes.c_uint32,
                ctypes.POINTER(ctypes.POINTER(_Package)),
                ctypes.POINTER(ctypes.c_uint32),
            ],
            "DismGetPackageInfo": [
                ctypes.c_uint32,
                ctypes.c_wchar_p,
                ctypes.c_int32,
                ctypes.POINTER(ctypes.POINTER(_PackageInfo)),
            ],
            "DismAddPackage": [
                ctypes.c_uint32,
                ctypes.c_wchar_p,
                ctypes.c_int32,
                ctypes.c_int32,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
            ],
            "DismRemovePackage": [
                ctypes.c_uint32,
                ctypes.c_wchar_p,
                ctypes.c_int32,
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_void_p,
            ],
            "DismGetLastErrorMessage": [ctypes.POINTER(ctypes.POINTER(_DismString))],
            "DismDelete": [ctypes.c_void_p],
            "DismCloseSession": [ctypes.c_uint32],
            "DismShutdown": [],
        }
        for name, arguments in signatures.items():
            operation = getattr(library, name)
            operation.argtypes = arguments
            operation.restype = ctypes.c_int32
    except (OSError, AttributeError) as error:
        raise OSError(_PREREQUISITE) from error
    return library


def _check(library, status, operation):
    if not status:
        return
    detail = ctypes.POINTER(_DismString)()
    message = ""
    try:
        if not library.DismGetLastErrorMessage(ctypes.byref(detail)) and detail:
            message = detail.contents.value or ""
    finally:
        if detail:
            library.DismDelete(detail)
    raise OSError(
        message
        or "{0} failed (HRESULT 0x{1:08X}).".format(operation, status & 0xFFFFFFFF)
    )


def _state(value):
    return _STATES[value] if 0 <= value < len(_STATES) else str(value)


def _reference_clr_image():
    # The released Windows PowerShell host uses CLR4. Native resource mapping
    # keeps the same existing file in use, but does not initialize or run CLR.
    # Missing CLR files do not add a new runtime prerequisite to native DISM.
    root = os.environ.get("SystemRoot")
    if root is None:
        return None
    framework = "Framework64" if ctypes.sizeof(ctypes.c_void_p) == 8 else "Framework"
    path = os.path.join(root, "Microsoft.NET", framework, "v4.0.30319", "clr.dll")
    return path if os.path.isfile(path) else None


@contextmanager
def _reference_file_use():
    path = _reference_clr_image()
    if path is None:
        yield None
        return
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.LoadLibraryExW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_uint32]
    api.LoadLibraryExW.restype = ctypes.c_void_p
    api.FreeLibrary.argtypes = [ctypes.c_void_p]
    api.FreeLibrary.restype = ctypes.c_int
    # LOAD_LIBRARY_AS_IMAGE_RESOURCE maps the image without static imports,
    # DllMain or CLR execution. Windows sees genuine file use during removal.
    # https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw
    image = api.LoadLibraryExW(path, None, 0x20)
    if not image:
        raise OSError(
            "failed to hold the reference host image {0}: {1}".format(
                path, ctypes.WinError(ctypes.get_last_error())
            )
        )
    primary = None
    try:
        yield {"path": path, "handle": image}
    except Exception as error:
        primary = error
        raise
    finally:
        if not api.FreeLibrary(image):
            cleanup = "failed to release the reference host image {0}: {1}".format(
                path, ctypes.WinError(ctypes.get_last_error())
            )
            if primary is not None:
                raise OSError("{0}; {1}".format(primary, cleanup)) from primary
            raise OSError(cleanup)


class HotfixSession:
    """Own an online native DISM session and every returned metadata buffer."""

    def __init__(self):
        self.library = None
        self.session = ctypes.c_uint32()
        self._opened = False
        self._initialized = False
        self._command = None

    def __enter__(self):
        try:
            library = _library()
        except OSError:
            tool = command.executable()
            if tool is None:
                raise
            self._command = command.DismCommand(tool)
            self._command.__enter__()
        else:
            self._start(library)
        return self

    def _start(self, library=None):
        self.library = library if library is not None else _library()
        _check(
            self.library, self.library.DismInitialize(2, None, None), "DismInitialize"
        )
        self._initialized = True
        try:
            self._open()
        except Exception:
            self._finish()
            raise

    def _open(self):
        _check(
            self.library,
            self.library.DismOpenSession(
                _ONLINE_IMAGE, None, None, ctypes.byref(self.session)
            ),
            "DismOpenSession",
        )
        self._opened = True

    def __exit__(self, _exc_type, _exc_value, _traceback):
        if self._command is not None:
            self._command.__exit__(_exc_type, _exc_value, _traceback)
        else:
            self._finish()

    def _finish(self):
        if not self._initialized:
            return
        try:
            if self._opened:
                status = self.library.DismCloseSession(self.session)
                # The measured reboot-requiring install also returns 3010
                # when closing its session. Preserve the operation's reported
                # restart instead of turning successful cleanup into failure.
                if status != 3010:
                    _check(self.library, status, "DismCloseSession")
                self._opened = False
        finally:
            self._initialized = False
            _check(self.library, self.library.DismShutdown(), "DismShutdown")

    def native_catalogue(self):
        """Return the complete native package inventory without visibility filtering.

        :returns: Ordered package metadata.
        :rtype: list
        :raises OSError: Enumeration fails or returns an invalid array.
        """
        if self._command is not None:
            return self._command.catalogue()
        values = ctypes.POINTER(_Package)()
        count = ctypes.c_uint32()
        try:
            _check(
                self.library,
                self.library.DismGetPackages(
                    self.session, ctypes.byref(values), ctypes.byref(count)
                ),
                "DismGetPackages",
            )
            if count.value and not values:
                raise OSError("DISM returned a count without a package array.")
            return [
                {"name": values[index].name, "state": _state(values[index].state)}
                for index in range(count.value)
            ]
        finally:
            if values:
                self.library.DismDelete(values)

    def catalogue(self):
        """Return the visible package catalogue used by the released cmdlet.

        The documented native array also contains hidden feature-on-demand
        packages on the measured Server 2025 image. The shipped DISM command
        exposes the cmdlet's visible package list and its order instead.

        :returns: Ordered package names and states.
        :rtype: list
        :raises OSError: DISM fails or returns an incomplete package record.
        """
        if self._command is not None:
            return self._command.catalogue()
        # A measured read stalled while the DLL and CLI opened the same image.
        # Finish the DLL image lifetime before invoking the independent tool.
        self._finish()
        try:
            return self._catalogue_command()
        finally:
            self._start()

    @staticmethod
    def _catalogue_command():
        executable = os.path.join(os.environ["SystemRoot"], "Sysnative", "dism.exe")
        if not os.path.isfile(executable):
            executable = os.path.join(os.environ["SystemRoot"], "System32", "dism.exe")
        with tempfile.TemporaryDirectory(
            prefix="legacy-windows-hotfix-list-"
        ) as directory:
            with subprocess.Popen(
                [
                    executable,
                    "/Online",
                    "/English",
                    "/Get-Packages",
                    "/ScratchDir:" + directory,
                    "/LogPath:" + os.path.join(directory, "dism.log"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            ) as process:
                output = process.communicate()[0].decode("mbcs", errors="replace")
                if process.returncode:
                    raise OSError(
                        "DISM failed ({0}): {1}".format(
                            process.returncode, output.strip()
                        )
                    )
        result = []
        for line in output.splitlines():
            if line.startswith("Package Identity : "):
                result.append({"name": line.split(" : ", 1)[1]})
            elif line.startswith("State : ") and result:
                result[-1]["state"] = line.split(" : ", 1)[1].replace(" ", "")
        if any(
            set(package) != {"name", "state"}
            or not package["name"]
            or package["state"] not in _STATES
            for package in result
        ):
            raise OSError("DISM returned an incomplete package catalogue.")
        return result

    def information(self, identifier, by_path=False):
        """Copy package metadata before releasing its native allocation.

        :param str identifier: Package name or absolute CAB filename.
        :param bool by_path: Interpret the identifier as a filename.
        :returns: Package name, state, description and applicability.
        :rtype: dict
        :raises OSError: Metadata cannot be retrieved.
        """
        if self._command is not None:
            return self._command.information(identifier, by_path)
        information = ctypes.POINTER(_PackageInfo)()
        try:
            _check(
                self.library,
                self.library.DismGetPackageInfo(
                    self.session,
                    identifier,
                    2 if by_path else 1,
                    ctypes.byref(information),
                ),
                "DismGetPackageInfo",
            )
            if not information:
                raise OSError("DISM returned no package information.")
            value = information.contents
            return {
                "name": value.name,
                "state": _state(value.state),
                "description": value.description,
                "applicable": bool(value.applicable),
            }
        finally:
            if information:
                self.library.DismDelete(information)

    def _changed(self, status, operation):
        if status == 1:
            # Successful servicing can invalidate only the current DISM session.
            _check(
                self.library,
                self.library.DismCloseSession(self.session),
                "DismCloseSession",
            )
            self._opened = False
            self._open()
            return False
        if status == 3010:
            return True
        _check(self.library, status, operation)
        return False

    def add(self, path):
        """Install one CAB without restarting Windows.

        :param str path: Expanded CAB package filename.
        :returns: Whether successful servicing requires a reboot.
        :rtype: bool
        :raises OSError: Servicing fails, possibly after partial changes.
        """
        if self._command is not None:
            return self._command.add(path)
        return self._changed(
            self.library.DismAddPackage(
                self.session, path, False, False, None, None, None
            ),
            "DismAddPackage",
        )

    def remove(self, name):
        """Remove one named package without restarting Windows.

        :param str name: Exact DISM package identifier.
        :returns: Whether successful servicing requires a reboot.
        :rtype: bool
        :raises OSError: Servicing fails, possibly after partial changes.
        """
        with _reference_file_use():
            if self._command is not None:
                return self._command.remove(name)
            return self._changed(
                self.library.DismRemovePackage(self.session, name, 1, None, None, None),
                "DismRemovePackage",
            )


def installed_kb(identifier):
    """Look for an installed QuickFixEngineering entry with the supplied ID.

    :param str identifier: KB identifier selected by the public request.
    :returns: Whether the WMI hotfix inventory contains that identifier.
    :rtype: bool
    :raises OSError: The native WMI query fails.
    """
    with WmiConnection() as connection:
        rows = connection.query(
            "SELECT HotFixID FROM Win32_QuickFixEngineering", ["HotFixID"]
        )
    return any((row["HotFixID"] or "").lower() == identifier.lower() for row in rows)


def metadata_from_name(session, name):
    """Read a named package, treating provider failures as an absent package.

    :param HotfixSession session: Open native package provider.
    :param str name: Requested DISM package identifier.
    :returns: Package name, state and first KB substring, or an absent stub.
    :rtype: dict
    """
    try:
        value = session.information(name)
    except OSError:
        value = {"name": name, "state": "NotPresent", "description": ""}
    match = re.search(r"KB\d*", value["description"] or "", re.IGNORECASE)
    return {
        "name": value["name"],
        "state": value["state"],
        "kb": match.group(0) if match else "UNKNOWN",
    }


def metadata_from_kb(session, kb):
    """Resolve an installed KB using package names, then descriptions.

    :param HotfixSession session: Open native package provider.
    :param str kb: Installed KB identifier.
    :returns: Matching package metadata.
    :rtype: dict
    :raises ValueError: No DISM package identifies the installed KB.
    """
    packages = session.catalogue()
    names = [
        value["name"]
        for value in packages
        if matching.matches(value["name"], ["*" + kb + "*"])
    ]
    if names:
        # The released untyped function passes a name array to the scalar
        # DISM cmdlet. Multiple matches therefore produce its absent stub.
        return (
            metadata_from_name(session, names[0])
            if len(names) == 1
            else {"name": names, "state": "NotPresent", "kb": "UNKNOWN"}
        )
    for package in packages:
        value = metadata_from_name(session, package["name"])
        if value["kb"].lower() == kb.lower():
            return value
    raise ValueError(
        "failed to get DISM package from KB, to continue specify "
        "hotfix_identifier instead"
    )


class ExpandedMsu:
    """Extract one MSU into an owned directory and always remove that directory.

    :param str source: Literal source filename.
    """

    def __init__(self, source):
        self.source = source
        self.path = None

    def __enter__(self):
        self.path = tempfile.mkdtemp(prefix="legacy-windows-hotfix-")
        arguments = [self.source, self.path, "-F:*"]
        try:
            process = subprocess.Popen(
                [os.path.join(os.environ["SystemRoot"], "System32", "expand.exe")]
                + arguments,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            process.communicate()
            if process.returncode:
                raise ValueError(
                    "failed to run expand.exe {0}: RC = {1}".format(
                        " ".join(arguments), process.returncode
                    )
                )
        except OSError as error:
            self.__exit__(None, None, None)
            raise OSError(
                "failed to run expand.exe {0}: {1}".format(" ".join(arguments), error)
            ) from error
        except Exception:
            self.__exit__(None, None, None)
            raise
        return self.path

    def __exit__(self, _exc_type, _exc_value, _traceback):
        if self.path is not None:
            shutil.rmtree(self.path)
            self.path = None


def _get_content(path):
    with open(path, "rb") as source:
        data = source.read()
    # Windows PowerShell recognizes these BOMs; unmarked text uses Windows ANSI.
    if data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        encoding = "utf-32"
    elif data.startswith((b"\xff\xfe", b"\xfe\xff")):
        encoding = "utf-16"
    elif data.startswith(b"\xef\xbb\xbf"):
        encoding = "utf-8-sig"
    else:
        encoding = "mbcs"
    return re.split(r"\r\n|\r|\n", data.decode(encoding, errors="replace"))


def _kb_from_properties(directory, entries):
    kb = "UNKNOWN"
    for name in entries:
        if os.path.splitext(name)[1].lower() != ".txt":
            continue
        for line in _get_content(os.path.join(directory, name)):
            if line.startswith("KB Article Number"):
                value = line.split("=")[-1]
                kb = "KB" + value[1:-1]
    return kb


def metadata_from_file(session, directory):
    """Read extracted servicing metadata and validate every referenced CAB.

    :param HotfixSession session: Open native package provider.
    :param str directory: Owned directory containing the expanded MSU files.
    :returns: Ordered dictionaries with path, name, state and KB identifier.
    :rtype: list
    :raises ValueError: Metadata is absent, invalid or inapplicable.
    :raises OSError: A CAB cannot be inspected.
    """
    entries = sorted(os.listdir(directory), key=lambda value: value.lower())
    xml_paths = [
        os.path.join(directory, name)
        for name in entries
        if os.path.splitext(name)[1].lower() == ".xml"
    ]
    if not xml_paths:
        raise ValueError(
            "failed to get metadata xml inside MSU file, cannot get "
            "hotfix metadata required for this task"
        )
    contents = []
    for path in xml_paths:
        contents.extend(_get_content(path))
    document = xml.fromstring(" ".join(contents))
    result = []
    # Local-name matching handles the default unattend XML namespace.
    for servicing in document:
        if servicing.tag.rsplit("}", 1)[-1] != "servicing":
            continue
        for package in servicing:
            if package.tag.rsplit("}", 1)[-1] != "package":
                continue
            for source in package:
                if source.tag.rsplit("}", 1)[-1] != "source":
                    continue
                filename = (
                    source.get("location", "").replace("\\", "/").rsplit("/", 1)[-1]
                )
                path = os.path.join(directory, filename)
                try:
                    information = session.information(path, by_path=True)
                except OSError as error:
                    raise OSError(
                        "failed to get DISM package metadata from path "
                        + directory
                        + ": "
                        + str(error)
                    ) from error
                if not information["applicable"]:
                    raise ValueError("hotfix package is not applicable for this server")
                kb = _kb_from_properties(directory, entries)
                result.append(
                    {
                        "path": path,
                        "name": information["name"],
                        "state": information["state"],
                        "kb": kb,
                    }
                )
    return result
