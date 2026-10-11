# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Inspect and deploy current-user MSIX packages through native Windows APIs."""

import ctypes
import os
import time
import uuid
import zipfile
from contextlib import contextmanager
from urllib.request import pathname2url
from xml.etree import ElementTree


# These fields are the documented native PACKAGE_ID/PACKAGE_VERSION ABI.
class _Win32Version(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        (name, ctypes.c_uint16) for name in ("revision", "build", "minor", "major")
    ]


# WinRT's PackageVersion has the opposite field order to Win32 PACKAGE_VERSION.
class _RuntimeVersion(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        (name, ctypes.c_uint16) for name in ("major", "minor", "build", "revision")
    ]


# The native identity is an ABI record, not a behavioral class interface.
class _PackageId(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("reserved", ctypes.c_uint32),
        ("architecture", ctypes.c_uint32),
        ("version", _Win32Version),
        ("name", ctypes.c_wchar_p),
        ("publisher", ctypes.c_wchar_p),
        ("resource", ctypes.c_wchar_p),
        ("publisher_id", ctypes.c_wchar_p),
    ]


class PackageApiError(OSError):
    """Retain a package HRESULT and its concrete failure diagnostic.

    :param int hresult: Signed native or released cmdlet exception HRESULT.
    :param str operation: Failed Windows package operation.
    :param str message: Complete deployment diagnostic, or None for an API failure.
    """

    def __init__(self, hresult, operation, message=None):
        self.hresult = ctypes.c_int32(hresult).value
        OSError.__init__(
            self,
            (
                message
                if message is not None
                else "{0} failed with HRESULT 0x{1:08X}".format(
                    operation, self.hresult & 0xFFFFFFFF
                )
            ),
        )


def _check(code, operation):
    if code < 0:
        raise PackageApiError(code, operation)


def _deployment_failure(code, text, activity):
    unsigned = code & 0xFFFFFFFF
    # These two measured cmdlet exceptions wrap the native deployment error.
    # Other unmeasured HRESULTs remain native, not guessed exception categories.
    if (
        unsigned == 0x80073CF0
    ):  # ERROR_INSTALL_OPEN_PACKAGE_FAILED: FileNotFoundException.
        exception_code = -2147024894
    elif unsigned == 0x80073D19:  # ERROR_DEPLOYMENT_BLOCKED_BY_USER_LOG_OFF: Exception.
        exception_code = -2146233088
    else:
        exception_code = code
    description = ctypes.FormatError(unsigned & 0xFFFF).rstrip("\r\n")
    message = (
        "Deployment failed with HRESULT: 0x{0:08X}, {1}\r\n\r\n{2}\n\n"
        "NOTE: For additional information, look for [ActivityId] {3} in the Event Log "
        "or use the command line Get-AppPackageLog -ActivityID {3}\n"
    ).format(unsigned, description, text, activity)
    return PackageApiError(exception_code, "PackageManager deployment", message)


def _guid(value):
    return (ctypes.c_ubyte * 16).from_buffer_copy(uuid.UUID(value).bytes_le)


def _call(pointer, index, arguments, *values):
    table = ctypes.cast(pointer, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)))
    operation = ctypes.WINFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, *arguments)(
        table[0][index]
    )
    return operation(pointer, *values)


def _release(pointer):
    if pointer:
        table = ctypes.cast(pointer, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)))
        ctypes.WINFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p)(table[0][2])(pointer)


@contextmanager
def _owned(pointer):
    try:
        yield pointer
    finally:
        _release(pointer)


def _query(pointer, identifier):
    result = ctypes.c_void_p()
    guid = _guid(identifier)
    _check(
        _call(
            pointer,
            0,
            [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)],
            ctypes.byref(guid),
            ctypes.byref(result),
        ),
        "QueryInterface",
    )
    return result.value


def _output(pointer, index, kind=ctypes.c_void_p):
    result = kind()
    _check(
        _call(pointer, index, [ctypes.POINTER(kind)], ctypes.byref(result)),
        "Windows package interface slot{0}".format(index),
    )
    return result.value


class PackageManager:
    """Own one initialized native current-user PackageManager apartment.

    :raises OSError: Native package activation is unavailable or fails.
    """

    def __init__(self):
        self.runtime = ctypes.WinDLL("combase", use_last_error=True)
        self.pointer = None
        self.initialized = False
        signatures = {
            "RoInitialize": ([ctypes.c_uint32], ctypes.c_int32),
            "RoUninitialize": ([], None),
            "RoActivateInstance": (
                [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)],
                ctypes.c_int32,
            ),
            "RoGetActivationFactory": (
                [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)],
                ctypes.c_int32,
            ),
            "WindowsCreateString": (
                [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)],
                ctypes.c_int32,
            ),
            "WindowsDeleteString": ([ctypes.c_void_p], ctypes.c_int32),
            "WindowsGetStringRawBuffer": (
                [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)],
                ctypes.c_void_p,
            ),
        }
        for name, (arguments, result) in signatures.items():
            operation = getattr(self.runtime, name)
            operation.argtypes, operation.restype = arguments, result

    def __enter__(self):
        code = self.runtime.RoInitialize(1)
        if code == -2147417850:  # RPC_E_CHANGED_MODE: MSI metadata already owns STA.
            code = self.runtime.RoInitialize(0)
        _check(code, "RoInitialize")
        self.initialized = True
        try:
            with self._string("Windows.Management.Deployment.PackageManager") as name:
                instance = ctypes.c_void_p()
                _check(
                    self.runtime.RoActivateInstance(name, ctypes.byref(instance)),
                    "RoActivateInstance PackageManager",
                )
            with _owned(instance.value) as pointer:
                self.pointer = _query(pointer, "9a7d4b65-5e8f-4fc7-a2e5-7f6925cb8b53")
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *unused):
        _release(self.pointer)
        self.pointer = None
        if self.initialized:
            self.runtime.RoUninitialize()
            self.initialized = False

    @contextmanager
    def _string(self, value):
        result = ctypes.c_void_p()
        # HSTRING length counts UTF-16 code units, not Python Unicode points.
        length = len(value.encode("utf-16-le")) // 2
        _check(
            self.runtime.WindowsCreateString(value, length, ctypes.byref(result)),
            "WindowsCreateString",
        )
        try:
            yield result.value
        finally:
            self.runtime.WindowsDeleteString(result)

    def _read_string(self, value):
        length = ctypes.c_uint32()
        try:
            buffer = self.runtime.WindowsGetStringRawBuffer(value, ctypes.byref(length))
            return (
                ctypes.string_at(buffer, length.value * 2).decode("utf-16-le")
                if length.value
                else ""
            )
        finally:
            self.runtime.WindowsDeleteString(value)

    def _package(self, pointer):
        with _owned(_output(pointer, 6)) as identity:
            result = {
                name: self._read_string(_output(identity, slot))
                for name, slot in [
                    ("Name", 6),
                    ("ResourceId", 9),
                    ("Publisher", 10),
                    ("PublisherId", 11),
                    ("PackageFullName", 12),
                    ("PackageFamilyName", 13),
                ]
            }
            version = _RuntimeVersion()
            _check(
                _call(
                    identity,
                    7,
                    [ctypes.POINTER(_RuntimeVersion)],
                    ctypes.byref(version),
                ),
                "PackageId.Version",
            )
            result["Version"] = "{0}.{1}.{2}.{3}".format(
                version.major, version.minor, version.build, version.revision
            )
            result["Architecture"] = _output(identity, 8, ctypes.c_uint32)
        result["IsFramework"] = bool(_output(pointer, 8, ctypes.c_ubyte))
        with _owned(
            _query(pointer, "a6612fb6-7688-4ace-95fb-359538e7aa01")
        ) as extended:
            result["IsResourcePackage"] = bool(_output(extended, 10, ctypes.c_ubyte))
            result["IsBundle"] = bool(_output(extended, 11, ctypes.c_ubyte))
        return result

    def packages(self, all_users=False):
        """Return native package records in provider enumeration order.

        :param bool all_users: Read machine registrations for fixture recovery only.
        :returns: All package identities, including bundle/resource metadata.
        :rtype: list
        :raises OSError: Native enumeration or an exact requested property fails.
        """
        result = ctypes.c_void_p()
        _check(
            _call(
                self.pointer,
                11 if all_users else 12,
                (
                    [ctypes.POINTER(ctypes.c_void_p)]
                    if all_users
                    else [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
                ),
                *([ctypes.byref(result)] if all_users else [None, ctypes.byref(result)])
            ),
            "PackageManager.FindPackagesForUser",
        )
        rows = []
        with _owned(result.value) as iterable, _owned(_output(iterable, 6)) as iterator:
            while _output(iterator, 7, ctypes.c_ubyte):
                with _owned(_output(iterator, 6)) as package:
                    rows.append(self._package(package))
                _output(iterator, 8, ctypes.c_ubyte)
        return rows

    @contextmanager
    def _uri(self, path):
        with self._string("Windows.Foundation.Uri") as name:
            factory = ctypes.c_void_p()
            interface = _guid("44a9796f-723e-4fdf-a218-033e75b0c084")
            _check(
                self.runtime.RoGetActivationFactory(
                    name, ctypes.byref(interface), ctypes.byref(factory)
                ),
                "RoGetActivationFactory Uri",
            )
        with _owned(factory.value) as pointer:
            with self._string("file:" + pathname2url(os.path.abspath(path))) as name:
                value = ctypes.c_void_p()
                _check(
                    _call(
                        pointer,
                        6,
                        [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)],
                        name,
                        ctypes.byref(value),
                    ),
                    "Uri.CreateUri",
                )
        with _owned(value.value) as pointer:
            yield pointer

    def _complete(self, pointer):
        with _owned(_query(pointer, "00000036-0000-0000-c000-000000000046")) as info:
            try:
                # The released provider waits indefinitely for deployment.
                # Polling avoids a Python callback retained by the native worker.
                status = _output(info, 7, ctypes.c_int32)
                while status == 0:
                    time.sleep(0.05)
                    status = _output(info, 7, ctypes.c_int32)
                result = ctypes.c_void_p()
                code = _call(
                    pointer,
                    10,
                    [ctypes.POINTER(ctypes.c_void_p)],
                    ctypes.byref(result),
                )
                with _owned(result.value) as deployment:
                    _check(code, "PackageManager deployment")
                    error = _output(deployment, 8, ctypes.c_int32)
                    # Terminal Error is authoritative; extended data is supplemental.
                    if status == 3 or error < 0:
                        general = _output(info, 8, ctypes.c_int32)
                        text = self._read_string(_output(deployment, 6))
                        activity = (ctypes.c_ubyte * 16)()
                        _check(
                            _call(
                                deployment, 7, [ctypes.c_void_p], ctypes.byref(activity)
                            ),
                            "DeploymentResult.ActivityId",
                        )
                        raise _deployment_failure(
                            general or error,
                            text,
                            str(uuid.UUID(bytes_le=bytes(activity))),
                        )
            finally:
                _check(_call(info, 10, []), "IAsyncInfo.Close")

    def install(self, path):
        """Wait for native AddPackageAsync with the released default options.

        :param str path: Literal local package or bundle path.
        :raises OSError: Native activation or package deployment fails.
        """
        with self._uri(path) as uri:
            result = ctypes.c_void_p()
            _check(
                _call(
                    self.pointer,
                    6,
                    [
                        ctypes.c_void_p,
                        ctypes.c_void_p,
                        ctypes.c_uint32,
                        ctypes.POINTER(ctypes.c_void_p),
                    ],
                    uri,
                    None,
                    0,
                    ctypes.byref(result),
                ),
                "PackageManager.AddPackageAsync",
            )
        with _owned(result.value) as operation:
            self._complete(operation)

    def remove(self, name):
        """Wait for native RemovePackageAsync for the resolved full name.

        :param str name: Installed package full name, not a wildcard expression.
        :raises OSError: Native removal fails.
        """
        with self._string(name) as value:
            result = ctypes.c_void_p()
            _check(
                _call(
                    self.pointer,
                    8,
                    [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)],
                    value,
                    ctypes.byref(result),
                ),
                "PackageManager.RemovePackageAsync",
            )
        with _owned(result.value) as operation:
            self._complete(operation)


def available():
    """Detect the native package API without guessing from the Windows version.

    :returns: Whether the required runtime activation exports are available.
    :rtype: bool
    """
    try:
        runtime = ctypes.WinDLL("combase", use_last_error=True)
        return bool(runtime.RoActivateInstance and runtime.RoInitialize)
    except (OSError, AttributeError):
        return False


def installed_status(path, identifier):
    """Apply the released name-then-full-name current-user selection.

    :param str path: Local archive path, or None for a product identifier.
    :param str identifier: Public product_id, or None when using a path.
    :returns: Resolved identifier and installed state.
    :rtype: dict
    :raises OSError: A native package query fails.
    :raises ValueError: Archive metadata cannot be read.
    """
    import legacy_windows_find_match as matching  # pylint: disable=import-outside-toplevel,import-error

    identities = manifest_identities(path) if path else [identifier]
    with PackageManager() as manager:
        # Get-AppxPackage's default type filter includes Main and Framework,
        # not the resource and bundle registration records.
        rows = [
            row
            for row in manager.packages()
            if not row["IsResourcePackage"] and not row["IsBundle"]
        ]
    selected = (
        []
        if path
        else [row for row in rows if matching.matches(row["Name"], [identifier])]
    )
    if not selected:
        names = [name.lower() for name in identities]
        selected = [row for row in rows if row["PackageFullName"].lower() in names]
    if selected:
        identifier = " ".join(row["PackageFullName"] for row in selected)
    return {"id": identifier, "installed": bool(selected)}


def full_name(identity, architecture_attribute="ProcessorArchitecture", resource=True):
    """Calculate the released manifest identity using PackageFullNameFromId.

    :param dict identity: XML identity attributes from an Appx or bundle package.
    :param str architecture_attribute: Manifest's architecture attribute name.
    :param bool resource: Whether this released manifest branch uses ResourceId.
    :returns: Exact native package full name.
    :rtype: str
    :raises OSError: Native package identity conversion fails.
    :raises ValueError: Version or architecture is invalid.
    """
    architectures = {"x86": 0, "arm": 5, "x64": 9, "neutral": 11, "arm64": 12}
    parts = identity["Version"].split(".", 3)
    numbers = [int(part) for part in parts] + [0] * (4 - len(parts))
    if any(number < 0 or number > 65535 for number in numbers):
        raise ValueError("Package version components must fit UInt16.")
    package = _PackageId(
        0,
        architectures[identity.get(architecture_attribute, "neutral").lower()],
        _Win32Version(*reversed(numbers)),
        identity["Name"],
        identity["Publisher"],
        identity.get("ResourceId", "") if resource else "",
        None,
    )
    library = ctypes.WinDLL("kernel32", use_last_error=True)
    operation = library.PackageFullNameFromId
    operation.argtypes = [
        ctypes.POINTER(_PackageId),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_wchar_p,
    ]
    operation.restype = ctypes.c_uint32
    length = ctypes.c_uint32()
    code = operation(ctypes.byref(package), ctypes.byref(length), None)
    if code != 122:
        raise ctypes.WinError(code)
    buffer = ctypes.create_unicode_buffer(length.value)
    code = operation(ctypes.byref(package), ctypes.byref(length), buffer)
    if code:
        raise ctypes.WinError(code)
    return buffer.value


def manifest_identities(path):
    """Read the exact released package/bundle manifest identity branches.

    :param str path: Local Appx/MSIX ZIP archive.
    :returns: Native full names used by the provider's installed-state query.
    :rtype: list
    :raises ValueError: The archive does not contain one released manifest.
    """
    with zipfile.ZipFile(path, "r") as archive:
        names = [
            name
            for name in archive.namelist()
            if name.lower()
            in ("appxmanifest.xml", "appxmetadata/appxbundlemanifest.xml")
        ]
        if len(names) != 1:
            raise ValueError(
                "Package must contain one released package or bundle manifest."
            )
        manifest = ElementTree.fromstring(archive.read(names[0]))
    namespace = manifest.tag.partition("}")[0] + "}" if "}" in manifest.tag else ""
    identity = manifest.find(namespace + "Identity").attrib
    if names[0].lower() == "appxmetadata/appxbundlemanifest.xml":
        return [
            full_name(
                dict(
                    package.attrib,
                    Name=identity["Name"],
                    Publisher=identity["Publisher"],
                ),
                architecture_attribute="Architecture",
            )
            for package in manifest.find(namespace + "Packages")
        ]
    # Released code's undefined $identityParent drops a standalone ResourceId.
    # Preserve that concrete branch rather than repairing the source contract.
    return [full_name(identity, resource=False)]
