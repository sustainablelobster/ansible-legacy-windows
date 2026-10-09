# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Install MSI, MSP, MSIX and registry packages through native Windows APIs."""

import ctypes
import hashlib
import ntpath
import os
import re
import tempfile
import uuid
from contextlib import contextmanager

import legacy_windows_acl as acl  # pylint: disable=import-error
import legacy_windows_process as processes  # pylint: disable=import-error
import legacy_windows_service_info as services  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_string,
    expand_environment,
)
from legacy_windows_package_msi import WindowsInstaller  # pylint: disable=import-error


class _UnhandledPackageError(ValueError):
    """Retain the released uncaught metadata or download failure boundary."""


def quote_argument(value):
    """Escape one argument using the released C-runtime quoting rules.

    :param str value: Literal argument, not a shell expression.
    :returns: Escaped command-line argument.
    :rtype: str
    """
    if not value:
        return '""'
    if not re.search(r'\s|"', value):
        return value
    result = ['"']
    backslashes = 0
    for index, character in enumerate(value):
        if character == "\\":
            backslashes += 1
            continue
        count = (
            2 * backslashes + 1
            if character == '"'
            else (
                2 * backslashes
                if character == "\n" and index == len(value) - 1
                else backslashes
            )
        )
        result.extend(("\\" * count, character))
        backslashes = 0
    result.extend(("\\" * (2 * backslashes), '"'))
    return "".join(result)


def _quote_msi_argument(value):
    name, separator, content = value.partition("=")
    # Legacy Windows Installer rejects a quoted whole PROPERTY=spaced value
    # assignment. Quote its value instead; leave embedded-quote syntax unchanged
    # until that separate public boundary has actual source/legacy measurements.
    if (
        separator
        and re.match(r"^[A-Za-z_][A-Za-z0-9_.]*$", name)
        and re.search(r"\s", content)
        and '"' not in content
    ):
        return name + '="' + content + '"'
    return quote_argument(value)


def installer_arguments(value, msi=False):
    """Preserve raw argument strings or escape every element of an argument list.

    :param value: Public raw arguments value.
    :type value: object
    :param bool msi: Quote MSI property values rather than whole assignments.
    :returns: Command-line suffix, or None.
    :rtype: str or None
    """
    if isinstance(value, list):
        quote = _quote_msi_argument if msi else quote_argument
        return " ".join(quote(as_string(item, "arguments") or "") for item in value)
    return as_string(value, "arguments")


def _registry_location(identifier):
    if not identifier:
        return None
    import winreg  # pylint: disable=import-outside-toplevel,import-error

    native64 = bool(os.environ.get("PROCESSOR_ARCHITEW6432")) or os.environ.get(
        "PROCESSOR_ARCHITECTURE", ""
    ).lower() in ("amd64", "arm64")
    access = winreg.KEY_READ | (0x100 if native64 else 0)
    for hive_name, hive in (
        ("HKLM", winreg.HKEY_LOCAL_MACHINE),
        ("HKCU", winreg.HKEY_CURRENT_USER),
    ):
        for branch in ("SOFTWARE", "SOFTWARE\\Wow6432Node"):
            path = (
                branch
                + "\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"
                + identifier
            )
            try:
                with winreg.OpenKey(hive, path, 0, access) as key:
                    values = {}
                    for name in ("QuietUninstallString", "UninstallString"):
                        try:
                            values[name] = winreg.QueryValueEx(key, name)[0]
                        except FileNotFoundError:
                            pass
                    return {"path": hive_name + ":\\" + path, "values": values}
            except FileNotFoundError:
                continue
    return None


def _file_version(path):
    library = ctypes.WinDLL("version", use_last_error=True)
    library.GetFileVersionInfoSizeW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p]
    library.GetFileVersionInfoSizeW.restype = ctypes.c_uint32
    library.GetFileVersionInfoW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    library.GetFileVersionInfoW.restype = ctypes.c_int32
    library.VerQueryValueW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.VerQueryValueW.restype = ctypes.c_int32
    size = library.GetFileVersionInfoSizeW(path, None)
    if not size:
        return "0.0.0.0"
    data = ctypes.create_string_buffer(size)
    if not library.GetFileVersionInfoW(path, 0, size, data):
        raise ctypes.WinError(ctypes.get_last_error())
    pointer, length = ctypes.c_void_p(), ctypes.c_uint32()
    if not library.VerQueryValueW(
        data, "\\", ctypes.byref(pointer), ctypes.byref(length)
    ):
        return "0.0.0.0"
    if length.value < 52:
        raise OSError("The file version record is truncated.")
    fields = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32))
    high, low = fields[2], fields[3]
    return "{0}.{1}.{2}.{3}".format(high >> 16, high & 65535, low >> 16, low & 65535)


def _has_service_pattern(name):
    escaped = False
    for character in name:
        if escaped:
            escaped = False
        elif character == "`":
            escaped = True
        elif character in "*?[":
            return True
    return False


def _service_exists(name):
    if _has_service_pattern(name):
        # Invalid patterns must fail even if Windows returns no visible services.
        services.matches_service_name("", [name])
        return any(
            services.matches_service_name(candidate, [name])
            for candidate in services.enumerate_names()
        )
    library = ctypes.WinDLL("advapi32", use_last_error=True)
    library.OpenSCManagerW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    ]
    library.OpenSCManagerW.restype = ctypes.c_void_p
    library.OpenServiceW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32]
    library.OpenServiceW.restype = ctypes.c_void_p
    library.GetServiceKeyNameW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.GetServiceKeyNameW.restype = ctypes.c_int32
    library.CloseServiceHandle.argtypes = [ctypes.c_void_p]
    library.CloseServiceHandle.restype = ctypes.c_int32
    # Repeat native SCM handle setup so the test observer stays independent.
    # pylint: disable=duplicate-code
    manager = library.OpenSCManagerW(None, None, 1)
    if not manager:
        raise ctypes.WinError(ctypes.get_last_error())
    service = None
    # pylint: enable=duplicate-code
    try:
        service = library.OpenServiceW(manager, name, 4)
        if not service:
            error = ctypes.get_last_error()
            if error != 1060:
                raise ctypes.WinError(error)
            # Share bounded SCM name lookup without suppressing access failures.
            key_name = (
                services._lookup_service_name(  # pylint: disable=protected-access
                    library.GetServiceKeyNameW, manager, name
                )
            )
            if key_name is None:
                return False
            service = library.OpenServiceW(manager, key_name, 4)
            if not service:
                error = ctypes.get_last_error()
                if error == 1060:
                    return False
                raise ctypes.WinError(error)
        return True
    finally:
        if service:
            library.CloseServiceHandle(service)
        library.CloseServiceHandle(manager)


def _patch_status(installer, path, identifier):
    if path:
        products = [
            (product, (1, 2, 4))
            for product in installer.summary_property(path, 7).split(";")
            if installer.product_state(product) == 5
        ]
        if not products:
            raise _UnhandledPackageError(
                "The specified patch does not apply to any installed MSI packages."
            )
        identifier = installer.summary_property(path, 9)[:38]
    else:
        products = [
            (patch["product"], (patch["context"],))
            for patch in installer.patches()
            if patch["patch"].lower() == identifier.lower()
        ]
    applied, skipped = [], []
    for product, contexts in products:
        for context in contexts:
            try:
                state = installer.patch_state(identifier, product, context)
            except OSError as error:
                if getattr(error, "winerror", error.errno) in (1605, 1647):
                    continue
                raise
            if state == 1 and product not in applied:
                applied.append(product)
            elif state in (2, 4):
                skipped.append(product)
    # Released PowerShell enumerates each string's Length on the generic list,
    # rather than reading Count. Keep that measured expression, including null
    # for an empty list and boolean conversion of a filtered multi-value array.
    skip = any(len(product) == len(applied) for product in skipped)
    return {
        "id": identifier,
        "installed": bool(applied),
        "product_codes": applied,
        "skip": skip,
    }


def _select_provider(installer, path, identifier, provider):
    if provider != "auto":
        return provider
    if path:
        kind = installer.package_type(path)
        if kind != "msi" and ntpath.splitext(path)[1].lower() in (
            ".appx",
            ".appxbundle",
            ".msix",
            ".msixbundle",
        ):
            kind = "msix"
        return kind or "registry"
    if installer.product_state(identifier) == 5:
        return "msi"
    import legacy_windows_package_msix as msix  # pylint: disable=import-outside-toplevel,import-error

    if msix.available() and msix.installed_status(None, identifier)["installed"]:
        return "msix"
    if _patch_status(installer, None, identifier)["installed"]:
        return "msp"
    return "registry"


def installed_status(installer, options):
    """Select the local package provider and apply the source's ordered guards.

    :param WindowsInstaller installer: Open native metadata provider.
    :param dict options: Converted public package parameters.
    :returns: Provider, identifier, installed flag and provider operation data.
    :rtype: dict
    :raises OSError: Native package metadata is unreadable.
    :raises ValueError: Provider is not implemented or creates_version names a directory.
    """
    path, identifier = options["path"], options["product_id"]
    provider = _select_provider(installer, path, identifier, options["provider"])
    status = {"provider": provider, "registry": None}
    registry = None
    if provider == "msi":
        if path:
            identifier = installer.product_code(path)
        installed = installer.product_state(identifier) == 5
    elif provider == "registry":
        registry = _registry_location(identifier)
        installed = registry is not None
    elif provider == "msp":
        status.update(_patch_status(installer, path, identifier))
        identifier, installed = status["id"], status["installed"]
    elif provider == "msix":
        import legacy_windows_package_msix as msix  # pylint: disable=import-outside-toplevel,import-error

        status.update(msix.installed_status(path, identifier))
        identifier, installed = status["id"], status["installed"]
    else:
        raise ValueError(
            "The {0} package provider is not implemented in this increment.".format(
                provider
            )
        )
    if options["creates_path"]:
        installed = os.path.exists(options["creates_path"])
        if options["creates_version"] and installed:
            if not os.path.isfile(options["creates_path"]):
                raise ValueError(
                    "creates_path must be a file not a directory when creates_version is set"
                )
            installed = options["creates_version"] == _file_version(
                options["creates_path"]
            )
    if options["creates_service"]:
        installed = _service_exists(options["creates_service"])
    status.update(id=identifier, installed=installed, registry=registry)
    return status


def _system_read(path):
    if path.startswith("\\\\"):
        return
    try:
        target = acl.resolve_target(path, True)
        with acl.open_acl(target) as (snapshot, writer):
            rule = acl.make_rule(target, "S-1-5-18", "Read", "allow", "None")
            writer(acl.add_rule(snapshot, rule))
    except (OSError, ValueError):
        # Upstream treats unavailable/readonly ACLs as noncritical too: SYSTEM
        # may already have sufficient access through an inherited permission.
        pass


def _uninstall_command(location):
    values = location["values"]
    if "QuietUninstallString" in values:
        command = values["QuietUninstallString"]
    elif "UninstallString" in values:
        command = values["UninstallString"]
    else:
        raise ValueError(
            "Failed to find registry uninstall string at registry path '{0}'".format(
                location["path"]
            )
        )
    if command.startswith(("%", '"%')):
        command = expand_environment(command)
    if not command.startswith('"') and " " in command:
        command = _recover_uninstall_command(command)
    return command


def _recover_uninstall_command(command):
    # Keep this fixed Win32 parsing ABI local; uninstall recovery needs no
    # process-launching helper or new shared wrapper for these signatures.
    # pylint: disable=duplicate-code
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    parse = shell.CommandLineToArgvW
    parse.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
    parse.restype = ctypes.POINTER(ctypes.c_wchar_p)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    count = ctypes.c_int()
    # pylint: enable=duplicate-code
    parsed = parse(command, ctypes.byref(count))
    if not parsed:
        raise ctypes.WinError()
    try:
        arguments = [parsed[index] for index in range(count.value)]
    finally:
        kernel.LocalFree(parsed)
    # Registry strings can omit quotes around a spaced executable path. Find
    # the first existing literal file; do not invent an extension or use PATH.
    candidate = ""
    for index, argument in enumerate(arguments):
        candidate += argument
        if os.path.isfile(candidate):
            return " ".join(
                quote_argument(value) for value in [candidate] + arguments[index + 1 :]
            )
        candidate += " "
    return command


def _msi_log(path):
    with open(path, "rb") as stream:
        data = stream.read()
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = data.decode("utf-16", "replace")
    elif data.startswith(b"\xef\xbb\xbf"):
        text = data.decode("utf-8-sig", "replace")
    else:
        text = data.decode("mbcs", "replace")
    lines = re.split(r"\r\n|\r|\n", text)
    if lines and lines[-1] == "":
        lines.pop()
    return "".join(line + "\r\n" for line in lines)


def _run_installer(options, command, encoding, log_path, result):
    run = processes.run_command
    if options["wait_for_children"]:
        import legacy_windows_package_children as children  # pylint: disable=import-outside-toplevel,import-error

        run = children.run_command
    child = run(
        None,
        command,
        {
            "chdir": options["chdir"],
            "stdin": None,
            "output_encoding_override": encoding,
        },
    )
    if not child["changed"]:
        raise OSError(child["msg"])
    code = ctypes.c_int32(child["rc"]).value
    result["rc"] = code
    if code not in options["expected_return_code"]:
        result.update(
            failed=True,
            stdout=child["stdout"],
            stderr=child["stderr"],
            msg="unexpected rc from '{0}': see rc, stdout, and stderr for more details".format(
                command
            ),
        )
        if log_path and os.path.isfile(log_path):
            result["log"] = _msi_log(log_path)
        return False
    result["failed"] = False
    if code == 3010:
        result["reboot_required"] = True
    return True


@contextmanager
def _installer_source(options, status, result):
    path = options["path"]
    if options["state"] != "present":
        yield path
        return
    _system_read(path)
    if status["provider"] != "msp" or ";" not in path:
        yield path
        return
    # MsiApplyPatchW interprets semicolons as patch separators. The released
    # provider uses cmd's mklink to give this one source a separator-free name.
    link = os.path.join(
        tempfile.gettempdir(), "win_package-" + uuid.uuid4().hex + ".msp"
    )
    if os.path.lexists(link):
        raise OSError("Temporary patch link already exists: " + link)
    executable = os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")
    command = " ".join(
        quote_argument(value) for value in [executable, "/c", "mklink", link, path]
    )
    try:
        child = processes.run_command(
            None,
            command,
            {"chdir": None, "stdin": None, "output_encoding_override": "utf-8"},
        )
        if not child["changed"]:
            raise OSError(child["msg"])
        if child["rc"] != 0:
            result.update(
                failed=True,
                rc=child["rc"],
                stdout=child["stdout"],
                stderr=child["stderr"],
                msg=(
                    "Failed to create temporary symlink '{0}' -> '{1}' for msiexec "
                    "patch install as path contains semicolon"
                ).format(link, path),
            )
            yield None
        else:
            yield link
    finally:
        if os.path.lexists(link):
            os.remove(link)


def _invoke_msix(options, status, result):
    import legacy_windows_package_msix as msix  # pylint: disable=import-outside-toplevel,import-error

    try:
        with msix.PackageManager() as manager:
            if options["state"] == "present":
                manager.install(options["path"])
            else:
                manager.remove(status["id"])
    except msix.PackageApiError as error:
        operation = (
            "Add-AppxPackage" if options["state"] == "present" else "Remove-AppxPackage"
        )
        result.update(
            failed=True,
            rc=error.hresult,
            stdout="",
            stderr=str(error),
            msg="unexpected status from {0}: see rc and stderr for more details".format(
                operation
            ),
        )
        return False
    result["rc"] = 0
    return True


def _invoke(options, status, result, temporary):
    if status["provider"] == "msix":
        return _invoke_msix(options, status, result)
    windows_installer = status["provider"] in ("msi", "msp")
    arguments = installer_arguments(options["arguments"], windows_installer)
    if not windows_installer:
        command = (
            quote_argument(options["path"])
            if options["path"]
            else _uninstall_command(status["registry"])
        )
        if arguments:
            command += " " + arguments
        return _run_installer(options, command, "utf-8", None, result)
    log_path = options["log_path"] or os.path.join(temporary, "msiexec.log")
    executable = os.path.join(os.environ["SystemRoot"], "System32", "msiexec.exe")
    with _installer_source(options, status, result) as path:
        if options["state"] == "present":
            if path is None:
                return False
            actions = [["/i" if status["provider"] == "msi" else "/update", path]]
        elif status["provider"] == "msi":
            actions = [["/x", status["id"]]]
        else:
            actions = [
                ["/uninstall", status["id"], "/package", product]
                for product in status["product_codes"]
            ]
        for action in actions:
            command = " ".join(
                quote_argument(value)
                for value in [executable]
                + action
                + ["/L*V", log_path, "/qn", "/norestart"]
            )
            if arguments:
                command += " " + arguments
            if not _run_installer(options, command, "unicode", log_path, result):
                return False
    return True


@contextmanager
def _package_options(options, result):
    options = dict(options)
    path = options["path"]
    if not path or not path.lower().startswith("http"):
        yield options, None
        return
    if options["product_id"] and options["state"] == "present":
        options["path"] = None
        with WindowsInstaller() as installer:
            status = installed_status(installer, options)
        if status["installed"]:
            yield options, status
            return
    # Local providers do not load networking helpers or their native APIs.
    import legacy_windows_package_url as remote  # pylint: disable=import-outside-toplevel,import-error

    with tempfile.TemporaryDirectory(prefix="legacy-windows-package-url-") as directory:
        try:
            options["path"] = remote.acquire(path, options, result, directory)
        except remote.PackageDownloadError as error:
            raise _UnhandledPackageError(str(error)) from error
        yield options, None


def _manage_local(options, result, check_mode, status):
    path = options["path"]
    if path and not os.path.exists(path) and not check_mode:
        raise ValueError("the file at the path '{0}' cannot be reached".format(path))
    if status is None:
        with WindowsInstaller() as installer:
            status = installed_status(installer, options)
    changed = not status.get("skip", False) and (
        (options["state"] == "present") != status["installed"]
    )
    result["rc"] = 0
    if changed and not check_mode:
        if options["checksum_algorithm"] and options["state"] == "present" and path:
            digest = hashlib.new(options["checksum_algorithm"])
            with open(path, "rb") as stream:
                for block in iter(lambda: stream.read(65536), b""):
                    digest.update(block)
            result["checksum"] = digest.hexdigest().upper()
            if (
                options["checksum"]
                and options["checksum"].lower() != result["checksum"].lower()
            ):
                raise ValueError(
                    "The checksum for {0} did not match '{1}', it was '{2}'".format(
                        path, options["checksum"], result["checksum"]
                    )
                )
        if options["verify_signature"] and options["state"] == "present" and path:
            import legacy_windows_package_signature as signature  # pylint: disable=import-outside-toplevel,import-error

            signature.verify(path)
        with tempfile.TemporaryDirectory(prefix="legacy-windows-package-") as temporary:
            if not _invoke(options, status, result, temporary):
                return
    result["changed"] = changed


def manage(options, check_mode=False):
    """Perform the concrete MSI/MSP/registry package decision and operation.

    :param dict options: Validated public parameters.
    :param bool check_mode: Inspect and predict without executing an installer.
    :returns: Complete public package result, retaining fields on failure.
    :rtype: dict
    """
    result = {"changed": False, "reboot_required": False}
    try:
        with _package_options(options, result) as (local_options, status):
            _manage_local(local_options, result, check_mode, status)
        if (
            options["path"]
            and options["path"].lower().startswith("http")
            and options["state"] == "absent"
            and options["product_id"] is None
            and not result.get("failed")
        ):
            result["changed"] = False
            raise ValueError(
                "Unable to find Product ID from the URL path. Please specify "
                "product_id when using state=absent"
            )
    except _UnhandledPackageError as error:
        return {
            "changed": False,
            "failed": True,
            "msg": "Unhandled exception while executing module: " + str(error),
        }
    except (OSError, ValueError) as error:
        result.update(failed=True, msg=str(error))
    return result
