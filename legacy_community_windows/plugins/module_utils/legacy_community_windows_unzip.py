# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Extract standard archive formats without a modern target dependency."""

import base64
import bz2
import gzip
import ntpath
import os
import shutil
import subprocess
import tarfile
import zipfile

from legacy_windows_file import file_info  # pylint: disable=import-error

_RECURSIVE_EXTENSIONS = (".zip", ".gz", ".bz2", ".tar", ".msu")


def _check_existing_path(path):
    current = os.path.abspath(path)
    while True:
        if os.name == "nt":
            information = file_info(current)
            linked = information is not None and information["attributes"] & 0x400
        else:
            linked = os.path.islink(current)
        if linked:
            raise ValueError(
                "Archive extraction cannot traverse a link or reparse point: " + current
            )
        parent = os.path.dirname(current)
        if parent == current:
            return
        current = parent


def _target(destination, name):
    normalized = ntpath.normpath(name.replace("/", "\\"))
    if ntpath.splitdrive(normalized)[0] or normalized.startswith("\\"):
        raise ValueError(
            "Archive member would extract outside the destination: " + name
        )
    parts = normalized.split("\\")
    if parts[0] == ".." or any(":" in part for part in parts):
        raise ValueError(
            "Archive member would extract outside the destination: " + name
        )
    reserved = {"CON", "PRN", "AUX", "NUL"}
    reserved.update(
        prefix + str(index) for prefix in ("COM", "LPT") for index in range(1, 10)
    )
    if any(
        part not in ("", ".")
        and (
            part.rstrip(" .") != part
            or part.split(".", 1)[0].upper() in reserved
            or any(ord(character) < 32 or character in '<>"|?*' for character in part)
        )
        for part in parts
    ):
        raise ValueError("Archive member is not a safe Windows file name: " + name)
    path = os.path.join(destination, *(part for part in parts if part not in ("", ".")))
    _check_existing_path(path)
    return path


def _copy_stream(source, destination):
    parent = os.path.dirname(destination)
    if not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(destination, "wb") as output:
        shutil.copyfileobj(source, output)


def _zip(source, destination, password, check_mode):
    with zipfile.ZipFile(source) as archive:
        entries = []
        for member in archive.infolist():
            name = member.filename
            if not member.flag_bits & 0x800:
                name = name.encode("cp437").decode("utf-8", "replace")
            entries.append(
                (member, _target(destination, name), name.endswith(("/", "\\")))
            )
        if not check_mode:
            os.makedirs(destination, exist_ok=True)
            for member, path, directory in entries:
                if directory:
                    os.makedirs(path, exist_ok=True)
                else:
                    with archive.open(
                        member, pwd=password.encode("utf-8") if password else None
                    ) as stream:
                        _copy_stream(stream, path)
        return bool(entries)


def _tar(source, destination, check_mode):
    with tarfile.open(source, "r:*") as archive:
        entries = []
        for member in archive.getmembers():
            if not member.isfile() and not member.isdir():
                raise ValueError(
                    "Archive links and special files are not supported: " + member.name
                )
            entries.append((member, _target(destination, member.name)))
        if not check_mode:
            os.makedirs(destination, exist_ok=True)
            for member, path in entries:
                if member.isdir():
                    os.makedirs(path, exist_ok=True)
                else:
                    with archive.extractfile(member) as stream:
                        _copy_stream(stream, path)
        return True


def _single(source, destination, extension, check_mode):
    name = os.path.basename(source)[: -len(extension)]
    path = _target(destination, name)
    if not check_mode:
        opener = gzip.open if extension == ".gz" else bz2.open
        with opener(source, "rb") as stream:
            _copy_stream(stream, path)
    return True


def _expand_cabinet(source, destination, check_mode):
    directory = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    cabinet_extractor = os.path.join(directory, "extrac32.exe")
    if os.path.isfile(cabinet_extractor):
        # XP's expand.exe ignores -F and can rename a member to the CAB name.
        # The installed cabinet extractor preserves all members' original names.
        command = [cabinet_extractor, "/Y", "/E", "/L", destination, source]
    else:
        executable = os.path.join(directory, "expand.exe")
        if not os.path.isfile(executable):
            raise ValueError(
                "Windows extrac32.exe or expand.exe is required to extract CAB/MSU archives."
            )
        command = [executable, source, "-F:*", destination]
    if not check_mode:
        os.makedirs(destination, exist_ok=True)
        # Retain the installed extractor's pipes and exit status here; these
        # standard subprocess arguments do not warrant a shared process layer.
        # pylint: disable=duplicate-code
        with subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as process:
            output, errors = process.communicate()
        if process.returncode:
            # pylint: enable=duplicate-code
            raise ValueError(
                "CAB/MSU extraction failed (exit {0}): {1} {2}".format(
                    process.returncode,
                    output.decode("utf-8", "replace"),
                    errors.decode("utf-8", "replace"),
                )
            )
    return True


def _pscx(source, destination, password, check_mode):
    executable = shutil.which("powershell.exe")
    if executable is None:
        raise ValueError(
            "This archive format requires the installed "
            "PowerShell Community Extensions (PSCX) engine."
        )

    def _literal(value):
        return "'" + value.replace("'", "''") + "'"

    command = "Expand-Archive -LiteralPath {0} -OutputPath {1} -Force".format(
        _literal(source), _literal(destination)
    )
    if password is not None:
        command += " -Password (ConvertTo-SecureString {0} -AsPlainText -Force)".format(
            _literal(password)
        )
    if check_mode:
        command += " -WhatIf"
    script = (
        "$ErrorActionPreference='Stop'; try { Import-Module PSCX -ErrorAction Stop; "
        + command
        + "; exit 0 } catch { [Console]::Error.Write($_.Exception.Message); exit 1 }"
    )
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    # Keep this vendor command and its captured streams together; identical
    # PowerShell switches elsewhere do not justify another execution wrapper.
    # pylint: disable=duplicate-code
    with subprocess.Popen(
        [
            executable,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            encoded,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        _output, errors = process.communicate()
    # pylint: enable=duplicate-code
    if process.returncode:
        raise ValueError(
            "PSCX archive extraction failed (exit {0}): {1}".format(
                process.returncode, errors.decode("utf-8", "replace")
            )
        )
    return True


def _extract(source, destination, password, check_mode):
    name = source.lower()
    if name.endswith(".zip"):
        try:
            return _zip(source, destination, password, check_mode), False
        except NotImplementedError:
            # AES and unsupported ZIP compression remain the installed vendor
            # engine's responsibility; ordinary ZIP/ZipCrypto use stdlib only.
            return _pscx(source, destination, password, check_mode), True
    if (
        name.endswith(
            (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")
        )
        and not password
    ):
        return _tar(source, destination, check_mode), False
    if name.endswith((".gz", ".bz2")) and not password:
        return (
            _single(
                source,
                destination,
                ".gz" if name.endswith(".gz") else ".bz2",
                check_mode,
            ),
            False,
        )
    if name.endswith((".cab", ".msu")) and not password:
        return _expand_cabinet(source, destination, check_mode), False
    return _pscx(source, destination, password, check_mode), True


def extract(options, check_mode=False):
    """Extract an archive and apply the public creates/recurse/delete guards.

    :param dict options: Normalized module arguments.
    :param bool check_mode: Predict extraction and deletion without mutations.
    :returns: Upstream-compatible source, destination, removed and skip fields.
    :rtype: dict
    :raises OSError: An archive or output file cannot be read or written.
    :raises ValueError: A member path escapes, a link is selected, or an engine fails.
    """
    source, destination = options["src"], options["dest"]
    result = {
        "changed": False,
        "src": source.rstrip("\\"),
        "dest": destination.rstrip("\\"),
        "removed": False,
    }
    if options["creates"] and os.path.exists(options["creates"]):
        result["skipped"] = True
        result["msg"] = "The file or directory '{0}' already exists.".format(
            options["creates"]
        )
        return result
    if not os.path.isfile(source):
        raise ValueError("File '{0}' does not exist.".format(source))
    _check_existing_path(destination)
    changed, pscx = _extract(source, destination, options["password"], check_mode)
    result["changed"] = changed
    if options["recurse"] and not check_mode:
        visited = {os.path.normcase(os.path.abspath(source))}
        while True:
            archives = sorted(
                os.path.join(directory, filename)
                for directory, _directories, files in os.walk(destination)
                for filename in files
                if filename.lower().endswith(_RECURSIVE_EXTENSIONS)
                and os.path.normcase(os.path.abspath(os.path.join(directory, filename)))
                not in visited
            )
            if not archives:
                break
            for archive in archives:
                visited.add(os.path.normcase(os.path.abspath(archive)))
                nested_changed, nested_pscx = _extract(
                    archive, destination, options["password"], False
                )
                result["changed"] = nested_changed or result["changed"]
                pscx = nested_pscx or pscx
                if options["delete_archive"]:
                    os.unlink(archive)
                    result["removed"] = True
    if pscx:
        result["pscx_status"] = "present"
    if options["delete_archive"]:
        if not check_mode:
            os.unlink(source)
        result["removed"] = True
    return result
