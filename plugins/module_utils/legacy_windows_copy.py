# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Execute the win_copy transfer protocol using native Windows filesystem calls."""

import base64
import ctypes
import datetime
import ntpath
import os
import shutil
import zipfile

import legacy_windows_calendar as calendar  # pylint: disable=import-error
import legacy_windows_file as filesystem  # pylint: disable=import-error
import legacy_windows_stat as metadata  # pylint: disable=import-error
import legacy_windows_time as native_time  # pylint: disable=import-error


def copy_file(source, destination, overwrite=True, force=False):
    """Copy a file and its Windows metadata without interpreting its contents.

    :param source: Literal source filename.
    :type source: str
    :param destination: Literal destination filename, with an existing parent.
    :type destination: str
    :param overwrite: Whether an existing destination may be replaced.
    :type overwrite: bool
    :param force: Whether to clear blocking destination attributes first.
    :type force: bool
    :raises ValueError: If the target is not Windows.
    :raises OSError: If Windows cannot copy the file or restore its attributes.
    """
    if os.name != "nt":
        raise ValueError("File copying requires a Windows target.")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CopyFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int]
    kernel.CopyFileW.restype = ctypes.c_int
    previous = filesystem.file_info(destination) if force else None
    if previous and previous["attributes"] & 7:
        filesystem.set_attributes(destination, previous["attributes"] & ~7)
    if not kernel.CopyFileW(source, destination, not overwrite):
        error = ctypes.WinError(ctypes.get_last_error())
        if previous and previous["attributes"] & 7:
            try:
                filesystem.set_attributes(destination, previous["attributes"])
            except OSError as restoration_error:
                raise OSError(
                    "{0}; could not restore destination attributes: {1}".format(
                        error, restoration_error
                    )
                ) from restoration_error
        raise error


def _kind(path):
    info = metadata.file_info(path)
    return None if info is None else "directory" if info["attributes"] & 16 else "file"


def _join(parent, child):
    return os.path.normpath(os.path.join(parent, child.lstrip("\\/")))


def _children(path):
    entries = metadata.directory_entries(path)
    # The filesystem provider visits directories first, preserving native order
    # within each group; this also controls the observable prepared diff.
    return [entry for entry in entries if entry["attributes"] & 16] + [
        entry for entry in entries if not entry["attributes"] & 16
    ]


def _size(path):
    info = metadata.file_info(path)
    if info is None:
        # The original size lookup terminates outside its partial copy result.
        # Let the shared unexpected-error boundary discard those fields too.
        raise RuntimeError(
            "Cannot find path '{0}' because it does not exist.".format(path)
        )
    if not info["attributes"] & 16:
        return info["size"]
    total = 0
    pending = [path]
    while pending:
        directory = pending.pop()
        try:
            entries = metadata.directory_entries(directory)
        except OSError:
            continue
        for entry in entries:
            if entry["attributes"] & 0x400:
                continue
            if entry["attributes"] & 16:
                pending.append(_join(directory, entry["name"]))
            else:
                total += entry["size"]
    return total


def _backup_name(path):
    now = datetime.datetime.now()
    year, month, day, _era = calendar.calendar_fields(
        calendar.get_culture(), now.date()
    )
    return "{0}.{1}.{2:04d}{3:02d}{4:02d}-{5:02d}{6:02d}{7:02d}.bak".format(
        path, os.getpid(), year, month, day, now.hour, now.minute, now.second
    )


def _archive_entry(name):
    remainder = len(name) % 4
    is_directory = remainder == 1 and name.endswith(("/", "\\"))
    if remainder and not is_directory:
        raise ValueError("invalid base64 archive name '{0}'".format(name))
    encoded = name[:-1] if is_directory else name
    relative = base64.b64decode(encoded.encode("ascii"), validate=True).decode("utf-8")
    parts = relative.replace("\\", "/").split("/")
    # These are internal controller-generated names, never an invitation to
    # extract absolute paths, parent traversal, or NTFS alternate data streams.
    invalid_component = any(
        part in ("", ".", "..") or part.endswith((" ", ".")) for part in parts
    )
    if (
        not relative
        or ntpath.isabs(relative)
        or ntpath.splitdrive(relative)[0]
        or invalid_component
        or any(character in relative for character in ':\x00<>"|?*')
    ):
        raise ValueError("Unsafe copy archive path: {0!r}".format(relative))
    return parts, is_directory


def _archive_target(destination, parts):
    target = destination
    for part in [None] + parts:
        if part is not None:
            target = _join(target, part)
        info = metadata.file_info(target)
        if info and info["attributes"] & 0x400:
            raise ValueError(
                "Copy archive destination contains a reparse point: " + target
            )
    return target


# The four internal protocol modes share one result and mutation policy; only
# execute_copy is public so callers cannot reuse partially completed state.
class _CopyOperation:  # pylint: disable=too-few-public-methods
    """Keep one operation's partial result and check-mode policy together."""

    def __init__(self, parameters, check_mode, diff_mode):
        self.parameters = parameters
        self.check_mode = check_mode
        self.result = {"changed": False}
        if diff_mode:
            self.result["diff"] = {}

    def _backup(self, destination):
        if not self.parameters["backup"]:
            return
        path = None
        if _kind(destination) == "file":
            path = _backup_name(destination)
            if not self.check_mode:
                try:
                    copy_file(destination, path)
                except OSError as error:
                    raise ValueError(
                        "Failed to create backup file '{0}' from '{1}'. ({2})".format(
                            path, destination, error
                        )
                    ) from error
        self.result["backup_file"] = path

    def _file(self, source, destination):
        checksum = (
            metadata.checksum(source, "sha1") if self.parameters["force"] else None
        )
        kind = _kind(destination)
        if kind == "directory":
            raise ValueError(
                "cannot copy file from '{0}' to '{1}': dest is already a folder".format(
                    source, destination
                )
            )
        if kind == "file" and (
            not self.parameters["force"]
            or metadata.checksum(destination, "sha1") == checksum
        ):
            return "", checksum
        parent = os.path.dirname(destination)
        parent_kind = _kind(parent)
        if parent_kind == "file":
            raise ValueError(
                "cannot copy file from '{0}' to '{1}': "
                "object at dest parent dir is not a folder".format(source, destination)
            )
        diff = ""
        if parent_kind is None:
            if not self.check_mode:
                os.makedirs(parent)
            diff += "+{0}\\\n".format(parent)
        self._backup(destination)
        if kind == "file":
            if not self.check_mode:
                filesystem.remove_path(destination)
            diff += "-{0}\n".format(destination)
        if not self.check_mode:
            copy_file(source, destination, force=True)
        self.result["changed"] = True
        return diff + "+{0}\n".format(destination), checksum

    def _folder(self, source, destination):
        diff = ""
        if _kind(destination) != "directory":
            if _kind(os.path.dirname(destination)) == "file":
                raise ValueError(
                    "cannot copy file from '{0}' to '{1}': "
                    "object at dest parent dir is not a folder".format(
                        source, destination
                    )
                )
            if _kind(destination) == "file":
                raise ValueError(
                    "cannot copy folder from '{0}' to '{1}': dest is already a file".format(
                        source, destination
                    )
                )
            if not self.check_mode:
                os.makedirs(destination)
            self.result["changed"] = True
            diff += "+{0}\\\n".format(destination)
        return diff + self._contents(source, destination)

    def _contents(self, source, destination):
        diff = ""
        for entry in _children(source):
            child_source = _join(source, entry["name"])
            child_destination = _join(destination, entry["name"])
            if entry["attributes"] & 16:
                diff += self._folder(child_source, child_destination)
            else:
                diff += self._file(child_source, child_destination)[0]
        return diff

    def _query(self):
        """Return the manifest entries whose target data needs updating."""
        files, directories = [], []
        destination = self.parameters["dest"]
        for entry in self.parameters["files"]:
            target = _join(destination, entry["dest"])
            if _kind(target) == "directory":
                target = _join(target, ntpath.basename(entry["src"]))
            kind = _kind(target)
            if kind == "directory":
                raise ValueError(
                    "cannot copy file to dest '{0}': "
                    "object at path is already a directory".format(target)
                )
            if kind is None or (
                self.parameters["force"]
                and metadata.checksum(target, "sha1") != entry.get("checksum")
            ):
                files.append(entry)
        for entry in self.parameters["directories"]:
            target = _join(destination, entry["dest"])
            if _kind(os.path.dirname(target)) == "file":
                raise ValueError(
                    "cannot copy folder to dest '{0}': "
                    "object at parent directory path is already a file".format(target)
                )
            kind = _kind(target)
            if kind == "file":
                raise ValueError(
                    "cannot copy folder to dest '{0}': "
                    "object at path is already a file".format(target)
                )
            if kind is None:
                directories.append(entry)
        self.result.update(files=files, directories=directories, symlinks=[])

    def _explode(self):
        """Extract the controller's encoded archive without following target links."""
        source, destination = self.parameters["src"], self.parameters["dest"]
        if _kind(source) != "file":
            raise ValueError(
                "Cannot expand src zip file: '{0}' as it does not exist".format(source)
            )
        with zipfile.ZipFile(source) as archive:
            for entry in archive.infolist():
                parts, is_directory = _archive_entry(entry.filename)
                target = _archive_target(destination, parts)
                parent = target if is_directory else os.path.dirname(target)
                if not self.check_mode:
                    if _kind(parent) is None:
                        os.makedirs(parent)
                    if not is_directory:
                        with archive.open(entry) as contents, open(
                            target, "wb"
                        ) as output:
                            shutil.copyfileobj(contents, output)
                        modified = datetime.datetime(*entry.date_time)
                        local_ticks = (
                            (modified.toordinal() - 1) * 86400
                            + modified.hour * 3600
                            + modified.minute * 60
                            + modified.second
                        ) * 10000000
                        filesystem.set_file_time(
                            target,
                            False,
                            "modification_time",
                            native_time.local_ticks_to_file_time(local_ticks),
                        )
        self.result["changed"] = True

    def _file_destination(self, basename):
        destination = self.parameters["dest"]
        target = destination
        if destination.endswith(("/", "\\")) or _kind(destination) == "directory":
            target = _join(destination, basename or "")
        if self.parameters["_copy_mode"] == "remote":
            self.result["dest"] = target
        parent = os.path.dirname(target) or os.getcwd()
        if _kind(parent) == "file":
            raise ValueError(
                "object at destination parent dir '{0}' is currently a file".format(
                    parent
                )
            )
        if _kind(parent) != "directory":
            if destination.lower() == target.lower():
                raise ValueError(
                    "Destination directory '{0}' does not exist".format(parent)
                )
            # The original creates this parent even in remote check mode.
            os.makedirs(parent)
        return target

    def _single(self):
        """Install one staged file after the controller has decided it changed."""
        source = self.parameters["src"]
        if _kind(source) != "file":
            raise ValueError(
                "Cannot copy src file: '{0}' as it does not exist".format(source)
            )
        target = self._file_destination(self.parameters["_original_basename"])
        self._backup(target)
        copy_file(source, target, force=True)
        self.result["changed"] = True

    def _remote(self):
        """Copy a target-local file or tree and return its observable metadata."""
        source, destination = self.parameters["src"], self.parameters["dest"]
        self.result.update(src=source, dest=destination)
        kind = _kind(source)
        if kind is None:
            raise ValueError(
                "Cannot copy src file: '{0}' as it does not exist".format(source)
            )
        target = destination
        if kind == "directory":
            self.result["operation"] = "folder_copy"
            if source.endswith(("/", "\\")):
                diff = self._contents(source, target)
            else:
                target = _join(destination, os.path.basename(os.path.abspath(source)))
                self.result["dest"] = target
                diff = self._folder(source, target)
        else:
            basename = os.path.basename(source)
            self.result.update(operation="file_copy", original_basename=basename)
            target = self._file_destination(basename)
            self.result["dest"] = target
            if not os.path.dirname(target):
                target = os.path.join(os.getcwd(), target)
            diff, self.result["checksum"] = self._file(source, target)
        self.result["size"] = (
            _size(target) if not self.check_mode or _kind(target) == "file" else None
        )
        if "diff" in self.result:
            self.result["diff"]["prepared"] = diff


def execute_copy(parameters, check_mode=False, diff_mode=False):
    """Execute one validated copy protocol request, preserving partial results.

    :param parameters: Validated module parameters, including the copy mode.
    :type parameters: dict
    :param check_mode: Whether remote operations should predict file changes.
    :type check_mode: bool
    :param diff_mode: Whether to include the prepared remote change description.
    :type diff_mode: bool
    :returns: Ansible result fields, including failure information when needed.
    :rtype: dict
    """
    operation = _CopyOperation(parameters, check_mode, diff_mode)
    try:
        getattr(operation, "_" + parameters["_copy_mode"])()
    except (OSError, ValueError, zipfile.BadZipFile, NotImplementedError) as error:
        operation.result.update(failed=True, msg=str(error))
    return operation.result
