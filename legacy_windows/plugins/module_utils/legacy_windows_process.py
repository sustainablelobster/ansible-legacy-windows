# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Launch Windows child processes and preserve their Ansible result fields."""

import codecs
import ctypes
import datetime
import ntpath
import os
import subprocess

# The action plugin stages target helpers beside this module.
import legacy_windows_text as text_codec  # pylint: disable=import-error


def resolve_executable(value, working_directory):
    """Resolve an executable through PATH before the requested working directory.

    :param value: Executable name or path, with an optional filename extension.
    :type value: str
    :param working_directory: Child working directory, or None.
    :type working_directory: str or None
    :returns: An existing absolute path or the unresolved name with its extension.
    :rtype: str
    :raises ValueError: If the executable is None.
    """
    if value is None:
        raise ValueError("The executable must not be null.")
    filename = ntpath.basename(value)
    if "." not in filename or filename.endswith("."):
        value += ".exe"
    if ntpath.dirname(value):
        candidates = [value]
    else:
        candidates = [os.path.join(folder, value) for folder in os.get_exec_path()]
    if working_directory:
        candidates.append(os.path.join(working_directory, value))
    for candidate in candidates:
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)
    return value


def _path_exists(path):
    try:
        os.stat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    return True


def skip_message(parameters):
    """Evaluate literal creates and removes guards, in that order.

    :param parameters: Converted creates and removes path arguments.
    :type parameters: dict
    :returns: The skip reason, or None when execution should continue.
    :rtype: str or None
    :raises OSError: If a filesystem guard cannot be checked.
    """
    creates = parameters["creates"]
    removes = parameters["removes"]
    if creates and _path_exists(creates):
        return "skipped, since " + creates + " exists"
    if removes and not _path_exists(removes):
        return "skipped, since " + removes + " does not exist"
    return None


def _application_from_command(command_line):
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    parse = shell.CommandLineToArgvW
    parse.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
    parse.restype = ctypes.POINTER(ctypes.c_wchar_p)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    count = ctypes.c_int()
    arguments = parse(command_line, ctypes.byref(count))
    if not arguments:
        raise ctypes.WinError()
    try:
        return arguments[0]
    finally:
        kernel.LocalFree(arguments)


def _start_process(executable, command_line, working_directory):
    if not command_line:
        raise ValueError("The command line is empty.")
    if os.name != "nt":
        raise ValueError("Process execution requires a Windows target.")
    if executable is None:
        executable = _application_from_command(command_line)
    executable = resolve_executable(executable, working_directory)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetConsoleWindow.restype = ctypes.c_void_p
    allocated_console = False
    if not kernel.GetConsoleWindow():
        allocated_console = bool(kernel.AllocConsole())
    # Upstream's PowerShell wrapper initializes existing consoles to UTF-8 too.
    # Python-over-CMD has no such wrapper, so initialize both launch paths here.
    kernel.SetConsoleCP(65001)
    kernel.SetConsoleOutputCP(65001)
    try:
        return subprocess.Popen(
            command_line,
            executable=executable,
            cwd=working_directory or None,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    finally:
        if allocated_console:
            kernel.FreeConsole()


def _output_encoding(name):
    name = name or "utf-8"
    try:
        if name.lower() in ("utf8", "cp65001"):
            raise LookupError("Use the Windows encoding name utf-8.")
        lookup_name = "utf-16-le" if name.lower() == "unicode" else name
        encoding = codecs.lookup(lookup_name).name
        if encoding == "shift_jis":
            encoding = "cp932"
        if encoding in (
            "punycode",
            "unicode-escape",
            "raw-unicode-escape",
            "unicode-internal",
        ):
            raise LookupError("Python text transforms are not Windows encodings.")
        # A nonempty bytes.decode probe rejects binary transforms and tests the
        # replacement policy; an empty input can bypass codec lookup entirely.
        b"\0".decode(encoding, "replace")
    except (LookupError, TypeError, UnicodeError) as error:
        raise ValueError("Unsupported output_encoding_override: " + name) from error
    return encoding


def _stdin_bytes(text):
    if not text:
        return None
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        # .NET's UTF-8 encoder replaces unpaired UTF-16 surrogates with U+FFFD.
        normalized = text.encode("utf-16-le", "surrogatepass").decode(
            "utf-16-le", "replace"
        )
        return normalized.encode("utf-8")


# Keep the existing command/result inputs explicit beside the opt-in pipe lifetime.
def _complete_process(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    process, stdin, encoding, command_line, started, keep_stdin_open=False
):
    # PsExec stops forwarding child output when its input pipe reaches EOF.
    # Only that caller retains an extra writer while communicate closes its own.
    retained_stdin = os.dup(process.stdin.fileno()) if keep_stdin_open else None
    try:
        stdout, stderr = process.communicate(stdin)
    finally:
        if retained_stdin is not None:
            os.close(retained_stdin)
    ended = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    elapsed = ended - started
    result = {
        "changed": True,
        "cmd": command_line,
        "rc": process.returncode,
        "stdout": text_codec.decode_bytes(stdout, encoding),
        "stderr": text_codec.decode_bytes(stderr, encoding),
        "start": started.strftime("%Y-%m-%d %H:%M:%S.%f"),
        "end": ended.strftime("%Y-%m-%d %H:%M:%S.%f"),
        "delta": "{0}:{1:02}:{2:02}.{3:06}".format(
            elapsed.seconds // 3600,
            (elapsed.seconds // 60) % 60,
            elapsed.seconds % 60,
            elapsed.microseconds,
        ),
    }
    if process.returncode != 0:
        result.update(failed=True, msg="non-zero return code")
    return result


def run_command(executable, command_line, parameters):
    """Run a child after validating its output encoding and standard input.

    :param executable: Explicit executable path, or None to parse the command.
    :type executable: str or None
    :param command_line: Complete Windows command line.
    :type command_line: str
    :param parameters: Converted chdir, stdin, and output_encoding_override values;
        optional internal keep_stdin_open retains a writer until the child exits.
    :type parameters: dict
    :returns: An Ansible result with streams and timings, or a launch failure.
    :rtype: dict
    :raises OSError: If communication with an already started child fails.
    """
    started = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    try:
        encoding = _output_encoding(parameters["output_encoding_override"])
        stdin = _stdin_bytes(parameters["stdin"])
        process = _start_process(executable, command_line, parameters["chdir"])
    except (OSError, ValueError) as error:
        return {
            "changed": False,
            "failed": True,
            "cmd": command_line,
            "rc": getattr(error, "winerror", None) or 2,
            "msg": "Failed to run: '{0}': {1}".format(command_line, error),
        }
    return _complete_process(
        process,
        stdin,
        encoding,
        command_line,
        started,
        keep_stdin_open=parameters.get("keep_stdin_open", False),
    )
