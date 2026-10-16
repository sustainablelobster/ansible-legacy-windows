# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Edit encoded text files while retaining their byte-order and newline policy."""

import codecs
import datetime
import os
import re
import shutil
import subprocess
import tempfile

from legacy_windows_text import decode_bytes  # pylint: disable=import-error

_PREAMBLES = (
    (codecs.BOM_UTF32_LE, "utf-32-le", "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32-be", "utf-32BE"),
    (codecs.BOM_UTF8, "utf-8", "utf-8"),
    (codecs.BOM_UTF16_LE, "utf-16-le", "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16-be", "utf-16BE"),
)


def _encoding(name, data):
    if name == "auto":
        for marker, codec, web_name in _PREAMBLES:
            if data.startswith(marker):
                return codec, marker, web_name
        return "utf-8", b"", "utf-8"
    selected = name.lower().replace("_", "-")
    selected = {
        "unicode": "utf-16-le",
        "unicodefffe": "utf-16-be",
        "utf-16": "utf-16-le",
        "utf-32": "utf-32-le",
        "utf-16be": "utf-16-be",
        "utf-32be": "utf-32-be",
    }.get(selected, selected)
    if selected.isdigit():
        selected = "cp" + selected
    try:
        codec = codecs.lookup(selected).name
    except LookupError as error:
        raise ValueError("Unknown text encoding: " + name) from error
    for marker, candidate, web_name in _PREAMBLES:
        if candidate == codec or (codec == "utf-8-sig" and candidate == "utf-8"):
            return candidate, marker, web_name
    return codec, b"", "windows-1252" if codec == "cp1252" else codec


def _compile(pattern):
    if not pattern:
        return None
    # These common .NET spellings map directly to standard-library re groups.
    translated = re.sub(r"\(\?<([A-Za-z_][A-Za-z_0-9]*)>", r"(?P<\1>", pattern)
    translated = re.sub(r"\\k<([A-Za-z_][A-Za-z_0-9]*)>", r"(?P=\1)", translated)
    try:
        return re.compile(translated)
    except re.error as error:
        raise ValueError(
            "Invalid or unsupported regular expression: " + str(error)
        ) from error


def _replacement(match, replacement, original):
    def _token(found):
        value = found.group(1)
        special = {
            "$": "$",
            "&": match.group(0),
            "`": original[: match.start()],
            "'": original[match.end() :],
            "_": original,
        }
        if value in special:
            return special[value]
        if value == "+":
            return next(
                (group for group in reversed(match.groups()) if group is not None), ""
            )
        name = value[1:-1] if value.startswith("{") else value
        if name.isdigit():
            name = int(name)
        try:
            return match.group(name) or ""
        except (IndexError, KeyError):
            return found.group(0)

    return re.sub(r"\$(\$|&|`|'|\+|_|\{[^}]+\}|[0-9]+)", _token, replacement)


def _present(lines, options):
    expression = _compile(options["regex"])
    before = options["insertbefore"]
    after = None if before else options["insertafter"]
    insertion = None
    if after and after not in ("BOF", "EOF"):
        insertion = _compile(after)
    elif before and before != "BOF":
        insertion = _compile(before)
    matched, location = -1, -1
    for index, current in enumerate(lines):
        if expression.search(current) if expression else current == options["line"]:
            matched = index
        elif insertion and insertion.search(current):
            location = index if before else index + 1
    if matched != -1:
        original = lines[matched]
        replacement = options["line"]
        if options["backrefs"]:
            replacement = expression.sub(
                lambda match: _replacement(match, options["line"], original), original
            )
        if original != replacement:
            lines[matched] = replacement
            return True, "line replaced"
        return False, ""
    if options["backrefs"]:
        return False, ""
    if before == "BOF" or after == "BOF":
        location = 0
    elif after == "EOF" or location == -1:
        location = len(lines)
    lines.insert(location, options["line"])
    return True, "line added"


def _validate(path, command):
    if not command:
        return
    if "%s" not in command:
        raise ValueError("validate must contain %s: " + command)
    command = command.replace("%s", path)
    # Windows parses this command line directly; no shell expansion is enabled.
    with subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ) as process:
        output, errors = process.communicate()
    if process.returncode:
        raise ValueError(
            "failed to validate {0} (exit {1}): {2} {3}".format(
                command,
                process.returncode,
                output.decode("utf-8", "replace"),
                errors.decode("utf-8", "replace"),
            )
        )


def _write(path, data, options, check_mode, result):
    descriptor, temporary = tempfile.mkstemp(prefix="legacy-lineinfile-", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        _validate(temporary, options["validate"])
        if check_mode:
            return
        if options["backup"] and os.path.exists(path):
            backup = "{0}.{1}.{2}.bak".format(
                path, os.getpid(), datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            )
            shutil.copyfile(path, backup)
            result["backup_file"] = backup
        # Copying retains the existing destination's permissions and file identity.
        shutil.copyfile(temporary, path)
    finally:
        os.unlink(temporary)


def _read_lines(path, encoding):
    data = b""
    if os.path.exists(path):
        with open(path, "rb") as source:
            data = source.read()
    codec, marker, web_name = _encoding(encoding, data)
    text = decode_bytes(data, codec)
    # StreamReader.ReadLine recognizes CR, LF and CRLF, not Unicode separators.
    lines = re.split(r"\r\n|\r|\n", text) if text else []
    terminal_newline = text.endswith(("\r", "\n"))
    if terminal_newline:
        lines.pop()
    return lines, terminal_newline, codec, marker, web_name


def manage(options, check_mode=False, diff_mode=False):
    """Apply a validated line request and preserve the selected text encoding.

    :param dict options: Normalized public module arguments.
    :param bool check_mode: Predict changes without modifying the destination.
    :param bool diff_mode: Include normalized before/after text when changed.
    :returns: Ansible change, encoding, backup, and removal information.
    :rtype: dict
    :raises OSError: Reading, validating, backing up, or writing a file fails.
    :raises ValueError: A selector, regular expression, or encoding is invalid.
    """
    path = options["path"]
    if os.path.isdir(path):
        raise ValueError("Path {0} is a directory".format(path))
    if not os.path.exists(path) and (
        options["state"] == "absent" or not options["create"]
    ):
        raise ValueError("Path {0} does not exist !".format(path))
    lines, terminal_newline, codec, marker, web_name = _read_lines(
        path, options["encoding"]
    )
    separator = "\n" if options["newline"] == "unix" else "\r\n"
    result = {"backup": "", "changed": False, "msg": "", "encoding": web_name}
    if diff_mode:
        result["diff"] = {
            "before": separator.join(lines + ([""] if terminal_newline else []))
        }
    if options["state"] == "present":
        if options["insertbefore"] and options["insertafter"]:
            result["warnings"] = [
                "Both insertbefore and insertafter parameters found, ignoring "
                '"insertafter={0}"'.format(options["insertafter"])
            ]
        result["changed"], result["msg"] = _present(lines, options)
        if terminal_newline:
            lines.append("")
    else:
        if terminal_newline:
            lines.append("")
        expression = _compile(options["regex"])
        remaining = [
            line
            for line in lines
            if not (expression.search(line) if expression else line == options["line"])
        ]
        result["found"] = len(lines) - len(remaining)
        result["changed"] = bool(result["found"])
        result["msg"] = "{0} line(s) removed".format(result["found"])
        lines = remaining
    if result["changed"]:
        after = separator.join(lines)
        encoded = marker + after.encode(codec, "replace")
        _write(path, encoded, options, check_mode, result)
        if diff_mode:
            result["diff"]["after"] = after
    return result
