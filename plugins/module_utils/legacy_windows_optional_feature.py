# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read and change online optional features with the shipped native DISM tool."""

import os
import re
import subprocess
import tempfile

_UNSUPPORTED = (
    "This version of Windows does not support the Enable-WindowsOptionalFeature."
)
_UNKNOWN_FEATURE = 0x800F080C


def _executable():
    root = os.environ["SystemRoot"]
    # A 32-bit Python process must launch native DISM for a 64-bit online image.
    native = os.path.join(root, "Sysnative", "dism.exe")
    if os.path.isfile(native):
        return native
    native = os.path.join(root, "System32", "dism.exe")
    if not os.path.isfile(native):
        raise OSError(_UNSUPPORTED)
    return native


def _decode(output):
    return output.decode("mbcs", errors="replace").strip()


class OptionalFeatures:
    """Own a temporary DISM log and scratch directory for online feature calls."""

    def __init__(self):
        self._tool = _executable()
        self._temporary = None
        self._workspace = None
        self._names = {}
        self._enable_help = None

    def __enter__(self):
        self._temporary = tempfile.TemporaryDirectory(
            prefix="legacy-windows-optional-feature-"
        )
        self._workspace = self._temporary.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return self._temporary.__exit__(exc_type, exc_value, traceback)

    def _execute(self, arguments):
        command = [
            self._tool,
            "/Online",
            "/English",
            "/LogPath:" + os.path.join(self._workspace, "dism.log"),
            "/ScratchDir:" + self._workspace,
        ] + arguments
        with subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        ) as process:
            output = _decode(process.communicate()[0])
        return process.returncode, output

    def _failure(self, status, output):
        raise OSError("DISM failed ({0}): {1}".format(status, output))

    def state(self, name):
        """Read one requested feature's native state before any changes.

        :param str name: Literal Windows feature name.
        :returns: Native English state, or None for an unknown feature.
        :rtype: str or None
        :raises OSError: DISM fails or returns no unique state field.
        """
        status, output = self._execute(["/Get-FeatureInfo", "/FeatureName:" + name])
        if status & 0xFFFFFFFF == _UNKNOWN_FEATURE:
            # Older DISM requires the catalogue's exact feature-name casing.
            status, catalogue = self._execute(["/Get-Features", "/Format:List"])
            if status:
                self._failure(status, catalogue)
            names = re.findall(
                r"^Feature Name[ \t]*:[ \t]*(.*)$", catalogue, re.MULTILINE
            )
            if not names:
                raise OSError("DISM returned no complete feature-name catalogue.")
            matches = [
                value.strip()
                for value in names
                if value.strip().lower() == name.lower()
            ]
            if not matches:
                return None
            if len(matches) != 1:
                raise OSError(
                    "DISM returned an ambiguous feature name for '" + name + "'."
                )
            self._names[name] = matches[0]
            status, output = self._execute(
                ["/Get-FeatureInfo", "/FeatureName:" + matches[0]]
            )
        if status:
            self._failure(status, output)
        states = re.findall(r"^State[ \t]*:[ \t]*(.*)$", output, re.MULTILINE)
        if len(states) != 1 or not states[0].strip():
            raise OSError("DISM returned no unique state for feature '" + name + "'.")
        return states[0].strip()

    def enable(self, names, include_parent, source):
        """Enable the prechecked feature batch without restarting Windows.

        :param list names: Requested names requiring installation, in order.
        :param bool include_parent: Enable required parents and dependencies.
        :param str source: Optional literal source path, already checked by the caller.
        :returns: Whether DISM reports that a reboot is needed.
        :rtype: bool
        :raises OSError: DISM fails, possibly after partial servicing changes.
        """
        self.validate_enable(include_parent, source)
        arguments = ["/Enable-Feature"] + [
            "/FeatureName:" + self._names.get(name, name) for name in names
        ]
        if include_parent:
            arguments.append("/All")
        if source:
            arguments.append("/Source:" + source)
        return self._change(arguments)

    def validate_enable(self, include_parent, source):
        """Check requested optional switches against the installed tool's help.

        :param bool include_parent: Whether the request needs the All switch.
        :param source: Optional source path whose use requires the Source switch.
        :type source: str or None
        :raises OSError: The installed tool cannot expose its enable contract.
        :raises ValueError: A meaningful requested switch is unavailable.
        """
        if not include_parent and not source:
            return
        if self._enable_help is None:
            status, output = self._execute(["/Enable-Feature", "/?"])
            if status:
                self._failure(status, output)
            self._enable_help = output
        for requested, switch in ((include_parent, "All"), (source, "Source")):
            if requested and not re.search(
                r"(?i)/" + switch + r"(?=[:\s\]]|$)", self._enable_help
            ):
                raise ValueError(
                    "The installed DISM enable-feature facility does not support /"
                    + switch
                    + "."
                )

    def disable(self, names):
        """Disable the prechecked feature batch without removing its payload.

        :param list names: Requested names requiring removal, in order.
        :returns: Whether DISM reports that a reboot is needed.
        :rtype: bool
        :raises OSError: DISM fails, possibly after partial servicing changes.
        """
        return self._change(
            ["/Disable-Feature"]
            + ["/FeatureName:" + self._names.get(name, name) for name in names]
        )

    def _change(self, arguments):
        status, output = self._execute(arguments + ["/NoRestart"])
        if status not in (0, 3010):
            self._failure(status, output)
        return status == 3010
