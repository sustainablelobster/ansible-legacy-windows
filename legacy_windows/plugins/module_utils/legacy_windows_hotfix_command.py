# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Use installed older DISM package commands when its native DLL is absent."""

import os
import subprocess
import tempfile


def executable():
    """Find native-architecture DISM without imposing an operating-system list.

    :returns: Installed tool path, or None when the facility is absent.
    :rtype: str or None
    """
    if os.name != "nt":
        return None
    for directory in ("Sysnative", "System32"):
        path = os.path.join(os.environ["SystemRoot"], directory, "dism.exe")
        if os.path.isfile(path):
            return path
    return None


class DismCommand:
    """Own scratch files for the existing Windows package-servicing commands."""

    def __init__(self, tool):
        self._tool = tool
        self._temporary = None
        self._workspace = None

    # This package boundary owns its scratch lifetime and fixed DISM invocation.
    # pylint: disable=duplicate-code
    def __enter__(self):
        self._temporary = tempfile.TemporaryDirectory(prefix="legacy-windows-hotfix-")
        self._workspace = self._temporary.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return self._temporary.__exit__(exc_type, exc_value, traceback)

    def _execute(self, arguments):
        command = [
            self._tool,
            "/Online",
            "/English",
            "/NoRestart",
            "/ScratchDir:" + self._workspace,
            "/LogPath:" + os.path.join(self._workspace, "dism.log"),
        ] + arguments
        with subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        ) as process:
            output = process.communicate()[0].decode("mbcs", "replace").strip()
        return process.returncode, output

    # pylint: enable=duplicate-code

    def _read(self, arguments):
        status, output = self._execute(arguments)
        if status:
            raise OSError("DISM failed ({0}): {1}".format(status, output))
        return output

    def catalogue(self):
        """Read package identifiers and actual states from the installed tool.

        :returns: Ordered package records.
        :rtype: list
        :raises OSError: DISM fails or returns incomplete package metadata.
        """
        rows = []
        for line in self._read(["/Get-Packages"]).splitlines():
            if line.startswith("Package Identity : "):
                rows.append({"name": line.split(" : ", 1)[1]})
            elif line.startswith("State : ") and rows:
                rows[-1]["state"] = line.split(" : ", 1)[1].replace(" ", "")
        if any(
            set(row) != {"name", "state"} or not row["name"] or not row["state"]
            for row in rows
        ):
            raise OSError("DISM returned incomplete package catalogue metadata.")
        return rows

    def information(self, identifier, by_path=False):
        """Read one package by its exact identity or CAB path.

        :param str identifier: Literal package name or CAB path.
        :param bool by_path: Select CAB inspection instead of an installed identity.
        :returns: Actual package name, state, description and applicability.
        :rtype: dict
        :raises OSError: The command fails or omits necessary metadata.
        """
        fields = {}
        selector = "/PackagePath:" if by_path else "/PackageName:"
        for line in self._read(
            ["/Get-PackageInfo", selector + identifier]
        ).splitlines():
            if " : " in line:
                key, value = line.split(" : ", 1)
                if key not in (
                    "Package Identity",
                    "State",
                    "Description",
                    "Applicable",
                ):
                    continue
                if key in fields:
                    raise OSError("DISM returned duplicate package metadata fields.")
                fields[key] = value
        required = ("Package Identity", "State", "Description")
        if any(name not in fields for name in required):
            raise OSError("DISM returned incomplete package information.")
        applicable = fields.get("Applicable")
        if by_path and applicable not in ("Yes", "No"):
            raise OSError("DISM did not report whether the CAB is applicable.")
        return {
            "name": fields["Package Identity"],
            "state": fields["State"].replace(" ", ""),
            "description": fields["Description"],
            "applicable": applicable == "Yes" if applicable is not None else None,
        }

    def _change(self, arguments):
        status, output = self._execute(arguments)
        if status not in (0, 3010):
            raise OSError("DISM failed ({0}): {1}".format(status, output))
        return status == 3010

    def add(self, path):
        """Install a CAB without allowing a restart.

        :param str path: Literal expanded CAB filename.
        :returns: Whether successful servicing requires restart.
        :rtype: bool
        :raises OSError: Native servicing fails.
        """
        return self._change(["/Add-Package", "/PackagePath:" + path])

    def remove(self, name):
        """Remove an installed package without allowing a restart.

        :param str name: Exact package identity.
        :returns: Whether successful servicing requires restart.
        :rtype: bool
        :raises OSError: Native servicing fails.
        """
        return self._change(["/Remove-Package", "/PackageName:" + name])
