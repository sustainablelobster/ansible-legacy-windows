# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Use the older OS-provided Server Manager command and its real catalogue."""

import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from legacy_windows_wmi import WmiConnection  # pylint: disable=import-error


def executable():
    """Locate an installed native-architecture Server Manager command.

    :returns: Tool path, or None when this older facility is absent.
    :rtype: str or None
    """
    for directory in ("Sysnative", "System32"):
        path = os.path.join(os.environ["SystemRoot"], directory, "ServerManagerCmd.exe")
        if os.path.isfile(path):
            return path
    return None


class ServerManager:
    """Own one temporary workspace for older Server Manager XML operations."""

    def __init__(self, tool):
        self._tool = tool
        self._temporary = None
        self._workspace = None

    def __enter__(self):
        self._temporary = tempfile.TemporaryDirectory(prefix="legacy-server-feature-")
        self._workspace = self._temporary.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return self._temporary.__exit__(exc_type, exc_value, traceback)

    def _execute(self, arguments):
        with subprocess.Popen(
            [self._tool]
            + arguments
            + ["-logpath", os.path.join(self._workspace, "servermanager.log")],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        ) as process:
            output = process.communicate()[0].decode("mbcs", "replace").strip()
        return process.returncode, output

    def catalogue(self):
        """Read every available feature and its actual display hierarchy.

        :returns: Ordered component records, including native default children.
        :rtype: list
        :raises OSError: The tool cannot return a catalogue.
        :raises ValueError: The returned catalogue is invalid.
        """
        path = os.path.join(self._workspace, "catalogue.xml")
        status, output = self._execute(["-query", path])
        if status:
            raise OSError(
                "ServerManagerCmd query failed ({0}): {1}".format(status, output)
            )
        components = []
        names = set()

        def _append(node, parent=""):
            kind = node.tag.rsplit("}", 1)[-1]
            if kind in ("Role", "RoleService", "Feature"):
                name = node.get("Id")
                installed = node.get("Installed")
                display = node.get("DisplayName")
                if (
                    not name
                    or name in names
                    or not display
                    or installed not in ("true", "false")
                ):
                    raise ValueError(
                        "ServerManagerCmd returned an invalid feature catalogue."
                    )
                names.add(name)
                components.append(
                    {
                        "UniqueName": name,
                        "DisplayName": display,
                        "ParentName": parent,
                        "Installed": int(installed == "true"),
                        "NumericId": None,
                        "FeatureType": {"Role": 0, "RoleService": 1, "Feature": 2}[
                            kind
                        ],
                        "InstallWithParentByDefault": node.get("Default") == "true",
                        "NonAncestorDependencies": None,
                        "OptionalCompanions": None,
                    }
                )
                parent = name
            for child in node:
                _append(child, parent)

        _append(ET.parse(path).getroot())
        if not components:
            raise ValueError("ServerManagerCmd returned an empty feature catalogue.")
        try:
            with WmiConnection() as connection:
                installed = connection.query(
                    "SELECT * FROM Win32_ServerFeature", ["ID", "Name"]
                )
        except OSError as error:
            if getattr(error, "hresult", None) != 0x80041010:
                raise
            # This installed-feature metadata enriches a complete tool
            # catalogue; absence leaves honest null IDs, not missing features.
            installed = []
        identifiers = {}
        for feature in installed:
            identifiers.setdefault(feature["Name"], []).append(feature["ID"])
        for component in components:
            matching = identifiers.get(component["DisplayName"], [])
            if len(matching) == 1:
                component["NumericId"] = matching[0]
        return components

    def change(self, names, installing, include_sub_features):
        """Submit a native feature batch without permitting automatic restart.

        :param list names: Literal identifiers already validated against the catalogue.
        :param bool installing: Install rather than remove the requested features.
        :param bool include_sub_features: Include all children when installing.
        :returns: Native exit status, text, and XML result root when available.
        :rtype: tuple
        """
        path = os.path.join(self._workspace, "result.xml")
        arguments = ["-install" if installing else "-remove"] + names
        if installing and include_sub_features:
            arguments.append("-allSubFeatures")
        status, output = self._execute(arguments + ["-resultpath", path])
        result = ET.parse(path).getroot() if os.path.isfile(path) else None
        return status, output, result
