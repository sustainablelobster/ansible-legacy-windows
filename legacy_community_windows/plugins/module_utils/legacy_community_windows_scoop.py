# Copyright: (c) 2020, Jamie Magee <jamie.magee@gmail.com>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Locate Scoop and invoke its installed command-line and bucket interfaces."""

import base64
import json
import os
import re
import subprocess
import tempfile

try:
    import winreg
except ImportError:
    winreg = None

from legacy_windows_process import run_command  # pylint: disable=import-error

_BOOTSTRAP = r"""
$ErrorActionPreference = 'Stop'
$protocol = [Net.ServicePointManager]::SecurityProtocol
if ([Net.SecurityProtocolType].GetMember('Tls12')) {
    $protocol = $protocol -bor [Net.SecurityProtocolType]::Tls12
}
[Net.ServicePointManager]::SecurityProtocol = $protocol
$installer = [ScriptBlock]::Create((New-Object Net.WebClient).DownloadString('https://get.scoop.sh'))
$principal = New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    & $installer -RunAsAdmin
}
else { & $installer }
"""

_BUCKETS = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$installed = @(& $env:LEGACY_SCOOP_SCRIPT bucket list)
$names = @($installed.Name)
$json = ConvertTo-Json -InputObject $names -Compress
[IO.File]::WriteAllText($env:LEGACY_SCOOP_RESULT, $json, (New-Object Text.UTF8Encoding($false)))
"""


def engine():
    """Find the installed Windows PowerShell engine used by Scoop.

    :returns: Absolute executable path.
    :rtype: str
    :raises OSError: If the engine is not installed.
    """
    root = os.environ.get("SystemRoot", r"C:\Windows")
    for system in ("Sysnative", "System32"):
        candidate = os.path.join(
            root, system, "WindowsPowerShell", "v1.0", "powershell.exe"
        )
        if os.path.isfile(candidate):
            return candidate
    raise OSError("Scoop requires an installed Windows PowerShell engine.")


def _registered_paths():
    if winreg is None:
        return []
    paths = []
    for hive, key_path in (
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        ),
        (winreg.HKEY_CURRENT_USER, "Environment"),
    ):
        try:
            with winreg.OpenKey(hive, key_path) as key:
                paths.append(os.path.expandvars(winreg.QueryValueEx(key, "Path")[0]))
        except FileNotFoundError:
            continue
    return paths


def locate():
    """Refresh persistent PATH entries and find the installed Scoop script.

    Process-local entries remain available for explicitly isolated installations.

    :returns: Scoop script path, or None when not installed.
    :rtype: str or None
    """
    paths = _registered_paths() + [os.environ.get("PATH", "")]
    os.environ["PATH"] = os.pathsep.join(paths)
    for folder in os.get_exec_path():
        candidate = os.path.join(folder, "scoop.ps1")
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)
    return None


def command(path, arguments):
    """Run an installed Scoop CLI command in a separate PowerShell process.

    :param path: Installed Scoop script.
    :type path: str
    :param arguments: Literal CLI arguments, never PowerShell source.
    :type arguments: list
    :returns: Native command result, including its exit status and output.
    :rtype: dict
    """
    executable = engine()
    # These fixed flags invoke Scoop's installed CLI, not a shared script host.
    # pylint: disable=duplicate-code
    argv = [
        executable,
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        path,
    ] + arguments
    # pylint: enable=duplicate-code
    line = subprocess.list2cmdline(argv)
    result = run_command(
        executable,
        line,
        {"chdir": None, "stdin": None, "output_encoding_override": None},
    )
    result["command"] = line
    return result


def bootstrap():
    """Run Scoop's official installer, retaining its native diagnostics.

    :returns: Installer command result; callers verify the installed script.
    :rtype: dict
    """
    executable = engine()
    encoded = base64.b64encode(_BOOTSTRAP.encode("utf-16-le")).decode("ascii")
    line = subprocess.list2cmdline(
        [
            executable,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            encoded,
        ]
    )
    return run_command(
        executable,
        line,
        {"chdir": None, "stdin": None, "output_encoding_override": None},
    )


def packages(output):
    """Read Scoop's released JSON and older textual export formats.

    :param output: Actual output from ``scoop export``.
    :type output: str
    :returns: Installed package names and global-install flags.
    :rtype: list
    """
    try:
        exported = json.loads(output)
    except ValueError:
        return [
            {"name": match.group(1), "global": bool(match.group(3))}
            for match in re.finditer(
                r"(.*?) \(v:(.*?)\)( \*global\*)? \[(.*?)\](\{32bit\})?", output
            )
        ]
    result = []
    for package in exported.get("apps", []):
        package = {key.lower(): value for key, value in package.items()}
        options = [
            value.strip().lower() for value in (package.get("info") or "").split(",")
        ]
        if "install failed" not in options:
            result.append(
                {"name": package["name"], "global": "global install" in options}
            )
    return result


def buckets(path):
    """Read bucket names from Scoop's own objects, not formatted table columns.

    :param path: Installed Scoop script.
    :type path: str
    :returns: Literal installed bucket names.
    :rtype: list
    :raises OSError: If the vendor operation fails or produces no result.
    :raises ValueError: If the vendor result is malformed.
    :raises BaseException: Interruption propagates after stopping the owned engine.
    """
    with tempfile.TemporaryDirectory(prefix="legacy-community-scoop-") as directory:
        result_path = os.path.join(directory, "buckets.json")
        environment = os.environ.copy()
        environment.update(LEGACY_SCOOP_SCRIPT=path, LEGACY_SCOOP_RESULT=result_path)
        encoded = base64.b64encode(_BUCKETS.encode("utf-16-le")).decode("ascii")
        # Bucket output is a Scoop-specific file contract; keep its owned child
        # and interruption cleanup here rather than generalizing engine I/O.
        # pylint: disable=duplicate-code
        with subprocess.Popen(
            [
                engine(),
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                encoded,
            ],
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as process:
            try:
                _stdout, stderr = process.communicate()
            except BaseException:
                process.kill()
                process.communicate()
                raise
        # pylint: enable=duplicate-code
        if process.returncode or not os.path.isfile(result_path):
            raise OSError(
                "Error checking Scoop buckets: "
                + stderr.decode("utf-8", "replace").strip()
            )
        with open(result_path, "r", encoding="utf-8-sig") as result_file:
            names = json.load(result_file)
        if not isinstance(names, list) or not all(
            isinstance(name, str) for name in names
        ):
            raise ValueError("Scoop returned an invalid bucket name list.")
        return names
