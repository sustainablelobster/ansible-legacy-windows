"""Read promotion state independently through native WMI and ADSI providers."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import glob
import json
import os
import subprocess
import sys
import tempfile

_NATIVE_OBSERVER = r"""
Option Explicit
Dim service, instance, root, dnsState
Set service = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
For Each instance In service.ExecQuery( _
    "SELECT LastBootUpTime FROM Win32_OperatingSystem")
    WScript.Echo instance.LastBootUpTime
Next
For Each instance In service.ExecQuery( _
    "SELECT DNSHostName,Domain,DomainRole FROM Win32_ComputerSystem")
    WScript.Echo instance.DNSHostName
    WScript.Echo instance.Domain
    WScript.Echo instance.DomainRole
Next
dnsState = "absent"
For Each instance In service.ExecQuery( _
    "SELECT State FROM Win32_Service WHERE Name='DNS'")
    dnsState = instance.State
Next
WScript.Echo dnsState
If WScript.Arguments.Count > 0 Then
    Set root = GetObject("LDAP://RootDSE")
    WScript.Echo root.Get("domainControllerFunctionality")
    WScript.Echo root.Get("domainFunctionality")
    WScript.Echo root.Get("forestFunctionality")
End If
"""


def observe(directory=False):
    """Read boot identity, server role and optional active directory levels.

    :param bool directory: Read RootDSE only after the controller is active.
    :returns: Native state and promotion answer-directory names, without secrets.
    :rtype: dict
    :raises OSError: Writing or removing the temporary observer script fails.
    :raises subprocess.CalledProcessError: A native provider read fails.
    :raises RuntimeError: Native providers return an unexpected number of rows.
    """
    descriptor, path = tempfile.mkstemp(prefix="legacy-ad-observer-", suffix=".vbs")
    try:
        with os.fdopen(descriptor, "wb") as script:
            script.write(_NATIVE_OBSERVER.encode("ascii"))
        command = [
            os.path.join(os.environ["SystemRoot"], "System32", "cscript.exe"),
            "//Nologo",
            "//U",
            path,
        ]
        if directory:
            command.append("directory")
        output = subprocess.check_output(command, stderr=subprocess.STDOUT)
    finally:
        os.remove(path)
    values = output.decode("utf-16-le").lstrip("\ufeff").splitlines()
    if len(values) != (8 if directory else 5):
        raise RuntimeError("Native promotion observer returned unexpected rows.")
    result = {
        "boot_id": values[0],
        "hostname": values[1],
        "domain": values[2],
        "role": int(values[3]),
        "dns_service_state": values[4],
        "python": list(sys.version_info[:3]),
        "answer_directories": sorted(
            glob.glob(os.path.join(tempfile.gettempdir(), "legacy-ad-promotion-*"))
        ),
    }
    if directory:
        result.update(
            controller_level=int(values[5]),
            domain_level=int(values[6]),
            forest_level=int(values[7]),
        )
    return result


if __name__ == "__main__":
    print(json.dumps(observe(directory="directory" in sys.argv[1:])))
