# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe a real, individually selected hotfix before and after servicing."""

import binascii
import ctypes
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

# These modules exist on the authorized Windows target, not the lint host.
import winreg  # pylint: disable=import-error
import xml.etree.ElementTree as xml

import legacy_windows_hotfix as hotfix  # pylint: disable=import-error
import legacy_windows_package_signature as signature  # pylint: disable=import-error

assert sys.version_info[:3] == (3, 4, 4)
ROOT = os.environ["SystemRoot"]
PENDING = (
    (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion"
        r"\Component Based Servicing\RebootPending"
    ),
    (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion"
        r"\WindowsUpdate\Auto Update\RebootRequired"
    ),
)
SERVICE_FIELDS = (
    "AcceptPause",
    "AcceptStop",
    "CheckPoint",
    "CreationClassName",
    "Description",
    "DesktopInteract",
    "DisplayName",
    "ErrorControl",
    "ExitCode",
    "InstallDate",
    "Name",
    "PathName",
    "ProcessId",
    "ServiceSpecificExitCode",
    "ServiceType",
    "Started",
    "StartMode",
    "StartName",
    "State",
    "Status",
    "SystemCreationClassName",
    "SystemName",
    "TagId",
    "WaitHint",
)


def _registry_key(path):
    # The recovery journal must enumerate registry state without tested helpers.
    # pylint: disable=duplicate-code
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
    except FileNotFoundError:
        return None
    # pylint: enable=duplicate-code
    with key:
        values = {}
        for index in range(winreg.QueryInfoKey(key)[1]):
            name, value, kind = winreg.EnumValue(key, index)
            if isinstance(value, bytes):
                value = {"hex": binascii.hexlify(value).decode("ascii")}
            values[name] = [value, kind]
        children = {
            winreg.EnumKey(key, index): _registry_key(
                path + "\\" + winreg.EnumKey(key, index)
            )
            for index in range(winreg.QueryInfoKey(key)[0])
        }
        return {"values": values, "children": children}


def _file_record(path):
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    api.GetFileAttributesW.restype = ctypes.c_uint32
    with open(path, "rb") as stream:
        digest = hashlib.sha256(stream.read()).hexdigest()
    attributes = api.GetFileAttributesW(path)
    assert attributes != 0xFFFFFFFF
    return {
        "sha256": digest,
        "size": os.stat(path).st_size,
        "mtime": os.stat(path).st_mtime,
        "attributes": attributes,
    }


def _observe(identifier, source=None):
    with hotfix.HotfixSession() as session:
        inventory = {
            "native": session.native_catalogue(),
            "visible": session.catalogue(),
        }
        selected = hotfix.metadata_from_name(session, identifier)
    with hotfix.WmiConnection() as connection:
        qfe = connection.query(
            "SELECT HotFixID FROM Win32_QuickFixEngineering", ["HotFixID"]
        )
        services = connection.query(
            "SELECT * FROM Win32_Service",
            list(SERVICE_FIELDS),
        )
    protected = [sys.executable] + [
        os.path.join(ROOT, "servicing", "Packages", identifier + suffix)
        for suffix in (".mum", ".cat")
    ]
    return {
        "python": sys.version,
        "packages": inventory,
        "selected": selected,
        "qfe": qfe,
        "pending": {path: _registry_key(path) for path in PENDING},
        "services": services,
        "protected": {
            path: _file_record(path) if os.path.isfile(path) else None
            for path in protected
        },
        "source": _file_record(source) if source is not None else None,
        "temporary": sorted(
            name
            for name in os.listdir(tempfile.gettempdir())
            if name.startswith("legacy-windows-hotfix-")
            or re.match(
                r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
                name,
            )
        ),
    }


def _expand_selected(source, folder, pattern):
    os.makedirs(folder)
    with subprocess.Popen(
        [os.path.join(ROOT, "System32", "expand.exe"), source, folder, "-F:" + pattern],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        output, error = process.communicate()
    assert process.returncode == 0, (
        output.decode("mbcs", errors="replace"),
        error.decode("mbcs", errors="replace"),
    )


def _package_manifest(cab, directory, identifier, removal):
    mum_path = os.path.join(ROOT, "servicing", "Packages", identifier + ".mum")
    installed_mum = _file_record(mum_path) if os.path.isfile(mum_path) else None
    source_mum = None
    if installed_mum is None:
        # A genuinely absent package has no installed manifest yet. Its
        # signed CAB still declares whether normal removal is permitted.
        folder = os.path.join(directory, "package-manifest")
        _expand_selected(cab, folder, "update.mum")
        mum_path = os.path.join(folder, "update.mum")
        source_mum = _file_record(mum_path)
    declarations = [
        node.attrib
        for node in xml.parse(mum_path).getroot().iter()
        if node.tag.rsplit("}", 1)[-1] == "package"
    ]
    assert declarations
    if removal:
        assert not any(node.get("permanence") == "permanent" for node in declarations)
    return {
        "installed_mum": installed_mum,
        "source_mum": source_mum,
        "declarations": declarations,
    }


def _inspect_source(source, identifier, kb, expected_digest, removal=True):
    source_record = _file_record(source)
    assert source_record["sha256"] == expected_digest
    with hotfix.ExpandedMsu(source) as directory:
        with hotfix.HotfixSession() as session:
            metadata = hotfix.metadata_from_file(session, directory)
        assert len(metadata) == 1, metadata
        assert metadata[0]["name"] == identifier, metadata
        assert metadata[0]["kb"] == kb, metadata
        catalogs = []
        folder = os.path.join(directory, "signed-catalog")
        _expand_selected(metadata[0]["path"], folder, "*.cat")
        for name in sorted(os.listdir(folder)):
            path = os.path.join(folder, name)
            if name.lower().endswith(".cat"):
                catalogs.append(
                    {
                        "name": name,
                        "file": _file_record(path),
                        "signature": signature.status(path),
                    }
                )
        assert catalogs and all(row["signature"] == "Valid" for row in catalogs)
        manifest = _package_manifest(
            metadata[0]["path"], directory, identifier, removal
        )
        metadata[0]["path"] = os.path.basename(metadata[0]["path"])
    return {
        "source": source_record,
        "metadata": metadata,
        "catalogs": catalogs,
        "installed_mum": manifest["installed_mum"],
        "source_mum": manifest["source_mum"],
        "declarations": manifest["declarations"],
        "state": _observe(identifier),
    }


def _remove_workspace(workspace):
    workspace = os.path.abspath(workspace)
    assert os.path.dirname(workspace).lower() == tempfile.gettempdir().lower()
    assert os.path.basename(workspace).startswith("legacy-windows-hotfix-lifecycle-")
    shutil.rmtree(workspace)
    assert not os.path.exists(workspace)
    return {"workspace_absent": True}


def _holder_process(pid):
    # This fixture verifies process birth independently of the async payload.
    # pylint: disable=duplicate-code
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    api.OpenProcess.restype = ctypes.c_void_p
    api.GetProcessTimes.argtypes = [ctypes.c_void_p] + [
        ctypes.POINTER(ctypes.c_uint64)
    ] * 4
    api.GetProcessTimes.restype = ctypes.c_int
    api.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    api.WaitForSingleObject.restype = ctypes.c_uint32
    api.CloseHandle.argtypes = [ctypes.c_void_p]
    api.CloseHandle.restype = ctypes.c_int
    handle = api.OpenProcess(0x100400, False, pid)
    if not handle:
        if ctypes.get_last_error() == 87:
            return None
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        clocks = [ctypes.c_uint64() for _ in range(4)]
        assert api.GetProcessTimes(handle, *[ctypes.byref(clock) for clock in clocks])
        return {
            "pid": pid,
            "created": clocks[0].value,
            "alive": api.WaitForSingleObject(handle, 0) == 258,
        }
    finally:
        assert api.CloseHandle(handle)
    # pylint: enable=duplicate-code


def _holder_path(workspace, name):
    workspace = os.path.abspath(workspace)
    assert os.path.dirname(workspace).lower() == tempfile.gettempdir().lower()
    assert os.path.basename(workspace).startswith("legacy-windows-hotfix-lifecycle-")
    return os.path.join(workspace, "reference-host-" + name)


def _holder_start(workspace):
    script = _holder_path(workspace, "holder.ps1")
    ready, release = (
        _holder_path(workspace, name) for name in ("ready.json", "release")
    )
    # This separately owned reference host models upstream's CLR file use.
    # It is fixture setup only, never a native payload dependency or fallback.
    program = r"""
param([string]$Ready, [string]$Release, [string]$Output)
$ErrorActionPreference = 'Stop'
try {
$process = [System.Diagnostics.Process]::GetCurrentProcess()
$modules = @($process.Modules | Where-Object {
    $_.FileName -match '\\Microsoft.NET\\' -and $_.ModuleName -eq 'clr.dll'
} | ForEach-Object {
    @{path=$_.FileName; version=$_.FileVersionInfo.FileVersion}
})
if ($modules.Count -ne 1) { throw 'Exactly one loaded Framework CLR is required' }
$record = @{pid=$PID; created=$process.StartTime.ToFileTimeUtc(); modules=$modules}
[System.IO.File]::WriteAllText(($Ready + '.partial'),
    (ConvertTo-Json -Depth 5 -InputObject $record))
[System.IO.File]::Move(($Ready + '.partial'), $Ready)
[System.IO.File]::WriteAllText($Output, 'Owned reference host ready')
while (-not (Test-Path -LiteralPath $Release)) {
    [System.Threading.Thread]::Sleep(100)
}
} catch {
    [System.IO.File]::WriteAllText($Output, ($_ | Out-String))
    exit 1
}
"""
    with open(script, "x", encoding="utf-8-sig") as stream:
        stream.write(program)
    executable = os.path.join(
        ROOT, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
    )
    output = _holder_path(workspace, "output.log")
    with open(output, "xb") as stream:
        stream.write(b"")
    # Python3.4 permits close_fds=True without stdio redirection. The reference
    # host writes its own error file so unused SSH pipes cannot hold task EOF.
    # Break away only this fixture child; do not change any inherited job policy.
    # The child outlives this call, so a Popen context would wait before release.
    # pylint: disable-next=consider-using-with
    process = subprocess.Popen(
        [
            executable,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            script,
            ready,
            release,
            output,
        ],
        creationflags=0x09000200,
        close_fds=True,
    )
    identity = _holder_process(process.pid)
    assert identity and identity["alive"]
    with open(
        _holder_path(workspace, "identity.json"), "x", encoding="utf-8"
    ) as stream:
        json.dump(identity, stream)
    deadline = time.monotonic() + 30
    while not os.path.isfile(ready):
        actual = _holder_process(process.pid)
        if actual != identity:
            with open(_holder_path(workspace, "output.log"), "rb") as stream:
                output = stream.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                "Owned reference host exited before readiness ({0}): {1}".format(
                    process.poll(), output
                )
            )
        if time.monotonic() >= deadline:
            raise RuntimeError("Owned reference host did not record its loaded CLR")
        time.sleep(0.1)
    with open(ready, encoding="utf-8-sig") as stream:
        actual = json.load(stream)
    assert actual["pid"] == identity["pid"]
    assert actual["created"] == identity["created"]
    assert _holder_process(process.pid) == identity
    for module in actual["modules"]:
        module["file"] = _file_record(module["path"])
    return {"native_identity": identity, "reference_host": actual}


def _holder_stop(workspace):
    with open(_holder_path(workspace, "identity.json"), encoding="utf-8") as stream:
        identity = json.load(stream)
    actual = _holder_process(identity["pid"])
    assert actual is None or actual["created"] == identity["created"]
    release = _holder_path(workspace, "release")
    expected = "Release only this journaled reference host\n"
    if os.path.exists(release):
        with open(release, encoding="utf-8") as stream:
            assert stream.read() == expected
    else:
        with open(release, "x", encoding="utf-8") as stream:
            stream.write(expected)
    deadline = time.monotonic() + 30
    while actual and actual["alive"]:
        if time.monotonic() >= deadline:
            raise RuntimeError("Owned reference host did not close after release")
        time.sleep(0.1)
        actual = _holder_process(identity["pid"])
        assert actual is None or actual["created"] == identity["created"]
    with open(_holder_path(workspace, "output.log"), "rb") as stream:
        output = stream.read().decode("utf-8", errors="replace")
    return {
        "identity": identity,
        "final": actual,
        "reference_host_output": output,
        "owned_reference_host_closed": True,
    }


def _native_image_proof():
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    api.GetModuleHandleW.restype = ctypes.c_void_p
    before = api.GetModuleHandleW("clr.dll")
    assert before is None
    # Exercise the exact production owner; resource handles have the image bit
    # set and never initialize CLR or expose it as an executable module.
    with hotfix._reference_file_use() as image:  # pylint: disable=protected-access
        assert image is not None
        assert image["handle"] & 3 == 2
        during = api.GetModuleHandleW("clr.dll")
        assert during is None
        protected = _file_record(image["path"])
    after = api.GetModuleHandleW("clr.dll")
    assert after is None
    assert _file_record(image["path"]) == protected
    return {
        "image": image,
        "file": protected,
        "executable_clr_modules": [before, during, after],
        "resource_image_verified": True,
        "native_scope_closed": True,
    }


def _main():
    operation, identifier = sys.argv[1:3]
    if operation == "observe":
        result = _observe(identifier, sys.argv[3] if len(sys.argv) > 3 else None)
    elif operation == "restored":
        result = _observe(identifier)
        assert not os.path.exists(sys.argv[3]), sys.argv[3]
        result["owned_workspace_absent"] = True
    elif operation == "match-source-time":
        source = sys.argv[3]
        workspace = os.path.abspath(os.path.dirname(source))
        assert os.path.dirname(workspace).lower() == tempfile.gettempdir().lower()
        assert os.path.basename(workspace).startswith(
            "legacy-windows-hotfix-lifecycle-"
        )
        assert os.path.basename(source) == "package.msu"
        assert _file_record(source)["sha256"] == sys.argv[4]
        stamp = float(sys.argv[5])
        os.utime(source, (stamp, stamp))
        result = _file_record(source)
        assert result["mtime"] == stamp
    elif operation in ("inspect", "inspect-install"):
        result = _inspect_source(
            sys.argv[3],
            identifier,
            sys.argv[4],
            sys.argv[5],
            removal=operation == "inspect",
        )
    elif operation == "image-proof":
        result = _native_image_proof()
    elif operation == "delete":
        result = _remove_workspace(sys.argv[3])
    elif operation == "holder-start":
        result = _holder_start(sys.argv[3])
    elif operation == "holder-stop":
        result = _holder_stop(sys.argv[3])
    else:
        raise ValueError(operation)
    print(json.dumps(result))


if __name__ == "__main__":
    _main()
