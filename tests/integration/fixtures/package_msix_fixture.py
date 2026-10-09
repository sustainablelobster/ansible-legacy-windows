"""Prepare and recover one uniquely owned signed MSIX package fixture."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import ctypes
import hashlib
import json
import os
import struct
import subprocess
import sys

# This fixture runs only on Windows; these imports are staged beside it there.
import winreg  # pylint: disable=import-error
import zipfile
import zlib

import legacy_windows_certificate_store as certificates  # pylint: disable=import-error
import legacy_windows_package_msix as msix  # pylint: disable=import-error

ROOT, OPERATION = sys.argv[1:3]
IDENTITY = "LegacyWindowsMSIXV41"
PUBLISHER = "CN=LegacyWindowsMSIXProbeV41"
POLICY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock"
VALUE = "AllowAllTrustedApps"
JOURNAL = os.path.join(ROOT, "journal.json")
PACKAGE = os.path.join(ROOT, "owned package.appx")
TOOLS_SHA256 = "703cf68b74655e0fef97262aa63669b5ad45842ccacbf7f3f21c2953daa4ff0f"


def _policy():
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            POLICY,
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        ) as key:
            try:
                value, kind = winreg.QueryValueEx(key, VALUE)
            except FileNotFoundError:
                return {"key": True, "value": None}
            assert kind == winreg.REG_DWORD and isinstance(value, int)
            return {"key": True, "value": [value, kind]}
    except FileNotFoundError:
        return {"key": False, "value": None}


def _set_policy(value):
    with winreg.CreateKeyEx(
        winreg.HKEY_LOCAL_MACHINE,
        POLICY,
        0,
        winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY,
    ) as key:
        winreg.SetValueEx(key, VALUE, 0, winreg.REG_DWORD, value)


def _stores():
    result = {}
    for scope in ("CurrentUser", "LocalMachine"):
        for name in ("My", "Root", "TrustedPeople"):
            with certificates.open_store(name, scope, "system", True) as store:
                result[scope + "/" + name] = [
                    {
                        "thumbprint": row["thumbprint"],
                        "key": row["has_private_key"],
                        "der": base64.b64encode(
                            certificates.encoded_certificate(row)
                        ).decode("ascii"),
                    }
                    for row in store.records
                ]
    return result


def _keys():
    result = {}
    native_attributes = ctypes.WinDLL(
        "kernel32", use_last_error=True
    ).GetFileAttributesW
    native_attributes.argtypes, native_attributes.restype = [
        ctypes.c_wchar_p
    ], ctypes.c_uint32
    roots = [
        os.path.join(os.environ["APPDATA"], "Microsoft", "Crypto"),
        os.path.join(os.environ["PROGRAMDATA"], "Microsoft", "Crypto"),
    ]
    for directory in roots:
        for path, _directories, names in os.walk(directory):
            for name in names:
                source = os.path.join(path, name)
                status = os.stat(source)
                attributes = native_attributes(source)
                if attributes == 0xFFFFFFFF:
                    raise ctypes.WinError(ctypes.get_last_error())
                value = {
                    "mtime": status.st_mtime,
                    "attributes": attributes,
                }
                try:
                    with open(source, "rb") as stream:
                        data = stream.read()
                    value.update(
                        sha256=hashlib.sha256(data).hexdigest(),
                        bytes=base64.b64encode(data).decode("ascii"),
                    )
                except PermissionError as error:
                    value["read_error"] = getattr(error, "winerror")
                result[source] = value
    return result


def _snapshot():
    with msix.PackageManager() as manager:
        current = manager.packages()
        machine = manager.packages(all_users=True)
    return {
        "current_packages": current,
        "machine_packages": machine,
        "stores": _stores(),
        "policy": _policy(),
        "keys": _keys(),
    }


def _inputs():
    result = {}
    attributes = ctypes.WinDLL("kernel32", use_last_error=True).GetFileAttributesW
    attributes.argtypes, attributes.restype = [ctypes.c_wchar_p], ctypes.c_uint32
    for name in (
        "cert.der",
        "cert.pfx",
        "package_msix_fixture.py",
        "legacy_windows_package_msix.py",
        "legacy_windows_certificate_store.py",
        "legacy_windows_module.py",
        "owned package.appx",
        "unsigned package.appx",
    ):
        path = os.path.join(ROOT, name)
        if os.path.isfile(path):
            with open(path, "rb") as stream:
                data = stream.read()
            value = attributes(path)
            assert value != 0xFFFFFFFF
            result[name] = {
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": base64.b64encode(data).decode("ascii"),
                "attributes": value,
                "mtime": os.stat(path).st_mtime,
            }
    return result


def _observation():
    return dict(_snapshot(), inputs=_inputs())


def _read():
    with open(JOURNAL, "r", encoding="utf-8") as stream:
        record = json.load(stream)
    assert record["root"] == ROOT and record["identity"] == IDENTITY
    return record


def _write(record):
    with open(JOURNAL, "w", encoding="utf-8") as stream:
        json.dump(record, stream, sort_keys=True)


def _run(arguments):
    with subprocess.Popen(
        arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ) as process:
        stdout, stderr = process.communicate()
        assert process.returncode == 0, (arguments, process.returncode, stdout, stderr)
    return {
        "argv": arguments,
        "rc": process.returncode,
        "stdout": stdout.decode("mbcs"),
        "stderr": stderr.decode("mbcs"),
    }


def _setup():
    assert sys.version_info[:3] == (3, 4, 4)
    assert not os.path.exists(JOURNAL)
    before = _snapshot()
    assert not any(row["Name"] == IDENTITY for row in before["machine_packages"])
    der_path = os.path.join(ROOT, "cert.der")
    with open(der_path, "rb") as stream:
        thumbprint = hashlib.sha1(stream.read()).hexdigest().upper()
    assert not any(
        row["thumbprint"] == thumbprint
        for rows in before["stores"].values()
        for row in rows
    )
    record = {
        "root": ROOT,
        "identity": IDENTITY,
        "before": before,
        "thumbprint": thumbprint,
        "package": PACKAGE,
        "tools": [],
    }
    _write(record)
    archive_path = os.path.join(ROOT, "sdk.zip")
    with open(archive_path, "rb") as stream:
        assert hashlib.sha256(stream.read()).hexdigest() == TOOLS_SHA256
    tools = os.path.join(ROOT, "sdk")
    os.mkdir(tools)
    with zipfile.ZipFile(archive_path, "r") as archive:
        assert all(
            not name.startswith("/")
            and "\\" not in name
            and ".." not in name.split("/")
            for name in archive.namelist()
        )
        archive.extractall(tools)
    content = os.path.join(ROOT, "content")
    os.mkdir(content)
    manifest = """<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
 xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
 xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
 IgnorableNamespaces="uap rescap">
 <Identity Name="{name}" Version="1.0.0.0" Publisher="{publisher}" ProcessorArchitecture="x64" />
 <Properties><DisplayName>Legacy Windows owned test</DisplayName>
 <PublisherDisplayName>Legacy Windows tests</PublisherDisplayName><Logo>icon.png</Logo></Properties>
 <Resources><Resource Language="en-us" /></Resources>
 <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.26100.0" /></Dependencies>
 <Capabilities><rescap:Capability Name="runFullTrust" /></Capabilities>
 <Applications><Application Id="OwnedTest" Executable="test.exe" EntryPoint="Windows.FullTrustApplication">
 <uap:VisualElements DisplayName="Owned test" Description="Disposable module fixture"
 Square150x150Logo="icon.png" Square44x44Logo="icon.png" BackgroundColor="transparent" />
 </Application></Applications>
</Package>""".format(
        name=IDENTITY, publisher=PUBLISHER
    )
    with open(
        os.path.join(content, "AppxManifest.xml"), "w", encoding="utf-8"
    ) as stream:
        stream.write(manifest)

    def _chunk(name, value):
        return (
            struct.pack(">I", len(value))
            + name
            + value
            + struct.pack(">I", zlib.crc32(name + value) & 0xFFFFFFFF)
        )

    icon = b"\x89PNG\r\n\x1a\n" + _chunk(
        b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    )
    icon += _chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00\xff")) + _chunk(
        b"IEND", b""
    )
    with open(os.path.join(content, "icon.png"), "wb") as stream:
        stream.write(icon)
    with open(os.path.join(content, "test.exe"), "wb") as stream:
        stream.write(b"")
    record["tools"].append(
        _run(
            [
                os.path.join(tools, "makeappx.exe"),
                "pack",
                "/d",
                content,
                "/p",
                PACKAGE,
                "/o",
            ]
        )
    )
    _write(record)
    record["tools"].append(
        _run(
            [
                os.path.join(tools, "signtool.exe"),
                "sign",
                "/a",
                "/v",
                "/fd",
                "SHA256",
                "/f",
                os.path.join(ROOT, "cert.pfx"),
                "/p",
                "OwnedFixtureOnlyV41",
                PACKAGE,
            ]
        )
    )
    _write(record)
    assert _keys() == before["keys"], "SignTool left a private-key resource"
    with certificates.read_file(der_path, None, False, "default") as source:
        assert len(source.records) == 1 and not source.records[0]["has_private_key"]
        with certificates.open_store("Root", "LocalMachine", "system", False) as store:
            store.add(source.records[0])
    _set_policy(1)
    identity = msix.manifest_identities(PACKAGE)
    assert len(identity) == 1 and identity[0].startswith(IDENTITY + "_1.0.0.0_x64__")
    record["full_name"] = identity[0]
    record["unsigned_package"] = os.path.join(ROOT, "unsigned package.appx")
    with zipfile.ZipFile(record["unsigned_package"], "w") as archive:
        archive.writestr("AppxManifest.xml", manifest)
    record["inputs"] = _inputs()
    _write(record)
    return {
        "package": PACKAGE,
        "name": IDENTITY,
        "full_name": identity[0],
        "unsigned_package": record["unsigned_package"],
        "tools": record["tools"],
        "before": before,
        "ready": _observation(),
    }


def _cleanup():
    record = _read()
    with msix.PackageManager() as manager:
        for row in manager.packages():
            if row["Name"] == IDENTITY:
                assert row["Publisher"] == PUBLISHER and row[
                    "PackageFullName"
                ].startswith(IDENTITY + "_")
                manager.remove(row["PackageFullName"])
    with certificates.open_store("Root", "LocalMachine", "system", False) as store:
        for row in store.records:
            if row["thumbprint"] == record["thumbprint"]:
                assert not row["has_private_key"]
                store.remove(row)
    original = record["before"]["policy"]
    if original["value"]:
        _set_policy(original["value"][0])
    elif _policy()["key"]:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            POLICY,
            0,
            winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY,
        ) as key:
            try:
                winreg.DeleteValue(key, VALUE)
            except FileNotFoundError:
                pass
        if not original["key"]:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                POLICY,
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            ) as key:
                assert winreg.QueryInfoKey(key)[:2] == (0, 0)
            winreg.DeleteKeyEx(
                winreg.HKEY_LOCAL_MACHINE, POLICY, winreg.KEY_WOW64_64KEY
            )
    after = _snapshot()
    record["after"] = after
    _write(record)
    assert (
        after == record["before"]
    ), "Literal package/certificate/key/policy recovery failed"
    if "inputs" in record:
        assert _inputs() == record["inputs"], "Protected fixture inputs changed"
    return dict(after, inputs=_inputs(), before=record["before"])


def _prepare():
    record = _read()
    desired = sys.argv[3]
    assert desired in ("present", "absent")
    with msix.PackageManager() as manager:
        owned = [row for row in manager.packages() if row["Name"] == IDENTITY]
        assert len(owned) <= 1
        if desired == "present" and not owned:
            manager.install(PACKAGE)
        elif desired == "absent" and owned:
            assert owned[0]["PackageFullName"] == record["full_name"]
            manager.remove(record["full_name"])
    result = _observation()
    assert result["inputs"] == record["inputs"]
    assert bool(
        [row for row in result["current_packages"] if row["Name"] == IDENTITY]
    ) == (desired == "present")
    return result


if OPERATION == "setup":
    output = _setup()
elif OPERATION == "observe":
    output = _observation()
elif OPERATION == "cleanup":
    output = _cleanup()
elif OPERATION == "prepare":
    output = _prepare()
else:
    raise ValueError("Unknown MSIX fixture operation")
print(json.dumps(output, sort_keys=True))
