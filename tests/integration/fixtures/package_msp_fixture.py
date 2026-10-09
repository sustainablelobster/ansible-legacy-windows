"""Own the official sample MSI/MSP lifecycle and retain literal recovery evidence."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import ctypes
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import winreg  # pylint: disable=import-error

# The public play embeds these adjacent Python 3.4 payload helpers before exec.
import legacy_windows_acl as acl  # pylint: disable=import-error
import legacy_windows_package_msi as msi  # pylint: disable=import-error
import legacy_windows_service as service  # pylint: disable=import-error
from legacy_windows_wmi import WmiConnection  # pylint: disable=import-error

ROOT, OPERATION = sys.argv[1:3]
JOURNAL = os.path.join(ROOT, "msp-journal.json")
PRODUCT = "{48C49ACE-90CF-4161-9C6E-9162115A54DD}"
PATCH = "{224C316C-5894-4771-BABF-21A3AC1F75FF}"
APPLICATION = os.path.join(
    os.environ.get("ProgramFiles(x86)", os.environ["ProgramFiles"]),
    "Patch Sample Directory",
)
DIGESTS = {
    "patch.msi": "27d065aa11c72c941300aca33dcbec1b96d6d032d540ac15d2b61070f0b6635f",
    "patch.msp": "ba8e417e9ea62dea1e2c056e2d7296fe1eaca7665846f869e16139037745d617",
}
PATCH_FILENAME = globals().get("PATCH_FILENAME", "patch.msp")
assert PATCH_FILENAME and not any(value in PATCH_FILENAME for value in ("/", "\\"))
assert PATCH_FILENAME.lower().endswith(".msp")
DIGESTS[PATCH_FILENAME] = DIGESTS["patch.msp"]


def _encode(value):
    if isinstance(value, bytes):
        return {"raw_bytes": base64.b64encode(value).decode("ascii")}
    raise TypeError("Unsupported MSP journal value")


def _decode(value):
    return (
        base64.b64decode(value["raw_bytes"]) if set(value) == {"raw_bytes"} else value
    )


def _write(record):
    with open(JOURNAL, "w", encoding="utf-8") as stream:
        json.dump(record, stream, default=_encode, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())


def _read():
    with open(JOURNAL, encoding="utf-8") as stream:
        record = json.load(stream, object_hook=_decode)
    assert record["workspace"] == ROOT and record["application"] == APPLICATION
    return record


def _file_state(path):
    with open(path, "rb") as stream:
        content = stream.read()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    kernel.GetFileAttributesW.restype = ctypes.c_uint32
    attributes = kernel.GetFileAttributesW(path)
    assert attributes != 0xFFFFFFFF
    with acl.open_acl(acl.resolve_target(path, True)) as (permissions, _writer):
        return {
            "bytes": content,
            "mtime": os.stat(path).st_mtime_ns,
            "attributes": attributes,
            "acl": permissions,
        }


def _sources():
    return {
        name: _file_state(os.path.join(ROOT, name))
        for name in DIGESTS
        if os.path.isfile(os.path.join(ROOT, name))
    }


def _outputs():
    result = {}
    for directory, _folders, files in os.walk(APPLICATION):
        for name in files:
            path = os.path.join(directory, name)
            result[os.path.relpath(path, APPLICATION)] = _file_state(path)
    return result


def _services():
    with WmiConnection() as connection:
        rows = connection.query(
            "SELECT Name,StartMode,PathName,StartName,State FROM Win32_Service",
            ["Name", "StartMode", "PathName", "StartName", "State"],
        )
    return {
        row["Name"]: {
            key: value
            for key, value in row.items()
            if key != "State" or row["Name"] in ("MSIServer", "BvSshServer")
        }
        for row in rows
    }


def _pending():
    result = {}
    for path in (
        r"SYSTEM\CurrentControlSet\Control\Session Manager",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
    ):
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ
            ) as key:
                if path.endswith("Session Manager"):
                    try:
                        value, kind = winreg.QueryValueEx(
                            key, "PendingFileRenameOperations"
                        )
                        result[path] = {"kind": kind, "value": value}
                    except FileNotFoundError:
                        result[path] = None
                else:
                    result[path] = [
                        winreg.EnumValue(key, index)
                        for index in range(winreg.QueryInfoKey(key)[1])
                    ]
        except FileNotFoundError:
            result[path] = None
    return result


def _uninstall_keys():
    result = {}
    view = 0x100 if ctypes.sizeof(ctypes.c_void_p) == 8 else 0
    for name, hive in (
        ("HKLM", winreg.HKEY_LOCAL_MACHINE),
        ("HKCU", winreg.HKEY_CURRENT_USER),
    ):
        for branch in ("SOFTWARE", r"SOFTWARE\Wow6432Node"):
            path = (
                branch + r"\Microsoft\Windows\CurrentVersion\Uninstall" + "\\" + PRODUCT
            )
            try:
                with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view) as key:
                    result[name + "\\" + path] = [
                        winreg.EnumValue(key, index)
                        for index in range(winreg.QueryInfoKey(key)[1])
                    ]
            except FileNotFoundError:
                result[name + "\\" + path] = None
    return result


def _snapshot():
    with msi.WindowsInstaller() as installer:
        operation = installer.library.MsiEnumProductsW
        operation.argtypes = [ctypes.c_uint32, ctypes.c_wchar_p]
        operation.restype = ctypes.c_uint32
        products = []
        while True:
            identifier = ctypes.create_unicode_buffer(39)
            status = operation(len(products), identifier)
            if status == 259:
                break
            assert status == 0, status
            products.append(
                {
                    "id": identifier.value,
                    "state": installer.product_state(identifier.value),
                }
            )
        patches = installer.patches()
        for patch in patches:
            patch["state"] = installer.patch_state(
                patch["patch"], patch["product"], patch["context"]
            )
        state = installer.product_state(PRODUCT)
    return {
        "products": products,
        "patches": patches,
        "state": state,
        "services": _services(),
        "pending": _pending(),
        "sources": _sources(),
        "outputs": _outputs(),
        "uninstall_keys": _uninstall_keys(),
    }


def _protected(value):
    result = dict(value)
    result["products"] = [row for row in value["products"] if row["id"] != PRODUCT]
    result["patches"] = [row for row in value["patches"] if row["product"] != PRODUCT]
    result["services"] = {name: dict(row) for name, row in value["services"].items()}
    result["services"].get("MSIServer", {}).pop("State", None)
    for field in ("state", "outputs", "uninstall_keys"):
        result.pop(field)
    return result


def _installer_command(actions):
    executable = os.path.join(os.environ["SystemRoot"], "System32", "msiexec.exe")
    command = subprocess.list2cmdline(
        [executable]
        + actions
        + [
            "/qn",
            "/norestart",
            "/L*V",
            os.path.join(ROOT, "fixture.log"),
        ]
    )
    with subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ) as child:
        stdout, stderr = child.communicate()
        assert child.returncode == 0, (child.returncode, stdout, stderr)


def _restore_sources(record):
    for name, original in record.get("sources", {}).items():
        path = os.path.join(ROOT, name)
        current = _file_state(path)
        assert {key: value for key, value in current.items() if key != "acl"} == {
            key: value for key, value in original.items() if key != "acl"
        }
        with acl.open_acl(acl.resolve_target(path, True)) as (_permissions, writer):
            writer(original["acl"])


def _restore_service(before):
    current = _services()
    if current.get("MSIServer") == before.get("MSIServer"):
        return
    original, running = before["MSIServer"], current["MSIServer"]
    assert original["State"] == "Stopped" and running["State"] == "Running"
    assert {key: value for key, value in original.items() if key != "State"} == {
        key: value for key, value in running.items() if key != "State"
    }
    service.control("MSIServer", "stopped")


def _remove_owned_product(record):
    with msi.WindowsInstaller() as installer:
        state = installer.product_state(PRODUCT)
    if state == 5:
        assert record["before"]["state"] == -1 and record["complete"]
        _installer_command(["/x", PRODUCT])
    else:
        assert state == -1, state
    # MSI may leave its own empty directory after uninstall. Never remove files
    # or adopt a directory that existed before this explicitly journaled product.
    if os.path.exists(APPLICATION):
        assert record["before"]["outputs"] == {} and os.path.isdir(APPLICATION)
        assert os.listdir(APPLICATION) == []
        os.rmdir(APPLICATION)


def _journal():
    assert os.listdir(ROOT) == [] and not os.path.exists(APPLICATION)
    before = _snapshot()
    assert before["state"] == -1
    assert all(row["product"] != PRODUCT for row in before["patches"])
    assert all(value is None for value in before["uninstall_keys"].values())
    record = {
        "workspace": ROOT,
        "application": APPLICATION,
        "before": before,
        "complete": False,
        "verified": False,
    }
    _write(record)
    return {
        "journaled": True,
        "runtime": sys.version,
        "before": before,
        "application": APPLICATION,
    }


def _setup():
    record = _read()
    assert not record["complete"] and not record["verified"]
    for name, digest in DIGESTS.items():
        with open(os.path.join(ROOT, name), "rb") as stream:
            assert hashlib.sha256(stream.read()).hexdigest() == digest
    with msi.WindowsInstaller() as installer:
        assert installer.product_code(os.path.join(ROOT, "patch.msi")) == PRODUCT
        assert installer.package_type(os.path.join(ROOT, "patch.msp")) == "msp"
        assert installer.summary_property(os.path.join(ROOT, "patch.msp"), 7) == PRODUCT
        assert (
            installer.summary_property(os.path.join(ROOT, "patch.msp"), 9)[:38] == PATCH
        )
    record["sources"] = _sources()
    record["complete"] = True
    _write(record)
    _restore_service(record["before"]["services"])
    return {"ready": True, "sha256": DIGESTS, "product": PRODUCT, "patch": PATCH}


def _prepare():
    record = _read()
    assert record["complete"] and not record["verified"]
    requested = sys.argv[3]
    assert requested in ("absent", "base", "patched")
    _remove_owned_product(record)
    _restore_sources(record)
    if requested != "absent":
        _installer_command(["/i", os.path.join(ROOT, "patch.msi")])
    if requested == "patched":
        _installer_command(["/update", os.path.join(ROOT, "patch.msp")])
    _restore_sources(record)
    _restore_service(record["before"]["services"])
    result = _snapshot()
    expected = dict(record["before"], sources=record["sources"])
    assert _protected(result) == _protected(expected)
    assert result["state"] == (-1 if requested == "absent" else 5)
    assert len(result["outputs"]) == (0 if requested == "absent" else 1)
    return result


def _cleanup():
    if not os.path.exists(JOURNAL):
        assert os.listdir(ROOT) == []
        return {"restored": True, "journal_absent": True}
    record = _read()
    _remove_owned_product(record)
    _restore_sources(record)
    _restore_service(record["before"]["services"])
    final = _snapshot()
    expected = dict(record["before"], sources=record.get("sources", {}))
    assert final == expected, [
        key for key, value in final.items() if value != expected[key]
    ]
    assert not os.path.exists(APPLICATION)
    record["verified"] = True
    _write(record)
    return {"restored": True, "before": expected, "after": final}


def _finalize():
    if not os.path.exists(JOURNAL):
        assert os.listdir(ROOT) == []
        return {"finalized": True, "journal_absent": True}
    record = _read()
    assert record["verified"]
    assert _snapshot() == dict(record["before"], sources=record.get("sources", {}))
    assert not os.path.exists(APPLICATION)
    os.remove(JOURNAL)
    return {"finalized": True}


def main():
    """Execute only a validated private fixture operation on Python 3.4.4."""
    assert sys.version_info[:3] == (3, 4, 4)
    assert os.path.basename(ROOT).startswith("legacy-windows-package-msp-")
    # This fixture owns its workspace check independently of installer payloads.
    # pylint: disable=duplicate-code
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetLongPathNameW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    ]
    kernel.GetLongPathNameW.restype = ctypes.c_uint32
    # pylint: enable=duplicate-code

    def _long_path(path):
        buffer = ctypes.create_unicode_buffer(32768)
        count = kernel.GetLongPathNameW(path, buffer, len(buffer))
        assert 0 < count < len(buffer)
        return os.path.normcase(buffer.value.rstrip("\\"))

    assert _long_path(os.path.dirname(ROOT)) == _long_path(tempfile.gettempdir())
    assert not os.path.islink(ROOT)
    operations = {
        "journal": _journal,
        "setup": _setup,
        "prepare": _prepare,
        "observe": _snapshot,
        "cleanup": _cleanup,
        "finalize": _finalize,
    }
    result = operations[OPERATION]()
    print(json.dumps(result, default=_encode, sort_keys=True))


if __name__ == "__main__":
    main()
