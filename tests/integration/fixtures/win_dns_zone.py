# SPDX-License-Identifier: GPL-3.0-or-later
"""Observe DNS state and recover only journal-owned zones and role preparation."""

# The native ExecMethod ABI necessarily repeats the payload's exact declaration;
# this fixture must not broaden shared WMI contracts merely to share that signature.
# pylint: disable=duplicate-code

import binascii
import ctypes
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time

# These imports run only on Windows through the explicitly frozen fixture.
import winreg  # pylint: disable=import-error
from contextlib import ExitStack, contextmanager

import legacy_windows_dns_zone as dns_zone  # pylint: disable=import-error
import legacy_windows_feature_info as feature_info  # pylint: disable=import-error
import legacy_windows_feature_manage as feature_manage  # pylint: disable=import-error
import legacy_windows_wmi as wmi  # pylint: disable=import-error
import win_dns_zone_state as state_comparison  # pylint: disable=import-error

_ROOTS = (
    r"SYSTEM\CurrentControlSet\Services\DNS",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server",
    r"SOFTWARE\Microsoft\DNS",
)
_DNS_NAMESPACE = r"ROOT\Microsoft\Windows\Dns"
_CLASSIC_NAMESPACE = r"ROOT\MicrosoftDNS"
_PREPARATION_NAMES = ("DNS", "RSAT-DNS-Server", "RSAT-Role-Tools", "RSAT")
_DNS_DIRECTORY = os.path.join(os.environ["SystemRoot"], "System32", "dns")
_SERVICES_ROOT = r"SYSTEM\CurrentControlSet\Services"


# These classes describe native ABI data, not behavioral Python objects.
class _Luid(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_int32)]


class _Privileges(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("count", ctypes.c_uint32),
        ("luid", _Luid),
        ("attributes", ctypes.c_uint32),
    ]


def _libraries():
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security.GetNamedSecurityInfoW.argtypes = (
        [ctypes.c_wchar_p, ctypes.c_int, ctypes.c_uint32]
        + [ctypes.c_void_p] * 4
        + [ctypes.POINTER(ctypes.c_void_p)]
    )
    security.GetNamedSecurityInfoW.restype = ctypes.c_uint32
    security.GetSecurityDescriptorLength.argtypes = [ctypes.c_void_p]
    security.GetSecurityDescriptorLength.restype = ctypes.c_uint32
    security.RegQueryValueExW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    security.RegQueryValueExW.restype = ctypes.c_long
    security.OpenProcessToken.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    security.OpenProcessToken.restype = ctypes.c_int
    security.LookupPrivilegeValueW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(_Luid),
    ]
    security.LookupPrivilegeValueW.restype = ctypes.c_int
    security.AdjustTokenPrivileges.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.POINTER(_Privileges),
        ctypes.c_uint32,
        ctypes.POINTER(_Privileges),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    security.AdjustTokenPrivileges.restype = ctypes.c_int
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    kernel.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    kernel.GetFileAttributesW.restype = ctypes.c_uint32
    return security, kernel


@contextmanager
def _audit_privilege():
    security, kernel = _libraries()
    token = ctypes.c_void_p()
    if not security.OpenProcessToken(
        kernel.GetCurrentProcess(), 0x28, ctypes.byref(token)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    previous, needed = _Privileges(), ctypes.c_uint32()
    try:
        requested = _Privileges(count=1, attributes=2)
        if not security.LookupPrivilegeValueW(
            None, "SeSecurityPrivilege", ctypes.byref(requested.luid)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if (
            not security.AdjustTokenPrivileges(
                token,
                False,
                ctypes.byref(requested),
                ctypes.sizeof(previous),
                ctypes.byref(previous),
                ctypes.byref(needed),
            )
            or ctypes.get_last_error()
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            yield
        finally:
            if previous.count and not security.AdjustTokenPrivileges(
                token, False, ctypes.byref(previous), 0, None, None
            ):
                raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.CloseHandle(token)


def _security(path, kind):
    security, kernel = _libraries()
    descriptor = ctypes.c_void_p()
    error = security.GetNamedSecurityInfoW(
        path, kind, 15, None, None, None, None, ctypes.byref(descriptor)
    )
    if error:
        raise ctypes.WinError(error)
    try:
        return binascii.hexlify(
            ctypes.string_at(
                descriptor, security.GetSecurityDescriptorLength(descriptor)
            )
        ).decode("ascii")
    finally:
        kernel.LocalFree(descriptor)


def _registry(path):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ)
    except FileNotFoundError:
        return None
    with key:
        security, _kernel = _libraries()
        values, children = {}, {}
        count, value_count, _written = winreg.QueryInfoKey(key)
        for index in range(value_count):
            name = winreg.EnumValue(key, index)[0]
            kind, size = ctypes.c_uint32(), ctypes.c_uint32()
            error = security.RegQueryValueExW(
                int(key), name, None, ctypes.byref(kind), None, ctypes.byref(size)
            )
            if error:
                raise ctypes.WinError(error)
            buffer = ctypes.create_string_buffer(size.value)
            error = security.RegQueryValueExW(
                int(key), name, None, ctypes.byref(kind), buffer, ctypes.byref(size)
            )
            if error:
                raise ctypes.WinError(error)
            values[name] = [
                kind.value,
                binascii.hexlify(buffer.raw[: size.value]).decode("ascii"),
            ]
        for index in range(count):
            name = winreg.EnumKey(key, index)
            children[name] = _registry(path + "\\" + name)
        return {
            "values": values,
            "children": children,
            "security": _security("MACHINE\\" + path, 4),
        }


def _files():
    if not os.path.exists(_DNS_DIRECTORY):
        return None
    result = {}
    _security_api, kernel = _libraries()
    paths = [_DNS_DIRECTORY]
    for current, directories, files in os.walk(_DNS_DIRECTORY):
        paths.extend(os.path.join(current, name) for name in directories + files)
    for path in sorted(paths):
        attributes = kernel.GetFileAttributesW(path)
        assert attributes != 0xFFFFFFFF and not attributes & 0x400, path
        row = {"attributes": attributes, "security": _security(path, 1)}
        if not attributes & 0x10:
            with open(path, "rb") as stream:
                row["bytes"] = binascii.hexlify(stream.read()).decode("ascii")
        result[os.path.relpath(path, _DNS_DIRECTORY)] = row
    return result


def _services():
    with wmi.WmiConnection() as connection:
        rows = connection.query(
            "SELECT * FROM Win32_Service",
            [
                "Name",
                "DisplayName",
                "StartMode",
                "PathName",
                "StartName",
                "ServiceType",
                "ErrorControl",
                "DesktopInteract",
                "State",
            ],
        )
    result = {}
    for row in rows:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, os.path.join(_SERVICES_ROOT, row["Name"])
        ) as key:
            row["NativeServiceType"] = winreg.QueryValueEx(key, "Type")[0]
        if (
            row["Name"] not in ("DNS", "TrustedInstaller")
            and "bvsshserver" not in (row["PathName"] or "").lower()
        ):
            del row["State"]
        result[row["Name"]] = row
    return result


def _service_templates():
    templates = {}
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _SERVICES_ROOT) as parent:
        names = [
            winreg.EnumKey(parent, index)
            for index in range(winreg.QueryInfoKey(parent)[0])
        ]
    for name in names:
        path = os.path.join(_SERVICES_ROOT, name)
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            try:
                kind = winreg.QueryValueEx(key, "Type")[0]
            except FileNotFoundError:
                continue
        if kind & 0x40 and not kind & 0x80:
            templates[name] = _registry(path)
    return templates


# Full fixture observations require the provider's native schema helpers.
# pylint: disable=protected-access
def _components():
    try:
        with wmi.WmiConnection(feature_info._NAMESPACE) as connection:
            return {
                row["UniqueName"]: row for row in feature_info._components(connection)
            }
    except OSError as error:
        if getattr(error, "hresult", None) not in (0x8004100E, 0x80041010):
            raise
    tool = feature_info.legacy.executable()
    if tool is None:
        return None
    with feature_info.legacy.ServerManager(tool) as manager:
        return {row["UniqueName"]: row for row in manager.catalogue()}


def _catalogue(workspace):
    tool = os.path.join(os.environ["SystemRoot"], "System32", "dism.exe")
    with subprocess.Popen(
        [
            tool,
            "/Online",
            "/English",
            "/Get-Features",
            "/LogPath:" + os.path.join(workspace, "dns-zone-servicing.log"),
            "/ScratchDir:" + workspace,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as child:
        stdout, stderr = child.communicate()
    assert child.returncode == 0, (stdout, stderr)
    records = re.findall(
        r"^Feature Name\s*:\s*([^\r\n]+)\r?\nState\s*:\s*([^\r\n]+)",
        stdout.decode("mbcs", "replace"),
        re.MULTILINE,
    )
    assert records and len(records) == len({name for name, _state in records})
    return {name.strip(): state.strip() for name, state in records}


def _native_dns():
    try:
        with wmi.WmiConnection(_CLASSIC_NAMESPACE) as connection:
            result = {}
            for class_name in (
                "MicrosoftDNS_Server",
                "MicrosoftDNS_Zone",
                "MicrosoftDNS_ResourceRecord",
            ):
                rows = []
                with ExitStack() as stack:
                    enumeration = wmi._query(
                        connection._services,
                        connection._automation,
                        stack,
                        "SELECT * FROM " + class_name,
                        0x30,
                    )
                    advance = wmi._method(
                        enumeration,
                        4,
                        wmi._LONG,
                        [
                            wmi._LONG,
                            wmi._ULONG,
                            wmi._POINTER_OUT,
                            ctypes.POINTER(wmi._ULONG),
                        ],
                    )
                    while True:
                        with ExitStack() as row_cleanup:
                            instance, returned = wmi._POINTER(), wmi._ULONG()
                            row_cleanup.callback(wmi._release, instance)
                            status = advance(
                                enumeration,
                                -1,
                                1,
                                ctypes.byref(instance),
                                ctypes.byref(returned),
                            )
                            wmi._check(status, "IEnumWbemClassObject.Next")
                            if not returned.value:
                                break
                            assert returned.value == 1 and instance
                            # RootHints records can be enumerated but cannot be
                            # reopened by their advertised object paths.
                            rows.append(
                                wmi._read_embedded_object(
                                    connection._automation, instance
                                )
                            )
                            if status == 1:
                                break
                result[class_name] = sorted(
                    rows, key=lambda row: json.dumps(row, sort_keys=True)
                )
            return result
    except OSError as error:
        if (
            getattr(error, "hresult", None) in (0x8004100E, 0x80041010)
            and "DNS" not in _services()
        ):
            return None
        raise


def _security_bytes(instance, automation):
    value, cim_type = wmi._Variant(), wmi._LONG()
    get = wmi._method(
        instance,
        4,
        wmi._LONG,
        [
            ctypes.c_wchar_p,
            wmi._LONG,
            ctypes.POINTER(wmi._Variant),
            ctypes.POINTER(wmi._LONG),
            ctypes.POINTER(wmi._LONG),
        ],
    )
    try:
        wmi._check(
            get(instance, "SD", 0, ctypes.byref(value), ctypes.byref(cim_type), None),
            "IWbemClassObject.Get(SD)",
        )
        assert value.kind == 0x2011
        assert automation.SafeArrayGetDim(value.data.array) == 1
        lower, upper = wmi._LONG(), wmi._LONG()
        wmi._check(
            automation.SafeArrayGetLBound(value.data.array, 1, ctypes.byref(lower)),
            "SD lower bound",
        )
        wmi._check(
            automation.SafeArrayGetUBound(value.data.array, 1, ctypes.byref(upper)),
            "SD upper bound",
        )
        result = []
        for position in range(lower.value, upper.value + 1):
            index, byte = wmi._LONG(position), ctypes.c_uint8()
            # SAFEARRAY's native element destination is void*. The shared
            # declaration types it for pointer elements, but this array owns bytes.
            destination = ctypes.cast(ctypes.byref(byte), wmi._POINTER_OUT)
            wmi._check(
                automation.SafeArrayGetElement(
                    value.data.array, ctypes.byref(index), destination
                ),
                "SD byte",
            )
            result.append(byte.value)
        return binascii.hexlify(bytes(result)).decode("ascii")
    finally:
        wmi._check(automation.VariantClear(ctypes.byref(value)), "VariantClear SD")


def _namespace_security(connection):
    with ExitStack() as stack:
        output = wmi._POINTER()
        stack.callback(wmi._release, output)
        execute = wmi._method(
            connection._services,
            24,
            result_type=wmi._LONG,
            argument_types=[
                wmi._POINTER,
                wmi._POINTER,
                wmi._LONG,
                wmi._POINTER,
                wmi._POINTER,
                wmi._POINTER_OUT,
                wmi._POINTER,
            ],
        )
        wmi._check(
            execute(
                connection._services,
                wmi._bstr(connection._automation, stack, "__SystemSecurity=@"),
                wmi._bstr(connection._automation, stack, "GetSD"),
                0,
                None,
                None,
                ctypes.byref(output),
                None,
            ),
            "IWbemServices.ExecMethod(GetSD)",
        )
        assert (
            output
            and wmi._read_property(output, connection._automation, "ReturnValue") == 0
        )
        return _security_bytes(output, connection._automation)


def _namespace_inventory(namespace):
    try:
        with wmi.WmiConnection(namespace) as connection:
            return {
                "classes": connection.query(
                    "SELECT * FROM meta_class", ["__CLASS", "__SUPERCLASS"]
                ),
                "providers": connection.query(
                    "SELECT * FROM __Win32Provider", ["Name", "CLSID", "HostingModel"]
                ),
                "children": connection.query("SELECT * FROM __Namespace", ["Name"]),
                "security": _namespace_security(connection),
            }
    except OSError as error:
        if getattr(error, "hresult", None) == 0x8004100E:
            return None
        raise


def _snapshot(workspace, include_roles=True):
    with _audit_privilege():
        dns = {
            "registry": {path: _registry(path) for path in _ROOTS},
            "files": _files(),
            "native": _native_dns(),
            "service_security": _security("DNS", 2) if "DNS" in _services() else None,
            "classic_namespace": _namespace_inventory(_CLASSIC_NAMESPACE),
            "modern_namespace": _namespace_inventory(_DNS_NAMESPACE),
        }
        templates = _service_templates()
    with wmi.WmiConnection() as connection:
        identity = connection.query(
            "SELECT * FROM Win32_OperatingSystem",
            ["Version", "BuildNumber", "LastBootUpTime"],
        )
    components = _components() if include_roles else None
    return {
        "dns": dns,
        "components": components,
        "features": _catalogue(workspace) if components is not None else None,
        "services": _services(),
        "service_templates": templates,
        "identity": identity,
        "python": sys.version,
    }


def _write(path, record):
    descriptor, temporary = tempfile.mkstemp(
        prefix=".dns-zone-journal-", dir=os.path.dirname(path)
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(record, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)


def _read(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def _restore_worker(original):
    old = original["TrustedInstaller"]
    current = _services()["TrustedInstaller"]
    assert {key: value for key, value in old.items() if key != "State"} == {
        key: value for key, value in current.items() if key != "State"
    }
    if old["State"] != current["State"]:
        assert old["State"] in ("Stopped", "Running")
        action = "stop" if old["State"] == "Stopped" else "start"
        with subprocess.Popen(
            [
                os.path.join(os.environ["SystemRoot"], "System32", "sc.exe"),
                action,
                "TrustedInstaller",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as child:
            stdout, stderr = child.communicate()
        assert child.returncode == 0, (stdout, stderr)
        deadline = time.monotonic() + 45
        while _services()["TrustedInstaller"] != old:
            assert time.monotonic() < deadline
            time.sleep(0.1)


def _delete_initially_absent_key(path, original):
    if original is not None:
        assert _registry(path) == original
        return
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ | winreg.KEY_WRITE
        )
    except FileNotFoundError:
        return
    with key:
        children = [
            winreg.EnumKey(key, index) for index in range(winreg.QueryInfoKey(key)[0])
        ]
    for child in children:
        _delete_initially_absent_key(path + "\\" + child, None)
    winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, path)


def _setup(workspace):
    journal = os.path.join(workspace, "dns-zone-journal.json")
    assert not os.path.exists(journal)
    # Record the worker's state before the first Server Manager enumeration.
    record = {
        "workspace": workspace,
        "before": _snapshot(workspace, False),
        "zones": [],
        "prepared": None,
    }
    _write(journal, record)
    record["before"]["components"] = _components()
    record["before"]["features"] = (
        _catalogue(workspace) if record["before"]["components"] is not None else None
    )
    _write(journal, record)
    _restore_worker(record["before"]["services"])
    return record


def _prepared(workspace):
    journal = os.path.join(workspace, "dns-zone-journal.json")
    record = _read(journal)
    record["prepared"] = _snapshot(workspace)
    before, after = record["before"]["components"], record["prepared"]["components"]
    assert before is not None and after is not None
    changed = [
        name for name in before if before[name]["Installed"] != after[name]["Installed"]
    ]
    assert set(changed).issubset(_PREPARATION_NAMES), changed
    record["role_changes"] = changed
    _write(journal, record)
    return record["prepared"]


def _note_reboot(workspace):
    journal = os.path.join(workspace, "dns-zone-journal.json")
    record = _read(journal)
    assert record["workspace"] == workspace and not record["zones"]
    before, current = record["before"]["components"], _components()
    changed = [
        name
        for name in before
        if before[name]["Installed"] != current[name]["Installed"]
    ]
    assert set(changed).issubset(_PREPARATION_NAMES), changed
    assert all(before[name]["Installed"] == 0 for name in changed)
    with _audit_privilege():
        record.setdefault("owned_role_artifacts", {})["files"] = _files()
    with wmi.WmiConnection() as connection:
        record["recovery_boot_before"] = connection.query(
            "SELECT * FROM Win32_OperatingSystem", ["LastBootUpTime"]
        )[0]["LastBootUpTime"]
    record["servicing_reboot"] = True
    _write(journal, record)
    return {
        "journaled": True,
        "boot_before": record["recovery_boot_before"],
        "changed_roles": changed,
        "files": record["owned_role_artifacts"]["files"],
    }


def _remove_owned_roles(record, journal):
    before = record["before"]
    current = _components()
    changed = [
        name
        for name in before["components"]
        if bool(current[name]["Installed"])
        != bool(before["components"][name]["Installed"])
    ]
    assert set(changed).issubset(_PREPARATION_NAMES), changed
    for name in changed:
        assert before["components"][name]["Installed"] == 0
    # Remove the role/tools before their container ancestors, never an original role.
    for names in (("DNS", "RSAT-DNS-Server"), ("RSAT-Role-Tools",), ("RSAT",)):
        selected = [name for name in names if name in changed]
        if selected:
            packet = feature_manage.manage(
                {
                    "names": selected,
                    "state": "absent",
                    "include_sub_features": False,
                    "include_management_tools": False,
                    "source": None,
                },
                False,
            )
            assert packet["success"], packet
            if packet["reboot_required"]:
                record["removal_requires_reboot"] = True
                _write(journal, record)
                return {
                    "restored": False,
                    "requires_reboot": True,
                    "role_result": packet,
                }
    return None


def _remove_owned_namespace(record, journal):
    if record["before"]["dns"]["classic_namespace"] is not None:
        return
    actual = _namespace_inventory(_CLASSIC_NAMESPACE)
    if actual is None:
        return
    expected = record["prepared"]["dns"]["classic_namespace"]
    assert expected is not None and not actual["children"]
    assert state_comparison._class_catalogue(
        actual
    ) == state_comparison._class_catalogue(expected)
    record["namespace_before_deletion"] = actual
    _write(journal, record)
    # Only the literal child proved absent before our role installation is owned.
    with wmi.WmiConnection("ROOT") as connection, ExitStack() as stack:
        delete = wmi._method(
            connection._services,
            16,
            wmi._LONG,
            [wmi._POINTER, wmi._LONG, wmi._POINTER, wmi._POINTER],
        )
        wmi._check(
            delete(
                connection._services,
                wmi._bstr(
                    connection._automation, stack, '__Namespace.Name="MicrosoftDNS"'
                ),
                0,
                None,
                None,
            ),
            "IWbemServices.DeleteInstance(owned MicrosoftDNS namespace)",
        )
    assert _namespace_inventory(_CLASSIC_NAMESPACE) is None


def _remove_owned_files(record, journal):
    if record["before"]["dns"]["files"] is not None or not os.path.exists(
        _DNS_DIRECTORY
    ):
        return
    expected = record.get("owned_role_artifacts", {}).get("files")
    if expected is None and record["prepared"]:
        expected = record["prepared"]["dns"]["files"]
    assert expected is not None
    with _audit_privilege():
        actual = _files()
    updates = {}
    for path, value in actual.items():
        assert path in expected, "Unjournaled DNS preparation file: " + path
        if value == expected[path]:
            continue
        # Stopping DNS appends its shutdown header to this role-created log.
        # Keep both byte streams, and reject any other path/security/attribute change.
        original = expected[path]
        assert (
            path == "dns.log"
            and {key: item for key, item in value.items() if key != "bytes"}
            == {key: item for key, item in original.items() if key != "bytes"}
            and value["bytes"].startswith(original["bytes"])
        ), ("DNS preparation file changed unexpectedly: " + path)
        updates[path] = {"before": original, "after": value}
    record["owned_shutdown_log_updates"] = updates
    _write(journal, record)
    for relative in sorted(
        actual, key=lambda value: (value.count(os.sep), len(value)), reverse=True
    ):
        path = (
            _DNS_DIRECTORY
            if relative == os.curdir
            else os.path.join(_DNS_DIRECTORY, relative)
        )
        if actual[relative]["attributes"] & 0x10:
            os.rmdir(path)
        else:
            os.remove(path)


def _comparison_snapshot(snapshot):
    compared = dict(snapshot)
    compared["components"] = state_comparison._comparable_components(
        snapshot["components"]
    )
    compared["dns"] = dict(snapshot["dns"])
    # WMI meta_class enumeration has changed row order even without servicing.
    # Compare class identity/definitions, retaining both raw row arrays separately.
    for key in ("classic_namespace", "modern_namespace"):
        compared["dns"][key] = state_comparison._class_catalogue(snapshot["dns"][key])
    return compared


def _qualify_servicing_boot(record, after, comparison_before, comparison_after):
    before = record["before"]
    assert after["identity"][0]["LastBootUpTime"] != record["recovery_boot_before"]
    assert after["service_templates"] == before["service_templates"]
    missing = set(before["services"]) - set(after["services"])
    assert not set(after["services"]) - set(before["services"])
    for name in missing:
        template, separator, suffix = name.rpartition("_")
        assert separator and re.match(r"^[0-9a-f]+$", suffix, re.IGNORECASE)
        assert template in before["service_templates"]
        assert before["services"][name]["NativeServiceType"] & 0xC0 == 0xC0
        assert before["service_templates"][template]["values"]["Type"][0] == 4
        kind = int.from_bytes(
            binascii.unhexlify(
                before["service_templates"][template]["values"]["Type"][1]
            ),
            "little",
        )
        assert kind & 0x40 and not kind & 0x80
    comparison_before["services"] = {
        name: row for name, row in before["services"].items() if name not in missing
    }
    for compared in (comparison_before, comparison_after):
        compared["identity"] = [
            {key: value for key, value in row.items() if key != "LastBootUpTime"}
            for row in compared["identity"]
        ]
    record["deleted_per_user_instances"] = sorted(missing)


def _verify_recovery(record, workspace):
    before = record["before"]
    deadline = time.monotonic() + 45
    while True:
        after = _snapshot(workspace)
        _restore_worker(before["services"])
        after["services"] = _services()
        comparison_after = _comparison_snapshot(after)
        comparison_before = _comparison_snapshot(before)
        if record.get("servicing_reboot"):
            _qualify_servicing_boot(record, after, comparison_before, comparison_after)
        if comparison_after == comparison_before:
            break
        assert time.monotonic() < deadline, {"before": before, "after": after}
        time.sleep(0.5)
    record["verified"] = after
    return {
        "restored": True,
        "before": before,
        "after": after,
        "raw_metadata_order_equal": after["components"] == before["components"],
        "metadata_order_qualification": ["SubFeatures", "OptionalCompanions"],
        "servicing_reboot": bool(record.get("servicing_reboot")),
        "deleted_per_user_instances": record.get("deleted_per_user_instances", []),
    }


def _cleanup(workspace):
    journal = os.path.join(workspace, "dns-zone-journal.json")
    if not os.path.exists(journal):
        assert not os.listdir(workspace), "Unjournaled workspace is not empty"
        return {"restored": True, "journal_absent": True}
    record = _read(journal)
    assert record["workspace"] == workspace
    assert not record["zones"], "Owned zone cleanup must precede role cleanup"
    pending = _remove_owned_roles(record, journal)
    if pending:
        return pending
    before = record["before"]
    _restore_worker(before["services"])
    if before["dns"]["native"] is None:
        assert "DNS" not in _services()
        with _audit_privilege():
            for path in _ROOTS:
                _delete_initially_absent_key(path, before["dns"]["registry"][path])
        _remove_owned_files(record, journal)
        _remove_owned_namespace(record, journal)
    result = _verify_recovery(record, workspace)
    _write(journal, record)
    return result


def _finalize(workspace):
    path = os.path.join(workspace, "dns-zone-journal.json")
    if not os.path.exists(path):
        assert not os.listdir(workspace)
        return {"finalized": True, "journal_absent": True}
    record = _read(path)
    assert record["workspace"] == workspace and record.get("verified")
    assert _verify_recovery(record, workspace)["restored"]
    os.remove(path)
    return {"finalized": True}


def _zone_options(name, zone_type, servers=None):
    return {
        "name": name,
        "type": zone_type,
        "state": "present",
        "replication": "none",
        "dynamic_update": "none" if zone_type == "primary" else None,
        "dns_servers": servers,
        "forwarder_timeout": None,
        "directory_partition": None,
    }


def _register_zone(workspace):
    journal = os.path.join(workspace, "dns-zone-journal.json")
    record = _read(journal)
    assert (
        record["workspace"] == workspace
        and record["prepared"] is not None
        and not record["zones"]
    )
    name = "dz" + hashlib.sha256(workspace.encode("utf-8")).hexdigest()[:8] + ".test"
    # This classic catalogue also exists alongside the modern DNS provider;
    # observe ownership independently of the provider the public module selects.
    with wmi.WmiConnection(_CLASSIC_NAMESPACE) as connection:
        rows = connection.query("SELECT * FROM MicrosoftDNS_Zone", ["Name"])
    assert all(row["Name"].lower() != name for row in rows)
    assert not os.path.exists(os.path.join(_DNS_DIRECTORY, name + ".dns"))
    record["zones"].append(name)
    _write(journal, record)
    return {"name": name, "journaled": True}


def _reset_zone(workspace):
    journal = os.path.join(workspace, "dns-zone-journal.json")
    record = _read(journal)
    assert record["workspace"] == workspace and len(record["zones"]) == 1
    name = record["zones"][0]
    options = _zone_options(name, None)
    options["state"] = "absent"
    result = dns_zone.manage(options)
    assert not result.get("failed"), result
    with _audit_privilege():
        files = _files()
    path = name + ".dns"
    if path in files:
        record.setdefault("owned_zone_files", {})[path] = files[path]
        _write(journal, record)
        os.remove(os.path.join(_DNS_DIRECTORY, path))
    return {"reset": True, "name": name}


def _seed_zone(workspace):
    _reset_zone(workspace)
    record = _read(os.path.join(workspace, "dns-zone-journal.json"))
    zone_type = sys.argv[3]
    assert zone_type in ("primary", "secondary", "stub", "forwarder")
    master = sys.argv[4] if len(sys.argv) > 4 else "127.0.0.1"
    result = dns_zone.manage(
        _zone_options(
            record["zones"][0],
            zone_type,
            [master] if zone_type != "primary" else None,
        )
    )
    assert not result.get("failed"), result
    return result


def _zones_cleanup(workspace):
    journal = os.path.join(workspace, "dns-zone-journal.json")
    record = _read(journal)
    _reset_zone(workspace)
    record = _read(journal)
    with _audit_privilege():
        current_files = _files()
    assert current_files == record["prepared"]["dns"]["files"]
    native = _native_dns()
    expected = record["prepared"]["dns"]["native"]
    role_owned = record["before"]["dns"]["native"] is None
    server = "MicrosoftDNS_Server"
    initialization = state_comparison._role_initialization(
        expected[server], native[server], role_owned
    )
    compared_native = dict(native)
    if initialization:
        # This newly installed role initialized during the owned operations.
        # Its original absent state must still be recovered by role removal.
        compared_native[server] = expected[server]
    record["owned_role_initialization"] = initialization
    # These two role-created localhost records count down in the native cache.
    # Retain both raw rows; public zone/record result arrays remain literal.
    countdown = state_comparison._cache_countdown(
        expected,
        compared_native,
        role_owned,
    )
    record["cache_countdown_qualification"] = countdown
    record["zones"] = []
    record.setdefault("owned_role_artifacts", {})["files"] = current_files
    _write(journal, record)
    return {
        "restored": True,
        "files": current_files,
        "native": native,
        "cache_countdown_qualification": countdown,
        "owned_role_initialization": initialization,
    }


def _main():
    assert sys.version_info[:3] == (3, 4, 4)
    workspace, operation = sys.argv[1:3]
    assert os.path.basename(os.path.abspath(workspace)).startswith(
        "legacy-windows-dns-zone-"
    )
    assert os.path.samefile(
        os.path.dirname(os.path.abspath(workspace)), tempfile.gettempdir()
    )
    operations = {
        "setup": _setup,
        "prepared": _prepared,
        "note_reboot": _note_reboot,
        "cleanup": _cleanup,
        "finalize": _finalize,
        "register_zone": _register_zone,
        "reset_zone": _reset_zone,
        "seed_zone": _seed_zone,
        "zones_cleanup": _zones_cleanup,
    }
    print(json.dumps(operations[operation](workspace), sort_keys=True))


if __name__ == "__main__":
    _main()
