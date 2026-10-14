# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read local directory roles and run the installed unattended promotion tool."""

import ctypes
import locale
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from contextlib import contextmanager

from legacy_ad_ldap import SCOPE_BASE, LDAPConnection  # pylint: disable=import-error

# Share the concrete controller-discovery ABI, without opening a trust policy.
from legacy_ad_trust_native import (  # pylint: disable=import-error,protected-access
    _ControllerInformation,
)
from legacy_windows_service import control  # pylint: disable=import-error
from legacy_windows_wmi import WmiConnection  # pylint: disable=import-error

_MODES = {
    "default": None,
    "win2003": 2,
    "win2008": 3,
    "win2008r2": 4,
    "win2012": 5,
    "win2012r2": 6,
    "winthreshold": 7,
    "win2025": 10,
}
_DS_DIRECTORY_SERVICE_REQUIRED = 0x00000010
_DS_GC_SERVER_REQUIRED = 0x00000040
_DS_IS_DNS_NAME = 0x00020000
_DS_RETURN_DNS_NAME = 0x40000000

# The older GUI engine does not implement /?:Promotion or /?:Demotion. These
# invariant fields are its documented native answer interface, not console help.
_LEGACY_ANSWER_FIELDS = (
    "ReplicaOrNewDomain",
    "NewDomain",
    "NewDomainDNSName",
    "ChildName",
    "ParentDomainDNSName",
    "ReplicaDomainDNSName",
    "RebootOnSuccess",
    "SafeModeAdminPassword",
    "UserName",
    "UserDomain",
    "Password",
    "DomainNetbiosName",
    "DatabasePath",
    "LogPath",
    "SYSVOLPath",
    "AutoConfigDNS",
    "DNSOnNetwork",
    "SiteName",
    "ReplicationSourceDC",
    "ReplicationSourcePath",
    "AdministratorPassword",
    "IsLastDCInDomain",
)


class _SecurityAttributes(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("length", ctypes.c_uint32),
        ("descriptor", ctypes.c_void_p),
        ("inherit", ctypes.c_int),
    ]


def current_state():
    """Read the running host's directory role without changing its configuration.

    :returns: Hostname, domain name and native DomainRole integer.
    :rtype: dict
    :raises OSError: Windows returns no unique computer-system role.
    """
    with WmiConnection() as connection:
        rows = connection.query(
            "SELECT Name,Domain,DomainRole FROM Win32_ComputerSystem",
            ["Name", "Domain", "DomainRole"],
        )
    if len(rows) != 1 or rows[0]["DomainRole"] is None:
        raise OSError("Windows returned no unique computer-system domain role.")
    return {
        "hostname": rows[0]["Name"],
        "domain": rows[0]["Domain"],
        "role": int(rows[0]["DomainRole"]),
    }


def is_domain_controller():
    """Read the active OS product role used by the released forest-creation test.

    :returns: Whether Win32_OperatingSystem reports the domain-controller role.
    :rtype: bool
    :raises OSError: Windows returns no unique operating-system product role.
    """
    with WmiConnection() as connection:
        rows = connection.query(
            "SELECT ProductType FROM Win32_OperatingSystem", ["ProductType"]
        )
    if len(rows) != 1 or rows[0]["ProductType"] is None:
        raise OSError("Windows returned no unique operating-system product role.")
    return int(rows[0]["ProductType"]) == 2


def forest_exists(name):
    """Check native forest discovery without creating a domain or using credentials.

    :param name: Requested forest DNS name.
    :type name: str
    :returns: Whether a domain controller in the requested forest is discoverable.
    :rtype: bool
    :raises OSError: Native discovery fails for a reason other than absence.
    """
    library = ctypes.WinDLL("netapi32", use_last_error=True)
    library.DsGetDcNameW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    library.DsGetDcNameW.restype = ctypes.c_uint32
    library.NetApiBufferFree.argtypes = [ctypes.c_void_p]
    library.NetApiBufferFree.restype = ctypes.c_uint32
    buffer = ctypes.c_void_p()
    try:
        code = library.DsGetDcNameW(
            None,
            name,
            None,
            None,
            _DS_DIRECTORY_SERVICE_REQUIRED
            | _DS_GC_SERVER_REQUIRED
            | _DS_IS_DNS_NAME
            | _DS_RETURN_DNS_NAME,
            ctypes.byref(buffer),
        )
        if code in (1355, 1908, 1722):
            return False
        if code:
            raise OSError(
                code, "Discover requested forest: " + ctypes.FormatError(code).strip()
            )
        if not buffer:
            raise OSError("Windows returned no discovered forest controller.")
        information = ctypes.cast(
            buffer, ctypes.POINTER(_ControllerInformation)
        ).contents
        return bool(
            information.forest_name and information.forest_name.lower() == name.lower()
        )
    finally:
        if buffer:
            library.NetApiBufferFree(buffer)


def assigned_roles(hostname):
    """Identify operation-master roles owned by this exact controller.

    :param hostname: Local host's computer-system name.
    :type hostname: str
    :returns: Existing FSMO role names, in the released display order.
    :rtype: list[str]
    :raises OSError: Authenticated local LDAP role discovery fails.
    :raises ValueError: The local controller identity is unavailable.
    """
    with LDAPConnection(hostname) as connection:
        root = connection.search("", SCOPE_BASE, "(objectClass=*)", ["dsServiceName"])
        values = (
            {name.lower(): value for name, value in root[0]["attributes"].items()}
            if len(root) == 1
            else {}
        )
        if not values.get("dsservicename"):
            raise ValueError(
                "The local controller does not advertise its NTDS service identity."
            )
        service_dn = values["dsservicename"][0].decode("utf-8").lower()
        domain = connection.naming_context()
        configuration = connection.naming_context("configurationNamingContext")
        schema = connection.naming_context("schemaNamingContext")
        roles = []
        for name, dn in (
            ("PDCEmulator", domain),
            ("RIDMaster", "CN=RID Manager$,CN=System," + domain),
            ("InfrastructureMaster", "CN=Infrastructure," + domain),
            ("SchemaMaster", schema),
            ("DomainNamingMaster", "CN=Partitions," + configuration),
        ):
            rows = connection.search(
                dn, SCOPE_BASE, "(objectClass=*)", ["fSMORoleOwner"]
            )
            owner = (
                {key.lower(): value for key, value in rows[0]["attributes"].items()}
                if len(rows) == 1
                else {}
            )
            if not owner.get("fsmoroleowner"):
                raise ValueError(
                    "Cannot determine the owner of operation master role " + name + "."
                )
            if owner["fsmoroleowner"][0].decode("utf-8").lower() == service_dn:
                roles.append(name)
        return roles


def _functional_attributes(connection, dn, names):
    rows = connection.search(dn, SCOPE_BASE, "(objectClass=*)", names)
    if len(rows) != 1:
        raise ValueError("Cannot read a unique functional-level directory entry.")
    return {name.lower(): values for name, values in rows[0]["attributes"].items()}


def complete_legacy_levels(dns_name, include_forest, result):
    """Finish the measured older promotion's levels after its requested reboot.

    This operation is only dispatched by the controller immediately after this
    task successfully creates a domain; ordinary existing-domain tasks skip it.

    :param dns_name: Exact domain that the preceding promotion created.
    :type dns_name: str
    :param include_forest: Whether this task created the forest root as well.
    :type include_forest: bool
    :param result: Result retaining each successful change on a later failure.
    :type result: dict
    :raises OSError: Native directory reads or modifications fail.
    :raises ValueError: The local domain or available level differs from the task.
    """
    state = current_state()
    if state["role"] not in (4, 5) or state["domain"].lower() != dns_name.lower():
        raise ValueError(
            "Cannot complete functional levels: the local controller is not in "
            + dns_name
            + "."
        )
    with LDAPConnection(state["hostname"]) as connection:
        attributes = _functional_attributes(
            connection, "", ["domainControllerFunctionality"]
        )
        if attributes.get("domaincontrollerfunctionality") != [b"2"]:
            raise ValueError(
                "The local controller does not provide normal Windows 2003 "
                "functional-level completion."
            )
        domain = connection.naming_context()
        partitions = "CN=Partitions," + connection.naming_context(
            "configurationNamingContext"
        )
        for dn, fields in (
            (domain, (("nTMixedDomain", 0), ("msDS-Behavior-Version", 2))),
            (partitions, (("msDS-Behavior-Version", 2),) if include_forest else ()),
        ):
            if not fields:
                continue
            values = _functional_attributes(
                connection, dn, [name for name, _value in fields]
            )
            for name, desired in fields:
                current = values.get(name.lower())
                if not current or len(current) != 1:
                    raise ValueError("Cannot read functional-level attribute " + name)
                if int(current[0]) == desired:
                    continue
                if name == "msDS-Behavior-Version" and int(current[0]) > desired:
                    raise ValueError(
                        "Cannot lower an existing directory functional level."
                    )
                # Microsoft requires native domain mode before raising behavior.
                # Each ordered write is retained if a later write fails.
                connection.modify(dn, [(2, name, [str(desired).encode("ascii")])])
                result["changed"] = True


def _engine_path():
    if os.name != "nt":
        raise OSError("Directory promotion requires a Windows target.")
    root = os.environ.get("SystemRoot")
    if not root:
        raise OSError("Windows does not advertise its system directory.")
    for directory in ("Sysnative", "System32"):
        path = os.path.join(root, directory, "dcpromo.exe")
        if os.path.isfile(path):
            return path
    raise OSError(
        "The target does not provide an unattended dcpromo.exe promotion engine."
    )


def _help(engine, operation):
    with subprocess.Popen(
        [engine, "/?:" + operation], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    ) as process:
        try:
            output = process.communicate(timeout=30)[0]
        except subprocess.TimeoutExpired as error:
            # This read-only help request has no role-change work to preserve.
            process.terminate()
            process.communicate()
            raise OSError(
                "The installed promotion engine did not return unattended "
                + operation.lower()
                + " help."
            ) from error
    return output.decode(locale.getpreferredencoding(False), "replace")


def _legacy_answer_format():
    # Windows exposes this standard-library API only on Windows targets.
    return sys.getwindowsversion().major < 6  # pylint: disable=no-member


def _levels(help_text, field):
    match = re.search(r"\b" + field + r"\s*:\s*\{([^}]+)\}", help_text, re.I)
    return (
        {int(value) for value in re.findall(r"\b\d+\b", match.group(1))}
        if match
        else set()
    )


def mode_value(name):
    """Convert a released functional-level name without implying engine support.

    :param name: Requested ADDS functional-level name, or None.
    :type name: str or None
    :returns: Documented native numeric level, or None for the engine default.
    :rtype: int or None
    :raises ValueError: The named level is not a released interface choice.
    """
    if name is None:
        return None
    if name.lower() not in _MODES:
        raise ValueError("Unknown directory functional level: " + name)
    return _MODES[name.lower()]


def _answer_bytes(settings):
    lines = ["[DCINSTALL]"]
    for name, value in settings.items():
        if (
            name in ("Password", "SafeModeAdminPassword", "AdministratorPassword")
            and value == "*"
        ):
            raise ValueError(
                "A literal '*' password is reserved for interactive prompting "
                "by the unattended promotion interface."
            )
        if "\r" in value or "\n" in value or "\0" in value:
            raise ValueError(
                "The unattended "
                + name
                + " value cannot contain line breaks or NUL characters."
            )
        lines.append(name + '="' + value + '"')
    contents = "\r\n".join(lines) + "\r\n"
    try:
        return contents.encode("ascii")
    except UnicodeEncodeError:
        # Native dcpromo reads the BOM; UTF-8 would corrupt non-ASCII secrets.
        return b"\xff\xfe" + contents.encode("utf-16-le")


@contextmanager
def _private_input(contents):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    pointer = ctypes.c_void_p
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.POINTER(pointer),
        ctypes.c_void_p,
    ]
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = ctypes.c_int
    kernel.CreateDirectoryW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.POINTER(_SecurityAttributes),
    ]
    kernel.CreateDirectoryW.restype = ctypes.c_int
    kernel.LocalFree.argtypes, kernel.LocalFree.restype = [pointer], pointer
    descriptor = pointer()
    directory = os.path.join(
        tempfile.gettempdir(), "legacy-ad-promotion-" + uuid.uuid4().hex
    )
    created = False
    try:
        if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", 1, ctypes.byref(descriptor), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        attributes = _SecurityAttributes(
            ctypes.sizeof(_SecurityAttributes), descriptor, False
        )
        if not kernel.CreateDirectoryW(directory, ctypes.byref(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())
        created = True
        answer = os.path.join(directory, "answer.ini")
        with open(answer, "xb") as stream:
            stream.write(contents)
        yield answer
    finally:
        if descriptor:
            kernel.LocalFree(descriptor)
        if created:
            shutil.rmtree(directory)


@contextmanager
def _private_answer(settings):
    with _private_input(_answer_bytes(settings)) as answer:
        yield answer


def _dns_installed():
    with WmiConnection() as connection:
        rows = connection.query(
            "SELECT Name FROM Win32_Service WHERE Name='DNS'", ["Name"]
        )
    if not rows:
        return False
    if len(rows) != 1 or not rows[0].get("Name"):
        raise OSError("Windows returned no unique DNS service installation state.")
    return True


class PromotionEngine:
    """Validate and run the installed engine's native unattended answer format."""

    def __init__(self, demotion=False):
        self.path = _engine_path()
        self.legacy_answer_format = _legacy_answer_format()
        self.help = (
            "\n".join(_LEGACY_ANSWER_FIELDS)
            if self.legacy_answer_format
            else _help(self.path, "Demotion" if demotion else "Promotion")
        )
        if not self.help.strip():
            raise OSError(
                "The installed promotion engine does not advertise "
                "unattended operation capabilities."
            )

    def supports(self, field):
        """Check an invariant option supported by the native answer format.

        :param field: Unattended option name.
        :type field: str
        :returns: Whether the engine supports that answer option.
        :rtype: bool
        """
        return bool(re.search(r"\b" + re.escape(field) + r"\b", self.help, re.I))

    def functional_level(self, name, field):
        """Select or validate a functional level supported by this engine.

        :param name: Requested released name, or None for the highest default.
        :type name: str or None
        :param field: DomainLevel or ForestLevel native option.
        :type field: str
        :returns: Supported level as text, or None when the engine owns its default.
        :rtype: str or None
        :raises ValueError: An explicit level is not advertised by this engine.
        """
        levels = _levels(self.help, field)
        value = mode_value(name)
        if value is None:
            return str(max(levels)) if levels else None
        if value not in levels:
            raise ValueError(
                "The installed promotion engine does not support "
                + field
                + "="
                + name
                + "."
            )
        return str(value)

    def validate(self, settings):
        """Reject unsupported fields and unrepresentable input before any change.

        :param settings: Complete concrete promotion or demotion answer fields.
        :type settings: dict[str, str]
        :raises ValueError: A field is unavailable or cannot be represented safely.
        """
        for field in settings:
            if not self.supports(field):
                raise ValueError(
                    "The installed promotion engine does not support the "
                    + field
                    + " option."
                )
        if self.legacy_answer_format and any(
            ord(character) > 127 for character in settings.get("DatabasePath", "")
        ):
            raise ValueError(
                "The installed legacy promotion engine requires ASCII database_path values."
            )
        _answer_bytes(settings)

    def ensure_dns_installed(self, result):
        """Install missing DNS quietly before the older promotion engine runs.

        The older engine launches DNS setup with interactive network messages,
        which leaves DHCP hosts waiting on an invisible IP-configuration dialog.
        Installing the requested component through its quiet native interface
        avoids that prompt without changing the host's IP configuration.

        :param result: Mutable result retaining DNS installation on later failure.
        :type result: dict
        :raises OSError: Native state reads, installer startup or cleanup fails.
        :raises ValueError: The installer fails or does not install DNS.
        """
        if _dns_installed():
            return
        executable = os.path.join(os.path.dirname(self.path), "sysocmgr.exe")
        definition = os.path.join(os.environ["SystemRoot"], "inf", "sysoc.inf")
        if not os.path.isfile(executable) or not os.path.isfile(definition):
            raise OSError(
                "The target does not provide the native DNS component installer."
            )
        contents = b"[Components]\r\nNetOC=On\r\n[NetOptionalComponents]\r\nDNS=1\r\n"
        with _private_input(contents) as answer:
            with subprocess.Popen(
                [executable, "/i:" + definition, "/u:" + answer, "/q", "/r"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            ) as process:
                output = process.communicate()[0]
                code = process.returncode
            installed = _dns_installed()
            if installed:
                result["changed"] = True
            if code != 0 or not installed:
                raise ValueError(
                    "Failed to install the requested DNS service, exited with {0} "
                    "(DNS installed: {1}): {2}".format(
                        code,
                        installed,
                        output.decode(
                            locale.getpreferredencoding(False), "replace"
                        ).strip(),
                    )
                )

    def run(self, settings):
        """Run one unattended native operation with a restricted temporary answer.

        :param settings: Prevalidated concrete native answer values.
        :type settings: dict[str, str]
        :returns: Native exit code and decoded diagnostic output.
        :rtype: tuple[int, str]
        :raises OSError: Creating the answer, starting the process or cleanup fails.
            ``promotion_completed`` is true when cleanup fails after a successful
            native role change.
        :raises ValueError: The answer cannot be represented safely.
        """
        self.validate(settings)
        code = None
        try:
            with _private_answer(settings) as answer:
                with subprocess.Popen(
                    [self.path, "/answer:" + answer],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                ) as process:
                    output = process.communicate()[0]
                    code = process.returncode
        except OSError as error:
            if code in (1, 2, 3, 4):
                error.promotion_completed = True
            raise
        return code, output.decode(locale.getpreferredencoding(False), "replace")


def start_netlogon():
    """Start Netlogon after a role change so the connection can request reboot.

    :raises OSError: The native service-control operation fails.
    :raises ValueError: The service does not reach its started state.
    """
    control("Netlogon", "started")
