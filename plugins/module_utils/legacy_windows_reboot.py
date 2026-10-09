# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read pending-reboot registry indicators and the latest System 1074 event."""

import ctypes
import datetime
import re
import struct
import uuid

try:
    import winreg
except ImportError:
    winreg = None

# Sibling helpers are staged beside the Python 3.4 target payload.
# pylint: disable=import-error
from legacy_windows_module import DOTNET_WHITESPACE
from legacy_windows_reg_stat import read_value
from legacy_windows_time import local_ticks_to_file_time

# pylint: enable=import-error

_CURRENT_VERSION = r"SOFTWARE\Microsoft\Windows\CurrentVersion"
_CONTROL = r"SYSTEM\CurrentControlSet\Control"
_CBS = _CURRENT_VERSION + r"\Component Based Servicing\RebootPending"
_WINDOWS_UPDATE = _CURRENT_VERSION + r"\WindowsUpdate\Auto Update\RebootRequired"
_SESSION_MANAGER = _CONTROL + r"\Session Manager"
_COMPUTER_NAME = _CONTROL + r"\ComputerName"
_NETLOGON = r"SYSTEM\CurrentControlSet\Services\Netlogon"
_SERVER_MANAGER = (
    r"SOFTWARE\Microsoft\ServerManager\ServicingStorage\ServerComponentCache"
)
_FILETIME_EPOCH = datetime.datetime(1601, 1, 1)
_UNIX_FILETIME_SECONDS = 11644473600
_WARN_OVERLOAD_ERROR = 'Cannot find an overload for "Warn" and the argument count: "2".'


def _key_exists(path):
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ):
            return True
    except OSError as error:
        # PowerShell's registry provider treats access denial as existence.
        return getattr(error, "winerror", error.errno) in (5, 1346)


def _value(path, name):
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ) as key:
            return read_value(key, name, expand=True)[0]
    except OSError:
        # These four upstream property reads use ErrorAction SilentlyContinue.
        return None


def _domain_join_pending():
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, _NETLOGON, 0, winreg.KEY_READ
        ) as key:
            for index in range(winreg.QueryInfoKey(key)[1]):
                name = winreg.EnumValue(key, index)[0]
                if name.lower() in ("joindomain", "avoidspnset"):
                    return True
    except OSError:
        pass
    return False


def _truthy(value):
    if isinstance(value, list):
        return len(value) > 1 or (bool(value) and _truthy(value[0]))
    return bool(value)


def _same_name(left, right):
    compare = ctypes.WinDLL("kernel32", use_last_error=True).CompareStringW
    # Keep this independently staged wrapper's native comparison binding local.
    # pylint: disable=duplicate-code
    compare.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    compare.restype = ctypes.c_int
    # PowerShell's case-insensitive string comparison uses invariant culture.
    result = compare(
        0x7F,
        1,
        left,
        len(left.encode("utf-16-le", "surrogatepass")) // 2,
        right,
        len(right.encode("utf-16-le", "surrogatepass")) // 2,
    )
    if not result:
        raise ctypes.WinError(ctypes.get_last_error())
    return result == 2
    # pylint: enable=duplicate-code


def pending_reboot_reasons():
    """Read the six upstream reboot indicators without changing the registry.

    Registry reads use the target process's view. Missing or unreadable values
    do not indicate a reboot; the two key-presence checks count access-denied
    keys as present, matching the PowerShell registry provider.

    :returns: Source/description dictionaries in the upstream check order.
    :rtype: list[dict]
    :raises OSError: Native computer-name comparison fails.
    """
    reasons = []
    if _key_exists(_CBS):
        reasons.append(
            {
                "source": "component_based_servicing",
                "description": "Component Based Servicing has a pending reboot.",
            }
        )
    if _key_exists(_WINDOWS_UPDATE):
        reasons.append(
            {
                "source": "windows_update",
                "description": "Windows Update has installed updates that require a reboot.",
            }
        )
    if _truthy(_value(_SESSION_MANAGER, "PendingFileRenameOperations")):
        reasons.append(
            {
                "source": "pending_file_rename",
                "description": "There are pending file rename operations that require a reboot.",
            }
        )
    pending = _value(_COMPUTER_NAME + r"\ComputerName", "ComputerName")
    active = _value(_COMPUTER_NAME + r"\ActiveComputerName", "ComputerName")
    if _truthy(pending) and _truthy(active) and not _same_name(pending, active):
        reasons.append(
            {
                "source": "pending_computer_rename",
                "description": "Computer name change pending from '{0}' to '{1}'.".format(
                    active, pending
                ),
            }
        )
    if _domain_join_pending():
        reasons.append(
            {
                "source": "domain_join",
                "description": "A domain join operation is pending and requires a reboot.",
            }
        )
    if _truthy(_value(_SERVER_MANAGER, "RestartRequired")):
        reasons.append(
            {
                "source": "server_manager",
                "description": "Server Manager indicates a component change requires a reboot.",
            }
        )
    return reasons


def _integer_text(text):
    text = text.strip(DOTNET_WHITESPACE)
    if text.startswith("#") or text[:2].lower() in ("0x", "&h"):
        digits = text[1 if text.startswith("#") else 2 :]
        if not re.match(r"\+?[0-9a-fA-F]+\Z", digits):
            raise ValueError("Invalid hexadecimal integer.")
        number = int(digits, 16)
        if number >= 1 << 64:
            raise OverflowError("Hexadecimal integer exceeds Int64.")
        return number - (1 << 64) if number >= 1 << 63 else number
    if re.match(r"[+-]?[0-9]+\Z", text):
        return int(text, 10)
    floating = r"[+-]?(?:[0-9][0-9,]*(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\Z"
    if re.match(floating, text):
        return int(round(float(text.replace(",", ""))))
    raise ValueError("Invalid integer text.")


def _reason_code(value):
    # Returning a failed array conversion enumerates it into the pipeline.
    if isinstance(value, list):
        return value[0] if len(value) == 1 else value or {}
    if value is None or value == "":
        return 0
    try:
        if isinstance(value, str):
            number = _integer_text(value)
        elif isinstance(value, (int, float)):
            number = int(round(value))
        else:
            return value
        return number if -(1 << 63) <= number < 1 << 63 else value
    except (ValueError, OverflowError):
        return value


# EVT_VARIANT has an eight-byte value union on both target architectures.
class _EventValue(ctypes.Union):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("pointer", ctypes.c_void_p),
        ("signed", ctypes.c_int64),
        ("unsigned", ctypes.c_uint64),
        ("single", ctypes.c_float),
        ("double", ctypes.c_double),
    ]


# Count and type follow the fixed-size union, not the process pointer width.
class _EventVariant(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("value", _EventValue),
        ("count", ctypes.c_uint32),
        ("type", ctypes.c_uint32),
    ]


_EVENT_NUMBERS = {
    3: ctypes.c_int8,
    4: ctypes.c_uint8,
    5: ctypes.c_int16,
    6: ctypes.c_uint16,
    7: ctypes.c_int32,
    8: ctypes.c_uint32,
    9: ctypes.c_int64,
    10: ctypes.c_uint64,
    11: ctypes.c_float,
    12: ctypes.c_double,
    13: ctypes.c_int32,
    16: ctypes.c_ssize_t,
    20: ctypes.c_int32,
    21: ctypes.c_uint64,
}


def _json_date(file_time):
    if not -504911232000000000 <= file_time <= 2650467743999999999:
        raise ValueError("Event FILETIME is outside the DateTime range.")
    epoch_ticks = file_time - _UNIX_FILETIME_SECONDS * 10000000
    milliseconds = abs(epoch_ticks) // 10000
    if epoch_ticks < 0:
        milliseconds = -milliseconds
    return "/Date({0})/".format(milliseconds)


def _system_date(pointer):
    fields = struct.unpack("<8H", ctypes.string_at(pointer, 16))
    date = datetime.datetime(
        fields[0],
        fields[1],
        fields[3],
        fields[4],
        fields[5],
        fields[6],
        fields[7] * 1000,
    )
    delta = date - datetime.datetime(1, 1, 1)
    ticks = ((delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds) * 10
    return _json_date(local_ticks_to_file_time(ticks))


def _sid_parts(pointer):
    header = ctypes.string_at(pointer, 8)
    count = header[1]
    if header[0] != 1 or count > 15:
        raise ValueError("Invalid event security identifier.")
    authority = int.from_bytes(header[2:], "big")
    subauthorities = struct.unpack(
        "<{0}L".format(count), ctypes.string_at(pointer + 8, count * 4)
    )
    text = "S-{0}-{1}".format(header[0], authority)
    if subauthorities:
        text += "-" + "-".join(str(value) for value in subauthorities)
    return 8 + count * 4, text


def _account_domain_sid(pointer):
    get_domain = ctypes.WinDLL(
        "advapi32", use_last_error=True
    ).GetWindowsAccountDomainSid
    get_domain.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    get_domain.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(68)
    size = ctypes.c_uint32(len(buffer))
    if not get_domain(pointer, buffer, ctypes.byref(size)):
        error = ctypes.get_last_error()
        if error == 1257:  # ERROR_NON_ACCOUNT_SID
            return None
        raise ctypes.WinError(error)
    return _sid_parts(ctypes.addressof(buffer))


def _sid_object(pointer):
    if not pointer:
        return None
    length, text = _sid_parts(pointer)
    domain = _account_domain_sid(pointer)
    nested = None
    if domain is not None:
        domain_length, domain_text = domain
        nested = domain_text
        # A SID is at depth 3 in result.last_reboot.details.<field>. Its
        # AccountDomainSid refers to the domain itself; ConvertTo-Json depth99
        # expands that chain through depth 99, then uses the SID string.
        for _ in range(96):
            nested = {
                "BinaryLength": domain_length,
                "AccountDomainSid": nested,
                "Value": domain_text,
            }
    return {"BinaryLength": length, "AccountDomainSid": nested, "Value": text}


def _variant_array(variant):
    kind = variant.type & 0x7F
    if kind not in tuple(range(1, 14)) + (15, 17, 18, 20, 21):
        raise ValueError("Invalid event array type: {0}".format(kind))
    pointer = variant.value.pointer
    if not pointer:
        return []
    if kind in _EVENT_NUMBERS:
        # The framework renders HexInt32 arrays unsigned, unlike its scalar.
        number_type = ctypes.c_uint32 if kind == 20 else _EVENT_NUMBERS[kind]
        values = list((number_type * variant.count).from_address(pointer))
        return [bool(value) for value in values] if kind == 13 else values
    if kind in (1, 2):
        pointers = (ctypes.c_void_p * variant.count).from_address(pointer)
        return [
            (
                (
                    ctypes.wstring_at(value)
                    if kind == 1
                    else ctypes.string_at(value).decode("mbcs")
                )
                if value
                else None
            )
            for value in pointers
        ]
    if kind == 17:
        return [
            _json_date(value)
            for value in (ctypes.c_uint64 * variant.count).from_address(pointer)
        ]
    if kind == 18:
        return [_system_date(pointer + index * 16) for index in range(variant.count)]
    return [
        str(uuid.UUID(bytes_le=ctypes.string_at(pointer + index * 16, 16)))
        for index in range(variant.count)
    ]


def _event_api():
    try:
        library = ctypes.WinDLL("wevtapi", use_last_error=True)
    except OSError as error:
        if getattr(error, "winerror", error.errno) == 126:
            return None
        raise
    library.EvtQuery.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    ]
    library.EvtQuery.restype = ctypes.c_void_p
    library.EvtNext.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.EvtNext.restype = ctypes.c_int
    library.EvtCreateRenderContext.argtypes = [
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_wchar_p),
        ctypes.c_uint32,
    ]
    library.EvtCreateRenderContext.restype = ctypes.c_void_p
    library.EvtRender.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.EvtRender.restype = ctypes.c_int
    library.EvtClose.argtypes = [ctypes.c_void_p]
    library.EvtClose.restype = ctypes.c_int
    return library


# Direct discriminator branches keep the native ABI conversions visible.
def _variant_value(variant):  # pylint: disable=too-many-return-statements
    kind = variant.type
    if kind & 0x80:
        return _variant_array(variant)
    if kind == 0:
        return None
    if kind == 1:
        return ctypes.wstring_at(variant.value.pointer) if variant.value.pointer else ""
    if kind == 2:
        return (
            ctypes.string_at(variant.value.pointer).decode("mbcs")
            if variant.value.pointer
            else ""
        )
    if kind in _EVENT_NUMBERS:
        # Framework's scalar SByte and Int16 paths both read its byte member;
        # their array paths correctly retain the signed element widths.
        number_type = ctypes.c_uint8 if kind in (3, 5) else _EVENT_NUMBERS[kind]
        value = number_type.from_buffer(variant.value).value
        return bool(value) if kind == 13 else value
    if kind == 14:
        return (
            list(bytearray(ctypes.string_at(variant.value.pointer, variant.count)))
            if variant.value.pointer
            else []
        )
    if kind == 15:
        return (
            str(uuid.UUID(bytes_le=ctypes.string_at(variant.value.pointer, 16)))
            if variant.value.pointer
            else str(uuid.UUID(int=0))
        )
    if kind == 17:
        return _json_date(variant.value.unsigned)
    if kind == 18:
        return _system_date(variant.value.pointer)
    if kind == 19:
        return _sid_object(variant.value.pointer)
    raise ValueError("Unsupported event property type: {0}".format(kind))


def _render_values(library, event, context_kind):
    context = library.EvtCreateRenderContext(0, None, context_kind)
    if not context:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        used = ctypes.c_uint32()
        count = ctypes.c_uint32()
        success = library.EvtRender(
            context, event, 0, 0, None, ctypes.byref(used), ctypes.byref(count)
        )
        if success and not count.value and context_kind == 2:
            return []
        if not success and ctypes.get_last_error() != 122:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_string_buffer(used.value)
        if not library.EvtRender(
            context,
            event,
            0,
            len(buffer),
            buffer,
            ctypes.byref(used),
            ctypes.byref(count),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        variants = ctypes.cast(buffer, ctypes.POINTER(_EventVariant))
        if context_kind == 1:
            # EvtSystemTimeCreated is the ninth system property. Other system
            # properties (GUID/SID/etc.) are irrelevant to the module result.
            if variants[8].type == 0:
                return None
            if variants[8].type != 17:
                raise ValueError("Invalid event timestamp type.")
            return variants[8].value.unsigned
        return [_variant_value(variants[index]) for index in range(count.value)]
    finally:
        library.EvtClose(context)


def _modern_event(library, cutoff):
    query = library.EvtQuery(None, "System", "*[System[(EventID=1074)]]", 0x1201)
    if not query:
        raise ctypes.WinError(ctypes.get_last_error())
    event = ctypes.c_void_p()
    try:
        returned = ctypes.c_uint32()
        while not library.EvtNext(
            query, 1, ctypes.byref(event), 0xFFFFFFFF, 0, ctypes.byref(returned)
        ):
            if ctypes.get_last_error() == 259:
                return None
            # Get-WinEvent suppresses iteration errors and continues reading.
        try:
            timestamp = _render_values(library, event, 1)
            properties = [] if timestamp < cutoff else _render_values(library, event, 2)
            return timestamp, properties
        finally:
            library.EvtClose(event)
    finally:
        library.EvtClose(query)


def _classic_api():
    library = ctypes.WinDLL("advapi32", use_last_error=True)
    library.OpenEventLogW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p]
    library.OpenEventLogW.restype = ctypes.c_void_p
    library.ReadEventLogW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.ReadEventLogW.restype = ctypes.c_int
    library.CloseEventLog.argtypes = [ctypes.c_void_p]
    library.CloseEventLog.restype = ctypes.c_int
    return library


def _classic_record(data, cutoff):
    offset = 0
    while offset < len(data):
        if len(data) - offset < 56:
            raise ValueError("Truncated event log record.")
        fields = struct.unpack_from("<6L4H6L", data, offset)
        length, generated, event_id = fields[0], fields[3], fields[5]
        if length < 60 or offset + length > len(data):
            raise ValueError("Invalid event log record length.")
        if event_id & 0xFFFF == 1074:
            timestamp = (generated + _UNIX_FILETIME_SECONDS) * 10000000
            if timestamp < cutoff:
                return timestamp, []
            position = fields[11]
            record = data[offset : offset + length - 4]
            strings = []
            if position < 56 or position > len(record):
                raise ValueError("Invalid event log string offset.")
            for _ in range(fields[7]):
                end = position
                while end + 2 <= len(record) and record[end : end + 2] != b"\0\0":
                    end += 2
                if end + 2 > len(record):
                    raise ValueError("Unterminated event log insertion string.")
                strings.append(
                    record[position:end].decode("utf-16-le", "surrogatepass")
                )
                position = end + 2
            return timestamp, strings
        offset += length
    return None


def _classic_event(cutoff):
    library = _classic_api()
    log = library.OpenEventLogW(None, "System")
    if not log:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        capacity = 65536
        while True:
            buffer = ctypes.create_string_buffer(capacity)
            read = ctypes.c_uint32()
            needed = ctypes.c_uint32()
            if not library.ReadEventLogW(
                log, 9, 0, buffer, capacity, ctypes.byref(read), ctypes.byref(needed)
            ):
                error = ctypes.get_last_error()
                if error == 38:
                    return None
                if error == 122 and needed.value > capacity:
                    capacity = needed.value
                    continue
                raise ctypes.WinError(error)
            event = _classic_record(buffer.raw[: read.value], cutoff)
            if event is not None:
                return event
    finally:
        library.CloseEventLog(log)


def recent_reboot(boot_time):
    """Return the latest System 1074 details if it meets the boot-time cutoff.

    Modern event timestamps retain 100-nanosecond precision for comparison;
    classic event logs on XP/2003 expose whole UTC seconds. No event, or one
    strictly older than boot minus five minutes, produces the upstream empty
    object. An event after boot is not excluded.

    :param boot_time: Last boot as a naive UTC datetime.
    :type boot_time: datetime.datetime
    :returns: Seven event fields, or an empty dictionary.
    :rtype: dict
    :raises RuntimeError: Query or property decoding fails; the message preserves
        the pinned module's failing two-argument Warn call.
    """
    try:
        delta = boot_time - _FILETIME_EPOCH
        cutoff = (
            (delta.days * 86400 + delta.seconds - 300) * 1000000 + delta.microseconds
        ) * 10
        library = _event_api()
        event = (
            _modern_event(library, cutoff)
            if library is not None
            else _classic_event(cutoff)
        )
        if event is None:
            return {}
        ticks, properties = event
        if ticks < cutoff:
            return {}
        timestamp = _FILETIME_EPOCH + datetime.timedelta(microseconds=ticks // 10)
        properties = list(properties) + [None] * max(0, 7 - len(properties))
        return {
            "process": properties[0],
            "reason": properties[2],
            "reason_code": _reason_code(properties[3]),
            "type": properties[4],
            "comment": properties[5],
            "initiated_by": properties[6],
            "event_time": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    except (OSError, ValueError, TypeError, OverflowError) as error:
        # The pinned Ansible.Basic has only Warn(string), so its catch block
        # itself terminates instead of emitting the intended warning.
        raise RuntimeError(_WARN_OVERLOAD_ERROR) from error
