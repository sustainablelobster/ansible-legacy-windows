# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read local WinRM listener certificates through native WSMan and CryptoAPI."""

import binascii
import contextlib
import ctypes
import datetime
import uuid
import xml.etree.ElementTree as xml

# Unchanged sibling helpers own the COM/VARIANT and certificate ABI layouts.
# Reusing those declarations avoids another native-layout implementation.
# pylint: disable=import-error,protected-access
import legacy_windows_certificate as certificate
import legacy_windows_uformat as uformat
import legacy_windows_wmi as wmi

# pylint: enable=import-error

_POINTER = ctypes.c_void_p
_OUT = ctypes.POINTER(_POINTER)
_LONG = ctypes.c_int32
_SESSION_IID = "FC84FC58-1286-40C4-9DA0-C8EF6EC241E0"
_ENUMERATOR_IID = "F3457CA9-ABB9-4FA5-B850-90E8CA300E7F"


def _guid(value):
    return wmi._Guid.from_buffer_copy(uuid.UUID(value).bytes_le)


def _interface(pointer, interface_id, cleanup):
    if not pointer:
        raise OSError("WSMan returned no interface for " + interface_id + ".")
    result = _POINTER()
    iid = _guid(interface_id)
    call = wmi._method(pointer, 0, _LONG, [ctypes.POINTER(wmi._Guid), _OUT])
    wmi._check(
        call(pointer, ctypes.byref(iid), ctypes.byref(result)), "WSMan QueryInterface"
    )
    if not result:
        raise OSError("WSMan returned an empty interface for " + interface_id + ".")
    cleanup.callback(wmi._release, result)
    return result


def _listeners():
    ole, automation = wmi._libraries()
    with contextlib.ExitStack() as cleanup:
        status = ole.CoInitializeEx(None, 2)
        wmi._check(status, "WSMan COM initialization")
        cleanup.callback(ole.CoUninitialize)
        clsid = _guid("BCED617B-EC03-420B-8508-977DC7A686BD")
        iid = _guid("190D8637-5CD3-496D-AD24-69636BB5A3B5")
        manager = _POINTER()
        wmi._check(
            ole.CoCreateInstance(
                ctypes.byref(clsid), None, 1, ctypes.byref(iid), ctypes.byref(manager)
            ),
            "WSMan automation creation",
        )
        if not manager:
            raise OSError("WSMan returned no automation interface.")
        cleanup.callback(wmi._release, manager)
        dispatch = _POINTER()
        create = wmi._method(manager, 7, _LONG, [_POINTER, _LONG, _POINTER, _OUT])
        wmi._check(
            create(manager, None, 0, None, ctypes.byref(dispatch)),
            "Local WSMan session creation",
        )
        cleanup.callback(wmi._release, dispatch)
        session = _interface(dispatch, _SESSION_IID, cleanup)
        resource = wmi._Variant()
        resource.kind = 8
        resource.data.bstr = wmi._bstr(
            automation,
            cleanup,
            "http://schemas.microsoft.com/wbem/wsman/1/config/listener",
        )
        enumeration = _POINTER()
        enumerate_call = wmi._method(
            session, 12, _LONG, [wmi._Variant, _POINTER, _POINTER, _LONG, _OUT]
        )
        status = enumerate_call(
            session, resource, None, None, 0, ctypes.byref(enumeration)
        )
        # The source uses Get-ChildItem -ErrorAction SilentlyContinue for this
        # enumeration. An unavailable endpoint therefore yields no listeners,
        # rather than a certificate-retrieval warning or fabricated fields.
        if status < 0:
            return []
        cleanup.callback(wmi._release, enumeration)
        reader = _interface(enumeration, _ENUMERATOR_IID, cleanup)
        return _listener_values(reader, automation)


def _listener_values(reader, automation):
    at_end = wmi._method(reader, 8, _LONG, [ctypes.POINTER(ctypes.c_int16)])
    read_item = wmi._method(reader, 7, _LONG, [_OUT])
    values = []
    while True:
        ended = ctypes.c_int16()
        wmi._check(at_end(reader, ctypes.byref(ended)), "WSMan enumeration state")
        if ended.value:
            return values
        item = _POINTER()
        wmi._check(read_item(reader, ctypes.byref(item)), "WSMan listener read")
        try:
            if not item:
                raise OSError("WSMan returned no listener XML.")
            text = ctypes.wstring_at(item, automation.SysStringLen(item))
            element = xml.fromstring(text)
            values.append(
                {child.tag.rsplit("}", 1)[-1]: child.text or "" for child in element}
            )
        finally:
            if item:
                automation.SysFreeString(item)


def _certificate_expiry(thumbprint):
    library = certificate._crypt32()
    store = library.CertOpenStore(10, 0, None, 0x20000 | 0x8000, "My")
    if not store:
        raise ctypes.WinError(ctypes.get_last_error())
    context = None
    try:
        data = certificate._thumbprint_bytes(thumbprint)
        buffer = ctypes.create_string_buffer(data)
        selector = certificate._Blob(
            len(data), ctypes.cast(buffer, certificate._BYTE_POINTER)
        )
        context = library.CertFindCertificateInStore(
            store, 0x10001, 0, 0x10000, ctypes.byref(selector), None
        )
        if not context:
            raise OSError(
                "WinRM listener certificate {0} is absent from LocalMachine\\My.".format(
                    thumbprint
                )
            )
        value = context.contents.info.contents.not_after
        return (value.high << 32) | value.low, binascii.hexlify(data).decode(
            "ascii"
        ).upper()
    finally:
        try:
            if context and not library.CertFreeCertificateContext(context):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            if not library.CertCloseStore(store, 0):
                raise ctypes.WinError(ctypes.get_last_error())


def read_facts(facts, warnings):
    """Return the earliest-expiring configured HTTPS listener certificate.

    :param facts: Receives expiry and thumbprint only if HTTPS certificates exist.
    :type facts: dict
    :param warnings: Receives an actionable retrieval warning on native failure.
    :type warnings: list[str]
    """
    try:
        certificates = [
            _certificate_expiry(listener["CertificateThumbprint"])
            for listener in _listeners()
            if listener.get("Transport", "").upper() == "HTTPS"
        ]
    except (OSError, ValueError, KeyError, xml.ParseError) as error:
        warnings.append(
            "Error during certificate expiration retrieval: {0}".format(error)
        )
        return
    if not certificates:
        return
    ticks, thumbprint = min(certificates, key=lambda value: value[0])
    local_ticks = uformat.native_time.file_time_to_local_ticks(ticks)
    days, remainder = divmod(local_ticks, 864000000000)
    local = datetime.datetime.fromordinal(days + 1) + datetime.timedelta(
        microseconds=remainder // 10
    )
    facts["ansible_win_rm_certificate_expires"] = uformat.format_date(
        local, "%Y-%m-%d %H:%M:%S"
    )
    facts["ansible_win_rm_certificate_thumbprint"] = thumbprint
