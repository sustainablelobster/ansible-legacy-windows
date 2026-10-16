# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Send native Windows Runtime toast notifications without a managed host."""

import ctypes
import datetime
import uuid
from contextlib import ExitStack
from xml.etree import ElementTree

from legacy_windows_wmi import WmiConnection  # pylint: disable=import-error


def _check(status, operation):
    if status < 0:
        raise OSError(
            "{0} failed with HRESULT 0x{1:08X}".format(operation, status & 0xFFFFFFFF)
        )


def _call(pointer, slot, arguments, *values):
    table = ctypes.cast(pointer, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)))
    operation = ctypes.WINFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, *arguments)(
        table[0][slot]
    )
    return operation(pointer, *values)


def _release(pointer):
    if pointer:
        _call(pointer, 2, [])


def available():
    """Require the native Windows Runtime exports, without an OS version gate.

    :raises OSError: This Windows installation has no notification-capable runtime.
    """
    try:
        runtime = ctypes.WinDLL("combase", use_last_error=True)
        for name in (
            "RoInitialize",
            "RoGetActivationFactory",
            "RoActivateInstance",
            "WindowsCreateString",
        ):
            getattr(runtime, name)
    except (OSError, AttributeError) as error:
        raise OSError(
            "Windows Runtime toast notification APIs are unavailable on this target."
        ) from error


def has_explorer():
    """Check the released provider's Explorer-process indication of a user.

    :returns: Whether any explorer.exe process is present.
    :rtype: bool
    :raises OSError: Native process enumeration fails.
    """
    with WmiConnection() as connection:
        return bool(
            connection.query(
                "SELECT ProcessId FROM Win32_Process WHERE Name='explorer.exe'",
                ["ProcessId"],
            )
        )


def _string(runtime, lifetime, value):
    result = ctypes.c_void_p()
    _check(
        runtime.WindowsCreateString(
            value, len(value.encode("utf-16-le")) // 2, ctypes.byref(result)
        ),
        "WindowsCreateString",
    )
    lifetime.callback(runtime.WindowsDeleteString, result)
    return result.value


def _query(pointer, identifier, lifetime):
    result = ctypes.c_void_p()
    guid = (ctypes.c_ubyte * 16).from_buffer_copy(uuid.UUID(identifier).bytes_le)
    # QueryInterface has a fixed COM ABI; this notification owns its references.
    # pylint: disable=duplicate-code
    _check(
        _call(
            pointer,
            0,
            [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)],
            ctypes.byref(guid),
            ctypes.byref(result),
        ),
        "QueryInterface notification API",
    )
    # pylint: enable=duplicate-code
    lifetime.callback(_release, result.value)
    return result.value


def _factory(runtime, lifetime, name, identifier):
    result = ctypes.c_void_p()
    guid = (ctypes.c_ubyte * 16).from_buffer_copy(uuid.UUID(identifier).bytes_le)
    _check(
        runtime.RoGetActivationFactory(
            _string(runtime, lifetime, name), ctypes.byref(guid), ctypes.byref(result)
        ),
        "RoGetActivationFactory " + name,
    )
    lifetime.callback(_release, result.value)
    return result.value


def _runtime():
    runtime = ctypes.WinDLL("combase", use_last_error=True)
    for name, arguments, result in (
        ("RoInitialize", [ctypes.c_uint32], ctypes.c_int32),
        ("RoUninitialize", [], None),
        (
            "WindowsCreateString",
            [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)],
            ctypes.c_int32,
        ),
        ("WindowsDeleteString", [ctypes.c_void_p], ctypes.c_int32),
        (
            "RoActivateInstance",
            [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)],
            ctypes.c_int32,
        ),
        (
            "RoGetActivationFactory",
            [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)],
            ctypes.c_int32,
        ),
    ):
        operation = getattr(runtime, name)
        operation.argtypes, operation.restype = arguments, result
    return runtime


def _notification(runtime, lifetime, parameters, expires):
    xml = ElementTree.Element("toast")
    binding = ElementTree.SubElement(
        ElementTree.SubElement(xml, "visual"), "binding", {"template": "ToastText02"}
    )
    for value in (parameters["title"], parameters["msg"]):
        ElementTree.SubElement(binding, "text").text = value
    document = ctypes.c_void_p()
    _check(
        runtime.RoActivateInstance(
            _string(runtime, lifetime, "Windows.Data.Xml.Dom.XmlDocument"),
            ctypes.byref(document),
        ),
        "RoActivateInstance XmlDocument",
    )
    lifetime.callback(_release, document.value)
    loader = _query(document.value, "6cd0e74e-ee65-4489-9ebf-ca43e87ba637", lifetime)
    _check(
        _call(
            loader,
            6,
            [ctypes.c_void_p],
            _string(runtime, lifetime, ElementTree.tostring(xml, encoding="unicode")),
        ),
        "XmlDocument.LoadXml",
    )
    factory = _factory(
        runtime,
        lifetime,
        "Windows.UI.Notifications.ToastNotification",
        "04124b20-82c6-4229-b109-fd9ed4662b53",
    )
    toast = ctypes.c_void_p()
    _check(
        _call(
            factory,
            6,
            [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)],
            document,
            ctypes.byref(toast),
        ),
        "ToastNotification.Create",
    )
    lifetime.callback(_release, toast.value)
    properties = _query(toast.value, "9dfb9fd1-143a-490e-90bf-b9fba7132de7", lifetime)
    for slot, name in ((6, "tag"), (8, "group")):
        _check(
            _call(
                properties,
                slot,
                [ctypes.c_void_p],
                _string(runtime, lifetime, parameters[name]),
            ),
            "ToastNotification." + name,
        )
    _check(
        _call(properties, 10, [ctypes.c_ubyte], not parameters["popup"]),
        "ToastNotification.SuppressPopup",
    )
    _set_expiration(runtime, lifetime, toast.value, expires)
    return toast.value


def _set_expiration(runtime, lifetime, toast, expires):
    values = _factory(
        runtime,
        lifetime,
        "Windows.Foundation.PropertyValue",
        "629bdbc8-d932-4ff4-96b9-8d96c5c1e858",
    )
    delta = expires - datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    ticks = ((delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds) * 10
    boxed = ctypes.c_void_p()
    _check(
        _call(
            values,
            21,
            [ctypes.c_int64, ctypes.POINTER(ctypes.c_void_p)],
            ticks,
            ctypes.byref(boxed),
        ),
        "PropertyValue.CreateDateTime",
    )
    lifetime.callback(_release, boxed.value)
    # This is the documented parameterized IReference<Windows.Foundation.DateTime> IID.
    date = _query(boxed.value, "5541d8a7-497c-5aa4-86fc-7713adbf2a2c", lifetime)
    _check(
        _call(toast, 7, [ctypes.c_void_p], date),
        "ToastNotification.ExpirationTime",
    )


def send(parameters, expires, check_mode=False):
    """Create a notifier, validate a toast and optionally show it.

    :param dict parameters: Title, message, tag, group and popup settings.
    :param datetime.datetime expires: UTC expiration time.
    :param bool check_mode: Validate the notifier and message without showing it.
    :raises OSError: The installed notification API or requested operation fails.
    """
    runtime = _runtime()
    status = runtime.RoInitialize(1)
    if status == -2147417850:
        status = runtime.RoInitialize(0)
    _check(status, "RoInitialize")
    with ExitStack() as lifetime:
        lifetime.callback(runtime.RoUninitialize)
        toast = _notification(runtime, lifetime, parameters, expires)
        manager = _factory(
            runtime,
            lifetime,
            "Windows.UI.Notifications.ToastNotificationManager",
            "50ac103f-d235-4598-bbef-98fe4d1a3ad4",
        )
        notifier = ctypes.c_void_p()
        _check(
            _call(
                manager,
                7,
                [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)],
                _string(runtime, lifetime, "Ansible"),
                ctypes.byref(notifier),
            ),
            "ToastNotificationManager.CreateToastNotifier",
        )
        lifetime.callback(_release, notifier.value)
        if not check_mode:
            _check(
                _call(notifier.value, 6, [ctypes.c_void_p], toast), "ToastNotifier.Show"
            )


def format_time(value, long_date=False, short_time=False):
    """Format returned timestamps using the target user's Windows culture.

    :param datetime.datetime value: Local or UTC wall-clock components.
    :param bool long_date: Use the long date emitted by PowerShell's display view.
    :param bool short_time: Return the default title's short-time component only.
    :returns: Culturally formatted date and time, or a short time.
    :rtype: str
    :raises OSError: Native culture formatting fails.
    """
    system_time = (ctypes.c_uint16 * 8)(
        value.year,
        value.month,
        (value.weekday() + 1) % 7,
        value.day,
        value.hour,
        value.minute,
        value.second,
        value.microsecond // 1000,
    )
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    outputs = []
    operations = (
        [("GetTimeFormatW", 2)]
        if short_time
        else [("GetDateFormatW", 2 if long_date else 0), ("GetTimeFormatW", 0)]
    )
    for name, flags in operations:
        operation = getattr(kernel, name)
        operation.argtypes = [
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_int,
        ]
        operation.restype = ctypes.c_int
        buffer = ctypes.create_unicode_buffer(512)
        if not operation(
            0x0400, flags, ctypes.byref(system_time), None, buffer, len(buffer)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        outputs.append(buffer.value)
    return " ".join(outputs)
