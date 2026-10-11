# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
"""Use the installed DHCP Server management API and own its RPC allocations."""

import ctypes
import os
import socket
import struct
from contextlib import contextmanager

_DWORD = ctypes.c_uint32
_BYTE = ctypes.c_ubyte
_POINTER = ctypes.c_void_p


# These fixed DHCP ABI layouts are data, not Python object models. Keep their
# encodings local to the RPC ownership boundary instead of importing unrelated APIs.
# pylint: disable=too-few-public-methods,too-many-instance-attributes,duplicate-code
class _DateTime(ctypes.Structure):
    _fields_ = [("low", _DWORD), ("high", _DWORD)]


class _Binary(ctypes.Structure):
    _fields_ = [("length", _DWORD), ("data", ctypes.POINTER(_BYTE))]


class _HostInfo(ctypes.Structure):
    _fields_ = [
        ("address", _DWORD),
        ("netbios", ctypes.c_wchar_p),
        ("name", ctypes.c_wchar_p),
    ]


class _SubnetInfo(ctypes.Structure):
    _fields_ = [
        ("address", _DWORD),
        ("mask", _DWORD),
        ("name", ctypes.c_wchar_p),
        ("comment", ctypes.c_wchar_p),
        ("primary", _HostInfo),
        ("state", ctypes.c_int32),
    ]


class _ClientV4(ctypes.Structure):
    _fields_ = [
        ("address", _DWORD),
        ("mask", _DWORD),
        ("hardware", _Binary),
        ("name", ctypes.c_wchar_p),
        ("comment", ctypes.c_wchar_p),
        ("expires", _DateTime),
        ("owner", _HostInfo),
        ("kind", _BYTE),
    ]


class _ClientV5(ctypes.Structure):
    # V5 extends the V4 field list, not the padded size of a nested V4 value.
    # pylint: disable=protected-access
    _fields_ = _ClientV4._fields_ + [("state", _BYTE)]
    # pylint: enable=protected-access


class _ClientArray(ctypes.Structure):
    _fields_ = [
        ("count", _DWORD),
        ("clients", ctypes.POINTER(ctypes.POINTER(_ClientV5))),
    ]


class _IpArray(ctypes.Structure):
    _fields_ = [("count", _DWORD), ("addresses", ctypes.POINTER(_DWORD))]


class _Reservation(ctypes.Structure):
    _fields_ = [
        ("address", _DWORD),
        ("client", ctypes.POINTER(_Binary)),
        ("allowed", _BYTE),
    ]


class _Element(ctypes.Structure):
    # Every alternative of the native subnet-element union is a pointer.
    _fields_ = [("kind", ctypes.c_int32), ("value", _POINTER)]


class _ElementArray(ctypes.Structure):
    _fields_ = [("count", _DWORD), ("elements", ctypes.POINTER(_Element))]


class _SearchKey(ctypes.Union):
    _fields_ = [
        ("address", _DWORD),
        ("client", _Binary),
        ("name", ctypes.c_wchar_p),
    ]


class _SearchInfo(ctypes.Structure):
    _fields_ = [("kind", ctypes.c_int32), ("key", _SearchKey)]


class _ReservedScope(ctypes.Structure):
    _fields_ = [("address", _DWORD), ("subnet", _DWORD)]


class _OptionScopeValue(ctypes.Union):
    _fields_ = [
        ("subnet", _DWORD),
        ("reserved", _ReservedScope),
        ("multicast", ctypes.c_wchar_p),
    ]


class _OptionScope(ctypes.Structure):
    _fields_ = [("kind", ctypes.c_int32), ("value", _OptionScopeValue)]


class _OptionValueUnion(ctypes.Union):
    _fields_ = [
        ("byte", _BYTE),
        ("word", ctypes.c_uint16),
        ("dword", _DWORD),
        ("words", _DateTime),
        ("string", ctypes.c_wchar_p),
        ("binary", _Binary),
    ]


class _OptionElement(ctypes.Structure):
    _fields_ = [("kind", ctypes.c_int32), ("value", _OptionValueUnion)]


class _OptionData(ctypes.Structure):
    _fields_ = [("count", _DWORD), ("elements", ctypes.POINTER(_OptionElement))]


class _OptionValue(ctypes.Structure):
    _fields_ = [("identifier", _DWORD), ("data", _OptionData)]


class _OptionInfo(ctypes.Structure):
    _fields_ = [
        ("identifier", _DWORD),
        ("name", ctypes.c_wchar_p),
        ("comment", ctypes.c_wchar_p),
        ("data", _OptionData),
        ("kind", ctypes.c_int32),
    ]


# pylint: enable=too-few-public-methods,too-many-instance-attributes,duplicate-code


def _ip(value):
    return struct.unpack("!I", socket.inet_aton(value))[0]


def _text(value):
    return socket.inet_ntoa(struct.pack("!I", value))


def _bytes(value):
    return ctypes.string_at(value.data, value.length) if value.length else b""


def _client(value):
    return {
        "address": _text(value.address),
        "mask": _text(value.mask),
        "hardware": _bytes(value.hardware),
        "name": value.name,
        "comment": value.comment,
        "expires": value.expires.low | value.expires.high << 32,
        "owner": (value.owner.address, value.owner.netbios, value.owner.name),
        "kind": value.kind,
    }


def _hardware(value):
    storage = (_BYTE * len(value)).from_buffer_copy(value)
    return _Binary(len(value), storage)


def _client_input(value):
    return _ClientV4(
        _ip(value["address"]),
        _ip(value["mask"]),
        _hardware(value["hardware"]),
        value["name"],
        value["comment"],
        _DateTime(value["expires"] & 0xFFFFFFFF, value["expires"] >> 32),
        _HostInfo(*value["owner"]),
        value["kind"],
    )


def _one_dword(data):
    if data.count != 1 or not data.elements or data.elements[0].kind != 2:
        raise ValueError("DHCP returned an invalid native lease-duration option.")
    return data.elements[0].value.dword


class DhcpApi:
    """Read and change DHCP records using the installed native server API.

    :param server: Optional local or remote server name accepted by Windows.
    :type server: str or None
    :raises ValueError: The required native management functions are unavailable.
    :raises OSError: Windows rejects an operation; earlier writes may remain applied.
    """

    def __init__(self, server=None):
        if server is not None and (not server or "\x00" in server):
            raise ValueError("computer_name must be a nonempty Windows server name.")
        self.server = server
        # This DLL loads into the current process. Let WOW64 redirect System32
        # to its matching DLL; Sysnative would select an incompatible 64-bit DLL.
        library = os.path.join(os.environ["SystemRoot"], "System32", "dhcpsapi.dll")
        self.api = ctypes.WinDLL(library)
        # These fixed RPC signatures belong to this DLL's allocation boundary.
        # pylint: disable=duplicate-code
        signatures = {
            "DhcpEnumSubnets": [
                ctypes.c_wchar_p,
                _POINTER,
                _DWORD,
                _POINTER,
                _POINTER,
                _POINTER,
            ],
            "DhcpGetSubnetInfo": [ctypes.c_wchar_p, _DWORD, _POINTER],
            "DhcpEnumSubnetClientsV5": [
                ctypes.c_wchar_p,
                _DWORD,
                _POINTER,
                _DWORD,
                _POINTER,
                _POINTER,
                _POINTER,
            ],
            "DhcpEnumSubnetElementsV5": [
                ctypes.c_wchar_p,
                _DWORD,
                ctypes.c_int32,
                _POINTER,
                _DWORD,
                _POINTER,
                _POINTER,
                _POINTER,
            ],
            "DhcpGetClientInfoV4": [ctypes.c_wchar_p, _POINTER, _POINTER],
            "DhcpCreateClientInfoV4": [ctypes.c_wchar_p, _POINTER],
            "DhcpSetClientInfoV4": [ctypes.c_wchar_p, _POINTER],
            "DhcpDeleteClientInfo": [ctypes.c_wchar_p, _POINTER],
            "DhcpAddSubnetElementV5": [ctypes.c_wchar_p, _DWORD, _POINTER],
            "DhcpRemoveSubnetElementV5": [
                ctypes.c_wchar_p,
                _DWORD,
                _POINTER,
                ctypes.c_int32,
            ],
            "DhcpGetOptionValue": [ctypes.c_wchar_p, _DWORD, _POINTER, _POINTER],
            "DhcpGetOptionInfo": [ctypes.c_wchar_p, _DWORD, _POINTER],
        }
        for name, arguments in signatures.items():
            function = getattr(self.api, name, None)
            if function is None:
                raise ValueError("Installed DHCP management API lacks " + name + ".")
            function.argtypes = arguments
            function.restype = _DWORD
        # pylint: enable=duplicate-code
        self.api.DhcpRpcFreeMemory.argtypes = [_POINTER]
        self.api.DhcpRpcFreeMemory.restype = None

    def _call(self, name, *arguments):
        status = getattr(self.api, name)(self.server, *arguments)
        if status:
            raise ctypes.WinError(status)

    @contextmanager
    def _result(self, name, structure, *arguments):
        pointer = ctypes.POINTER(structure)()
        try:
            self._call(name, *(arguments + (ctypes.byref(pointer),)))
            if not pointer:
                raise OSError(name + " returned no native data.")
            yield pointer.contents
        finally:
            if pointer:
                self.api.DhcpRpcFreeMemory(pointer)

    def subnets(self):
        """Return canonical subnet addresses in the server's enumeration order.

        :returns: Subnet address strings.
        :rtype: list
        """
        return list(self._enumerate("DhcpEnumSubnets", _IpArray, "addresses", []))

    def _enumerate(self, name, structure, field, arguments):
        resume, count, total = _DWORD(), _DWORD(), _DWORD()
        while True:
            pointer = ctypes.POINTER(structure)()
            try:
                status = getattr(self.api, name)(
                    self.server,
                    *(
                        arguments
                        + [
                            ctypes.byref(resume),
                            0xFFFFFFFF,
                            ctypes.byref(pointer),
                            ctypes.byref(count),
                            ctypes.byref(total),
                        ]
                    )
                )
                if status not in (0, 234, 259):
                    raise ctypes.WinError(status)
                if pointer:
                    data = pointer.contents
                    for index in range(data.count):
                        value = getattr(data, field)[index]
                        if field == "addresses":
                            yield _text(value)
                        elif field == "clients":
                            row = _client(value.contents)
                            row["state"] = value.contents.state
                            yield row
                        else:
                            reservation = ctypes.cast(
                                value.value, ctypes.POINTER(_Reservation)
                            ).contents
                            yield {
                                "address": _text(reservation.address),
                                "hardware": _bytes(reservation.client.contents),
                                "allowed": reservation.allowed,
                            }
                if status != 234:
                    return
            finally:
                if pointer:
                    self.api.DhcpRpcFreeMemory(pointer)

    def subnet(self, address):
        """Read one actual subnet and its configured native mask and state.

        :param str address: Canonical subnet address.
        :returns: Literal subnet metadata.
        :rtype: dict
        """
        with self._result("DhcpGetSubnetInfo", _SubnetInfo, _ip(address)) as value:
            return {
                "address": _text(value.address),
                "mask": _text(value.mask),
                "name": value.name,
                "comment": value.comment,
                "state": value.state,
                "primary": (
                    value.primary.address,
                    value.primary.netbios,
                    value.primary.name,
                ),
            }

    def clients(self, subnet):
        """Read actual clients, including offered, expired and reserved entries.

        :param str subnet: Canonical subnet address.
        :returns: Client metadata copied before native allocations are freed.
        :rtype: list
        """
        return list(
            self._enumerate(
                "DhcpEnumSubnetClientsV5", _ClientArray, "clients", [_ip(subnet)]
            )
        )

    def reservations(self, subnet):
        """Read real reservations without inferring them from client-type bits.

        :param str subnet: Canonical subnet address.
        :returns: Address, client bytes and allowed native protocol types.
        :rtype: list
        """
        return list(
            self._enumerate(
                "DhcpEnumSubnetElementsV5", _ElementArray, "elements", [_ip(subnet), 2]
            )
        )

    def client(self, address):
        """Read the native V4 client selected by its exact address.

        :param str address: Canonical client address.
        :returns: Native client metadata.
        :rtype: dict
        """
        search = _SearchInfo(0, _SearchKey(address=_ip(address)))
        with self._result(
            "DhcpGetClientInfoV4", _ClientV4, ctypes.byref(search)
        ) as value:
            return _client(value)

    def save_client(self, value, create=False):
        """Create or update a client with explicitly supplied native metadata.

        :param dict value: Native client fields, including hardware bytes and expiry.
        :param bool create: Select creation rather than an existing-address write.
        """
        native = _client_input(value)
        self._call(
            "DhcpCreateClientInfoV4" if create else "DhcpSetClientInfoV4",
            ctypes.byref(native),
        )

    def remove_client(self, address):
        """Delete the client selected by its literal existing IPv4 address.

        :param str address: Canonical existing client address.
        """
        search = _SearchInfo(0, _SearchKey(address=_ip(address)))
        self._call("DhcpDeleteClientInfo", ctypes.byref(search))

    def reserve(self, subnet, address, hardware, remove=False):
        """Add or remove exactly one existing-scope reservation.

        :param str subnet: Canonical containing subnet address.
        :param str address: Canonical reserved client address.
        :param bytes hardware: Native DHCP client identifier bytes.
        :param bool remove: Remove the specified binding rather than create it.
        """
        # Adds take the server's scoped UID; removals retain the observed UID.
        uid = (
            hardware if remove else struct.pack("<I", _ip(subnet)) + b"\x01" + hardware
        )
        client = _hardware(uid)
        reservation = _Reservation(_ip(address), ctypes.pointer(client), 3)
        element = _Element(2, ctypes.cast(ctypes.pointer(reservation), _POINTER))
        arguments = [_ip(subnet), ctypes.byref(element)]
        if remove:
            arguments.append(1)
        self._call(
            "DhcpRemoveSubnetElementV5" if remove else "DhcpAddSubnetElementV5",
            *arguments
        )

    def lease_duration(self, subnet):
        """Read the configured subnet, server or native default lease option.

        :param str subnet: Canonical containing subnet address.
        :returns: Native lease duration in seconds; never an invented default.
        :rtype: int
        :raises OSError: Windows cannot read the configured or default option.
        """
        for kind in (2, 1):
            scope = _OptionScope(
                kind, _OptionScopeValue(subnet=_ip(subnet) if kind == 2 else 0)
            )
            try:
                with self._result(
                    "DhcpGetOptionValue", _OptionValue, 51, ctypes.byref(scope)
                ) as value:
                    return _one_dword(value.data)
            except OSError as error:
                if getattr(error, "winerror", None) != 20010:
                    raise
        with self._result("DhcpGetOptionInfo", _OptionInfo, 51) as value:
            return _one_dword(value.data)
