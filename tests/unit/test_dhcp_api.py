"""Check native DHCP data ownership, real status handling and literal selectors."""

# SPDX-License-Identifier: GPL-3.0-or-later
# The tests inspect the fixed ctypes ABI, not a second DHCP implementation.
# pylint: disable=protected-access

import ctypes
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="native")
def native_api(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load only the DHCP ABI against controller-owned native-call substitutes.

    :param monkeypatch: Scoped DLL/error replacements.
    :returns: Target helper and native call recorder, not Windows proof.
    """
    helper = load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_dhcp_api.py",
        "dhcp_api_test",
    )
    api = MagicMock()
    monkeypatch.setenv("SystemRoot", "owned-system-root")
    monkeypatch.delenv("PROCESSOR_ARCHITEW6432", raising=False)
    monkeypatch.setattr(helper.ctypes, "WinDLL", lambda _path: api, raising=False)

    def _error(status: int) -> OSError:
        result = OSError(status, "native failure")
        result.winerror = status  # type: ignore[attr-defined]
        return result

    monkeypatch.setattr(helper.ctypes, "WinError", _error, raising=False)
    return helper, api, helper.DhcpApi("dhcp.invalid")


def _out(output: Any, structure: Any) -> None:
    ctypes.cast(output, ctypes.POINTER(ctypes.POINTER(type(structure))))[0] = (
        ctypes.pointer(structure)
    )


@pytest.mark.parametrize("wow64_architecture", [None, "AMD64", "ARM64"])
def test_in_process_dll_keeps_native_process_redirection(
    native: Any,
    monkeypatch: pytest.MonkeyPatch,
    wow64_architecture: str | None,
) -> None:
    helper, api, _session = native
    if wow64_architecture is None:
        monkeypatch.delenv("PROCESSOR_ARCHITEW6432", raising=False)
    else:
        monkeypatch.setenv("PROCESSOR_ARCHITEW6432", wow64_architecture)
    loader = MagicMock(return_value=api)
    monkeypatch.setattr(helper.ctypes, "WinDLL", loader)
    session = helper.DhcpApi("dhcp.invalid")
    loader.assert_called_once_with(
        helper.os.path.join("owned-system-root", "System32", "dhcpsapi.dll")
    )
    assert session.api is api


def test_literals_are_bound_and_native_rpc_result_is_freed(native: Any) -> None:
    helper, api, session = native
    data = helper._SubnetInfo(
        helper._ip("192.0.2.0"),
        helper._ip("255.255.255.0"),
        "owned scope",
        "description",
        helper._HostInfo(),
        1,
    )

    def _subnet(server: str, address: int, output: Any) -> int:
        assert server == "dhcp.invalid" and address == 0xC0000200
        _out(output, data)
        return 0

    api.DhcpGetSubnetInfo.side_effect = _subnet
    assert session.subnet("192.0.2.0") == {
        "address": "192.0.2.0",
        "mask": "255.255.255.0",
        "name": "owned scope",
        "comment": "description",
        "state": 1,
        "primary": (0, None, None),
    }
    api.DhcpRpcFreeMemory.assert_called_once()


def test_reservation_add_uses_scoped_uid_and_removal_uses_observed_uid(
    native: Any,
) -> None:
    helper, api, session = native
    hardware = bytes.fromhex("020000000025")
    uid = bytes.fromhex("000200c001020000000025")

    def _add(_server: str, subnet: int, pointer: Any) -> int:
        assert subnet == 0xC0000200
        element = ctypes.cast(pointer, ctypes.POINTER(helper._Element)).contents
        value = ctypes.cast(element.value, ctypes.POINTER(helper._Reservation)).contents
        assert element.kind == 2 and value.allowed == 3
        assert helper._bytes(value.client.contents) == uid
        return 0

    def _remove(server: str, subnet: int, pointer: Any, force: int) -> int:
        assert force == 1
        return _add(server, subnet, pointer)

    api.DhcpAddSubnetElementV5.side_effect = _add
    api.DhcpRemoveSubnetElementV5.side_effect = _remove
    session.reserve("192.0.2.0", "192.0.2.25", hardware)
    session.reserve("192.0.2.0", "192.0.2.25", uid, remove=True)


@pytest.mark.parametrize("allocated", [False, True])
def test_read_error_does_not_leak_an_allocated_native_result(
    native: Any, allocated: bool
) -> None:
    helper, api, session = native
    data = helper._SubnetInfo()

    def _failed(_server: str, _address: int, output: Any) -> int:
        if allocated:
            _out(output, data)
        return 5

    api.DhcpGetSubnetInfo.side_effect = _failed
    with pytest.raises(OSError) as raised:
        session.subnet("192.0.2.0")
    assert raised.value.winerror == 5  # type: ignore[attr-defined]
    assert api.DhcpRpcFreeMemory.call_count == int(allocated)


def test_subnet_pagination_retains_actual_order_and_releases_each_page(
    native: Any,
) -> None:
    helper, api, session = native
    arrays = [
        (helper._DWORD * 1)(helper._ip("198.51.100.0")),
        (helper._DWORD * 1)(helper._ip("192.0.2.0")),
    ]
    pages = [helper._IpArray(1, values) for values in arrays]

    def _page(
        _server: str, resume: Any, _size: int, output: Any, _count: Any, _total: Any
    ) -> int:
        handle = ctypes.cast(resume, ctypes.POINTER(helper._DWORD))
        index = handle[0]
        _out(output, pages[index])
        handle[0] += 1
        return 234 if index == 0 else 0

    api.DhcpEnumSubnets.side_effect = _page
    assert session.subnets() == ["198.51.100.0", "192.0.2.0"]
    assert api.DhcpRpcFreeMemory.call_count == 2


def test_empty_enumeration_is_not_a_fabricated_subnet(native: Any) -> None:
    _helper, api, session = native
    api.DhcpEnumSubnets.return_value = 259
    assert session.subnets() == []
    api.DhcpRpcFreeMemory.assert_not_called()


def test_client_write_retains_native_unicode_hardware_and_expiry(native: Any) -> None:
    helper, api, session = native
    observed: list[dict[str, Any]] = []

    def _write(_server: str, pointer: Any) -> int:
        value = ctypes.cast(pointer, ctypes.POINTER(helper._ClientV4)).contents
        observed.append(helper._client(value))
        return 0

    api.DhcpCreateClientInfoV4.side_effect = _write
    request = {
        "address": "192.0.2.25",
        "mask": "255.255.255.0",
        "hardware": b"\x02\x00\x00\x00\x00\x25",
        "name": "Unicode Ω",
        "comment": "literal description",
        "expires": 135379296001234560,
        "owner": (0, None, None),
        "kind": 1,
    }
    session.save_client(request, create=True)
    assert observed == [request]
    api.DhcpSetClientInfoV4.assert_not_called()


def test_clients_read_real_address_state_with_fixed_v5_layout(native: Any) -> None:
    helper, api, session = native
    client = helper._ClientV5()
    client.address = helper._ip("192.0.2.25")
    client.mask = helper._ip("255.255.255.0")
    client.hardware = helper._hardware(b"\x02\x00\x00\x00\x00\x25")
    client.kind, client.state = 100, 0x21
    client.name = "original.invalid"
    pointers = (ctypes.POINTER(helper._ClientV5) * 1)(ctypes.pointer(client))
    page = helper._ClientArray(1, pointers)

    def _clients(
        _server: str,
        subnet: int,
        _resume: Any,
        _size: int,
        output: Any,
        _count: Any,
        _total: Any,
    ) -> int:
        assert subnet == 0xC0000200
        _out(output, page)
        return 0

    api.DhcpEnumSubnetClientsV5.side_effect = _clients
    row = session.clients("192.0.2.0")[0]
    assert row["state"] == 0x21 and row["kind"] == 100
    assert row["hardware"] == b"\x02\x00\x00\x00\x00\x25"
    assert helper._ClientV5.state.offset == helper._ClientV4.kind.offset + 1
    api.DhcpRpcFreeMemory.assert_called_once()


def test_default_duration_uses_actual_native_option_data(native: Any) -> None:
    helper, api, session = native
    elements = (helper._OptionElement * 1)(
        helper._OptionElement(2, helper._OptionValueUnion(dword=604800))
    )
    value = helper._OptionValue(51, helper._OptionData(1, elements))

    def _option(_server: str, identifier: int, scope: Any, output: Any) -> int:
        assert identifier == 51
        selection = ctypes.cast(scope, ctypes.POINTER(helper._OptionScope)).contents
        assert selection.kind == 2 and selection.value.subnet == 0xC0000200
        _out(output, value)
        return 0

    api.DhcpGetOptionValue.side_effect = _option
    assert session.lease_duration("192.0.2.0") == 604800
    api.DhcpGetOptionInfo.assert_not_called()
    api.DhcpRpcFreeMemory.assert_called_once()


def test_missing_functions_are_real_capability_failures(
    native: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper, _api, _session = native
    monkeypatch.setattr(helper.ctypes, "WinDLL", lambda _path: SimpleNamespace())
    with pytest.raises(ValueError, match="DhcpEnumSubnets"):
        helper.DhcpApi()
