"""Exercise public DHCP workflows at the real older-provider boundary."""

# SPDX-License-Identifier: GPL-3.0-or-later
# pylint: disable=protected-access

import socket
import struct
from typing import Any
from unittest.mock import MagicMock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="classic")
def classic_server(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load the actual adapter with only its native API substituted.

    :param monkeypatch: Scoped module imports and RPC boundary replacements.
    :returns: Adapter module, native recorder and actual classic server object.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    module = load_module(
        ROOT / "plugins/module_utils/legacy_windows_dhcp_lease.py", "classic_dhcp_test"
    )
    api = MagicMock()
    api.subnets.return_value = ["192.0.2.0"]
    api.subnet.return_value = {"mask": "255.255.255.0"}
    api.lease_duration.return_value = 604800
    api.reservations.return_value = []
    api.clients.return_value = []
    monkeypatch.setattr(module, "DhcpApi", lambda _server: api)
    monkeypatch.setattr(
        module, "values_equal", lambda left, right: left.casefold() == right.casefold()
    )
    return module, api, module._ClassicDhcpServer("dhcp.invalid")


def _row(**changes: Any) -> dict[str, Any]:
    return {
        "address": "192.0.2.25",
        "mask": "255.255.255.0",
        "hardware": bytes.fromhex("020000000025"),
        "name": "original.invalid",
        "comment": "original description",
        "expires": 123456789,
        "owner": (1, "actual-server", "actual.invalid"),
        "kind": 100,
        "state": 1,
        **changes,
    }


def _values(**changes: Any) -> dict[str, Any]:
    return {
        "ClientId": "02-00-00-00-00-25",
        "IPAddress": "192.0.2.25",
        "ScopeId": "192.0.2.0",
        **changes,
    }


def test_actual_reservations_not_manual_client_type_bits_define_reservation(
    classic: Any,
) -> None:
    _, api, server = classic
    api.clients.return_value = [_row(kind=100)]
    assert server.find(None, None, "192.0.2.25")[0]["AddressState"] == "Active"
    api.reservations.return_value = [{"address": "192.0.2.25"}]
    assert (
        server.get("02-00-00-00-00-25", "192.0.2.0", True)[0]["AddressState"]
        == "ActiveReservation"
    )
    api.clients.return_value = [_row(state=0)]
    assert (
        server.get("02-00-00-00-00-25", "192.0.2.0", True)[0]["AddressState"]
        == "InactiveReservation"
    )


@pytest.mark.parametrize("state", [0, 2, 3])
def test_default_selection_excludes_nonactive_ordinary_leases(
    classic: Any,
    state: int,
) -> None:
    _, api, server = classic
    api.clients.return_value = [_row(state=state)]
    assert server.find(None, None, "192.0.2.25") == []


def test_native_scope_prefix_is_removed_only_when_exactly_present(classic: Any) -> None:
    module, _, _ = classic
    hardware = bytes.fromhex("020000000025")
    prefix = struct.pack("<I", struct.unpack("!I", socket.inet_aton("192.0.2.0"))[0])
    assert module._client_id(prefix + b"\x01" + hardware, "192.0.2.0") == (
        "02-00-00-00-00-25"
    )
    assert module._client_id(hardware, "192.0.2.0") == "02-00-00-00-00-25"
    assert module._client_id(prefix + b"\x02" + hardware, "192.0.2.0").endswith(
        "02-02-00-00-00-00-25"
    )


@pytest.mark.parametrize("field", ["Name", "HostName", "Description"])
def test_native_names_cannot_be_silently_truncated_after_a_reservation_write(
    classic: Any,
    field: str,
) -> None:
    _, api, server = classic
    with pytest.raises(ValueError, match="NUL"):
        server.create("Reservation", _values(**{field: "wrong\x00name"}))
    api.reserve.assert_not_called()
    api.save_client.assert_not_called()


@pytest.mark.parametrize("registration", ["A", "NoRegistration"])
def test_nondefault_dns_policy_fails_before_native_creation(
    classic: Any,
    registration: str,
) -> None:
    _, api, server = classic
    with pytest.raises(ValueError, match="DNS registration"):
        server.create("Lease", _values(DnsRR=registration))
    api.reserve.assert_not_called()
    api.save_client.assert_not_called()


def test_explicit_lease_expiry_does_not_require_an_invented_duration(
    classic: Any,
) -> None:
    _, api, server = classic
    server.create(
        "Lease", _values(LeaseExpiryTime="20990101000000.000000+000", HostName="actual")
    )
    api.lease_duration.assert_not_called()
    actual = api.save_client.call_args.args[0]
    assert actual["name"] == "actual" and actual["expires"] > 0
    assert api.save_client.call_args.kwargs == {"create": True}


def test_reservation_edit_retains_actual_expiry_owner_and_native_client_kind(
    classic: Any,
) -> None:
    _, api, server = classic
    original = _row()
    api.client.return_value = dict(original)
    api.reservations.return_value = [original]
    server.update("192.0.2.25", _values(Name="updated", Description="new"))
    api.reserve.assert_not_called()
    written = api.save_client.call_args.args[0]
    assert written == dict(original, name="updated", comment="new")


@pytest.mark.parametrize("hresult", [0x8004100E, 0x80041010])
def test_only_genuine_missing_management_provider_selects_native_api(
    classic: Any,
    monkeypatch: pytest.MonkeyPatch,
    hresult: int,
) -> None:
    module, api, _ = classic
    connection = MagicMock()
    error: Any = OSError("missing native provider")
    error.hresult = hresult
    connection.__enter__.side_effect = error
    monkeypatch.setattr(module, "WmiConnection", lambda _namespace: connection)
    with module.DhcpServer() as server:
        assert server.api is api


def test_access_denied_does_not_switch_management_backends(
    classic: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, _, _ = classic
    connection = MagicMock()
    error: Any = OSError("denied")
    error.hresult = 0x80070005
    connection.__enter__.side_effect = error
    monkeypatch.setattr(module, "WmiConnection", lambda _namespace: connection)
    with pytest.raises(OSError, match="denied"), module.DhcpServer():
        pass
