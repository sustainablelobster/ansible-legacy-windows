"""Verify DHCP provider inputs, enumeration and native resource ownership."""

# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Any
from unittest.mock import MagicMock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="native")
def native_helper(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load the DHCP helper against a controlled native WMI connection.

    :param monkeypatch: Scoped helper imports and native boundary replacements.
    :returns: Helper, connection recorder and provider object.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    helper = load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_dhcp_lease.py",
        "dhcp_native_test",
    )
    connection = MagicMock()
    monkeypatch.setattr(helper, "WmiConnection", lambda _: connection)
    monkeypatch.setattr(
        helper, "values_equal", lambda left, right: left.lower() == right.lower()
    )
    return helper, connection, helper.DhcpServer("dhcp.invalid")


def _reply(output: Any) -> dict[str, Any]:
    return {"ReturnValue": 0, "cmdletOutput": output}


def test_provider_connection_is_closed_after_success_and_failure(native: Any) -> None:
    _, connection, server = native
    with server as entered:
        assert entered is server
    connection.__enter__.assert_called_once()
    connection.__exit__.assert_called_once_with(None, None, None)
    with pytest.raises(ValueError), server:
        raise ValueError("failed")
    assert connection.__exit__.call_count == 2


def test_client_precedence_and_second_scope_pass_for_address_fallback(
    native: Any,
) -> None:
    _, connection, server = native
    scopes = [{"ScopeId": "192.0.2.0"}, {"ScopeId": "198.51.100.0"}]
    row = {"ClientId": "02-00-00-00-00-25", "IPAddress": "192.0.2.25"}
    connection.call_method.side_effect = [_reply(scopes), _reply([row]), _reply([])]
    assert server.find(None, row["ClientId"], "198.51.100.25") == [row]
    assert connection.call_method.call_count == 3
    connection.reset_mock()
    connection.call_method.side_effect = [
        _reply(scopes),
        _reply([]),
        _reply([]),
        _reply(scopes),
        _reply([row]),
        _reply([]),
    ]
    assert server.find(None, "missing", row["IPAddress"]) == [row]
    assert connection.call_method.call_count == 6


def test_provider_scope_filter_remote_server_and_active_only_default(
    native: Any,
) -> None:
    _, connection, server = native
    connection.call_method.side_effect = [
        _reply([{"ScopeId": "192.0.2.0"}]),
        _reply([]),
    ]
    assert server.find("192.0.2.0", None, "192.0.2.25") == []
    assert connection.call_method.call_args_list[0].args == (
        "PS_DhcpServerv4Scope",
        "Get",
        ["ReturnValue", "cmdletOutput"],
        {"ScopeId": ["192.0.2.0"], "ComputerName": "dhcp.invalid"},
    )
    assert connection.call_method.call_args_list[1].args[3] == {
        "ScopeId": "192.0.2.0",
        "ComputerName": "dhcp.invalid",
    }


@pytest.mark.parametrize("address", ["192.0.537", "0xc0000219", "192.0.2.25"])
def test_address_selection_compares_parsed_ipv4_objects(
    native: Any, address: str
) -> None:
    _, connection, server = native
    row = {"IPAddress": "192.0.2.25"}
    connection.call_method.side_effect = [
        _reply([{"ScopeId": "192.0.2.0"}]),
        _reply([row]),
    ]
    assert server.find(None, None, address) == [row]


def test_invalid_address_selector_is_unmatched_without_bind_failure(
    native: Any,
) -> None:
    _, connection, server = native
    connection.call_method.side_effect = [
        _reply([{"ScopeId": "192.0.2.0"}]),
        _reply([{"IPAddress": "192.0.2.25"}]),
    ]
    assert server.find(None, None, "invalid") == []


@pytest.mark.parametrize("reservation", [False, True])
def test_get_uses_typed_client_array_and_correct_projection(
    native: Any, reservation: bool
) -> None:
    _, connection, server = native
    connection.call_method.return_value = _reply({"Name": "fixture"})
    assert server.get("client", "192.0.2.0", reservation) == [{"Name": "fixture"}]
    args = connection.call_method.call_args.args
    assert args[0] == "PS_DhcpServerv4" + ("Reservation" if reservation else "Lease")
    assert args[1] == "GetByClientId" and args[3]["ClientId"] == ["client"]


@pytest.mark.parametrize("reservation", [False, True])
def test_selected_missing_client_is_not_a_successful_empty_getter(
    native: Any, reservation: bool
) -> None:
    _, connection, server = native
    connection.call_method.return_value = {}
    kind = "reservation" if reservation else "lease"
    with pytest.raises(
        OSError,
        match="Failed to get "
        + kind
        + " information for ClientId client from DHCP server dhcp.invalid.",
    ):
        server.get("client", "192.0.2.0", reservation)


@pytest.mark.parametrize("reservation", [False, True])
def test_remove_keeps_provider_row_order_and_stops_on_failure(
    native: Any, monkeypatch: pytest.MonkeyPatch, reservation: bool
) -> None:
    helper, connection, server = native
    monkeypatch.setattr(
        helper.ctypes,
        "WinError",
        lambda status: OSError(status, "denied"),
        raising=False,
    )
    connection.call_method.side_effect = [
        _reply(None),
        {"ReturnValue": 5, "cmdletOutput": None},
    ]
    with pytest.raises(OSError) as raised:
        server.remove(
            [
                {"IPAddress": "192.0.2.25"},
                {"IPAddress": "192.0.2.26"},
                {"IPAddress": "192.0.2.27"},
            ],
            reservation,
        )
    assert raised.value.errno == 5 and connection.call_method.call_count == 2
    assert [
        call.args[3]["IPAddress"] for call in connection.call_method.call_args_list
    ] == [["192.0.2.25"], ["192.0.2.26"]]


@pytest.mark.parametrize(
    "value,expected",
    [("192.0.2.25", "192.0.2.25"), ("127.1", "127.0.0.1"), ("0x7f000001", "127.0.0.1")],
)
def test_ipv4_binding_preserves_shipped_ipv4_parser_spellings(
    native: Any, value: str, expected: str
) -> None:
    helper, _, _ = native
    assert helper.ipv4(value, "ip") == expected


@pytest.mark.parametrize(
    "value",
    [None, "", "192.0.2.25 suffix", "::1", "999.1.1.1", "192.0.2.25\x00ignored"],
)
def test_invalid_ipv4_requests_fail_before_native_methods(
    native: Any, value: Any
) -> None:
    helper, connection, _ = native
    with pytest.raises(ValueError, match="ip must be an IPv4 address"):
        helper.ipv4(value, "ip")
    connection.call_method.assert_not_called()


def test_duration_uses_existing_native_local_calendar_conversion(
    native: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper, _, _ = native
    observed = []
    monkeypatch.setattr(helper, "current_local_ticks", lambda: 100)

    def _convert(ticks: int) -> int:
        observed.append(ticks)
        return 135379296001234560

    monkeypatch.setattr(helper, "local_ticks_to_file_time", _convert)
    assert helper.lease_expiry(14) == "20300101000000.123456+000"
    assert observed == [100 + 14 * 864000000000]
