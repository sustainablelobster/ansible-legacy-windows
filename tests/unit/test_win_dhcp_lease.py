"""Exercise complete DHCP public responses and nontransactional behavior."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These native substitutes establish controller behavior, not Windows support.

import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload


def _record(reservation: bool = False, **updates: Any) -> dict[str, Any]:
    record = {
        "AddressState": "InactiveReservation" if reservation else "Active",
        "ClientId": "02-00-00-00-00-25",
        "IPAddress": "192.0.2.25",
        "ScopeId": "192.0.2.0",
        "HostName": "client.invalid",
        "Description": "old description",
    }
    record.update(updates)
    return record


@pytest.fixture(name="run_request")
def request_runner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> Any:
    """Run the real JSON entry point with an independently controlled provider.

    :param monkeypatch: Scoped native and argument-file replacements.
    :param tmp_path: Isolated argument directory.
    :param capsys: Captured module JSON.
    :returns: Payload, run_request function and provider recorder.
    """
    payload = load_payload("win_dhcp_lease", monkeypatch)
    server = MagicMock()
    server.find.return_value = []
    server.get.return_value = [_record(True, Name="fixture")]
    constructor = MagicMock()
    constructor.return_value.__enter__.return_value = server
    monkeypatch.setattr(payload.dhcp, "DhcpServer", constructor)
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    monkeypatch.setattr(
        payload.dhcp,
        "values_equal",
        lambda left, right: (
            left is right
            if left is None or right is None
            else left.lower() == right.lower()
        ),
    )
    monkeypatch.setattr(
        payload.dhcp, "lease_expiry", lambda _: "20300101000000.000000+000"
    )
    # pylint: enable=duplicate-code
    path = tmp_path / "arguments.json"
    monkeypatch.setattr(sys, "argv", ["win_dhcp_lease.py", str(path)])

    def _run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        path.write_text(json.dumps(arguments), encoding="utf-8")
        return invoke_payload(payload, capsys)

    return payload, _run, server, constructor


def _arguments(**updates: Any) -> dict[str, Any]:
    arguments = {"ip": "192.0.2.25", "mac": "020000000025", "scope_id": "192.0.2.0"}
    arguments.update(updates)
    return arguments


def _expected_record(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "address_state": row["AddressState"],
        "client_id": row["ClientId"],
        "ip_address": row["IPAddress"],
        "scope_id": row["ScopeId"],
        "name": row.get("Name"),
        "description": row["Description"],
    }


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("kind", ["reservation", "lease"])
@pytest.mark.parametrize("client_id", [None, ""])
def test_creation_requires_client_id_before_writes_or_preview(
    run_request: Any, check: bool, kind: str, client_id: str | None
) -> None:
    _, run, server, _ = run_request
    code, result = run(_arguments(mac=client_id, type=kind, _ansible_check_mode=check))
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    assert code == 1
    assert result == {
        "changed": False,
        "failed": True,
        "msg": (
            f"Could not create DHCP {kind}: Cannot validate argument on parameter "
            "'ClientId'. The argument is null or empty. Provide an argument "
            "that is not null or empty, and then try the command again."
        ),
    }
    # pylint: enable=duplicate-code
    server.create.assert_not_called()
    server.get.assert_not_called()


@pytest.mark.parametrize("check", [False, True])
def test_unavailable_lease_duration_cannot_remove_an_existing_reservation(
    run_request: Any,
    check: bool,
) -> None:
    _, run, server, _ = run_request
    server.find.return_value = [_record(True)]
    server.validate_create.side_effect = ValueError("No actual native lease duration")
    code, result = run(_arguments(type="lease", _ansible_check_mode=check))
    assert code == 1 and result["changed"] is False
    assert "No actual native lease duration" in result["msg"]
    server.remove.assert_not_called()
    server.create.assert_not_called()


@pytest.mark.parametrize("check", [False, True])
def test_create_reservation_uses_dns_name_and_omits_preview_record(
    run_request: Any, check: bool
) -> None:
    _, run, server, constructor = run_request
    code, result = run(_arguments(dns_hostname="fixture", _ansible_check_mode=check))
    assert code == 0 and result["changed"]
    constructor.assert_called_once_with(None)
    server.find.assert_called_once_with("192.0.2.0", "02-00-00-00-00-25", "192.0.2.25")
    assert ("lease" in result) is not check
    if check:
        server.create.assert_not_called()
        server.get.assert_not_called()
    else:
        server.create.assert_called_once_with(
            "Reservation",
            {
                "ClientId": "02-00-00-00-00-25",
                "IPAddress": "192.0.2.25",
                "ScopeId": "192.0.2.0",
                "Name": "fixture",
            },
        )
        assert result["lease"]["name"] == "fixture"


@pytest.mark.parametrize("duration", [None, 0, 14, -1])
@pytest.mark.parametrize(
    "dns,expected",
    [("aptr", "AandPTR"), ("a", "A"), ("noreg", "NoRegistration"), (None, None)],
)
def test_lease_creation_uses_only_creation_inputs(
    run_request: Any, duration: Any, dns: Any, expected: Any
) -> None:
    _, run, server, _ = run_request
    code, result = run(
        _arguments(
            type="lease",
            duration=duration,
            dns_regtype=dns,
            dns_hostname="client.invalid",
            description="lease description",
        )
    )
    assert code == 0 and result["changed"]
    kind, values = server.create.call_args.args
    assert kind == "Lease" and values["AddressState"] == "Active"
    assert (
        values["HostName"] == "client.invalid"
        and values["Description"] == "lease description"
    )
    assert values.get("DnsRR") == expected
    assert ("LeaseExpiryTime" in values) == bool(duration)


@pytest.mark.parametrize("check", [False, True])
def test_existing_ordinary_lease_does_not_update_any_requested_field(
    run_request: Any, check: bool
) -> None:
    _, run, server, _ = run_request
    server.find.return_value = [_record()]
    assert run(
        _arguments(
            type="lease", description="ignored", duration=14, _ansible_check_mode=check
        )
    ) == (
        0,
        {"changed": False, "diff": {"before": _expected_record(_record())}},
    )
    server.create.assert_not_called()
    server.update.assert_not_called()


@pytest.mark.parametrize("check", [False, True])
def test_reservation_repeat_preview_and_ignored_empty_values(
    run_request: Any, check: bool
) -> None:
    _, run, server, _ = run_request
    original = _record(True, Name="original")
    server.find.return_value = [original]
    server.get.return_value = [original]
    code, result = run(
        _arguments(description="", reservation_name="", _ansible_check_mode=check)
    )
    assert code == 0 and result["changed"] == check
    assert result["diff"] == {"before": _expected_record(original)}
    if check:
        server.update.assert_not_called()
        assert "lease" not in result
    else:
        server.update.assert_called_once_with(
            "192.0.2.25",
            {
                "ClientId": original["ClientId"],
                "Name": "original",
                "Description": original["Description"],
            },
        )
        assert result["lease"] == _expected_record(original)


def test_reservation_changed_client_id_reads_back_original_id(run_request: Any) -> None:
    _, run, server, _ = run_request
    server.find.return_value = [_record(True)]
    server.get.side_effect = OSError("missing original client")
    code, result = run(_arguments(mac="020000000026"))
    assert code == 1
    assert result == {
        "changed": False,
        "failed": True,
        "msg": "Unhandled exception while executing module: missing original client",
    }
    server.get.assert_called_once_with("02-00-00-00-00-25", "192.0.2.0")
    assert server.update.call_args.args[1]["Name"] == "reservation-02-00-00-00-00-25"


@pytest.mark.parametrize("reservation", [False, True])
@pytest.mark.parametrize("check", [False, True])
def test_conversion_preserves_source_field_selection(
    run_request: Any, reservation: bool, check: bool
) -> None:
    _, run, server, _ = run_request
    original = _record(reservation)
    server.find.return_value = [original]
    code, result = run(
        _arguments(
            type="lease" if reservation else "reservation",
            duration=14,
            description="new description",
            dns_hostname="ignored.invalid",
            _ansible_check_mode=check,
        )
    )
    if check and not reservation:
        assert code == 1 and not result["changed"]
        assert result["msg"] == "Could not convert lease to a reservation"
        server.create.assert_not_called()
        server.update.assert_not_called()
        server.remove.assert_not_called()
        assert "lease" not in result
        return
    assert code == 0 and result["changed"]
    if check:
        server.create.assert_not_called()
        server.remove.assert_not_called()
        assert "lease" not in result
    elif reservation:
        server.remove.assert_called_once_with([original], True)
        server.create.assert_called_once_with(
            "Lease",
            {
                "ClientId": original["ClientId"],
                "IPAddress": original["IPAddress"],
                "ScopeId": original["ScopeId"],
                "HostName": original["HostName"],
                "AddressState": "Active",
            },
        )
    else:
        assert (
            server.create.call_args.args[1]["Name"]
            == "reservation-" + original["ClientId"]
        )
        assert server.create.call_args.args[1]["Description"] == "new description"
        server.update.assert_called_once()


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("reservation", [False, True])
def test_remove_and_repeat_results(
    run_request: Any, check: bool, reservation: bool
) -> None:
    _, run, server, _ = run_request
    assert run(_arguments(state="absent", _ansible_check_mode=check)) == (
        0,
        {"changed": False, "msg": "The lease doesn't exist."},
    )
    original = _record(reservation)
    server.find.return_value = [original]
    code, result = run(_arguments(state="absent", _ansible_check_mode=check))
    assert code == 0 and result["changed"] and "lease" not in result
    if check:
        server.remove.assert_not_called()
    else:
        server.remove.assert_called_once_with([original], reservation)


def test_remove_failure_keeps_original_diff_and_lease(run_request: Any) -> None:
    _, run, server, _ = run_request
    original = _record(True)
    server.find.return_value = [original]
    server.remove.side_effect = OSError("denied")
    assert run(_arguments(state="absent")) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "Unable to remove lease/reservation: denied",
            "diff": {"before": _expected_record(original)},
            "lease": _expected_record(original),
        },
    )


def test_conversion_failure_preserves_prior_write_without_claiming_change(
    run_request: Any,
) -> None:
    _, run, server, _ = run_request
    server.find.return_value = [_record()]
    server.update.side_effect = OSError("denied")
    code, result = run(_arguments())
    assert code == 1 and result["failed"] and not result["changed"]
    assert result["msg"] == "Could not convert lease to a reservation"
    server.create.assert_called_once()


@pytest.mark.parametrize(
    "mac,expected",
    [
        ("020000000025", "02-00-00-00-00-25"),
        ("02:00:00:00:00:25", "02-00-00-00-00-25"),
        ("zzzzzzzzzzzz", "zz-zz-zz-zz-zz-zz"),
        ("02-00-00-00-00-25", "02-00-00-00-00-25"),
        ("", ""),
        (None, None),
    ],
)
def test_mac_binding_preserves_upstream_length_only_rule(
    run_request: Any, mac: Any, expected: Any
) -> None:
    _, run, server, _ = run_request
    code, result = run(_arguments(mac=mac, state="absent"))
    assert code == 0 and not result["changed"]
    assert server.find.call_args.args[1] == expected


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"ip": None},
        {"mac": "short"},
        {"ip": "192.0.2.25", "duration": 1.5},
        {"ip": "192.0.2.25", "type": "wrong"},
        {"ip": "192.0.2.25", "state": "wrong"},
        {"ip": "192.0.2.25", "dns_regtype": "wrong"},
        {"ip": "192.0.2.25", "extra": 1},
    ],
)
def test_invalid_requests_never_write_records(
    run_request: Any, arguments: dict[str, Any]
) -> None:
    _, run, server, _ = run_request
    code, result = run(arguments)
    assert code == 1 and result["failed"] and not result["changed"]
    server.create.assert_not_called()
    server.update.assert_not_called()
    server.remove.assert_not_called()


def test_missing_scope_is_reported_only_after_failed_lookup(run_request: Any) -> None:
    _, run, server, _ = run_request
    code, result = run({"ip": "192.0.2.25"})
    assert code == 1 and result["msg"].startswith("The scope_id parameter is required")
    server.find.assert_called_once_with(None, None, "192.0.2.25")


def test_remote_server_is_forwarded_without_changing_the_connection(
    run_request: Any,
) -> None:
    _, run, _, constructor = run_request
    assert run(_arguments(state="absent", computer_name="dhcp.invalid"))[0] == 0
    constructor.assert_called_once_with("dhcp.invalid")
