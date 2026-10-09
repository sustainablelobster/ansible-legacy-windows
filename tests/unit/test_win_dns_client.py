"""Exercise public DNS requests with native operations replaced offline."""

# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

Request = Callable[[dict[str, Any]], tuple[int, dict[str, Any]]]


@pytest.fixture(name="native")
def dns_state() -> Any:
    """Keep one named adapter and a global suffix list across public calls.

    :returns: Persistent configuration and native call recorder.
    """
    state = SimpleNamespace(
        adapters=[
            {
                "name": "Ethernet",
                "guid": "owned-guid",
                "path": "owned-path",
                "families": [
                    {
                        "version": 4,
                        "servers": ["192.0.2.51"],
                        "dhcp": False,
                        "bad_format": False,
                    }
                ],
            }
        ],
        suffixes=[],
        calls=Mock(),
    )
    state.calls.read_adapters.side_effect = lambda names: (
        copy.deepcopy(state.adapters) if names else []
    )
    state.calls.read_suffixes.side_effect = lambda: list(state.suffixes)

    def servers(unused_adapter: Any, values: list[str]) -> None:
        state.adapters[0]["families"][0].update(
            servers=list(values), dhcp=not values, bad_format=False
        )

    state.calls.write_servers.side_effect = servers
    state.calls.write_suffixes.side_effect = lambda values: setattr(
        state, "suffixes", list(values)
    )
    return state


@pytest.fixture(name="run_request")
def request_runner(
    monkeypatch: pytest.MonkeyPatch,
    native: Any,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> Request:
    """Run the real JSON entry point against persistent native substitutes.

    :param monkeypatch: Scoped native and command-line replacements.
    :param native: Configuration shared across requests.
    :param tmp_path: Isolated request directory.
    :param capsys: Captured module protocol.
    :returns: Request runner returning exit status and the complete response.
    """
    payload = load_payload("win_dns_client", monkeypatch)
    for name in ("read_adapters", "read_suffixes", "write_servers", "write_suffixes"):
        monkeypatch.setattr(payload.dns, name, getattr(native.calls, name))
    path = tmp_path / "request.json"
    monkeypatch.setattr(sys, "argv", ["win_dns_client.py", str(path)])

    def _run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        path.write_text(json.dumps(arguments), encoding="utf-8")
        return invoke_payload(payload, capsys)

    return _run


def test_ordered_servers_check_real_repeat_and_reset(
    native: Any, run_request: Request
) -> None:
    args: dict[str, Any] = {
        "adapter_names": "Ethernet",
        "dns_servers": ["192.0.2.53", "192.0.2.54"],
        "_ansible_diff": True,
    }
    before = copy.deepcopy(native.adapters)
    assert run_request(dict(args, _ansible_check_mode=True)) == (0, {"changed": True})
    assert native.adapters == before
    assert run_request(args) == (0, {"changed": True})
    assert native.adapters[0]["families"][0]["servers"] == args["dns_servers"]
    assert run_request(args) == (0, {"changed": False})
    assert run_request(dict(args, dns_servers=list(reversed(args["dns_servers"])))) == (
        0,
        {"changed": True},
    )
    assert run_request({"dns_servers": []}) == (0, {"changed": True})
    assert run_request({"dns_servers": []}) == (0, {"changed": False})
    native.calls.read_adapters.assert_called_with(["*"])


@pytest.mark.parametrize(
    "alias", ["dns_servers", "ipv4_addresses", "ip_addresses", "addresses"]
)
def test_server_aliases_and_single_strings(
    native: Any, run_request: Request, alias: str
) -> None:
    assert run_request({alias: "192.0.2.53"}) == (0, {"changed": True})
    assert native.adapters[0]["families"][0]["servers"] == ["192.0.2.53"]


@pytest.mark.parametrize(
    "alias", ["dns_servers", "ipv4_addresses", "ip_addresses", "addresses"]
)
def test_explicit_null_servers_fail_before_writes_in_normal_and_check_mode(
    native: Any, run_request: Request, alias: str
) -> None:
    before = copy.deepcopy(native.adapters)
    assert run_request({alias: None, "_ansible_check_mode": True}) == (
        1,
        {"changed": False, "msg": "Invalid IP address(es): ()", "failed": True},
    )
    assert run_request({alias: None}) == (
        1,
        {"changed": False, "msg": "Invalid IP address(es): ()", "failed": True},
    )
    assert native.adapters == before
    native.calls.read_adapters.assert_called_with(["*"])
    native.calls.write_servers.assert_not_called()
    native.calls.write_suffixes.assert_not_called()


def test_adapter_resolution_precedes_null_address_validation(
    native: Any, run_request: Request
) -> None:
    native.calls.read_adapters.side_effect = ValueError("adapter is unavailable")
    assert run_request({"dns_servers": None}) == (
        1,
        {"changed": False, "msg": "adapter is unavailable", "failed": True},
    )
    native.calls.write_servers.assert_not_called()
    native.calls.write_suffixes.assert_not_called()


def test_unknown_options_are_ignored_without_changing_known_binding(
    native: Any, run_request: Request
) -> None:
    args = {
        "dns_servers": ["192.0.2.53"],
        "unexpected_dns_option": {"ignored": [True, None, 3]},
    }
    assert run_request(dict(args, _ansible_check_mode=True)) == (
        0,
        {"changed": True},
    )
    native.calls.write_servers.assert_not_called()
    assert run_request(args) == (0, {"changed": True})
    assert native.adapters[0]["families"][0]["servers"] == ["192.0.2.53"]
    assert run_request(args) == (0, {"changed": False})


def test_suffix_omission_null_order_case_and_empty_list(
    native: Any, run_request: Request
) -> None:
    args: dict[str, Any] = {
        "dns_servers": ["192.0.2.51"],
        "suffix_search_list": ["one.invalid", "two.invalid"],
    }
    assert run_request(dict(args, _ansible_check_mode=True)) == (0, {"changed": True})
    assert native.suffixes == []
    assert run_request(args) == (0, {"changed": True})
    assert run_request(args) == (0, {"changed": False})
    assert run_request(
        dict(args, suffix_search_list=["ONE.INVALID", "TWO.INVALID"])
    ) == (0, {"changed": False})
    assert run_request({"dns_servers": ["192.0.2.51"]}) == (0, {"changed": False})
    assert run_request(dict(args, suffix_search_list=None)) == (0, {"changed": False})
    assert run_request(
        dict(args, suffix_search_list=list(reversed(args["suffix_search_list"])))
    ) == (0, {"changed": True})
    assert run_request(dict(args, suffix_search_list=[], _ansible_check_mode=True)) == (
        0,
        {"changed": False},
    )
    assert run_request(dict(args, suffix_search_list=[])) == (0, {"changed": False})
    assert native.suffixes == ["two.invalid", "one.invalid"]


def test_invalid_addresses_are_reported_before_any_write(
    native: Any, run_request: Request
) -> None:
    status, result = run_request({"dns_servers": ["192.0.2.53", "bad", "also bad"]})
    assert status == 1 and result["changed"] is False
    assert result["msg"] == "Invalid IP address(es): (bad, also bad)"
    native.calls.write_servers.assert_not_called()
    native.calls.write_suffixes.assert_not_called()


@pytest.mark.parametrize("args", [{}, {"unexpected_dns_option": "ignored"}])
def test_missing_servers_fail_without_provider_work(
    native: Any, run_request: Request, args: dict[str, object]
) -> None:
    assert run_request(args)[0] == 1
    native.calls.read_adapters.assert_not_called()


def test_bad_registry_separators_are_rewritten(
    native: Any, run_request: Request
) -> None:
    native.adapters[0]["families"][0]["bad_format"] = True
    assert run_request({"dns_servers": ["192.0.2.51"]}) == (0, {"changed": True})
    assert run_request({"dns_servers": ["192.0.2.51"]}) == (0, {"changed": False})


def test_native_failure_recovers_on_a_later_request(
    native: Any, run_request: Request
) -> None:
    setter = native.calls.write_servers.side_effect
    native.calls.write_servers.side_effect = OSError("DNS provider refused change")
    status, result = run_request({"dns_servers": ["192.0.2.53"]})
    assert status == 1 and result["msg"] == "DNS provider refused change"
    assert native.adapters[0]["families"][0]["servers"] == ["192.0.2.51"]
    native.calls.write_servers.side_effect = setter
    assert run_request({"dns_servers": ["192.0.2.53"]}) == (0, {"changed": True})


def test_optional_log_is_written_in_check_mode(
    run_request: Request, tmp_path: Path
) -> None:
    path = tmp_path / "dns.log"
    assert run_request(
        {
            "dns_servers": ["192.0.2.53"],
            "log_path": str(path),
            "_ansible_check_mode": True,
        }
    ) == (0, {"changed": True})
    assert "Getting DNS config for adapter Ethernet" in path.read_text()


def test_families_compare_order_separately(native: Any, run_request: Request) -> None:
    native.adapters[0]["families"][0]["servers"] = ["192.0.2.53"]
    native.adapters[0]["families"].append(
        {
            "version": 6,
            "servers": ["2001:db8::53"],
            "dhcp": False,
            "bad_format": False,
        }
    )
    assert run_request({"dns_servers": ["2001:db8::53", "192.0.2.53"]}) == (
        0,
        {"changed": False},
    )
    assert run_request(
        {"dns_servers": ["192.0.2.53"], "_ansible_check_mode": True}
    ) == (
        0,
        {"changed": True},
    )
    native.calls.write_servers.assert_not_called()
    assert run_request({"dns_servers": ["192.0.2.53"]}) == (
        0,
        {"changed": True},
    )
    assert native.adapters[0]["families"][1]["servers"] == ["2001:db8::53"]
    assert run_request({"dns_servers": ["192.0.2.53"]}) == (
        0,
        {"changed": True},
    )


def test_requested_family_is_not_ignored_when_ipv4_uses_dhcp(
    native: Any, run_request: Request
) -> None:
    native.adapters[0]["families"][0]["dhcp"] = True
    assert run_request(
        {"dns_servers": ["2001:db8::53"], "_ansible_check_mode": True}
    ) == (
        0,
        {"changed": True},
    )
    native.calls.write_servers.assert_not_called()
