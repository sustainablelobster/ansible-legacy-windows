"""Exercise gateway interfaces with an independent native provider boundary."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from contextlib import nullcontext
from copy import deepcopy
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from tests.unit.payload_support import ROOT, invoke_payload, load_module

CAP = "Win32_TSGatewayConnectionAuthorizationPolicy"
RAP = "Win32_TSGatewayResourceAuthorizationPolicy"
SETTINGS = "Win32_TSGatewayServerSettings"


class NativeGateway:
    """Model policy persistence and native method effects separately from planning."""

    def __init__(self) -> None:
        self.rows: dict[str, list[dict[str, Any]]] = {
            CAP: [],
            RAP: [],
            "Win32_TSGatewayResourceGroup": [{"Name": "Owned computers"}],
            SETTINGS: [
                {
                    "__PATH": "settings/250",
                    "MaxConnections": 250,
                    "MaximumAllowedConnectionsBySku": 250,
                    "UnlimitedConnections": True,
                    "OnlyConsentCapableClients": False,
                    "SslBridging": 0,
                    "CertHash": None,
                    "IsConfigured": False,
                }
            ],
        }
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []
        self.validated: set[str] = set()
        self.missing: str | None = None
        self.fail_configure_once = False

    def __enter__(self) -> "NativeGateway":
        return self

    def __exit__(self, *_arguments: Any) -> None:
        return None

    def records(self, class_name: str, fields: list[str]) -> list[dict[str, Any]]:
        """Return only explicitly requested native values.

        :param class_name: Native class name.
        :param fields: Selected properties.
        :returns: Independent native property copies.
        """
        return [
            {key: deepcopy(row[key]) for key in fields} for row in self.rows[class_name]
        ]

    def validate(self, _class_name: str, calls: list[Any]) -> None:
        """Reject an unavailable method before a mutation is submitted.

        :param calls: Requested native operations.
        :raises OSError: A requested method is unavailable.
        """
        for method, _inputs in calls:
            if method == self.missing:
                raise OSError("Installed gateway method unavailable: " + method)
            self.validated.add(method)

    def call(
        self, path: str, method: str, inputs: dict[str, Any] | None = None
    ) -> None:
        """Apply independently modeled native effects to persistent records.

        :param path: Fixed class or existing instance identity.
        :param method: Native operation name.
        :param inputs: Native method inputs.
        :raises AssertionError: An operation was not validated or its path is stale.
        :raises OSError: The native configuration failure is injected once.
        """
        assert method in self.validated
        self.calls.append((path, method, inputs))
        values = inputs or {}
        if method == "Create":
            self._create(path, values)
            return
        matches = [
            (cls, row)
            for cls, rows in self.rows.items()
            for row in rows
            if row.get("__PATH") == path
        ]
        assert len(matches) == 1, "stale native instance path"
        cls, row = matches[0]
        if method == "Delete":
            self.rows[cls].remove(row)
            if cls == CAP:
                for other in self.rows[CAP]:
                    if other["Order"] > row["Order"]:
                        other["Order"] -= 1
        elif method in ("MoveUp", "MoveDown"):
            self._move(row, method)
        elif method == "SetPasswordAllowed":
            row["PasswordAllowed"] = values["Allowed"]
        elif method == "SetSmartcardAllowed":
            row["SmartcardAllowed"] = values["Allowed"]
        elif method.startswith("Disable"):
            native = {
                "DisableClipboard": "ClipboardDisabled",
                "DisableDiskDrives": "DiskDrivesDisabled",
                "DisablePrinters": "PrintersDisabled",
                "DisableSerialPorts": "SerialPortsDisabled",
                "DisablePlugAndPlayDevices": "PlugAndPlayDevicesDisabled",
            }[method]
            row[native] = values["Disabled"]
        elif method == "SetMaxConnections":
            row.update(
                MaxConnections=values["Connections"],
                UnlimitedConnections=values["IsUnlimited"],
            )
            row["__PATH"] = "settings/" + str(values["Connections"])
        elif method == "Configure":
            self._configure(row)
        else:
            row.update(values)

    def _move(self, row: dict[str, Any], method: str) -> None:
        step = 1 if method == "MoveDown" else -1
        for other in self.rows[CAP]:
            if other is not row and other["Order"] == row["Order"] + step:
                other["Order"] -= step
        row["Order"] += step

    def _configure(self, row: dict[str, Any]) -> None:
        if self.fail_configure_once:
            self.fail_configure_once = False
            raise OSError("Configure failed after certificate assignment")
        row["IsConfigured"] = True

    def _create(self, cls: str, values: dict[str, Any]) -> None:
        if cls == CAP:
            for row in self.rows[CAP]:
                row["Order"] += 1
            row = {
                "Order": 1,
                "PasswordAllowed": False,
                "SmartcardAllowed": False,
                "ComputerGroupNames": None,
                "IdleTimeout": 0,
                "SessionTimeout": 0,
                "SessionTimeoutAction": 0,
                "AllowOnlySDRServers": False,
                "DeviceRedirectionType": 2,
                "DiskDrivesDisabled": False,
                "PrintersDisabled": False,
                "SerialPortsDisabled": False,
                "ClipboardDisabled": False,
                "PlugAndPlayDevicesDisabled": False,
            }
        else:
            row = {"Description": "", "ResourceGroupName": None}
        row.update(Enabled=False, **values)
        row["__PATH"] = cls + "/" + values["Name"]
        self.rows[cls].append(row)


@pytest.fixture(name="gateway")
def native_gateway() -> NativeGateway:
    """Create an isolated native persistence model.

    :returns: Empty gateway with installed local capabilities.
    """
    return NativeGateway()


@pytest.fixture(name="rds")
def gateway_payload(
    monkeypatch: pytest.MonkeyPatch, gateway: NativeGateway
) -> ModuleType:
    """Load target code without contacting Windows or importing a modern dependency.

    :param monkeypatch: Scoped native boundary replacements.
    :param gateway: Independent provider model.
    :returns: Target-compatible module imported by the development interpreter.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    helper = load_module(
        ROOT
        / "legacy_community_windows/plugins/module_utils/legacy_community_windows_rds.py",
        "tested_community_rds",
    )
    monkeypatch.setattr(helper, "Gateway", lambda: gateway)
    names = {
        "builtin\\users": "BUILTIN\\Users",
        "builtin\\administrators": "BUILTIN\\Administrators",
    }

    def _sid(value: str) -> str:
        if value.lower() not in names:
            raise OSError("Unknown local or domain account: " + value)
        return value.lower()

    monkeypatch.setattr(helper, "name_to_sid", _sid)
    monkeypatch.setattr(helper, "sid_to_name", lambda value: names[value])
    monkeypatch.setitem(sys.modules, "legacy_community_windows_rds", helper)
    return helper


def test_rap_lifecycle_preserves_released_defaults_and_changes_idempotently(
    rds: ModuleType, gateway: NativeGateway
) -> None:
    arguments = {
        "name": "Owned RAP",
        "user_groups": ["Users@builtin"],
        "allowed_ports": [3389, 3390],
        "state": "enabled",
        "description": "Owned policy",
        "_ansible_diff": True,
    }
    first = rds.manage("win_rds_rap", arguments)
    assert first["changed"] is True and "+[Owned RAP]" in first["diff"]["prepared"]
    assert gateway.rows[RAP][0]["PortNumbers"] == "3389;3390"
    assert gateway.rows[RAP][0]["Enabled"] is True
    assert rds.manage("win_rds_rap", arguments) == {"changed": False}
    updated = dict(
        arguments, description="Revised", allowed_ports=["any"], state="disabled"
    )
    assert rds.manage("win_rds_rap", updated)["changed"] is True
    assert rds.manage("win_rds_rap", updated) == {"changed": False}
    assert rds.manage("win_rds_rap", {"name": "Owned RAP", "state": "absent"}) == {
        "changed": True
    }
    assert rds.manage("win_rds_rap", {"name": "Owned RAP", "state": "absent"}) == {
        "changed": False
    }


def test_cap_lifecycle_applies_authentication_timeouts_groups_and_redirection(
    rds: ModuleType, gateway: NativeGateway
) -> None:
    arguments = {
        "name": "Owned CAP",
        "user_groups": ["BUILTIN\\Users"],
        "state": "enabled",
        "session_timeout": 30,
        "session_timeout_action": "reauth",
        "idle_timeout": 10,
        "allow_only_sdrts_servers": True,
        "redirect_clipboard": True,
        "redirect_drives": False,
    }
    assert rds.manage("win_rds_cap", arguments)["changed"] is True
    row = gateway.rows[CAP][0]
    assert row["PasswordAllowed"] is True and row["SmartcardAllowed"] is False
    assert row["SessionTimeout"] == 30 and row["SessionTimeoutAction"] == 1
    assert row["ClipboardDisabled"] is False and row["DiskDrivesDisabled"] is True
    assert rds.manage("win_rds_cap", arguments) == {"changed": False}
    updated = dict(
        arguments,
        auth_method="smartcard",
        user_groups=["BUILTIN\\Administrators"],
        computer_groups=["BUILTIN\\Users"],
    )
    assert rds.manage("win_rds_cap", updated)["changed"] is True
    auth_calls = [
        (method, values)
        for _path, method, values in gateway.calls
        if method in ("SetSmartcardAllowed", "SetPasswordAllowed")
    ]
    assert auth_calls[-2:] == [
        ("SetSmartcardAllowed", {"Allowed": True}),
        ("SetPasswordAllowed", {"Allowed": False}),
    ]
    updated_row = gateway.rows[CAP][0]
    assert updated_row["PasswordAllowed"] is False
    assert updated_row["SmartcardAllowed"] is True
    assert rds.manage("win_rds_cap", updated) == {"changed": False}
    assert rds.manage("win_rds_cap", {"name": "Owned CAP", "state": "absent"}) == {
        "changed": True
    }
    assert rds.manage("win_rds_cap", {"name": "Owned CAP", "state": "absent"}) == {
        "changed": False
    }


@pytest.mark.parametrize("module", ["win_rds_cap", "win_rds_rap"])
def test_policy_check_mode_predicts_create_update_and_remove_without_writes(
    rds: ModuleType, gateway: NativeGateway, module: str
) -> None:
    arguments = {
        "name": "Owned policy",
        "user_groups": ["BUILTIN\\Users"],
        "state": "enabled",
    }
    assert (
        rds.manage(module, dict(arguments, _ansible_check_mode=True))["changed"] is True
    )
    assert not gateway.calls
    rds.manage(module, arguments)
    before = deepcopy(gateway.rows)
    gateway.calls.clear()
    assert (
        rds.manage(
            module,
            {"name": "Owned policy", "state": "disabled", "_ansible_check_mode": True},
        )["changed"]
        is True
    )
    assert (
        rds.manage(
            module,
            {"name": "Owned policy", "state": "absent", "_ansible_check_mode": True},
        )["changed"]
        is True
    )
    assert not gateway.calls and gateway.rows == before


@pytest.mark.parametrize(
    "module,arguments,message",
    [
        ("win_rds_cap", {"name": "bad/name"}, "Invalid character"),
        ("win_rds_cap", {"name": "Owned", "order": 0}, "order must"),
        ("win_rds_cap", {"name": "Owned", "user_groups": []}, "empty list"),
        ("win_rds_cap", {"name": "Owned"}, "User groups must"),
        (
            "win_rds_rap",
            {"name": "Owned", "allowed_ports": ["3389"]},
            "valid port number",
        ),
        (
            "win_rds_rap",
            {"name": "Owned", "allowed_ports": [True]},
            "valid port number",
        ),
        (
            "win_rds_rap",
            {
                "name": "Owned",
                "computer_group_type": "rdg_group",
                "computer_group": "Missing",
            },
            "gateway managed",
        ),
        (
            "win_rds_rap",
            {"name": "Owned", "computer_group_type": "rdg_group"},
            "computer_group is required",
        ),
    ],
)
def test_invalid_policies_fail_before_native_writes(
    rds: ModuleType,
    gateway: NativeGateway,
    module: str,
    arguments: dict[str, Any],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        rds.manage(module, arguments)
    assert not gateway.calls


def test_missing_requested_capability_is_rejected_before_creation(
    rds: ModuleType, gateway: NativeGateway
) -> None:
    gateway.missing = "SetSessionTimeout"
    with pytest.raises(OSError, match="SetSessionTimeout"):
        rds.manage(
            "win_rds_cap",
            {"name": "Owned", "user_groups": ["BUILTIN\\Users"], "session_timeout": 30},
        )
    assert not gateway.calls and not gateway.rows[CAP]


def test_settings_rebind_mutable_instance_identity_and_repeat_idempotently(
    rds: ModuleType, gateway: NativeGateway
) -> None:
    arguments = {
        "max_connections": 50,
        "ssl_bridging": "https_http",
        "enable_only_messaging_capable_clients": True,
        "_ansible_diff": True,
    }
    result = rds.manage("win_rds_settings", arguments)
    assert (
        result["changed"] is True
        and "+MaxConnections = 50" in result["diff"]["prepared"]
    )
    assert rds.manage("win_rds_settings", arguments) == {"changed": False}
    assert rds.manage("win_rds_settings", {"max_connections": -1})["changed"] is True
    assert gateway.rows[SETTINGS][0]["UnlimitedConnections"] is True


def test_settings_validation_and_check_mode_do_not_write(
    rds: ModuleType, gateway: NativeGateway
) -> None:
    assert (
        rds.manage(
            "win_rds_settings", {"max_connections": 50, "_ansible_check_mode": True}
        )["changed"]
        is True
    )
    assert not gateway.calls
    with pytest.raises(ValueError, match="license/SKU"):
        rds.manage(
            "win_rds_settings", {"max_connections": 251, "ssl_bridging": "https_http"}
        )
    assert not gateway.calls


@pytest.mark.usefixtures("rds")
@pytest.mark.parametrize(
    "case",
    [
        ("win_rds_cap", {"name": "Owned CAP", "user_groups": ["BUILTIN\\Users"]}),
        ("win_rds_rap", {"name": "Owned RAP", "user_groups": ["BUILTIN\\Users"]}),
        ("win_rds_settings", {"max_connections": 50}),
    ],
)
def test_public_json_frontends_stage_the_released_argument_contract(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    case: tuple[str, dict[str, Any]],
) -> None:
    name, arguments = case
    source = ROOT / "legacy_community_windows/plugins/modules" / (name + ".py")
    payload = load_module(source, "tested_" + name)
    argument_file = tmp_path / (name + ".json")
    argument_file.write_text(json.dumps(arguments), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [name + ".py", str(argument_file)])
    code, result = invoke_payload(payload, capsys)
    assert code == 0 and result == {"changed": True}
    argument_file.write_text(
        json.dumps({key.upper(): value for key, value in arguments.items()}),
        encoding="utf-8",
    )
    code, repeated = invoke_payload(payload, capsys)
    assert code == 0 and repeated == {"changed": False}


def test_certificate_configuration_uses_byte_buffer_and_native_completion(
    rds: ModuleType, gateway: NativeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    thumbprint = "AB" * 20
    monkeypatch.setattr(
        rds,
        "open_store",
        lambda *_arguments: nullcontext(
            SimpleNamespace(records=[{"thumbprint": thumbprint}])
        ),
    )
    parameters = {"certificate_hash": thumbprint}
    assert rds.manage("win_rds_settings", dict(parameters, _ansible_check_mode=True))[
        "changed"
    ]
    assert not gateway.calls
    assert rds.manage("win_rds_settings", parameters) == {"changed": True}
    assert [(method, inputs) for _path, method, inputs in gateway.calls] == [
        ("SetCertificate", {"CertHash": bytes.fromhex(thumbprint)}),
        ("Configure", None),
    ]
    assert rds.manage("win_rds_settings", parameters) == {"changed": False}


def test_unavailable_certificate_configuration_is_rejected_before_assignment(
    rds: ModuleType, gateway: NativeGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    thumbprint = "AB" * 20
    monkeypatch.setattr(
        rds,
        "open_store",
        lambda *_arguments: nullcontext(
            SimpleNamespace(records=[{"thumbprint": thumbprint}])
        ),
    )
    gateway.missing = "Configure"
    with pytest.raises(OSError, match="Configure"):
        rds.manage("win_rds_settings", {"certificate_hash": thumbprint})
    assert not gateway.calls


def test_cap_evaluation_order_and_capping_preserve_other_policies(
    rds: ModuleType, gateway: NativeGateway
) -> None:
    for name in ("Owned first", "Owned second"):
        rds.manage("win_rds_cap", {"name": name, "user_groups": ["BUILTIN\\Users"]})
    assert [row["Order"] for row in gateway.rows[CAP]] == [2, 1]
    assert rds.manage("win_rds_cap", {"name": "Owned first", "order": 1})["changed"]
    assert [row["Order"] for row in gateway.rows[CAP]] == [1, 2]
    assert rds.manage("win_rds_cap", {"name": "Owned first", "order": 1}) == {
        "changed": False
    }
    capped = rds.manage("win_rds_cap", {"name": "Owned first", "order": 99})
    assert capped["changed"] and "capped to '2'" in capped["warnings"][0]
    assert [row["Order"] for row in gateway.rows[CAP]] == [2, 1]
    gateway.calls.clear()
    repeated = rds.manage("win_rds_cap", {"name": "Owned first", "order": 99})
    assert repeated["changed"] is False
    assert "capped to '2'" in repeated["warnings"][0]
    assert not gateway.calls


def test_gateway_order_query_uses_supported_full_instance_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = load_module(
        ROOT
        / "legacy_community_windows/plugins/module_utils/legacy_community_windows_rds.py",
        "tested_community_rds_order_query",
    )
    fields = ["Name", "Order"]
    rows = [{"Name": "Owned CAP", "Order": 1}]

    def _query(query: str, selected: list[str]) -> list[dict[str, Any]]:
        assert query == "SELECT * FROM " + CAP
        assert selected == fields
        return rows

    monkeypatch.setattr(
        helper, "WmiConnection", lambda _namespace: SimpleNamespace(query=_query)
    )
    assert helper.Gateway().records(CAP, fields) == rows


def test_rap_resource_group_modes_and_check_mode_preserve_installed_state(
    rds: ModuleType, gateway: NativeGateway
) -> None:
    arguments = {
        "name": "Owned RAP",
        "user_groups": ["BUILTIN\\Users"],
        "computer_group_type": "rdg_group",
        "computer_group": "Owned computers",
    }
    assert rds.manage("win_rds_rap", arguments)["changed"]
    assert gateway.rows[RAP][0]["ResourceGroupType"] == "RG"
    assert rds.manage("win_rds_rap", arguments) == {"changed": False}
    desired = dict(
        arguments,
        computer_group_type="ad_network_resource_group",
        computer_group="Administrators@builtin",
    )
    before = deepcopy(gateway.rows)
    gateway.calls.clear()
    assert rds.manage("win_rds_rap", dict(desired, _ansible_check_mode=True))["changed"]
    assert gateway.rows == before and not gateway.calls
    assert rds.manage("win_rds_rap", desired)["changed"]
    assert gateway.rows[RAP][0]["ResourceGroupName"] == "BUILTIN\\Administrators"
    assert rds.manage("win_rds_rap", desired) == {"changed": False}
    assert rds.manage("win_rds_rap", dict(arguments, computer_group_type="allow_any"))[
        "warnings"
    ]
    assert gateway.rows[RAP][0]["ResourceGroupType"] == "ALL"


def test_rap_any_port_marker_matches_released_case_insensitive_comparison(
    rds: ModuleType, gateway: NativeGateway
) -> None:
    arguments = {
        "name": "Owned RAP",
        "user_groups": ["BUILTIN\\Users"],
        "allowed_ports": ["ANY"],
    }
    assert rds.manage("win_rds_rap", arguments)["changed"]
    assert gateway.rows[RAP][0]["PortNumbers"] == "*"
    assert rds.manage("win_rds_rap", arguments) == {"changed": False}


def test_maximum_sku_connections_normalize_to_released_effective_unlimited_state(
    rds: ModuleType, gateway: NativeGateway
) -> None:
    gateway.rows[SETTINGS][0]["UnlimitedConnections"] = False
    assert rds.manage("win_rds_settings", {"max_connections": 250})["changed"]
    assert gateway.rows[SETTINGS][0]["UnlimitedConnections"] is True
    assert rds.manage("win_rds_settings", {"max_connections": 250}) == {
        "changed": False
    }
    assert rds.manage("win_rds_settings", {"max_connections": -1}) == {"changed": False}
    gateway.rows[SETTINGS][0]["UnlimitedConnections"] = False
    assert rds.manage("win_rds_settings", {"max_connections": -1})["changed"]
    assert gateway.rows[SETTINGS][0]["UnlimitedConnections"] is True


@pytest.mark.parametrize("configured", [False, True])
def test_certificate_retry_finishes_configuration_after_assignment_succeeded(
    rds: ModuleType,
    gateway: NativeGateway,
    monkeypatch: pytest.MonkeyPatch,
    configured: bool,
) -> None:
    thumbprint = "AB" * 20
    monkeypatch.setattr(
        rds,
        "open_store",
        lambda *_arguments: nullcontext(
            SimpleNamespace(records=[{"thumbprint": thumbprint}])
        ),
    )
    gateway.rows[SETTINGS][0]["IsConfigured"] = configured
    gateway.fail_configure_once = True
    with pytest.raises(OSError, match="Configure failed"):
        rds.manage("win_rds_settings", {"certificate_hash": thumbprint})
    assert gateway.rows[SETTINGS][0]["CertHash"] == bytes.fromhex(thumbprint)
    gateway.calls.clear()
    assert rds.manage("win_rds_settings", {"certificate_hash": thumbprint}) == {
        "changed": not configured
    }
    assert gateway.calls == [("settings/250", "Configure", None)]
    assert rds.manage("win_rds_settings", {"certificate_hash": thumbprint}) == {
        "changed": False
    }
    gateway.calls.clear()
    assert rds.manage(
        "win_rds_settings",
        {"certificate_hash": thumbprint, "_ansible_check_mode": True},
    ) == {"changed": False}
    assert not gateway.calls
