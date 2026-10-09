"""Exercise native DNS zone planning, public projection and failure ordering."""

# SPDX-License-Identifier: GPL-3.0-or-later
# pylint: disable=protected-access

import copy
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from tests.unit.payload_support import ROOT, load_module


def _zone(**updates: Any) -> dict[str, Any]:
    row = {
        "ZoneName": "Owned.INVALID",
        "ZoneType": "Primary",
        "IsPaused": False,
        "IsShutdown": False,
        "DynamicUpdate": "None",
        "IsReverseLookupZone": False,
        "IsDsIntegrated": False,
        "ReplicationScope": "None",
        "ZoneFile": "Owned.INVALID.dns",
        "MasterServers": None,
        "ForwarderTimeout": None,
        "DirectoryPartitionName": None,
    }
    row.update(updates)
    return row


def _options(**updates: Any) -> dict[str, Any]:
    values = {
        "name": "Owned.INVALID",
        "type": "primary",
        "state": "present",
        "dynamic_update": None,
        "replication": "none",
        "dns_servers": None,
        "forwarder_timeout": None,
        "directory_partition": None,
    }
    values.update(updates)
    return values


@pytest.fixture(name="native")
def native_helper(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load native helper with an observable WMI method boundary.

    :param monkeypatch: Scoped helper import and native substitutions.
    :returns: Helper and provider operation recorder.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    helper = load_module(
        ROOT / "plugins/module_utils/legacy_windows_dns_zone.py", "dns_zone_test"
    )
    connection = MagicMock()
    constructor = MagicMock()
    constructor.return_value.__enter__.return_value = connection
    connection.query.return_value = [{"__CLASS": "PS_DnsServerZone"}]
    monkeypatch.setattr(helper.wmi, "WmiConnection", constructor)
    monkeypatch.setattr(
        helper,
        "_call",
        lambda connection, class_name, method_name, inputs, output=False: connection.call_method(
            class_name,
            method_name,
            ["ReturnValue", "cmdletOutput"] if output else ["ReturnValue"],
            inputs,
        ),
    )
    monkeypatch.setattr(
        helper.ctypes,
        "FormatError",
        lambda code: "native status " + str(code),
        raising=False,
    )
    return SimpleNamespace(
        helper=helper, connection=connection, constructor=constructor
    )


@pytest.mark.parametrize("has_message", [False, True])
def test_native_extended_error_is_read_before_com_cleanup_and_preserves_hresult(
    monkeypatch: pytest.MonkeyPatch,
    has_message: bool,
) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    helper = load_module(
        ROOT / "plugins/module_utils/legacy_windows_dns_zone.py", "dns_zone_error_test"
    )
    connection = MagicMock()
    connection._method_inputs.return_value = 11
    monkeypatch.setattr(helper.wmi, "_bstr", lambda _api, _stack, text: text)
    events = []
    monkeypatch.setattr(helper.wmi, "_method", lambda *_: lambda *_args: 0x80041001)
    monkeypatch.setattr(
        helper.wmi, "_release", lambda _pointer: events.append("release")
    )

    def _message(_connection: Any) -> Any:
        events.append("message")
        return "Measured provider message" if has_message else None

    monkeypatch.setattr(helper, "_provider_message", _message)
    with pytest.raises(OSError) as raised:
        helper._call(connection, "Class", "Method", {"Name": "owned.invalid"})
    assert raised.value.hresult == 0x80041001  # type: ignore[attr-defined]
    assert str(raised.value) == (
        "Measured provider message"
        if has_message
        else "IWbemServices.ExecMethod(Method) failed (HRESULT 0x80041001)."
    )
    assert events == ["message", "release"]


def _replies(native: Any, before: Any, after: Any) -> None:
    native.connection.call_method.side_effect = [
        {"ReturnValue": None, "cmdletOutput": [before] if before else []},
        {"ReturnValue": None},
        {"ReturnValue": None, "cmdletOutput": [after] if after else []},
    ]


@pytest.mark.parametrize("zone_type", ["Primary", "Secondary", "Stub", "Forwarder"])
@pytest.mark.parametrize("servers", [None, ["127.0.0.1"], ["127.0.0.2", "127.0.0.1"]])
def test_projection_keeps_scalar_singleton_array_order_and_conditional_fields(
    native: Any, zone_type: str, servers: Any
) -> None:
    row = _zone(ZoneType=zone_type, MasterServers=servers, ForwarderTimeout=3)
    result = native.helper._project(row)
    assert result["name"] == "owned.invalid" and result["type"] == zone_type.lower()
    assert ("dns_servers" in result) == bool(servers)
    if servers:
        assert result["dns_servers"] == (servers[0] if len(servers) == 1 else servers)
    assert ("forwarder_timeout" in result) == (zone_type == "Forwarder")
    assert "reverse_lookup" not in result and "directory_partition" not in result
    assert result["replication"] == "none" and result["zone_file"] == row["ZoneFile"]


@pytest.mark.parametrize("scope", ["Forest", "Domain", "Legacy", "Custom"])
def test_ad_projection_keeps_only_applicable_storage_fields(
    native: Any, scope: str
) -> None:
    result = native.helper._project(
        _zone(
            IsDsIntegrated=True,
            ReplicationScope=scope,
            DirectoryPartitionName="owned.invalid",
            IsReverseLookupZone=True,
        )
    )
    assert "zone_file" not in result and result["reverse_lookup"] is True
    assert result["replication"] == scope.lower()
    assert ("directory_partition" in result) == (scope == "Custom")


def test_create_primary_reads_back_and_returns_full_changed_diff(native: Any) -> None:
    _replies(native, None, _zone())
    result = native.helper.manage(_options(), diff_mode=True)
    assert result == {
        "changed": True,
        "zone": native.helper._project(_zone()),
        "diff": {"before": "", "after": native.helper._project(_zone())},
    }
    calls = native.connection.call_method.call_args_list
    assert calls[1].args == (
        "PS_DnsServerPrimaryZone",
        "AddByFileForwardLookupZone",
        ["ReturnValue"],
        {"Name": "Owned.INVALID", "ZoneFile": "Owned.INVALID.dns", "PassThru": True},
    )
    native.constructor.assert_called_once_with(r"ROOT\Microsoft\Windows\Dns")
    native.constructor.return_value.__exit__.assert_called_once()


def test_repeat_primary_omits_zone_and_after_diff_and_preserves_case(
    native: Any,
) -> None:
    native.connection.call_method.side_effect = [
        {"ReturnValue": None, "cmdletOutput": [_zone()]},
        {"ReturnValue": None, "cmdletOutput": [_zone()]},
    ]
    assert native.helper.manage(_options(type=None), diff_mode=True) == {
        "changed": False,
        "diff": {"before": native.helper._project(_zone())},
    }
    assert native.connection.call_method.call_count == 2


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("update", ["secure", "nonsecureandsecure"])
def test_file_primary_update_rejects_removed_dynamic_update_before_write(
    native: Any, check: bool, update: str
) -> None:
    native.connection.call_method.return_value = {
        "ReturnValue": None,
        "cmdletOutput": [_zone()],
    }
    assert native.helper.manage(_options(dynamic_update=update), check, True) == {
        "changed": False,
        "failed": True,
        "diff": {"before": native.helper._project(_zone())},
        "warnings": [
            "Secure DNS updates are available only for Active Directory-integrated zones"
        ],
        "msg": "Failed to set properties on the zone Owned.INVALID: "
        "Cannot validate argument on parameter 'DynamicUpdate'. The argument "
        '"" does not belong to the set "None,Secure,NonsecureAndSecure" specified '
        "by the ValidateSet attribute. Supply an argument that is in the set "
        "and then try the command again.",
    }
    assert native.connection.call_method.call_count == 1


@pytest.mark.parametrize("check", [False, True])
def test_absent_existing_preserves_source_check_mode_nochange(
    native: Any, check: bool
) -> None:
    native.connection.call_method.side_effect = [
        {"ReturnValue": None, "cmdletOutput": [_zone()]},
        {"ReturnValue": None},
    ]
    result = native.helper.manage(_options(state="absent"), check, True)
    assert result["changed"] is not check
    assert result["diff"]["before"] == native.helper._project(_zone())
    assert ("after" in result["diff"]) is not check
    assert native.connection.call_method.call_count == (1 if check else 2)
    assert "zone" not in result


def test_absent_missing_is_sparse_noop_without_write(native: Any) -> None:
    native.connection.call_method.return_value = {
        "ReturnValue": None,
        "cmdletOutput": [],
    }
    assert native.helper.manage(_options(state="absent")) == {"changed": False}
    assert native.connection.call_method.call_count == 1


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("replication", ["domain", "forest", "legacy"])
def test_file_to_ad_guard_rejects_before_any_write_even_for_absence(
    native: Any, check: bool, replication: str
) -> None:
    native.connection.call_method.return_value = {
        "ReturnValue": None,
        "cmdletOutput": [_zone()],
    }
    result = native.helper.manage(
        _options(replication=replication, state="absent"), check, True
    )
    assert result["failed"] and not result["changed"]
    assert (
        result["msg"]
        == "Converting a file backed DNS zone to Active Directory integrated zone is unsupported"
    )
    assert native.connection.call_method.call_count == 1


@pytest.mark.parametrize("zone_type", ["secondary", "stub", "forwarder"])
@pytest.mark.parametrize("servers", [None, []])
def test_new_transfer_zone_requires_nonempty_servers(
    native: Any, zone_type: str, servers: Any
) -> None:
    native.connection.call_method.return_value = {
        "ReturnValue": None,
        "cmdletOutput": [],
    }
    result = native.helper.manage(
        _options(type=zone_type, dns_servers=servers), True, True
    )
    assert (
        result["failed"]
        and result["msg"]
        == "The dns_servers param is required when creating new stub, forwarder or secondary zones"
    )
    assert native.connection.call_method.call_count == 1


@pytest.mark.parametrize("update", ["secure", "nonsecureandsecure"])
def test_file_backed_primary_creation_warns_and_ignores_update(
    native: Any, update: str
) -> None:
    _replies(native, None, _zone())
    result = native.helper.manage(
        _options(dynamic_update=update, dns_servers=["invalid but ignored"])
    )
    assert result["changed"] and result["warnings"] == [
        "Secure DNS updates are available only for Active Directory-integrated zones"
    ]
    inputs = native.connection.call_method.call_args_list[1].args[3]
    assert "DynamicUpdate" not in inputs and "MasterServers" not in inputs


def test_existing_preview_diff_keeps_old_type_and_source_truthy_updates(
    native: Any,
) -> None:
    row = _zone(ZoneType="Forwarder", MasterServers=["127.0.0.1"], ForwarderTimeout=5)
    native.connection.call_method.return_value = {
        "ReturnValue": None,
        "cmdletOutput": [row],
    }
    result = native.helper.manage(
        _options(
            type="forwarder",
            dns_servers=["127.0.0.2", "127.0.0.1"],
            forwarder_timeout=0,
        ),
        True,
        True,
    )
    assert not result["changed"] and "zone" not in result
    assert result["diff"]["after"]["dns_servers"] is None
    assert result["diff"]["after"]["forwarder_timeout"] == 5
    assert native.connection.call_method.call_count == 2


@pytest.mark.parametrize("zone_type", ["Secondary", "Stub", "Forwarder"])
@pytest.mark.parametrize("servers", [["127.0.0.1"], ["127.0.0.2", "127.0.0.1"]])
def test_preview_input_address_strings_preserve_source_null_projection(
    native: Any, zone_type: str, servers: list[str]
) -> None:
    row = _zone(ZoneType=zone_type, MasterServers=["127.0.0.1"], ForwarderTimeout=3)
    native.connection.call_method.return_value = {
        "ReturnValue": None,
        "cmdletOutput": [row],
    }
    result = native.helper.manage(_options(type=None, dns_servers=servers), True, True)
    before = native.helper._project(row)
    assert result == {
        "changed": False,
        "diff": {"before": before, "after": dict(before, dns_servers=None)},
    }
    assert native.connection.call_method.call_count == 2


@pytest.mark.parametrize("zone_type", ["Secondary", "Stub", "Forwarder"])
def test_preview_without_supplied_addresses_retains_provider_projection(
    native: Any, zone_type: str
) -> None:
    row = _zone(ZoneType=zone_type, MasterServers=["127.0.0.1"], ForwarderTimeout=3)
    native.connection.call_method.return_value = {
        "ReturnValue": None,
        "cmdletOutput": [row],
    }
    result = native.helper.manage(_options(type=None), True, True)
    projected = native.helper._project(row)
    assert result == {
        "changed": False,
        "diff": {"before": projected, "after": projected},
    }
    assert native.connection.call_method.call_count == 2


def test_secondary_conversion_preview_retains_original_provider_addresses(
    native: Any,
) -> None:
    row = _zone(ZoneType="Forwarder", MasterServers=["127.0.0.1"], ForwarderTimeout=3)
    native.connection.call_method.return_value = {
        "ReturnValue": None,
        "cmdletOutput": [row],
    }
    result = native.helper.manage(
        _options(type="secondary", dns_servers=["127.0.0.2"]), True, True
    )
    projected = native.helper._project(row)
    assert result == {
        "changed": False,
        "diff": {"before": projected, "after": projected},
    }
    assert native.connection.call_method.call_count == 2


def test_missing_zone_preview_fails_final_lookup_without_any_write(native: Any) -> None:
    native.connection.call_method.return_value = {
        "ReturnValue": None,
        "cmdletOutput": [],
    }
    result = native.helper.manage(_options(), True, True)
    assert result["failed"] and not result["changed"]
    assert result["msg"].startswith("Failed to lookup new zone Owned.INVALID:")
    assert result["diff"] == {"before": ""}
    assert native.connection.call_method.call_count == 2


def test_set_failure_keeps_original_before_diff_and_stops_followup_reads(
    native: Any,
) -> None:
    native.connection.call_method.side_effect = [
        {"ReturnValue": None, "cmdletOutput": [_zone()]},
        OSError("denied"),
    ]
    result = native.helper.manage(_options(dynamic_update="none"), diff_mode=True)
    assert result == {
        "changed": False,
        "failed": True,
        "msg": "Failed to set properties on the zone Owned.INVALID: denied",
        "diff": {"before": native.helper._project(_zone())},
    }
    assert native.connection.call_method.call_count == 2


@pytest.mark.parametrize("zone_type", ["stub", "forwarder"])
def test_unsupported_type_conversion_rejects_before_write(
    native: Any, zone_type: str
) -> None:
    native.connection.call_method.return_value = {
        "ReturnValue": None,
        "cmdletOutput": [_zone()],
    }
    result = native.helper.manage(_options(type=zone_type, dns_servers=["127.0.0.1"]))
    assert (
        result["msg"]
        == "Failed to convert DNS zone Owned.INVALID to "
        + zone_type
        + ", unsupported conversion"
    )
    assert native.connection.call_method.call_count == 1


@pytest.mark.parametrize("zone_type", ["primary", "secondary"])
def test_shutdown_conversion_guard_is_not_skipped_in_preview(
    native: Any, zone_type: str
) -> None:
    row = _zone(ZoneType="Stub", IsShutdown=True)
    native.connection.call_method.return_value = {
        "ReturnValue": None,
        "cmdletOutput": [row],
    }
    result = native.helper.manage(_options(type=zone_type), True)
    assert (
        result["msg"]
        == "Failed to convert DNS zone Owned.INVALID: this zone is shutdown and cannot be modified"
    )
    assert native.connection.call_method.call_count == 1


@pytest.mark.parametrize("code", [0x8004100E, 0x80041010])
def test_missing_namespace_or_class_is_explicit_and_closes_connection(
    native: Any, code: int
) -> None:
    error = OSError("provider absent")
    error.hresult = code  # type: ignore[attr-defined]
    native.connection.query.side_effect = error
    with pytest.raises(OSError, match="provider is unavailable"):
        native.helper.manage(_options(state="absent"), True)
    native.connection.call_method.assert_not_called()
    assert native.constructor.return_value.__exit__.call_count == 2


def test_other_catalogue_failure_does_not_select_another_provider(native: Any) -> None:
    error = OSError("provider read failed")
    error.hresult = 0x80041002  # type: ignore[attr-defined]
    native.connection.query.side_effect = error
    with pytest.raises(OSError, match="provider read failed"):
        native.helper.manage(_options(state="absent"), True)
    native.constructor.assert_called_once_with(r"ROOT\Microsoft\Windows\Dns")
    native.connection.call_method.assert_not_called()


def test_missing_class_definition_is_not_successful_noop(native: Any) -> None:
    native.connection.query.return_value = []
    with pytest.raises(OSError, match="provider is unavailable"):
        native.helper.manage(_options(state="absent"))
    native.connection.call_method.assert_not_called()


def test_native_provider_nonzero_status_is_actionable(native: Any) -> None:
    native.connection.call_method.return_value = {"ReturnValue": 5}
    with pytest.raises(OSError, match="returned error 5: native status 5"):
        native.helper._invoke(
            native.connection, "PS_DnsServerZone", "Remove", {"Name": "owned.invalid"}
        )


def test_planning_does_not_mutate_caller_options_or_current_zone(native: Any) -> None:
    options, row = _options(type="forwarder", dns_servers=["127.0.0.1"]), _zone(
        ZoneType="Forwarder"
    )
    before = copy.deepcopy((options, row))
    native.helper._operations(options, row, "forwarder", [])
    assert (options, row) == before


@pytest.mark.parametrize("check", [False, True])
def test_stub_timeout_rejects_the_actual_absent_provider_parameter_before_write(
    native: Any, check: bool
) -> None:
    row = _zone(ZoneType="Stub", MasterServers=["127.0.0.1"])
    native.connection.call_method.return_value = {
        "ReturnValue": None,
        "cmdletOutput": [row],
    }
    result = native.helper.manage(
        _options(type="stub", forwarder_timeout=3), check, True
    )
    assert result["failed"] and not result["changed"]
    assert result["msg"] == (
        "Failed to set properties on the zone Owned.INVALID: A parameter cannot "
        "be found that matches parameter name 'ForwarderTimeout'."
    )
    assert native.connection.call_method.call_count == 1


@pytest.mark.parametrize("check", [False, True])
def test_omitted_file_primary_scope_does_not_silently_become_a_native_noop(
    native: Any, check: bool
) -> None:
    native.connection.call_method.return_value = {
        "ReturnValue": None,
        "cmdletOutput": [_zone()],
    }
    result = native.helper.manage(_options(replication=None), check, True)
    assert result["failed"] and "ReplicationScope" in result["msg"]
    assert native.connection.call_method.call_count == 1


def test_later_validation_failure_preserves_an_earlier_submitted_scope_operation(
    native: Any,
) -> None:
    operations = [
        (
            "PS_DnsServerConditionalForwarder",
            "SetByADZone",
            {"Name": "Owned.INVALID", "ReplicationScope": "Domain"},
        ),
        (
            "PS_DnsServerConditionalForwarder",
            "SetByParameters",
            {"Name": "Owned.INVALID", "ForwarderTimeout": 16},
        ),
    ]
    native.connection.call_method.return_value = {"ReturnValue": None}
    message = native.helper._apply_operations(
        native.connection, operations, "forwarder", "Owned.INVALID", False
    )
    assert message == (
        "Failed to set properties on the zone Owned.INVALID: ForwarderTimeout "
        "must be between 0 and 15."
    )
    assert native.connection.call_method.call_count == 1


@pytest.mark.parametrize("servers", [["invalid"], ["127.0.0.1 extra"], [""]])
def test_preview_checks_master_address_binding_without_submitting_writes(
    native: Any, servers: list[str]
) -> None:
    native.connection.call_method.return_value = {
        "ReturnValue": None,
        "cmdletOutput": [],
    }
    result = native.helper.manage(
        _options(type="forwarder", dns_servers=servers), True, True
    )
    assert result["failed"] and result["msg"].startswith("Failed to add forwarder zone")
    assert native.connection.call_method.call_count == 1
