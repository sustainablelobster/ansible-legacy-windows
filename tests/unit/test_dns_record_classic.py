"""Exercise ordinary record workflows against a stateful older native boundary."""

# SPDX-License-Identifier: GPL-3.0-or-later
# pylint: disable=protected-access

import codecs
import copy
from typing import Any
from unittest.mock import MagicMock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="server")
def classic_server(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Retain native rows while exercising the real public reconciliation.

    :param monkeypatch: Scoped sibling imports and native boundaries.
    :returns: Helper, connection, actual row state and observed mutation calls.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    helper = load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_dns_record.py",
        "classic_records_test",
    )
    state: dict[str, Any] = {
        "rows": [],
        "writes": [],
        "srv_property": "SRVDomainName",
        "srv_input": "SRVDomainName",
    }
    connection = MagicMock()
    connection._method_inputs.return_value = "srv-creation-inputs"
    monkeypatch.setattr(helper.wmi, "_get_object", lambda *_args: "srv-class")
    monkeypatch.setattr(
        helper.wmi,
        "_read_embedded_object",
        lambda _automation, instance: {
            state["srv_property" if instance == "srv-class" else "srv_input"]: None
        },
    )

    def _query(query: str, fields: list[str]) -> list[dict[str, Any]]:
        if "meta_class" in query:
            return [{"__CLASS": "MicrosoftDNS_AType"}]
        if "MicrosoftDNS_Zone" in query:
            return [{"Name": "owned.invalid"}]
        if "MicrosoftDNS_SRVType" in query and state["rows"]:
            if any(field not in state["rows"][0] for field in fields):
                raise OSError("The SRV class does not expose that property.")
        return copy.deepcopy(state["rows"])

    connection.query.side_effect = _query
    monkeypatch.setattr(helper, "_dns_tool", lambda: None)

    def _srv_update_path(row: dict[str, Any]) -> str:
        path = str(row["__PATH"])
        if state["srv_property"] == "DomainName":
            return path.replace(
                ',DomainName="' + row["DomainName"] + '"',
                ',DomainName="' + row["OwnerName"] + '"',
                1,
            )
        return path

    def _call(
        _connection: Any, path: str, method: str, inputs: dict[str, Any]
    ) -> dict[str, Any]:
        state["writes"].append((path, method, copy.deepcopy(inputs)))
        if method == "CreateInstanceFromPropertyData":
            if path == "MicrosoftDNS_SRVType":
                target = state["srv_input"]
                if target not in inputs:
                    raise OSError("The SRV creation signature requires " + target)
                inputs = dict(inputs)
                inputs[state["srv_property"]] = inputs.pop(target)
            state["rows"].append(
                {
                    "__PATH": "native-record-" + str(len(state["rows"])),
                    "OwnerName": inputs["OwnerName"],
                    "TTL": inputs.get("TTL", 3600),
                    "Timestamp": 0,
                    **{
                        key: value
                        for key, value in inputs.items()
                        if key
                        not in (
                            "DnsServerName",
                            "ContainerName",
                            "RecordClass",
                            "OwnerName",
                            "TTL",
                        )
                    },
                }
            )
            if path == "MicrosoftDNS_SRVType":
                state["rows"][-1]["__PATH"] = (
                    'MicrosoftDNS_SRVType.ContainerName="owned.invalid",'
                    'DomainName="' + inputs[state["srv_property"]] + '",'
                    'OwnerName="' + inputs["OwnerName"] + '"'
                )
        else:
            assert method == "Modify"
            selected = [
                row
                for row in state["rows"]
                if (
                    _srv_update_path(row)
                    if "MicrosoftDNS_SRVType" in row["__PATH"]
                    else row["__PATH"]
                )
                == path
            ]
            if not selected:
                raise OSError("The provider cannot look up that SRV path.")
            assert len(selected) == 1
            if "MicrosoftDNS_SRVType" in path and all(
                name in inputs and inputs[name] == selected[0][name]
                for name in ("Port", "Priority", "Weight")
            ):
                # Native older providers can acknowledge a TTL-only request
                # yet remove its record when unchanged service fields are sent.
                state["rows"].remove(selected[0])
                return {}
            selected[0].update(inputs)
        return {}

    def _delete(_connection: Any, path: str) -> None:
        state["writes"].append((path, "delete"))
        state["rows"] = [row for row in state["rows"] if row["__PATH"] != path]

    monkeypatch.setattr(helper.classic, "call", _call)
    monkeypatch.setattr(helper.classic, "delete", _delete)
    return helper, connection, state


def _options(kind: str = "A", **changes: Any) -> dict[str, Any]:
    return {
        "name": "record",
        "zone": "owned.invalid",
        "type": kind,
        "state": "present",
        "value": ["192.0.2.1"],
        "ttl": 300,
        "aging": False,
        "allow_update_any": False,
        "computer_name": None,
        "zone_scope": None,
        "port": 123,
        "weight": 5,
        "priority": 7,
        **changes,
    }


@pytest.mark.parametrize(
    "kind,value",
    [
        ("A", "192.0.2.1"),
        ("AAAA", "2001:db8::1"),
        ("CNAME", "target.example.test."),
        ("NS", "target.example.test."),
        ("PTR", "target.example.test."),
        ("TXT", "owned text"),
        ("SRV", "target.example.test."),
    ],
)
def test_public_classic_create_edit_repeat_preview_remove(
    server: Any, kind: str, value: str
) -> None:
    helper, connection, state = server
    options = _options(kind, value=[value], ttl=300)
    provider = helper._ClassicRecords(connection, options)
    assert helper._manage(provider, options, False, True)["changed"]
    assert helper._manage(provider, options, False, True)["changed"] is False
    before = copy.deepcopy(state)
    edited = dict(options, ttl=600)
    assert helper._manage(provider, edited, True, True)["changed"]
    assert state == before
    assert helper._manage(provider, edited, False, True)["changed"]
    assert helper._manage(provider, edited, False, True)["changed"] is False
    removed = dict(edited, state="absent", value=[])
    assert helper._manage(provider, removed, False, True)["changed"]
    assert state["rows"] == []
    assert helper._manage(provider, removed, False, True)["changed"] is False


@pytest.mark.parametrize("target_field", ["DomainName", "SRVDomainName"])
def test_srv_lifecycle_uses_the_installed_class_and_creation_signature(
    server: Any, target_field: str
) -> None:
    helper, connection, state = server
    state["srv_property"] = target_field
    state["srv_input"] = target_field
    options = _options("SRV", value=["target.example.test."], ttl=600)
    provider = helper._ClassicRecords(connection, options)
    preview = copy.deepcopy(state)
    assert helper._manage(provider, options, True, True)["changed"]
    assert state == preview
    result = helper._manage(provider, options, False, True)
    assert not result.get("failed"), result
    assert result["changed"]
    assert state["rows"][0][target_field] == "target.example.test."
    assert state["rows"][0]["TTL"] == 600
    for _repeat in range(2):
        assert helper._manage(provider, options, False, True)["changed"] is False
    edited = dict(options, ttl=900, port=23456, priority=11, weight=21)
    assert helper._manage(provider, edited, False, True)["changed"]
    assert provider.read()[0]["RecordData"] == {
        "DomainName": "target.example.test.",
        "Port": 23456,
        "Priority": 11,
        "Weight": 21,
    }
    assert state["rows"][0]["TTL"] == 900
    assert helper._manage(provider, edited, False, True)["changed"] is False
    absent = dict(edited, state="absent", value=[])
    assert helper._manage(provider, absent, False, True)["changed"]
    assert not state["rows"]
    assert helper._manage(provider, absent, False, True)["changed"] is False


@pytest.mark.parametrize("contract", ["srv_property", "srv_input"])
def test_unrecognized_srv_schema_fails_before_mutation(
    server: Any, contract: str
) -> None:
    helper, connection, state = server
    state[contract] = "UnrecognizedTarget"
    with pytest.raises(ValueError, match="SRV .* schema has no supported target"):
        helper._ClassicRecords(connection, _options("SRV", value=["target.test."]))
    assert not state["writes"]


def test_srv_domain_name_edit_keeps_exact_other_path_keys(server: Any) -> None:
    helper, connection, state = server
    state["srv_property"] = state["srv_input"] = "DomainName"
    options = _options("SRV", value=["target.example.test."], ttl=600)
    provider = helper._ClassicRecords(connection, options)
    assert helper._manage(provider, options, False, True)["changed"]
    original = state["rows"][0]["__PATH"]
    assert helper._manage(provider, dict(options, ttl=900), False, True)["changed"]
    assert state["writes"][-1] == (
        original.replace(
            ',DomainName="target.example.test."', ',DomainName="record.owned.invalid"'
        ),
        "Modify",
        {"TTL": 900},
    )


@pytest.mark.parametrize("target_field", ["DomainName", "SRVDomainName"])
@pytest.mark.parametrize("target_suffix", ["", "."])
def test_srv_ttl_only_edit_retains_service_fields_and_unchanged_repeat(
    server: Any, target_field: str, target_suffix: str
) -> None:
    helper, connection, state = server
    state["srv_property"] = state["srv_input"] = target_field
    options = _options("SRV", value=["target.example.test" + target_suffix], ttl=600)
    provider = helper._ClassicRecords(connection, options)
    assert helper._manage(provider, options, False, True)["changed"]
    before = copy.deepcopy(state)
    edited = dict(options, ttl=900)
    assert helper._manage(provider, edited, True, True)["changed"]
    assert state == before
    assert helper._manage(provider, edited, False, True)["changed"]
    assert state["writes"][-1][2] == {"TTL": 900}
    assert len(state["rows"]) == 1
    assert state["rows"][0]["TTL"] == 900
    assert provider.read()[0]["RecordData"] == {
        "DomainName": "target.example.test.",
        "Port": 123,
        "Priority": 7,
        "Weight": 5,
    }
    assert helper._manage(provider, edited, False, True)["changed"] is False


@pytest.mark.parametrize("field", ["port", "priority", "weight"])
def test_srv_edit_omits_other_unchanged_service_fields(server: Any, field: str) -> None:
    helper, connection, state = server
    options = _options("SRV", value=["target.example.test."], ttl=600)
    provider = helper._ClassicRecords(connection, options)
    assert helper._manage(provider, options, False, True)["changed"]
    edited = dict(options, **{field: 42})
    assert helper._manage(provider, edited, False, True)["changed"]
    assert state["writes"][-1][2] == {"TTL": 600, field.title(): 42}
    assert helper._manage(provider, edited, False, True)["changed"] is False


def test_srv_silent_native_deletion_fails_and_next_apply_recovers(
    server: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper, connection, state = server
    options = _options("SRV", value=["target.example.test."], ttl=600)
    provider = helper._ClassicRecords(connection, options)
    assert helper._manage(provider, options, False, True)["changed"]
    native_call = helper.classic.call

    def _lose_record(*args: Any) -> dict[str, Any]:
        result: dict[str, Any] = native_call(*args)
        state["rows"].clear()
        return result

    monkeypatch.setattr(helper.classic, "call", _lose_record)
    edited = dict(options, ttl=900)
    with pytest.raises(OSError, match="did not retain the requested target"):
        helper._manage(provider, edited, False, True)
    assert not state["rows"]
    assert len(state["writes"]) == 2
    monkeypatch.setattr(helper.classic, "call", native_call)
    provider = helper._ClassicRecords(connection, edited)
    assert helper._manage(provider, edited, False, True)["changed"]
    assert state["rows"][0]["TTL"] == 900
    assert helper._manage(provider, edited, False, True)["changed"] is False


@pytest.mark.parametrize("mismatch", ["TTL", "Port", "Timestamp"])
def test_srv_native_acknowledgement_requires_exact_requested_state(
    server: Any, monkeypatch: pytest.MonkeyPatch, mismatch: str
) -> None:
    helper, connection, state = server
    options = _options("SRV", value=["target.example.test."], ttl=600)
    provider = helper._ClassicRecords(connection, options)
    assert helper._manage(provider, options, False, True)["changed"]
    native_call = helper.classic.call

    def _wrong_state(*args: Any) -> dict[str, Any]:
        result: dict[str, Any] = native_call(*args)
        state["rows"][0][mismatch] = 1
        return result

    monkeypatch.setattr(helper.classic, "call", _wrong_state)
    with pytest.raises(OSError, match="did not retain the requested target"):
        helper._manage(provider, dict(options, ttl=900), False, True)
    assert len(state["writes"]) == 2


def test_srv_verification_propagates_read_failure_without_recreation(
    server: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper, connection, state = server
    options = _options("SRV", value=["target.example.test."], ttl=600)
    provider = helper._ClassicRecords(connection, options)
    assert helper._manage(provider, options, False, True)["changed"]
    native_call = helper.classic.call
    read_failure = OSError(5, "Native DNS state cannot be read")

    def _fail_verification(*args: Any) -> dict[str, Any]:
        result: dict[str, Any] = native_call(*args)
        connection.query.side_effect = read_failure
        return result

    monkeypatch.setattr(helper.classic, "call", _fail_verification)
    with pytest.raises(OSError) as raised:
        helper._manage(provider, dict(options, ttl=900), False, True)
    assert raised.value is read_failure
    assert len(state["rows"]) == 1
    assert len(state["writes"]) == 2


def test_srv_ttl_edit_preserves_sibling_records(server: Any) -> None:
    helper, connection, state = server
    options = _options(
        "SRV", value=["first.example.test.", "second.example.test."], ttl=600
    )
    provider = helper._ClassicRecords(connection, options)
    assert helper._manage(provider, options, False, True)["changed"]
    original = copy.deepcopy(state["rows"])
    old = provider.read()[0]
    new = helper._edited_record(old, dict(options, ttl=900))
    provider.update(old, new)
    assert state["rows"][0] == dict(original[0], TTL=900)
    assert state["rows"][1] == original[1]


@pytest.mark.parametrize("aging,open_acl", [(True, False), (False, True)])
def test_srv_tool_create_honors_nondefault_ttl_and_repeats(
    server: Any,
    monkeypatch: pytest.MonkeyPatch,
    aging: bool,
    open_acl: bool,
) -> None:
    helper, connection, state = server
    monkeypatch.setattr(helper, "_dns_tool", lambda: "installed-dnscmd")
    options = _options(
        "SRV",
        value=["target.example.test."],
        aging=aging,
        allow_update_any=open_acl,
    )
    provider = helper._ClassicRecords(connection, options)

    def _command(arguments: list[str]) -> str:
        assert arguments == [
            "/RecordAdd",
            "owned.invalid",
            "record",
            "/Aging" if aging else "/OpenAcl",
            "300",
            "SRV",
            "7",
            "5",
            "123",
            "target.example.test.",
        ]
        state["rows"] = [
            {
                "__PATH": "native-srv",
                "OwnerName": "record.owned.invalid",
                "TTL": 300,
                "Timestamp": 3732171 if aging else 0,
                "SRVDomainName": "target.example.test.",
                "Priority": 7,
                "Weight": 5,
                "Port": 123,
            }
        ]
        return ""

    monkeypatch.setattr(provider, "_command", _command)
    before = copy.deepcopy(state)
    assert helper._manage(provider, options, True, True)["changed"]
    assert state == before
    assert helper._manage(provider, options, False, True)["changed"]
    assert state["rows"][0]["TTL"] == 300
    assert helper._manage(provider, options, False, True)["changed"] is False
    assert helper._manage(provider, options, True, True)["changed"] is False


def test_native_record_edits_use_exact_path_and_preserve_raw_txt(server: Any) -> None:
    helper, connection, state = server
    options = _options("TXT", value=["owned text"])
    state["rows"] = [
        {
            "__PATH": "only-observed-record",
            "OwnerName": "record.owned.invalid",
            "TTL": 300,
            "Timestamp": 0,
            "DescriptiveText": "owned text",
        }
    ]
    provider = helper._ClassicRecords(connection, options)
    assert helper._manage(provider, dict(options, ttl=600), False, True)["changed"]
    assert state["writes"] == [
        (
            "only-observed-record",
            "Modify",
            {"TTL": 600, "DescriptiveText": "owned text"},
        )
    ]


def test_utf8_txt_lifetime_edit_avoids_lossy_provider_setter(
    server: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper, connection, state = server
    monkeypatch.setattr(helper, "_dns_tool", lambda: "installed-dnscmd")
    monkeypatch.setattr(helper, "_classic_text", lambda _value: "owned Unicode Ω")
    state["rows"] = [
        {
            "__PATH": "only-observed-record",
            "OwnerName": "record.owned.invalid",
            "TTL": 300,
            "Timestamp": 0,
            "DescriptiveText": "owned Unicode Î©",
        }
    ]
    options = _options("TXT", value=["owned Unicode Ω"])
    provider = helper._ClassicRecords(connection, options)
    command = MagicMock()
    command.side_effect = lambda _arguments: state["rows"][0].update(TTL=600)
    monkeypatch.setattr(provider, "_command", command)
    assert helper._manage(provider, dict(options, ttl=600), False, True)["changed"]
    command.assert_called_once_with(
        ["/RecordAdd", "owned.invalid", "record", "600", "TXT", "owned Unicode Ω"]
    )
    assert state["writes"] == []
    assert state["rows"][0]["DescriptiveText"] == "owned Unicode Î©"


@pytest.mark.parametrize(
    "options",
    [
        _options(aging=True),
        _options(allow_update_any=True),
        _options("DHCID", value=["AAEB"]),
        _options("TXT", value=["Unicode Ω"]),
    ],
)
def test_missing_meaningful_tool_fails_before_any_record_change(
    server: Any, options: dict[str, Any]
) -> None:
    helper, connection, state = server
    with pytest.raises(ValueError, match="installed dnscmd"):
        helper._ClassicRecords(connection, options)
    assert state["writes"] == []
    connection.query.assert_not_called()


def test_missing_real_zone_scope_fails_before_any_record_change(server: Any) -> None:
    helper, connection, state = server
    with pytest.raises(ValueError, match="zone scopes"):
        helper._ClassicRecords(connection, _options(zone_scope="other"))
    assert state["writes"] == []
    connection.query.assert_not_called()


def test_native_queries_cannot_interpolate_owner_names(server: Any) -> None:
    helper, connection, _state = server
    provider = helper._ClassicRecords(connection, _options(name="owned'\\record"))
    provider.read()
    query = connection.query.call_args.args[0]
    assert "OwnerName='owned\\'\\\\record.owned.invalid'" in query


@pytest.mark.parametrize("timestamp", [0, 3732171])
def test_dhcid_reads_actual_stable_rpc_fields(
    server: Any, monkeypatch: pytest.MonkeyPatch, timestamp: int
) -> None:
    helper, connection, state = server
    monkeypatch.setattr(helper, "_dns_tool", lambda: "installed-dnscmd")
    commands: list[list[str]] = []

    def _command(
        _self: Any, arguments: list[str], allowed_errors: tuple[int, ...] = ()
    ) -> str:
        commands.append(arguments)
        if arguments == ["/RecordAdd"]:
            assert allowed_errors == (87,)
            return "DHCID <Base64Data>"
        return (
            "ptr = 1234\ndwTtlSeconds = 300\ndwTimeStamp = "
            + str(timestamp)
            + " ([ 0: 0: 0] [ 1/ 1/1601]) DHCID\tAAEB\n"
        )

    monkeypatch.setattr(helper._ClassicRecords, "_command", _command)
    provider = helper._ClassicRecords(
        connection, _options("DHCID", value=["AAEB"], aging=bool(timestamp))
    )
    result = helper._manage(provider, provider.options, False, True)
    assert result["changed"] is False
    assert provider.read()[0]["Timestamp"] == (timestamp or None)
    assert provider.read()[0]["RecordData"] == {"DhcId": "AAEB"}
    assert commands[0] == ["/RecordAdd"]
    assert state["writes"] == []


def test_unreadable_existing_dhcid_is_not_treated_as_absent(
    server: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper, connection, state = server
    monkeypatch.setattr(helper, "_dns_tool", lambda: "installed-dnscmd")
    monkeypatch.setattr(
        helper._ClassicRecords,
        "_command",
        lambda _self, arguments, **_kwargs: (
            "DHCID <Base64Data>"
            if arguments == ["/RecordAdd"]
            else "wType = DHCID (49)\nunrecognized data"
        ),
    )
    provider = helper._ClassicRecords(connection, _options("DHCID", value=["AAEB"]))
    with pytest.raises(ValueError, match="unreadable DHCID"):
        helper._manage(provider, provider.options, False, True)
    assert state["writes"] == []


@pytest.mark.parametrize("operation", ["add", "update", "remove"])
@pytest.mark.parametrize("confirmed", [False, True])
def test_dhcid_tool_crash_requires_exact_native_write_confirmation(
    server: Any, monkeypatch: pytest.MonkeyPatch, operation: str, confirmed: bool
) -> None:
    helper, connection, _state = server
    monkeypatch.setattr(helper, "_dns_tool", lambda: "installed-dnscmd")
    monkeypatch.setattr(
        helper._ClassicRecords, "_command", lambda *_args, **_kwargs: "DHCID"
    )
    provider = helper._ClassicRecords(connection, _options("DHCID", value=["AAEB"]))
    row = {
        "RecordData": {"DhcId": "AAEB"},
        "TimeToLive": helper._interval(300),
        "Timestamp": None,
    }
    original = OSError(0xC0000005, "installed tool crashed")

    def _crash(*_args: Any, **_kwargs: Any) -> str:
        raise original

    monkeypatch.setattr(provider, "_command", _crash)
    if operation == "remove":
        rows = [] if confirmed else [row]
    else:
        rows = [row] if confirmed else [dict(row, TimeToLive=helper._interval(60))]
    monkeypatch.setattr(provider, "_dhcid", lambda: rows)
    arguments = (
        (row, row)
        if operation == "update"
        else (row,) if operation == "remove" else ("AAEB",)
    )
    if confirmed:
        getattr(provider, operation)(*arguments)
    else:
        with pytest.raises(OSError) as raised:
            getattr(provider, operation)(*arguments)
        assert raised.value is original


@pytest.mark.parametrize("status", [5, 87, 9711])
def test_other_dhcid_write_errors_never_become_success(
    server: Any, monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    helper, connection, _state = server
    monkeypatch.setattr(helper, "_dns_tool", lambda: "installed-dnscmd")
    monkeypatch.setattr(
        helper._ClassicRecords, "_command", lambda *_args, **_kwargs: "DHCID"
    )
    provider = helper._ClassicRecords(connection, _options("DHCID", value=["AAEB"]))
    reader = MagicMock()
    monkeypatch.setattr(provider, "_dhcid", reader)
    monkeypatch.setattr(
        provider, "_command", MagicMock(side_effect=OSError(status, "failed"))
    )
    with pytest.raises(OSError):
        provider.add("AAEB")
    reader.assert_not_called()


def test_absent_dhcid_capability_is_not_invented_from_a_version(
    server: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper, connection, state = server
    monkeypatch.setattr(helper, "_dns_tool", lambda: "installed-dnscmd")
    monkeypatch.setattr(
        helper._ClassicRecords,
        "_command",
        lambda *_args, **_kwargs: "A <IPAddress>\nTXT <String>",
    )
    with pytest.raises(ValueError, match="do not provide DHCID"):
        helper._ClassicRecords(connection, _options("DHCID", value=["AAEB"]))
    assert state["writes"] == []


def test_classic_txt_decodes_wire_utf8_and_retains_existing_ansi(server: Any) -> None:
    helper, _connection, _state = server

    def _codec(name: str) -> Any:
        return codecs.lookup("cp1252") if name == "mbcs" else None

    codecs.register(_codec)
    try:
        assert (
            helper._classic_text("owned Unicode Î© record") == "owned Unicode Ω record"
        )
        assert helper._classic_text("existing café") == "existing café"
        assert helper._classic_text("ASCII text") == "ASCII text"
    finally:
        codecs.unregister(_codec)


def test_modern_authorization_failure_does_not_switch_providers(
    server: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper, _connection, state = server
    failure = OSError("access denied")
    failure.hresult = 0x80041003  # type: ignore[attr-defined]
    factory = MagicMock(side_effect=failure)
    monkeypatch.setattr(helper.wmi, "WmiConnection", factory)
    with pytest.raises(OSError, match="access denied"):
        helper.manage(_options(), False, False)
    factory.assert_called_once_with(helper._NAMESPACE)
    assert state["writes"] == []
