"""Exercise released rule behavior around the installed firewall capabilities."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Stateful native boundary substitutes keep routine checks controller-only.
# pylint: disable=protected-access

import copy
import ctypes
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module

_DIRECTORY = ROOT / "legacy_community_windows/plugins/module_utils"


# The doubles mirror only actual rule and collection operations.
# pylint: disable=missing-function-docstring,missing-return-doc
class _Rule:
    def __init__(self, provider: "_Provider", kind: str, profile: int | None) -> None:
        self.provider, self.kind, self.profile = provider, kind, profile
        self.fields = {
            name: None
            for name in (
                "Name",
                "Description",
                "Grouping",
                "ApplicationName",
                "ServiceName",
                "Protocol",
                "LocalPorts",
                "RemotePorts",
                "LocalAddresses",
                "RemoteAddresses",
                "IcmpTypesAndCodes",
                "Direction",
                "Action",
                "Profiles",
                "InterfaceTypes",
                "EdgeTraversalOptions",
                "SecureFlags",
                "Enabled",
            )
        }
        if kind == "port":
            self.fields = {
                name: None
                for name in (
                    "Name",
                    "Protocol",
                    "LocalPorts",
                    "RemoteAddresses",
                    "Enabled",
                )
            }
        if kind == "application":
            self.fields = {
                name: None
                for name in ("Name", "ApplicationName", "RemoteAddresses", "Enabled")
            }
        self.values: dict[str, Any] = {
            "Name": None,
            "Description": None,
            "Grouping": None,
            "ApplicationName": None,
            "ServiceName": None,
            "Protocol": 6 if kind == "port" else 256,
            "LocalPorts": "0" if kind == "port" else None,
            "RemotePorts": None,
            "LocalAddresses": "*",
            "RemoteAddresses": "*",
            "IcmpTypesAndCodes": None,
            "Direction": 1,
            "Action": 1,
            "Profiles": 0x7FFFFFFF,
            "InterfaceTypes": "All",
            "EdgeTraversalOptions": 0,
            "SecureFlags": 0,
            "Enabled": False,
        }

    def get(self, field: str) -> Any:
        return self.values.get(field)

    def put(self, field: str, value: Any) -> None:
        assert field in self.fields
        if (
            self.kind == "modern"
            and self in self.provider.rows
            and field == "Protocol"
            and value not in (6, 17)
            and any(
                self.values[name] not in (None, "", "*")
                for name in ("LocalPorts", "RemotePorts")
            )
        ):
            raise OSError("clear live ports before changing protocol")
        if field == "LocalPorts" and self.kind == "port":
            if not 1 <= int(value) <= 65535:
                raise OSError("port outside native range")
            value = str(value)
        if field == "RemoteAddresses" and value == "bad address":
            raise OSError("invalid native address")
        if self in self.provider.rows:
            self.provider.writes.append(("put", self.profile, field, value))
        self.values[field] = value


class _Provider:
    def __init__(self) -> None:
        self.classic = False
        self.rows: list[_Rule] = []
        self.writes: list[Any] = []
        self.fail_add = 0

    def __enter__(self) -> "_Provider":
        return self

    def __exit__(self, *_arguments: Any) -> None:
        return None

    def records(self) -> list[_Rule]:
        return list(self.rows)

    def new(self, kind: str = "modern", profile: int | None = None) -> _Rule:
        return _Rule(self, kind, profile)

    def add(self, rule: _Rule) -> None:
        if self.fail_add:
            self.fail_add -= 1
            raise OSError("controlled Add failure")
        self.writes.append(("add", rule.profile, rule.get("Name")))
        self.rows.append(rule)

    def remove(self, rule: _Rule) -> None:
        self.writes.append(("remove", rule.profile, rule.get("Name")))
        self.rows.remove(rule)


# pylint: enable=missing-function-docstring,missing-return-doc


@pytest.fixture(name="firewall")
def fixture_firewall(monkeypatch: pytest.MonkeyPatch) -> tuple[ModuleType, _Provider]:
    """Load public normalization and policy logic around a native boundary.

    :param monkeypatch: Scoped imports and provider substitution.
    :returns: Imported rule manager and its native boundary.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(str(_DIRECTORY))
    module = load_module(
        _DIRECTORY / "legacy_community_windows_firewall_rule.py",
        "tested_firewall_rules",
    )
    provider = _Provider()
    monkeypatch.setattr(module, "FirewallRules", lambda: provider)
    return module, provider


def _options(module: ModuleType, **values: Any) -> Any:
    arguments = {
        "name": "Owned test rule",
        "protocol": "tcp",
        "localport": "47889",
        "remoteip": "127.0.0.1",
        "enabled": False,
    }
    arguments.update(values)
    return module.parameters(arguments)


@pytest.mark.parametrize("classic", [False, True])
def test_create_repeat_update_check_removal_and_cleanup(
    firewall: tuple[ModuleType, _Provider], classic: bool
) -> None:
    module, provider = firewall
    provider.classic = classic
    options = _options(module)
    assert module.manage(options, True)["changed"] is True
    assert not provider.rows and not provider.writes
    assert module.manage(options)["changed"] is True
    assert len(provider.rows) == (2 if classic else 1)
    assert module.manage(options)["changed"] is False
    update = module.parameters({"name": "OWNED TEST RULE", "enabled": True})
    assert module.manage(update)["changed"] is True
    assert all(rule.get("Enabled") is True for rule in provider.rows)
    assert module.manage(update)["changed"] is False
    absent = module.parameters({"name": "Owned test rule", "state": "absent"})
    assert module.manage(absent, True, True)["changed"] is True
    assert provider.rows
    assert module.manage(absent)["changed"] is True
    assert module.manage(absent)["changed"] is False
    assert not provider.rows


@pytest.mark.parametrize("classic", [False, True])
def test_any_remote_address_clears_specific_filter_idempotently(
    firewall: tuple[ModuleType, _Provider], classic: bool
) -> None:
    module, provider = firewall
    provider.classic = classic
    module.manage(_options(module))
    options = module.parameters({"name": "Owned test rule", "remoteip": "any"})
    assert module.manage(options)["changed"] is True
    assert all(rule.get("RemoteAddresses") == "*" for rule in provider.rows)
    assert module.manage(options)["changed"] is False


def test_group_update_changes_all_names_and_missing_group_is_unchanged(
    firewall: tuple[ModuleType, _Provider],
) -> None:
    module, provider = firewall
    module.manage(_options(module, name="first", group="owned group"))
    module.manage(_options(module, name="second", group="owned group"))
    options = module.parameters({"group": "OWNED GROUP", "enabled": True})
    result = module.manage(options)
    assert (
        result["changed"] is True
        and "first" in result["msg"]
        and "second" in result["msg"]
    )
    assert module.manage(options)["changed"] is False
    assert module.manage(module.parameters({"group": "missing"})) == {"changed": False}
    assert all(rule.get("Enabled") is True for rule in provider.rows)


def test_classic_foreign_native_key_is_never_overwritten(
    firewall: tuple[ModuleType, _Provider],
) -> None:
    module, provider = firewall
    provider.classic = True
    module.manage(_options(module, name="Foreign rule", remoteip="any"))
    snapshot = [copy.deepcopy(rule.values) for rule in provider.rows]
    provider.writes.clear()
    result = module.manage(_options(module))
    assert result["failed"] is True and result["changed"] is False
    assert "another name" in result["msg"]
    assert not provider.writes
    assert [rule.values for rule in provider.rows] == snapshot


@pytest.mark.parametrize(
    "values",
    [
        {"direction": "out"},
        {"action": "block"},
        {"description": "new description"},
        {"localip": "127.0.0.1"},
        {"remoteport": "80"},
        {"service": "W32Time"},
        {"group": "group"},
        {"localport": "80-90"},
        {"profiles": ["private"]},
        {"interfacetypes": ["lan"]},
        {"icmp_type_code": ["8:*"]},
        {"program": "C:\\application.exe"},
        {"profiles": []},
    ],
)
def test_unrepresentable_classic_requests_fail_before_policy_writes(
    firewall: tuple[ModuleType, _Provider], values: dict[str, Any]
) -> None:
    module, provider = firewall
    provider.classic = True
    result = module.manage(_options(module, **values))
    assert result["failed"] is True and result["changed"] is False
    assert not provider.rows and not provider.writes


def test_classic_scope_migration_preserves_filters_and_is_idempotent(
    firewall: tuple[ModuleType, _Provider],
) -> None:
    module, provider = firewall
    provider.classic = True
    module.manage(_options(module))
    domain = module.parameters({"name": "Owned test rule", "profiles": ["domain"]})
    assert module.manage(domain)["changed"] is True
    assert len(provider.rows) == 1 and provider.rows[0].profile == 0
    assert provider.rows[0].get("LocalPorts") == "47889"
    assert module.manage(domain)["changed"] is False
    both = module.parameters(
        {"name": "Owned test rule", "profiles": ["domain", "private", "public"]}
    )
    assert module.manage(both)["changed"] is True
    assert len(provider.rows) == 2
    assert all(rule.get("RemoteAddresses") == "127.0.0.1" for rule in provider.rows)
    assert module.manage(both)["changed"] is False


def test_classic_port_identity_update_and_failed_add_restore(
    firewall: tuple[ModuleType, _Provider],
) -> None:
    module, provider = firewall
    provider.classic = True
    module.manage(_options(module))
    options = module.parameters(
        {"name": "Owned test rule", "protocol": "udp", "localport": "47890"}
    )
    assert module.manage(options)["changed"] is True
    assert all(
        (rule.get("Protocol"), rule.get("LocalPorts")) == (17, "47890")
        for rule in provider.rows
    )
    assert module.manage(options)["changed"] is False
    snapshot = sorted(
        (rule.profile, copy.deepcopy(rule.values)) for rule in provider.rows
    )
    provider.fail_add = 1
    failed = module.manage(
        module.parameters({"name": "Owned test rule", "protocol": "tcp"})
    )
    assert failed["failed"] is True and failed["changed"] is True
    assert "Add failure" in failed["msg"]
    assert sorted((rule.profile, rule.values) for rule in provider.rows) == snapshot


def test_classic_program_exception_and_image_update(
    firewall: tuple[ModuleType, _Provider],
) -> None:
    module, provider = firewall
    provider.classic = True
    options = module.parameters(
        {"name": "program rule", "program": "C:\\first.exe", "enabled": False}
    )
    assert module.manage(options)["changed"] is True
    assert module.manage(options)["changed"] is False
    update = module.parameters({"name": "program rule", "program": "C:\\second.exe"})
    assert module.manage(update)["changed"] is True
    assert all(
        rule.get("ApplicationName") == "C:\\second.exe" for rule in provider.rows
    )
    assert module.manage(update)["changed"] is False


def test_invalid_native_address_does_not_touch_existing_rules(
    firewall: tuple[ModuleType, _Provider],
) -> None:
    module, provider = firewall
    provider.classic = True
    module.manage(_options(module))
    provider.writes.clear()
    result = module.manage(
        module.parameters({"name": "Owned test rule", "remoteip": "bad address"})
    )
    assert result["failed"] is True and result["changed"] is False
    assert not provider.writes


def test_modern_address_order_and_case_do_not_cause_changes(
    firewall: tuple[ModuleType, _Provider],
) -> None:
    module, provider = firewall
    options = _options(
        module, remoteip="10.0.0.1,10.0.0.2", interfacetypes=["lan", "wireless", "lan"]
    )
    assert module.manage(options)["changed"] is True
    assert provider.rows[0].get("InterfaceTypes") == "Lan,Wireless"
    assert (
        module.manage(
            _options(
                module, remoteip="10.0.0.2,10.0.0.1", interfacetypes=["lan", "wireless"]
            )
        )["changed"]
        is False
    )


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"name": "owned", "protocol": "nonsense"},
        {"name": "owned", "direction": "wrong"},
        {"name": "owned", "profiles": ["wrong"]},
    ],
)
def test_invalid_arguments_are_rejected_without_native_access(
    firewall: tuple[ModuleType, _Provider], arguments: dict[str, Any]
) -> None:
    module, provider = firewall
    with pytest.raises(ValueError):
        module.parameters(arguments)
    assert not provider.writes


@pytest.mark.parametrize(
    "protocol", [str(2**31), str(-(2**31) - 1), "4294967302", "-4294967290"]
)
def test_protocol_overflow_fails_before_native_policy_access(
    firewall: tuple[ModuleType, _Provider],
    monkeypatch: pytest.MonkeyPatch,
    protocol: str,
) -> None:
    module, _provider = firewall
    factory = Mock(side_effect=AssertionError("must not access native policy"))
    monkeypatch.setattr(module, "FirewallRules", factory)
    with pytest.raises(ValueError, match="signed 32-bit integer"):
        module.parameters({"name": "Owned test rule", "protocol": protocol})
    factory.assert_not_called()


@pytest.mark.parametrize("protocol", [-(2**31), 2**31 - 1])
def test_protocol_integer_boundaries_do_not_wrap_during_argument_conversion(
    firewall: tuple[ModuleType, _Provider], protocol: int
) -> None:
    module, _provider = firewall
    assert module._protocol(str(protocol)) == protocol


@pytest.mark.parametrize("port", ["0", "65536", "4294967376", "-4294967216"])
@pytest.mark.parametrize("existing", [False, True])
def test_classic_port_bounds_fail_before_creating_a_detached_rule(
    firewall: tuple[ModuleType, _Provider],
    monkeypatch: pytest.MonkeyPatch,
    port: str,
    existing: bool,
) -> None:
    module, provider = firewall
    provider.classic = True
    if existing:
        assert module.manage(_options(module))["changed"] is True
    provider.writes.clear()
    factory = Mock(wraps=provider.new)
    monkeypatch.setattr(provider, "new", factory)
    result = module.manage(_options(module, localport=port))
    assert result["changed"] is False and result["failed"] is True
    assert "1 through 65535" in result["msg"]
    assert not provider.writes
    factory.assert_not_called()


@pytest.mark.parametrize("port", ["1", "65535"])
def test_classic_port_bounds_accept_each_inclusive_endpoint(
    firewall: tuple[ModuleType, _Provider], port: str
) -> None:
    module, provider = firewall
    provider.classic = True
    options = _options(module, localport=port)
    assert module.manage(options)["changed"] is True
    assert module.manage(options)["changed"] is False
    assert all(rule.get("LocalPorts") == port for rule in provider.rows)


@pytest.mark.parametrize(
    "field, value, kind",
    [
        ("Protocol", 2**31, "modern"),
        ("Protocol", -(2**31) - 1, "modern"),
        ("Protocol", 4294967302, "modern"),
        ("Protocol", -4294967290, "modern"),
        ("LocalPorts", 0, "port"),
        ("LocalPorts", 65536, "port"),
        ("LocalPorts", 4294967376, "port"),
        ("LocalPorts", -4294967216, "port"),
    ],
)
def test_native_integer_overflow_and_classic_port_bounds_never_reach_setter(
    monkeypatch: pytest.MonkeyPatch, field: str, value: int, kind: str
) -> None:
    monkeypatch.syspath_prepend(str(HELPER.parent))
    native = load_module(
        _DIRECTORY / "legacy_community_windows_firewall_rule_native.py",
        "tested_firewall_native_integer_rejection",
    )
    owner = SimpleNamespace(automation=Mock(), interface=Mock(return_value=101))
    rule = native._Rule(owner, 100, kind)
    setter = Mock(side_effect=AssertionError("must not resolve native setter"))
    monkeypatch.setattr(native, "_method", setter)
    with pytest.raises(ValueError, match="signed 32-bit integer|1 through 65535"):
        rule.put(field, str(value))
    setter.assert_not_called()


@pytest.mark.parametrize(
    "field, value, kind",
    [
        ("Protocol", -(2**31), "modern"),
        ("Protocol", 2**31 - 1, "modern"),
        ("LocalPorts", 1, "port"),
        ("LocalPorts", 65535, "port"),
    ],
)
def test_native_integer_boundaries_arrive_unchanged_at_a_c_callback(
    monkeypatch: pytest.MonkeyPatch, field: str, value: int, kind: str
) -> None:
    monkeypatch.syspath_prepend(str(HELPER.parent))
    native = load_module(
        _DIRECTORY / "legacy_community_windows_firewall_rule_native.py",
        "tested_firewall_native_integer_boundary",
    )
    owner = SimpleNamespace(automation=Mock(), interface=Mock(return_value=101))
    rule = native._Rule(owner, 100, kind)
    received: list[int] = []

    def receive(_pointer: Any, argument: int) -> int:
        """Record the signed native value rather than a Python-only mock value.

        :param argument: Value after the actual ctypes C argument conversion.
        :returns: Successful HRESULT.
        """
        received.append(argument)
        return 0

    callback = ctypes.CFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.c_int32)(
        receive
    )
    monkeypatch.setattr(native, "_method", lambda *_arguments: callback)
    rule.put(field, str(value))
    assert received == [value]


def test_classic_native_port_getter_and_setter_use_documented_slots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(HELPER.parent))
    native = load_module(
        _DIRECTORY / "legacy_community_windows_firewall_rule_native.py",
        "tested_firewall_native",
    )
    owner = SimpleNamespace(automation=Mock())
    calls: list[Any] = []

    def _method(pointer: Any, slot: int, _result: Any, _types: Any) -> Any:
        assert pointer == 100

        def _invoke(_pointer: Any, value: Any) -> int:
            calls.append(slot)
            if slot == 13:
                ctypes.cast(value, ctypes.POINTER(ctypes.c_int32)).contents.value = (
                    47889
                )
            else:
                assert slot == 14 and value == 47890
            return 0

        return _invoke

    monkeypatch.setattr(native, "_method", _method)
    rule = native._Rule(owner, 100, "port")
    assert rule.get("LocalPorts") == "47889"
    rule.put("LocalPorts", "47890")
    assert calls == [13, 14]


def test_modern_program_any_clears_image_filter_with_native_null(
    firewall: tuple[ModuleType, _Provider],
) -> None:
    module, provider = firewall
    assert (
        module.manage(_options(module, program="C:\\application.exe"))["changed"]
        is True
    )
    cleared = module.parameters({"name": "Owned test rule", "program": "ANY"})
    assert module.manage(cleared)["changed"] is True
    assert provider.rows[0].get("ApplicationName") is None
    assert module.manage(cleared)["changed"] is False


def test_modern_protocol_transition_clears_requested_ports_before_protocol(
    firewall: tuple[ModuleType, _Provider],
) -> None:
    module, provider = firewall
    module.manage(_options(module))
    provider.writes.clear()
    options = module.parameters(
        {
            "name": "Owned test rule",
            "protocol": "icmpv4",
            "localport": "any",
            "remoteport": "any",
            "icmp_type_code": ["8:*"],
        }
    )
    result = module.manage(options)
    assert result["changed"] is True and not result.get("failed")
    assert provider.writes[:2] == [
        ("put", None, "LocalPorts", None),
        ("put", None, "Protocol", 1),
    ]
    assert provider.rows[0].get("IcmpTypesAndCodes") == "8:*"
    assert module.manage(options)["changed"] is False


def test_native_enumerator_retains_typed_interface_before_clearing_variant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(HELPER.parent))
    native = load_module(
        _DIRECTORY / "legacy_community_windows_firewall_rule_native.py",
        "tested_firewall_enumerator",
    )
    owner = native.FirewallRules()
    sequence: list[Any] = []
    owner.automation = SimpleNamespace(
        VariantClear=lambda _value: sequence.append("clear")
    )
    monkeypatch.setattr(
        owner, "object_property", lambda _collection, slot: 100 if slot == 11 else None
    )

    def _interface(pointer: int, identifier: str) -> int:
        sequence.append((pointer, identifier))
        return pointer + 1

    calls = 0

    def _method(pointer: int, slot: int, _result: Any, types: Any) -> Any:
        assert pointer == 101 and slot == 3 and len(types) == 3

        def _next(_pointer: Any, count: int, output: Any, fetched: Any) -> int:
            nonlocal calls
            assert count == 1
            calls += 1
            if calls == 1:
                value = ctypes.cast(output, ctypes.POINTER(native._Variant)).contents
                value.kind = 9
                value.data.bstr = 200
                ctypes.cast(fetched, ctypes.POINTER(ctypes.c_uint32)).contents.value = 1
                return 0
            return 1

        return _next

    monkeypatch.setattr(owner, "interface", _interface)
    monkeypatch.setattr(native, "_method", _method)
    assert owner._items(1, "requested-interface") == [201]
    assert sequence == [
        (100, "00020404-0000-0000-c000-000000000046"),
        (200, "requested-interface"),
        "clear",
        "clear",
    ]
