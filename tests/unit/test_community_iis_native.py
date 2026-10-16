"""Check IIS Automation ownership, HTTP ABI layouts and metabase conversions."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Native ABI helpers are deliberately examined without Windows execution.
# pylint: disable=protected-access

import ctypes
import struct
import uuid
from contextlib import ExitStack
from types import ModuleType
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module


@pytest.fixture(name="native")
def native_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load IIS native ABI declarations without connecting to Windows.

    :param monkeypatch: Scoped native-boundary substitutions.
    :returns: Modeled native result or loaded test helper.
    :rtype: object
    """
    # This fixture declares its staged import paths independently; a shared
    # loader would hide which native helper closure this test exercises.
    # pylint: disable=duplicate-code
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(
        str(ROOT / "legacy_community_windows/plugins/module_utils")
    )
    return load_module(
        ROOT
        / "legacy_community_windows/plugins/module_utils/legacy_community_windows_iis_native.py",
        "tested_iis_native",
    )
    # pylint: enable=duplicate-code


def test_unknown_apphost_results_query_dispatch_not_enumeration(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = native.IisAutomation()
    owner.cleanup = ExitStack()
    queried = []

    def method(_pointer: Any, slot: int, _result: Any, _types: Any) -> Any:
        """Model one native operation without contacting Windows.

        :param slot: Native operation argument.
        :returns: Modeled native result or loaded test helper.
        :rtype: object
        """
        assert slot == 0

        def query(_interface: Any, interface_id: Any, destination: Any) -> int:
            """Model one native operation without contacting Windows.

            :param interface_id: Native operation argument.
            :param destination: Native operation argument.
            :returns: Modeled native result or loaded test helper.
            :rtype: object
            """
            queried.append(uuid.UUID(bytes_le=ctypes.string_at(interface_id, 16)))
            ctypes.cast(destination, ctypes.POINTER(ctypes.c_void_p))[0] = (
                ctypes.c_void_p(0x4321)
            )
            return 0

        return query

    monkeypatch.setattr(native, "_method", method)
    release = Mock()
    monkeypatch.setattr(native, "_release", release)
    value = native._Variant()
    value.kind, value.data.bstr = 13, 0x1234
    result = owner.decode(value)
    assert result.pointer.value == 0x4321
    assert queried == [uuid.UUID("00020400-0000-0000-c000-000000000046")]
    owner.cleanup.close()
    release.assert_called_once()


@pytest.mark.parametrize(
    "number,kind",
    [
        (-(2**63), 20),
        (-(2**31) - 1, 20),
        (-(2**31), 3),
        (-1, 3),
        (0, 3),
        (2**31 - 1, 3),
        (2**31, 19),
        (2**32 - 1, 19),
        (2**32, 20),
        (2**32 + 3, 20),
        (2**63 - 1, 20),
        (2**63, 21),
        (2**64 - 1, 21),
    ],
)
def test_native_integer_arguments_preserve_exact_supported_widths(
    native: ModuleType, number: int, kind: int
) -> None:
    owner = native.IisAutomation()
    value = native._Variant()
    owner.encode(value, number)
    assert value.kind == kind
    assert owner.decode(value) == number


@pytest.mark.parametrize("number", [-(2**63) - 1, 2**64, 2**100])
def test_native_integer_arguments_reject_overflow_without_truncation(
    native: ModuleType, number: int
) -> None:
    owner = native.IisAutomation()
    value = native._Variant()
    with pytest.raises(ValueError, match="64-bit"):
        owner.encode(value, number)
    assert value.kind == 0


@pytest.mark.usefixtures("native")
def test_metabase_unsigned_limits_return_exact_values_and_repeat_without_writes() -> (
    None
):
    legacy = load_module(
        ROOT
        / "legacy_community_windows/plugins/module_utils/legacy_community_windows_iis_legacy.py",
        "tested_metabase_unsigned_limits",
    )
    pool = Mock()
    pool.call.return_value = -1
    assert legacy._get(pool, "PeriodicRestartRequests") == 4294967295
    assert legacy._update(pool, {"PeriodicRestartRequests": 4294967295}) is False
    assert pool.call.call_args_list == [
        call("Get", "PeriodicRestartRequests"),
        call("Get", "PeriodicRestartRequests"),
    ]


def test_only_explicit_adsi_enumeration_uses_enumvariant(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = native.IisAutomation()
    enumerate_native = Mock(return_value=["owned"])
    monkeypatch.setattr(owner, "_enumerate", enumerate_native)
    value = native._Variant()
    value.kind, value.data.bstr = 13, 0x1234
    assert owner.decode(value, enumeration=True) == ["owned"]
    enumerate_native.assert_called_once_with(0x1234)


def test_dispatch_exception_retains_native_hresult_without_description(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = native.IisAutomation()
    owner.cleanup = ExitStack()
    owner.automation = Mock()
    monkeypatch.setattr(native, "_release", Mock())
    instance = native.AutomationObject(owner, ctypes.c_void_p(0x1234))
    exception = native._ExceptionInfo()
    exception.status = 0x8000500D
    with pytest.raises(OSError) as error:
        instance._check_exception(0x80020009, exception, "Get")
    assert getattr(error.value, "hresult") == 0x8000500D
    owner.cleanup.close()


@pytest.mark.parametrize(
    "kind, field, value, expected",
    [
        (3, "signed32", -42, -42),
        (19, "unsigned32", 4294967295, 4294967295),
        (21, "integer", -1, 18446744073709551615),
        (11, "signed16", -1, True),
        (17, "byte", 255, 255),
    ],
)
def test_native_scalar_decoding_preserves_signedness(
    native: ModuleType, kind: int, field: str, value: Any, expected: Any
) -> None:
    record = native._Variant()
    record.kind = kind
    setattr(record.data, field, value)
    assert native.IisAutomation().decode(record) == expected


@pytest.fixture(name="ssl")
def ssl_helper(native: ModuleType) -> ModuleType:
    """Load native HTTP endpoint records with the developer interpreter.

    :param native: Loaded Automation ABI helper.
    :returns: Modeled native result or loaded test helper.
    :rtype: object
    """
    assert native is not None
    return load_module(
        ROOT
        / "legacy_community_windows/plugins/module_utils/legacy_community_windows_iis_ssl.py",
        "tested_iis_ssl",
    )


@pytest.mark.parametrize("ip, expected", [("*", "0.0.0.0"), ("127.0.0.1", "127.0.0.1")])
def test_http_endpoint_addresses_use_windows_network_byte_order(
    ssl: ModuleType, ip: str, expected: str
) -> None:
    address = ssl._address(ip, 8443)
    raw = bytes(address.bytes)
    assert len(raw) == 128
    assert struct.unpack("<H", raw[:2])[0] == 2
    assert struct.unpack("!H", raw[2:4])[0] == 8443
    assert ".".join(str(part) for part in raw[4:8]) == expected


def test_http_key_classes_are_selected_by_actual_binding_flags(ssl: ModuleType) -> None:
    ordinary = ssl._key({"port": 8443}, "0")
    sni = ssl._key({"port": 8443, "host_header": "owned.example"}, "1")
    central = ssl._key({"port": 8443}, "2")
    assert ordinary[0] == 1
    assert sni[0] == 5
    assert central[0] == 6
    assert sni[3].host == "owned.example"
    assert ctypes.sizeof(ssl._Address) == 128
    assert ctypes.alignment(ssl._Address) == 8


def test_sni_requires_a_hostname_before_native_endpoint_access(ssl: ModuleType) -> None:
    with pytest.raises(ValueError, match="SNI requires"):
        ssl._key({"port": 8443}, "1")


@pytest.fixture(name="legacy")
def legacy_helper(native: ModuleType) -> ModuleType:
    """Load the metabase mapping without binding an ADSI object.

    :param native: Loaded Automation ABI helper.
    :returns: Modeled native result or loaded test helper.
    :rtype: object
    """
    assert native is not None
    return load_module(
        ROOT
        / "legacy_community_windows/plugins/module_utils/legacy_community_windows_iis_legacy.py",
        "tested_iis_legacy",
    )


def test_metabase_pool_mapping_preserves_representable_features(
    legacy: ModuleType,
) -> None:
    assert legacy._pool_values(
        {
            "queueLength": 1234,
            "managedPipelineMode": "Classic",
            "processModel.identityType": "NetworkService",
            "processModel.idleTimeout": "00:20:00",
            "recycling.periodicRestart.schedule": "03:00:00,06:30:00",
        }
    ) == {
        "AppPoolQueueLength": 1234,
        "AppPoolIdentityType": 2,
        "IdleTimeout": 20,
        "PeriodicRestartSchedule": ["03:00:00", "06:30:00"],
    }


@pytest.mark.parametrize(
    "attribute,value",
    [
        ("managedPipelineMode", "Integrated"),
        ("startMode", "AlwaysRunning"),
        ("processModel.identityType", "ApplicationPoolIdentity"),
    ],
)
def test_metabase_rejects_only_unrepresentable_pool_features(
    legacy: ModuleType, attribute: str, value: str
) -> None:
    with pytest.raises(ValueError, match="cannot express|does not support"):
        legacy._pool_values({attribute: value})


def test_metabase_durations_reject_subminute_loss(legacy: ModuleType) -> None:
    with pytest.raises(ValueError, match="whole minutes"):
        legacy._pool_values({"processModel.idleTimeout": "00:20:01"})


def test_metabase_public_pool_preview_preserves_its_changed_flag(
    legacy: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    automation, container = Mock(), Mock()
    monkeypatch.setattr(legacy, "_pool_container", lambda _automation: container)
    monkeypatch.setattr(legacy, "_find_pool", lambda _automation, _name: None)
    result = legacy.manage_legacy(
        automation, "win_iis_webapppool", {"name": "owned", "_ansible_check_mode": True}
    )
    assert result["changed"] is True
    assert result["info"]["name"] == "owned"
    assert container.call.call_count == 0


def test_metabase_state_waits_for_activation_then_observes_native_stop(
    legacy: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed = iter([0, 1, 2, 4])
    monkeypatch.setattr(legacy, "_read_state", lambda _element, _pool: next(observed))
    monkeypatch.setattr(legacy.time, "sleep", Mock())
    element = Mock()
    changed, state = legacy._state(element, "stopped", pool=True)
    assert changed is True
    assert state == "Stopped"
    element.call.assert_called_once_with("Stop")


def test_metabase_unavailable_runtime_has_a_bounded_actionable_failure(
    legacy: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    times = iter([0, 11])
    monkeypatch.setattr(legacy.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(legacy, "_read_state", lambda _element, _pool: 0)
    with pytest.raises(OSError, match="Verify that W3SVC is running"):
        legacy._state(Mock(), "stopped", pool=True)


def test_ssl_update_restores_previous_assignment_if_replacement_fails(
    ssl: ModuleType,
) -> None:
    existing, replacement = ssl._SslSet(), ssl._SslSet()
    replacement.parameters.hash_length = 20
    library = Mock()
    library.HttpDeleteServiceConfiguration.return_value = 0
    library.HttpSetServiceConfiguration.side_effect = [5, 0]
    with pytest.raises(OSError, match="HttpSetServiceConfiguration"):
        ssl._replace(library, 1, replacement, existing)
    assert library.HttpDeleteServiceConfiguration.call_count == 1
    assert library.HttpSetServiceConfiguration.call_count == 2


def test_central_certificate_query_preserves_empty_assignment_and_existence(
    ssl: ModuleType,
) -> None:
    result = ssl._information(ssl._CcsSet())
    assert result == {
        "certificateHash": "",
        "certificateStoreName": "",
        "_exists": True,
    }
    assert ssl._information(None)["_exists"] is False
