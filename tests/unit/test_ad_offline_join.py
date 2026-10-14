"""Exercise offline provisioning outputs, idempotence, and native capability gates."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Tests inspect native ABI arguments and replace target-only boundaries.
# pylint: disable=protected-access

import ctypes
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Callable
from unittest.mock import Mock, call

import pytest
from ansible_collections.sustainablelobster.legacy_ad.plugins.action.offline_join import (
    ActionModule,
)

from tests.unit.payload_support import ROOT, invoke_payload, load_module
from tests.unit.test_python_action import _action

_DOMAIN = "example.test"
_DOMAIN_DN = "DC=example,DC=test"
_COMPUTERS_DN = "CN=Computers," + _DOMAIN_DN
_COMPUTER_DN = "CN=My\\, Computer," + _COMPUTERS_DN


@pytest.fixture(name="native")
def _native() -> Mock:
    native = Mock()
    native.computer_account.return_value = (_DOMAIN, "MyComputer")
    native.provision.return_value = b"native\0blob"
    return native


@pytest.fixture(name="run_request")
def _request(
    monkeypatch: pytest.MonkeyPatch,
    native: Mock,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> Callable[[dict[str, Any]], tuple[int, dict[str, Any]]]:
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    monkeypatch.setitem(sys.modules, "legacy_ad_offline_join", native)
    module = load_module(
        ROOT / "legacy_ad/plugins/modules/offline_join.py", "tested_ad_offline_join"
    )
    arguments = tmp_path / "arguments.json"
    monkeypatch.setattr(sys, "argv", ["offline_join.py", str(arguments)])

    def _run(values: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        arguments.write_text(json.dumps(values), encoding="utf-8")
        return invoke_payload(module, capsys)

    return _run


def test_returned_blob_is_base64_and_regeneration_always_reports_change(
    run_request: Callable[..., Any],
    native: Mock,
) -> None:
    for _ in range(2):
        assert run_request({"name": "My, Computer", "domain_server": "DC"}) == (
            0,
            {"changed": True, "blob": "bmF0aXZlAGJsb2I="},
        )
    assert (
        native.mock_calls
        == [
            call.computer_account(None, "My, Computer", None, "DC"),
            call.provisioning_api(False),
            call.provision(_DOMAIN, "MyComputer", "DC", False),
        ]
        * 2
    )


@pytest.mark.parametrize("file_output", [False, True])
def test_check_mode_checks_account_and_native_capabilities_without_password_or_file_write(
    run_request: Callable[..., Any],
    native: Mock,
    tmp_path: Path,
    file_output: bool,
) -> None:
    target = tmp_path / "provision.bin"
    arguments: dict[str, Any] = {"identity": "MyComputer$", "_ansible_check_mode": True}
    if file_output:
        arguments["blob_path"] = str(target)
    assert run_request(arguments) == (
        0,
        {"changed": True, "blob": None if file_output else ""},
    )
    assert native.mock_calls == [
        call.computer_account("MyComputer$", None, None, None),
        call.provisioning_api(False),
    ]
    assert not target.exists()


def test_blob_file_is_binary_and_existing_path_does_not_reset_password_again(
    run_request: Callable[..., Any],
    native: Mock,
    tmp_path: Path,
) -> None:
    target = tmp_path / "provision.bin"
    arguments = {"identity": "MyComputer$", "blob_path": str(target)}
    assert run_request(arguments) == (0, {"changed": True, "blob": None})
    assert target.read_bytes() == b"native\0blob"
    previous = target.stat().st_mtime_ns
    native.reset_mock()
    assert run_request(dict(arguments, provision_root_ca_certs=True)) == (
        0,
        {"changed": False, "blob": None},
    )
    assert native.mock_calls == [call.computer_account("MyComputer$", None, None, None)]
    assert (
        target.read_bytes() == b"native\0blob" and target.stat().st_mtime_ns == previous
    )


def test_existing_file_does_not_bypass_account_resolution_failure(
    run_request: Callable[..., Any],
    native: Mock,
    tmp_path: Path,
) -> None:
    target = tmp_path / "existing.bin"
    target.write_bytes(b"unchanged")
    native.computer_account.side_effect = ValueError(
        "Failed to find domain computer account 'missing'."
    )
    code, result = run_request({"identity": "missing", "blob_path": str(target)})
    assert code == 1 and result["changed"] is False and result["blob"] is None
    native.provision.assert_not_called()
    assert target.read_bytes() == b"unchanged"


def test_missing_parent_reports_failure_after_provisioning_without_creating_directory(
    run_request: Callable[..., Any],
    native: Mock,
    tmp_path: Path,
) -> None:
    target = tmp_path / "missing" / "provision.bin"
    code, result = run_request({"name": "MyComputer", "blob_path": str(target)})
    assert code == 1 and result["changed"] is True and result["blob"] is None
    native.provision.assert_called_once()
    assert not target.parent.exists()


@pytest.mark.parametrize("check", [False, True])
def test_unsupported_root_ca_option_cannot_reset_password(
    run_request: Callable[..., Any],
    native: Mock,
    check: bool,
) -> None:
    native.provisioning_api.side_effect = OSError(
        "provision_root_ca_certs requires NetCreateProvisioningPackage"
    )
    code, result = run_request(
        {
            "name": "MyComputer",
            "provision_root_ca_certs": True,
            "_ansible_check_mode": check,
        }
    )
    assert code == 1 and result["changed"] is False and result["blob"] is None
    native.provision.assert_not_called()


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"name": "name", "identity": "other"},
        {"identity": "bad\0name"},
        {"name": "name", "provision_root_ca_certs": "not-bool"},
    ],
)
def test_invalid_arguments_fail_before_account_search(
    run_request: Callable[..., Any],
    native: Mock,
    arguments: dict[str, Any],
) -> None:
    assert run_request(arguments)[0] == 1
    assert native.mock_calls == []


@pytest.fixture(name="helper")
def _helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    return load_module(
        ROOT / "legacy_ad/plugins/module_utils/legacy_ad_offline_join.py",
        "tested_offline_native",
    )


@pytest.fixture(name="connection")
def _connection(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Mock:
    connection = Mock()
    connection.__enter__ = Mock(return_value=connection)
    connection.__exit__ = Mock(return_value=None)
    connection.naming_context.side_effect = lambda name="defaultNamingContext": (
        _DOMAIN_DN
        if name == "defaultNamingContext"
        else "CN=Configuration," + _DOMAIN_DN
    )

    def _search(
        base: str, _scope: int, _filter: str, attributes: list[str]
    ) -> list[dict[str, Any]]:
        if attributes == ["wellKnownObjects"]:
            return [
                {
                    "dn": _DOMAIN_DN,
                    "attributes": {
                        "wellKnownObjects": [
                            (
                                "B:32:AA312825768811D1ADED00C04FD8D5CD:" + _COMPUTERS_DN
                            ).encode(),
                        ]
                    },
                }
            ]
        if attributes == ["dnsRoot"]:
            return [
                {
                    "dn": "CN=example,CN=Partitions",
                    "attributes": {"dnsRoot": [_DOMAIN.encode()]},
                }
            ]
        return [{"dn": base, "attributes": {"sAMAccountName": [b"MyComputer$"]}}]

    connection.search.side_effect = _search
    monkeypatch.setattr(helper.ldap, "LDAPConnection", Mock(return_value=connection))
    return connection


def test_computer_name_uses_advertised_container_and_sam_account_not_cn(
    helper: ModuleType,
    connection: Mock,
) -> None:
    assert helper.computer_account(name="My, Computer", server="DC") == (
        _DOMAIN,
        "MyComputer",
    )
    helper.ldap.LDAPConnection.assert_called_once_with("DC")
    assert connection.search.call_args_list[1] == call(
        _COMPUTER_DN, 0, "(objectClass=computer)", ["sAMAccountName"]
    )
    assert connection.search.call_args_list[2] == call(
        "CN=Configuration," + _DOMAIN_DN,
        2,
        "(&(objectClass=crossRef)(nCName=" + _DOMAIN_DN + "))",
        ["dnsRoot"],
    )


@pytest.mark.parametrize(
    "identity,filter_part",
    [
        ("MyComputer", "(sAMAccountName=MyComputer$)"),
        ("MyComputer$", "(sAMAccountName=MyComputer$)"),
        ("my*(computer)", r"(sAMAccountName=my\2a\28computer\29$)"),
        (
            "01234567-89ab-cdef-0123-456789abcdef",
            r"(objectGUID=\67\45\23\01\ab\89\ef\cd\01\23\45\67\89\ab\cd\ef)",
        ),
    ],
)
def test_identity_search_escapes_ldap_and_supports_guid_or_sam(
    helper: ModuleType,
    connection: Mock,
    identity: str,
    filter_part: str,
) -> None:
    assert helper.computer_account(identity=identity) == (_DOMAIN, "MyComputer")
    assert connection.search.call_args_list[0] == call(
        _DOMAIN_DN,
        2,
        "(&(objectClass=computer)" + filter_part + ")",
        ["sAMAccountName"],
    )


def test_explicit_dn_uses_base_search_and_does_not_interpret_filter_characters(
    helper: ModuleType,
    connection: Mock,
) -> None:
    assert helper.computer_account(identity=_COMPUTER_DN) == (_DOMAIN, "MyComputer")
    assert connection.search.call_args_list[0] == call(
        _COMPUTER_DN, 0, "(objectClass=computer)", ["sAMAccountName"]
    )


def test_sid_identity_is_searched_as_binary_object_sid(
    helper: ModuleType,
    connection: Mock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        helper.accounts, "sid_bytes", Mock(return_value=b"\x01\x02\xff")
    )
    assert helper.computer_account(identity="S-1-5-21-1-2-3-1000") == (
        _DOMAIN,
        "MyComputer",
    )
    helper.accounts.sid_bytes.assert_called_once_with("S-1-5-21-1-2-3-1000")
    assert connection.search.call_args_list[0] == call(
        _DOMAIN_DN,
        2,
        r"(&(objectClass=computer)(objectSid=\01\02\ff))",
        ["sAMAccountName"],
    )


@pytest.mark.parametrize("modern", [False, True])
def test_provisioning_native_output_is_copied_and_freed_using_exact_binary_length(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    modern: bool,
) -> None:
    api = Mock()
    blob = ctypes.create_string_buffer(b"binary\0secret")
    observed: list[tuple[Any, ...]] = []

    def _provision(*arguments: Any) -> int:
        observed.append(arguments)
        ctypes.cast(arguments[-3], ctypes.POINTER(ctypes.c_void_p))[0] = (
            ctypes.addressof(blob)
        )
        ctypes.cast(arguments[-2], ctypes.POINTER(ctypes.c_uint32))[0] = 13
        return 0

    name = "NetCreateProvisioningPackage" if modern else "NetProvisionComputerAccount"
    getattr(api, name).side_effect = _provision
    monkeypatch.setattr(helper, "provisioning_api", lambda _root: (api, name))
    assert helper.provision(_DOMAIN, "MyComputer", "DC", modern) == b"binary\0secret"
    api.NetApiBufferFree.assert_called_once()
    assert api.NetApiBufferFree.call_args.args[0].value == ctypes.addressof(blob)
    if modern:
        params = ctypes.cast(
            observed[0][0], ctypes.POINTER(helper._ProvisioningParameters)
        ).contents
        assert (
            params.version,
            params.domain,
            params.machine_name,
            params.domain_controller,
            params.options,
        ) == (1, _DOMAIN, "MyComputer", "DC", 0x12)
    else:
        assert observed[0][:5] == (_DOMAIN, "MyComputer", None, "DC", 2)


@pytest.mark.parametrize(
    "scenario",
    [
        (True, True, True, "NetCreateProvisioningPackage"),
        (False, True, False, "NetProvisionComputerAccount"),
        (False, True, True, None),
        (False, False, False, None),
    ],
)
def test_provisioning_capability_gate_never_calls_password_changing_functions(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    scenario: tuple[bool, bool, bool, str | None],
) -> None:
    modern, legacy, root_ca, expected = scenario
    api = Mock()
    if not modern:
        api.NetCreateProvisioningPackage = None
    if not legacy:
        api.NetProvisionComputerAccount = None
    monkeypatch.setattr(helper.os, "name", "nt")
    monkeypatch.setattr(ctypes, "WinDLL", Mock(return_value=api), raising=False)
    if expected:
        assert helper.provisioning_api(root_ca) == (api, expected)
    else:
        with pytest.raises(OSError, match="requires"):
            helper.provisioning_api(root_ca)
    assert not api.mock_calls


def test_offline_action_stages_only_its_owned_closure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, shell, events = _action(ActionModule, monkeypatch)
    action.run()
    names = [Path(str(event[1])).name for event in events if event[0] == "transfer"]
    assert names == [
        "legacy_windows_module.py",
        "legacy_windows_account.py",
        "legacy_ad_ldap.py",
        "legacy_ad_offline_join.py",
        "legacy_ad_result.py",
    ]
    assert shell.tmpdir is None
