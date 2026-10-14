"""Exercise public KDS payload contracts against independent directory state."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Native state inspection below tests the documented binary field layouts.
# pylint: disable=protected-access

import copy
import importlib
import json
import struct
import sys
import uuid
from pathlib import Path
from types import ModuleType
from typing import Any, Callable
from unittest.mock import Mock

import pytest

# Ansible provides the real collection loaders but does not publish type stubs.
from ansible.plugins.loader import (  # type: ignore[import-untyped]
    action_loader,
    module_loader,
)

from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module
from tests.unit.test_python_action import _action

DOMAIN = "DC=example,DC=test"
CONFIG = "CN=Configuration," + DOMAIN
SERVICE = "CN=Group Key Distribution Service,CN=Services," + CONFIG
CONTAINER = "CN=Master Root Keys," + SERVICE
SERVER = "CN=DC01,CN=Servers,CN=DefaultSite,CN=Sites," + CONFIG
COMPUTER = "CN=DC01,OU=Domain Controllers," + DOMAIN
NOW = 134153604051234560
KEY = "86b7e89a-77b4-4a5d-8f90-b09a28792c21"


class Directory:
    """Keep observable LDAP reads and writes separate from payload projection."""

    def __init__(self) -> None:
        self.keys: dict[str, dict[str, list[bytes]]] = {}
        self.configuration: dict[str, list[bytes]] = {"msKds-Version": [b"1"]}
        self.calls: list[tuple[Any, ...]] = []
        self.closed = False
        self.capable = True
        self.failure: str | None = None
        self.server_reference: str | None = COMPUTER

    def __enter__(self) -> "Directory":
        return self

    def __exit__(self, *_values: Any) -> None:
        self.closed = True

    def naming_context(self, name: str = "defaultNamingContext") -> str:
        """Return the independently defined directory partitions.

        :param name: Requested naming context.
        :returns: Domain or configuration partition.
        """
        return CONFIG if name == "configurationNamingContext" else DOMAIN

    def search(
        self, base: str, scope: int, predicate: str, attributes: list[str]
    ) -> list[dict[str, Any]]:
        """Apply native query selection without invoking the implementation.

        :param base: Search root.
        :param scope: LDAP scope.
        :param predicate: LDAP filter.
        :param attributes: Requested attributes.
        :returns: Independent raw LDAP entries.
        :raises OSError: If the independent read-denial injection is active.
        """
        self.calls.append(("search", base, scope, predicate, attributes))
        if self.failure == "search":
            raise OSError(50, "Read denied")
        if base == "":
            return [{"dn": "", "attributes": {"serverName": [SERVER.encode()]}}]
        if base == SERVER:
            return [
                {
                    "dn": SERVER,
                    "attributes": (
                        {"serverReference": [self.server_reference.encode()]}
                        if self.server_reference is not None
                        else {}
                    ),
                }
            ]
        if base == CONTAINER and scope == 0:
            return (
                [{"dn": CONTAINER, "attributes": {"cn": [b"Master Root Keys"]}}]
                if self.capable
                else []
            )
        if base == "CN=Server Configuration," + SERVICE:
            return (
                [
                    {
                        "dn": "CN=Configuration," + base,
                        "attributes": copy.deepcopy(self.configuration),
                    }
                ]
                if self.configuration
                else []
            )
        assert base == CONTAINER
        wanted = {name.lower() for name in attributes}
        entries = []
        for dn, raw in self.keys.items():
            key_id = raw["cn"][0].decode()
            if (
                "(cn=" in predicate
                and "(cn=" + key_id.lower() + ")" not in predicate.lower()
            ):
                continue
            entries.append(
                {
                    "dn": dn,
                    "attributes": {
                        name: list(values)
                        for name, values in raw.items()
                        if name.lower() in wanted
                    },
                }
            )
        return entries

    def add(self, dn: str, attributes: dict[str, list[bytes]]) -> None:
        """Create observable independent key state after optional write rejection.

        :param dn: New object DN.
        :param attributes: Raw LDAP values.
        :raises OSError: If the independent create-denial injection is active.
        """
        self.calls.append(("add", dn))
        if self.failure == "add":
            raise OSError(50, "Create denied")
        assert dn not in self.keys
        self.keys[dn] = copy.deepcopy(attributes)

    def delete(self, dn: str) -> None:
        """Remove the requested exact key after optional write rejection.

        :param dn: Observed key DN.
        :raises OSError: If the independent removal-denial injection is active.
        """
        self.calls.append(("delete", dn))
        if self.failure == "delete":
            raise OSError(50, "Remove denied")
        del self.keys[dn]


@pytest.fixture(name="directory")
def directory_state() -> Directory:
    """Provide a fresh independently owned protocol fixture.

    :returns: Directory state.
    """
    return Directory()


@pytest.fixture(name="run")
def payload_runner(
    monkeypatch: pytest.MonkeyPatch,
    directory: Directory,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> Callable[..., dict[str, Any]]:
    """Invoke public JSON payloads with only the native boundary substituted.

    :param monkeypatch: Scoped substitutions.
    :param directory: Independent LDAP state.
    :param tmp_path: Disposable arguments directory.
    :param capsys: Captured module output.
    :returns: KDS payload invocation function.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(str(ROOT / "legacy_ad/plugins/module_utils"))
    helper = importlib.import_module("legacy_ad_kds")
    monkeypatch.setattr(helper, "LDAPConnection", Mock(return_value=directory))
    monkeypatch.setattr(helper, "_filetime_now", lambda: NOW)
    payloads: dict[str, ModuleType] = {
        kind: load_module(
            ROOT / "legacy_ad/plugins/modules" / (kind + ".py"), "tested_ad_" + kind
        )
        for kind in ("kds_root_key", "kds_root_key_info")
    }

    def _run(
        kind: str, arguments: dict[str, Any] | None = None, failed: bool = False
    ) -> dict[str, Any]:
        source = tmp_path / "arguments.json"
        source.write_text(json.dumps(arguments or {}), encoding="utf-8")
        monkeypatch.setattr(sys, "argv", [kind + ".py", str(source)])
        status, result = invoke_payload(payloads[kind], capsys)
        assert status == (1 if failed else 0), result
        return result

    return _run


def test_create_read_repeat_and_owned_delete(run: Any, directory: Directory) -> None:
    created = run("kds_root_key", {"effective_time_hours": 0})
    assert created["changed"] is True
    key_id = str(uuid.UUID(created["key_id"]))
    dn = "CN=" + key_id + "," + CONTAINER
    raw = directory.keys[dn]
    assert raw["objectClass"] == [b"msKds-ProvRootKey"]
    assert len(raw["msKds-RootKeyData"][0]) == 64
    assert int(raw["msKds-CreateTime"][0]) == NOW
    assert int(raw["msKds-UseStartTime"][0]) == NOW - 360000000000
    assert raw["msKds-DomainID"] == [COMPUTER.encode()]
    assert run("kds_root_key") == {
        "changed": False,
        "key_id": "00000000-0000-0000-0000-000000000000",
    }
    assert run("kds_root_key", {"match_by": "key_id", "key_id": key_id}) == {
        "changed": False,
        "key_id": None,
    }
    info = run("kds_root_key_info", {"key_id": key_id.upper()})
    assert info == {
        "changed": False,
        "kds_root_keys": [
            {
                "key_id": key_id,
                "creation_time": "2026-02-12T09:00:05.1234560Z",
                "effective_time": "2026-02-11T23:00:05.1234560Z",
                "version_number": 1,
            }
        ],
    }
    assert "msKds-RootKeyData" not in json.dumps(info)
    assert run("kds_root_key", {"state": "absent", "key_id": key_id}) == {
        "changed": True,
        "key_id": key_id,
    }
    assert run("kds_root_key", {"state": "absent", "key_id": key_id}) == {
        "changed": False,
        "key_id": key_id,
    }
    assert run("kds_root_key_info") == {"changed": False, "kds_root_keys": []}
    assert directory.closed


@pytest.mark.parametrize("hours", [None, "10", " +10 ", 0, -1, 1, 11])
def test_requested_effective_times(run: Any, directory: Directory, hours: Any) -> None:
    values = {} if hours is None else {"effective_time_hours": hours}
    created = run("kds_root_key", values)
    raw = directory.keys["CN=" + created["key_id"] + "," + CONTAINER]
    expected = 10 if hours is None else int(hours)
    assert int(raw["msKds-UseStartTime"][0]) == NOW + (expected - 10) * 36000000000


def test_never_and_missing_match_create_generated_identifiers(
    run: Any, directory: Directory
) -> None:
    first = run("kds_root_key", {"match_by": "never"})
    second = run("kds_root_key", {"match_by": "never"})
    matched = run("kds_root_key", {"match_by": "key_id", "key_id": KEY})
    assert len(directory.keys) == 3
    assert len({first["key_id"], second["key_id"], matched["key_id"], KEY}) == 4


def test_case_insensitive_choices_preserve_lifecycle(
    run: Any, directory: Directory
) -> None:
    created = run("kds_root_key", {"state": "Present", "match_by": "ANY"})
    assert created["changed"] is True
    assert (
        run("kds_root_key", {"state": "PRESENT", "match_by": "Any"})["changed"] is False
    )
    removed = run("kds_root_key", {"state": "ABSENT", "key_id": created["key_id"]})
    assert removed["changed"] is True
    assert directory.keys == {}


@pytest.mark.parametrize(
    "format_name", ["canonical", "upper", "braces", "parentheses", "hex", "hex_fields"]
)
def test_existing_guid_formats_match_and_return_the_upstream_null(
    run: Any, directory: Directory, format_name: str
) -> None:
    created = run("kds_root_key")
    key = created["key_id"]
    supplied = {
        "canonical": key,
        "upper": key.upper(),
        "braces": "{" + key + "}",
        "parentheses": "(" + key + ")",
        "hex": key.replace("-", ""),
        "hex_fields": (
            "{0x"
            + key[:8]
            + ",0x"
            + key[9:13]
            + ",0x"
            + key[14:18]
            + ",{"
            + ",".join(
                "0x" + key.replace("-", "")[index : index + 2]
                for index in range(16, 32, 2)
            )
            + "}}"
        ),
    }[format_name]
    for preview in (False, True):
        assert run(
            "kds_root_key",
            {
                "match_by": "key_id",
                "key_id": supplied,
                "_ansible_check_mode": preview,
            },
        ) == {"changed": False, "key_id": None}
    assert len(directory.keys) == 1


@pytest.mark.parametrize(
    "invalid_form",
    ["duplicate_braces", "doubled_hyphens", "wrapped_hex", "parenthesized_hex"],
)
def test_malformed_guid_forms_do_not_match_existing_keys(
    run: Any, directory: Directory, invalid_form: str
) -> None:
    key = run("kds_root_key")["key_id"]
    supplied = {
        "duplicate_braces": "{{" + key + "}}",
        "doubled_hyphens": key.replace("-", "--"),
        "wrapped_hex": "{" + key.replace("-", "") + "}",
        "parenthesized_hex": "(" + key.replace("-", "") + ")",
    }[invalid_form]
    preview = run(
        "kds_root_key",
        {"match_by": "key_id", "key_id": supplied, "_ansible_check_mode": True},
    )
    assert preview == {
        "changed": True,
        "key_id": "00000000-0000-0000-0000-000000000000",
    }
    assert len(directory.keys) == 1


def test_creation_and_removal_check_mode_do_not_write(
    run: Any, directory: Directory
) -> None:
    for arguments in ({}, {"match_by": "never"}, {"match_by": "key_id", "key_id": KEY}):
        preview = run("kds_root_key", {**arguments, "_ansible_check_mode": True})
        assert preview == {
            "changed": True,
            "key_id": "00000000-0000-0000-0000-000000000000",
        }
    assert directory.keys == {}
    created = run("kds_root_key")
    before = copy.deepcopy(directory.keys)
    preview = run(
        "kds_root_key",
        {"state": "absent", "key_id": created["key_id"], "_ansible_check_mode": True},
    )
    assert preview == {"changed": True, "key_id": created["key_id"]}
    assert directory.keys == before
    assert (
        run(
            "kds_root_key",
            {
                "match_by": "key_id",
                "key_id": created["key_id"],
                "_ansible_check_mode": True,
            },
        )["changed"]
        is False
    )
    assert run("kds_root_key_info", {"_ansible_check_mode": True}) == run(
        "kds_root_key_info"
    )


@pytest.mark.parametrize(
    "arguments",
    [
        {"state": "absent"},
        {"match_by": "key_id"},
        {"state": "invalid"},
        {"state": ""},
        {"match_by": "invalid"},
        {"match_by": ""},
        {"effective_time_hours": "x"},
        {"effective_time_hours": 1.2},
        {"effective_time_hours": 1.0},
        {"effective_time_hours": True},
        {"effective_time_hours": False},
        {"effective_time_hours": "1_0"},
        {"effective_time_hours": "0xa"},
        {"effective_time_hours": "١٠"},
        {"effective_time_hours": 2**31},
        {"effective_time_hours": -(2**31) - 1},
        {"domain_server": "invented.test"},
    ],
)
def test_invalid_options_fail_before_connecting(
    run: Any, directory: Directory, arguments: dict[str, Any]
) -> None:
    result = run("kds_root_key", arguments, failed=True)
    assert result["changed"] is False
    assert result["key_id"] is None
    assert directory.calls == []


@pytest.mark.parametrize("kind", ["kds_root_key", "kds_root_key_info"])
def test_unsupported_directory_is_capability_failure(
    run: Any, directory: Directory, kind: str
) -> None:
    directory.capable = False
    result = run(kind, failed=True)
    assert result["changed"] is False
    assert "KDS root-key container" in result["msg"]
    assert directory.keys == {}


@pytest.mark.parametrize("operation", ["search", "add", "delete"])
def test_native_denial_keeps_failure_state_and_closes_connection(
    run: Any, directory: Directory, operation: str
) -> None:
    key = run("kds_root_key")["key_id"] if operation == "delete" else None
    before = copy.deepcopy(directory.keys)
    directory.failure = operation
    arguments = {"state": "absent", "key_id": key} if key else {}
    result = run("kds_root_key", arguments, failed=True)
    assert result["changed"] is False
    assert "denied" in result["msg"]
    assert directory.keys == before
    assert directory.closed


def test_default_configuration_binary_fields(run: Any, directory: Directory) -> None:
    created = run("kds_root_key")
    raw = directory.keys["CN=" + created["key_id"] + "," + CONTAINER]
    kdf = raw["msKds-KDFParam"][0]
    assert struct.unpack("<IIII", kdf[:16]) == (0, 1, 14, 0)
    assert kdf[16:].decode("utf-16-le") == "SHA512\0"
    dh = raw["msKds-SecretAgreementParam"][0]
    assert struct.unpack("<I4sI", dh[:12]) == (len(dh), b"DHPM", 256)
    assert len(dh) == 524
    assert dh[12:16].hex() == "87a8e61d"
    assert dh[268:272].hex() == "3fb32c9b"


def test_live_configuration_is_copied_not_replaced(
    run: Any, directory: Directory
) -> None:
    configuration = {
        "msKds-Version": [b"9"],
        "msKds-KDFAlgorithmID": [b"custom"],
        "msKds-KDFParam": [b"custom-parameters"],
        "msKds-SecretAgreementAlgorithmID": [b"ECDH_P256"],
        "msKds-PublicKeyLength": [b"256"],
        "msKds-PrivateKeyLength": [b"256"],
    }
    directory.configuration = copy.deepcopy(configuration)
    created = run("kds_root_key")
    raw = directory.keys["CN=" + created["key_id"] + "," + CONTAINER]
    assert all(raw[name] == value for name, value in configuration.items())
    assert "msKds-SecretAgreementParam" not in raw
    assert directory.configuration == configuration


def test_creation_configuration_failure_is_nonmutating(
    run: Any, directory: Directory
) -> None:
    directory.configuration = {}
    assert run("kds_root_key", failed=True)["changed"] is False
    assert directory.keys == {}


def test_native_missing_container_is_a_specific_capability_failure(
    run: Any, directory: Directory, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = importlib.import_module("legacy_ad_kds")
    monkeypatch.setattr(
        directory, "search", Mock(side_effect=helper.LDAPError(32, "No such object"))
    )
    result = run("kds_root_key_info", failed=True)
    assert "KDS root-key container" in result["msg"]
    assert directory.keys == {}
    assert directory.closed


def test_metadata_retains_the_seventh_fractional_digit(
    run: Any, directory: Directory, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = importlib.import_module("legacy_ad_kds")
    monkeypatch.setattr(helper, "_filetime_now", lambda: NOW + 7)
    run("kds_root_key")
    key = run("kds_root_key_info")["kds_root_keys"][0]
    assert key["creation_time"] == "2026-02-12T09:00:05.1234567Z"
    assert key["effective_time"] == key["creation_time"]
    assert len(directory.keys) == 1


def test_out_of_range_effective_time_fails_without_a_write(
    run: Any, directory: Directory
) -> None:
    result = run("kds_root_key", {"effective_time_hours": 2**31 - 1}, failed=True)
    assert result["changed"] is False
    assert "supported Windows date range" in result["msg"]
    assert directory.keys == {}


def test_created_key_links_the_selected_dc_not_the_domain_or_executor(
    run: Any, directory: Directory
) -> None:
    # The actual vendor baseline recorded this link on the owned modern DC.
    vendor_dc = "CN=ADCAPDC,OU=Domain Controllers,DC=adcap,DC=owned,DC=test"
    directory.server_reference = vendor_dc
    created = run("kds_root_key")
    raw = directory.keys["CN=" + created["key_id"] + "," + CONTAINER]
    assert raw["msKds-DomainID"] == [vendor_dc.encode()]
    assert raw["msKds-DomainID"] != [DOMAIN.encode()]


def test_missing_selected_dc_computer_link_fails_before_key_creation(
    run: Any, directory: Directory
) -> None:
    directory.server_reference = None
    result = run("kds_root_key", failed=True)
    assert result["changed"] is False
    assert "serverReference" in result["msg"]
    assert directory.keys == {}


@pytest.mark.parametrize("filter_id", ["", "  ", None])
def test_blank_info_filter_returns_all_metadata(run: Any, filter_id: Any) -> None:
    run("kds_root_key")
    run("kds_root_key", {"match_by": "never"})
    assert len(run("kds_root_key_info", {"key_id": filter_id})["kds_root_keys"]) == 2


def test_key_filter_is_escaped_and_no_secret_attribute_is_read(
    run: Any, directory: Directory
) -> None:
    assert run("kds_root_key_info", {"key_id": "*)(cn=*)"})["kds_root_keys"] == []
    call = directory.calls[-1]
    assert call[3] == "(&(objectClass=msKds-ProvRootKey)(cn=\\2a\\29\\28cn=\\2a\\29))"
    assert all(
        "mskds-rootkeydata" not in [name.lower() for name in call[4]]
        for call in directory.calls
        if call[0] == "search"
    )


@pytest.mark.parametrize("kind", ["kds_root_key", "kds_root_key_info"])
def test_actions_resolve_and_stage_the_complete_native_closure(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fqcn = "sustainablelobster.legacy_ad." + kind
    action_class = action_loader.get(fqcn, class_only=True)
    assert action_class is not None
    assert module_loader.find_plugin(fqcn) is not None
    action, _connection, events = _action(action_class, monkeypatch)
    action.run()
    paths = [Path(str(event[1])).name for event in events if event[0] == "transfer"]
    assert paths == [
        "legacy_windows_module.py",
        "legacy_ad_arguments.py",
        "legacy_ad_ldap.py",
        "legacy_ad_kds.py",
    ]
