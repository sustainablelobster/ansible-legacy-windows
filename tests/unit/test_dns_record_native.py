"""Check observable DNS reconciliation through a stateful provider substitute."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These tests exercise reconciliation without requiring an installed Windows provider.
# pylint: disable=protected-access

import copy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tests.unit.payload_support import load_module

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(name="dns")
def dns_helper(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load native DNS code without invoking Windows APIs.

    :param monkeypatch: Temporary sibling helper import path.
    :returns: Native helper using developer Python, not target-runtime evidence.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins" / "module_utils"))
    return load_module(
        ROOT / "plugins" / "module_utils" / "legacy_windows_dns_record.py",
        "tested_dns_record",
    )


def options(**updates: Any) -> dict[str, Any]:
    """Supply one valid public DNS request for behavior tests.

    :param updates: Individual request changes.
    :returns: Converted DNS record options.
    """
    return {
        "name": "database",
        "zone": "owned.test",
        "type": "A",
        "state": "present",
        "value": ["192.0.2.1"],
        "ttl": 3600,
        "aging": False,
        "allow_update_any": False,
        "zone_scope": None,
        "computer_name": None,
        "port": None,
        "weight": None,
        "priority": None,
        **updates,
    }


def record(
    dns: Any,
    value: str,
    *,
    ttl: int = 3600,
    timestamp: str | None = None,
    kind: str = "A"
) -> dict[str, Any]:
    """Build one native provider observation for the selected record type.

    :param dns: Loaded helper supplying the DMTF interval encoder.
    :param value: Native record value.
    :param ttl: Observed lifetime in seconds.
    :param timestamp: Provider scavenging timestamp, or None for a static record.
    :param kind: Record type.
    :returns: Native record dictionary.
    """
    fields: dict[str, Any] = {
        "__CLASS": "DnsServerResourceRecord" + kind,
        dns._PROPERTIES[kind]: value,
    }
    if kind == "SRV":
        fields.update(Port=1, Weight=2, Priority=3)
    return {
        "__CLASS": "DnsServerResourceRecord",
        "HostName": "database",
        "RecordType": kind,
        "RecordClass": "IN",
        "TimeToLive": dns._interval(ttl),
        "Timestamp": timestamp,
        "RecordData": fields,
    }


class Provider:
    """Observe mutations and retain the resulting record list for complete diffs."""

    def __init__(self, rows: list[dict[str, Any]], *, fail_add: bool = False):
        self.rows = copy.deepcopy(rows)
        self.original = copy.deepcopy(rows)
        self.removed: list[dict[str, Any]] = []
        self.updated: list[tuple[dict[str, Any], dict[str, Any]]] = []
        self.added: list[str] = []
        self.fail_add = fail_add

    def read(self) -> list[dict[str, Any]]:
        """Return independent observations, not mutable aliases.

        :returns: Complete retained provider rows.
        """
        return copy.deepcopy(self.rows)

    def remove(self, row: dict[str, Any]) -> None:
        """Remove the selected existing record.

        :param row: Previously observed record to remove.
        """
        self.removed.append(row)
        self.rows.remove(row)

    def update(self, old: dict[str, Any], new: dict[str, Any]) -> None:
        """Replace only the selected record.

        :param old: Previously observed record.
        :param new: Replacement record.
        """
        self.updated.append((old, new))
        self.rows[self.rows.index(old)] = new

    def add(self, value: str) -> None:
        """Record a requested addition or simulate a provider rejection.

        :param value: Requested DNS value.
        :raises OSError: If this substitute is configured to reject additions.
        """
        if self.fail_add:
            raise OSError("provider rejection")
        self.added.append(value)

    def validate_add(self, value: str) -> None:
        """Simulate provider validation without an addition.

        :param value: Requested DNS value.
        :raises OSError: If the configured provider rejects the value.
        """
        if self.fail_add:
            raise OSError("provider rejection: " + value)


@pytest.mark.parametrize(
    "expected",
    [
        [0],
        [1, 0],
        [2, 1, 0],
        [2, 3, 0, 1],
        [3, 4, 2, 0, 1],
        [5, 4, 7, 6, 1, 0, 3, 2],
        [10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5],
        [11, 12, 9, 10, 15, 16, 13, 14, 8, 2, 3, 0, 1, 6, 7, 4, 5],
        [
            21,
            20,
            23,
            22,
            17,
            16,
            19,
            18,
            29,
            28,
            31,
            30,
            25,
            24,
            27,
            26,
            5,
            4,
            7,
            6,
            1,
            0,
            3,
            2,
            13,
            12,
            15,
            14,
            9,
            8,
            11,
            10,
        ],
        [
            22,
            21,
            24,
            23,
            18,
            17,
            20,
            19,
            30,
            29,
            32,
            31,
            26,
            25,
            28,
            27,
            16,
            5,
            4,
            7,
            6,
            1,
            0,
            3,
            2,
            13,
            12,
            15,
            14,
            9,
            8,
            11,
            10,
        ],
    ],
)
def test_equal_cim_order_matches_actual_released_sort(
    dns: Any, expected: list[int]
) -> None:
    original = list(range(len(expected)))
    assert dns._released_order(original) == expected
    assert original == list(range(len(expected)))
    assert dns._released_order([]) == []


@pytest.mark.parametrize(
    "value,accepted",
    [
        ("AAEB", True),
        ("AAAA", True),
        ("0000", True),
        ("AAEB \t\r\n", True),
        ("000101" + "a" * 64, False),
        ("invalid!", False),
        ("a", False),
        ("", False),
        ("Ω", False),
    ],
)
def test_dhcid_native_validation_is_nonmutating(
    dns: Any,
    value: str,
    accepted: bool,
) -> None:
    if accepted:
        dns._validate_dhcid(value)
    else:
        with pytest.raises(OSError, match="nonempty base64"):
            dns._validate_dhcid(value)


def test_failed_preview_validation_does_not_predict_or_mutate(dns: Any) -> None:
    provider = Provider([], fail_add=True)
    assert dns._manage(
        provider, options(type="DHCID", value=["invalid!"]), True, True
    ) == {
        "changed": False,
        "failed": True,
        "debug_splat_args": {"DHCID": True, "DhcpIdentifier": "invalid!"},
        "msg": "Error adding DNS DHCID resource database in zone owned.test with value invalid!",
    }
    assert not provider.added and not provider.updated and not provider.removed


@pytest.mark.parametrize("check", [False, True])
def test_identical_record_is_idempotent_with_complete_diff(
    dns: Any, check: bool
) -> None:
    provider = Provider([record(dns, "192.0.2.1")])
    text = "[owned.test] database 3600 IN A 192.0.2.1\n"
    assert dns._manage(provider, options(), check, True) == {
        "changed": False,
        "diff": {"before": "" if check else text, "after": "" if check else text},
    }
    assert not provider.removed and not provider.updated and not provider.added


@pytest.mark.parametrize("check", [False, True])
def test_ttl_edit_preserves_original_observation(dns: Any, check: bool) -> None:
    old = record(dns, "192.0.2.1", ttl=60)
    provider = Provider([old])
    assert dns._manage(provider, options(), check, True) == {
        "changed": True,
        "diff": {
            "before": "[owned.test] database 60 IN A 192.0.2.1\n",
            "after": "[owned.test] database 3600 IN A 192.0.2.1\n",
        },
    }
    assert old == provider.original[0]
    assert bool(provider.updated) is not check


def test_absent_request_removes_all_selected_records(dns: Any) -> None:
    provider = Provider([record(dns, "192.0.2.1"), record(dns, "192.0.2.2")])
    result = dns._manage(provider, options(state="absent", value=[]), False, True)
    assert result["changed"] and result["diff"]["after"] == ""
    assert len(provider.removed) == 2 and not provider.rows


@pytest.mark.parametrize("kind", ["CNAME", "NS", "PTR", "SRV"])
def test_addition_uses_released_target_suffix_and_diagnostic(
    dns: Any, kind: str
) -> None:
    provider = Provider([])
    result = dns._manage(
        provider,
        options(type=kind, value=["Target.TEST"], port=123, weight=2, priority=3),
        True,
        True,
    )
    assert result == {
        "changed": True,
        "debug_splat_args": {kind: True, dns._PROPERTIES[kind]: "Target.TEST."},
        "diff": {
            "before": "",
            "after": "[owned.test] database 3600 IN " + kind + " Target.TEST.\n",
        },
    }
    assert not provider.added


def test_aging_replacement_has_no_preview_mutation(dns: Any) -> None:
    provider = Provider(
        [record(dns, "192.0.2.1", timestamp="20261002010000.000000+000")]
    )
    result = dns._manage(provider, options(), True, True)
    assert result["changed"] and result["debug_splat_args"] == {
        "A": True,
        "IPv4Address": "192.0.2.1",
    }
    assert (
        provider.rows == provider.original
        and not provider.removed
        and not provider.added
    )


def test_provider_add_failure_preserves_source_public_shape(dns: Any) -> None:
    provider = Provider([], fail_add=True)
    assert dns._manage(provider, options(), False, True) == {
        "changed": False,
        "debug_splat_args": {"A": True, "IPv4Address": "192.0.2.1"},
        "failed": True,
        "msg": "Error adding DNS A resource database in zone owned.test with value 192.0.2.1",
    }


@pytest.mark.parametrize(
    "method, output, expected", [("AddByA", False, None), ("Get", True, [])]
)
def test_success_without_provider_output_is_not_an_error(
    dns: Any, monkeypatch: pytest.MonkeyPatch, method: str, output: bool, expected: Any
) -> None:
    connection = SimpleNamespace(
        _services=None,
        _automation=None,
        _method_inputs=lambda *_args: None,
    )
    monkeypatch.setattr(dns.wmi, "_method", lambda *_args: lambda *_inputs: 0)
    monkeypatch.setattr(dns.wmi, "_bstr", lambda *_args: None)
    assert dns._call(connection, method, {}, output=output) == expected


def test_provider_failure_without_output_remains_an_error(
    dns: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = SimpleNamespace(
        _services=None,
        _automation=None,
        _method_inputs=lambda *_args: None,
    )
    monkeypatch.setattr(dns.wmi, "_method", lambda *_args: lambda *_inputs: 0x80041001)
    monkeypatch.setattr(dns.wmi, "_bstr", lambda *_args: None)
    monkeypatch.setattr(dns, "_provider_message", lambda *_args: "provider rejection")
    with pytest.raises(OSError, match="provider rejection") as error:
        dns._call(connection, "AddByA", {})
    assert getattr(error.value, "hresult") == 0x80041001


def test_srv_preview_includes_source_ordered_numeric_fields(dns: Any) -> None:
    provider = Provider([record(dns, "host.test.", kind="SRV")])
    result = dns._manage(
        provider,
        options(type="SRV", value=["host.test"], port=123, weight=5, priority=7),
        True,
        True,
    )
    assert result == {
        "changed": True,
        "diff": {
            "before": "[owned.test] database 3600 IN SRV host.test. 1 2 3\n",
            "after": "[owned.test] database 3600 IN SRV host.test. 123 5 7\n",
        },
    }
    assert not provider.updated


def test_modern_srv_creation_honors_ttl_before_identical_repeats(
    dns: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows: list[dict[str, Any]] = []

    def _call(
        _connection: Any,
        method: str,
        arguments: dict[str, Any],
        output: bool = False,
    ) -> Any:
        if method == "Get":
            assert output
            return copy.deepcopy(rows)
        if method == "AddBySrv":
            observed = record(dns, arguments["DomainName"], kind="SRV")
            observed["TimeToLive"] = arguments.get("TimeToLive", dns._interval(3600))
            observed["RecordData"].update(
                {name: arguments[name] for name in ("Port", "Priority", "Weight")}
            )
            rows.append(observed)
            return None
        if method == "RemoveByInputObject":
            rows.remove(arguments["InputObject"])
            return None
        raise AssertionError("An identical SRV request must not edit the created row.")

    monkeypatch.setattr(dns, "_call", _call)
    request = options(
        type="SRV",
        value=["target.example.test"],
        ttl=600,
        port=12345,
        priority=10,
        weight=20,
    )
    provider = dns._Records(None, request)
    assert dns._manage(provider, request, True, True)["changed"]
    assert not rows
    assert dns._manage(provider, request, False, True)["changed"]
    assert dns._seconds(rows[0]["TimeToLive"]) == 600
    assert rows[0]["RecordData"]["DomainName"] == "target.example.test."
    for _repeat in range(2):
        assert dns._manage(provider, request, False, True)["changed"] is False
    assert dns._manage(provider, request, True, True)["changed"] is False
    absent = dict(request, state="absent", value=[])
    assert dns._manage(provider, absent, False, True)["changed"]
    assert not rows
    assert dns._manage(provider, absent, False, True)["changed"] is False
