"""Check literal state protection and recovery in the older DHCP fixture."""

# SPDX-License-Identifier: GPL-3.0-or-later
# pylint: disable=protected-access

import copy
import json
from typing import Any
from unittest.mock import MagicMock

import pytest

# PyYAML comes from the pinned developer environment without typing stubs.
import yaml  # type: ignore[import-untyped]
from jinja2 import Environment

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="fixture")
def classic_fixture(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load maintained ownership checks without executing a Windows operation.

    :param monkeypatch: Scoped target helper imports.
    :returns: Actual fixture module and a fully observed owned-scope journal.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    module = load_module(
        ROOT / "tests/integration/fixtures/win_dhcp_lease_classic.py",
        "dhcp_fixture_test",
    )
    original = {
        "network": [{"ip": "protected"}],
        "services": [],
        "runtime": [],
        "bindings": "actual binding",
        "scopes": [],
        "records": {},
    }
    sibling = {"address": "192.0.2.254", "hardware": "02fffffffffe"}
    initial = dict(
        original,
        scopes=[
            {"address": "192.0.2.0", "name": "legacy-windows-dhcp-owned", "state": 1}
        ],
        records={"192.0.2.0": {"leases": [sibling], "reservations": [sibling]}},
    )
    journal = {
        "scope": "192.0.2.0",
        "name": "legacy-windows-dhcp-owned",
        "original": original,
        "initial": initial,
    }
    return module, journal


@pytest.mark.parametrize("field", ["network", "services", "runtime", "bindings"])
def test_protected_literal_fields_cannot_be_hidden_by_owned_scope_filter(
    fixture: Any,
    field: str,
) -> None:
    module, journal = fixture
    current = copy.deepcopy(journal["initial"])
    current[field] = "unexpected change"
    with pytest.raises(AssertionError):
        module._verify(current, journal)


@pytest.mark.parametrize("change", [{"state": 0}, {"name": "unrelated"}])
def test_wrong_name_or_active_scope_cannot_be_deleted(
    fixture: Any, change: Any
) -> None:
    module, journal = fixture
    api = MagicMock()
    api.subnet.return_value = dict(journal["initial"]["scopes"][0], **change)
    module._command = MagicMock()
    with pytest.raises(AssertionError):
        module._remove_scope(api, journal)
    module._command.assert_not_called()


@pytest.mark.parametrize("kind", ["leases", "reservations"])
def test_unowned_record_and_protected_sibling_change_stop_recovery(
    fixture: Any,
    kind: str,
) -> None:
    module, journal = fixture
    current = copy.deepcopy(journal["initial"])
    current["records"]["192.0.2.0"][kind].append(
        {
            "address": "192.0.2.80",
            "hardware": "020000000080",
        }
    )
    with pytest.raises(AssertionError):
        module._verify(current, journal)
    current = copy.deepcopy(journal["initial"])
    current["records"]["192.0.2.0"][kind][0]["comment"] = "changed"
    with pytest.raises(AssertionError):
        module._verify(current, journal)


def test_native_scoped_uid_and_literal_mac_are_both_owned(fixture: Any) -> None:
    module, journal = fixture
    current = copy.deepcopy(journal["initial"])
    for kind, prefix in (("leases", ""), ("reservations", "000200c001")):
        current["records"]["192.0.2.0"][kind].append(
            {
                "address": "192.0.2.25",
                "hardware": prefix + "020000000025",
            }
        )
    module._verify(current, journal)


def test_scope_is_disabled_before_a_range_or_reservation_is_added(fixture: Any) -> None:
    module, journal = fixture
    api = MagicMock()
    api.subnet.return_value = {"state": 0}
    calls = MagicMock()
    module._command = calls
    with pytest.raises(AssertionError):
        module._create_scope(api, journal)
    assert calls.call_count == 2
    assert calls.call_args.args[0][-3:] == ["set", "state", "0"]


@pytest.mark.parametrize("guard", [{"check": True}, {"nonmutating": True}])
def test_declared_nonmutation_requires_complete_observation_equality(
    guard: dict[str, bool],
) -> None:
    tasks = yaml.safe_load(
        (ROOT / "tests/integration/tasks/win_dhcp_lease_case.yml").read_text(
            encoding="utf-8"
        )
    )
    task = next(
        item
        for item in tasks
        if item["name"] == "Require declared public behavior and check-mode nonmutation"
    )
    expression = task["ansible.builtin.assert"]["that"][3]
    environment = Environment()
    environment.filters["from_json"] = json.loads
    check = environment.compile_expression(expression)
    original = {"native": {"lease": "protected"}}
    arguments = {
        "dhcp_case": guard,
        "dhcp_case_before": {"stdout": json.dumps(original)},
        "dhcp_case_after": {"stdout": json.dumps(original)},
    }
    assert check(**arguments)
    arguments["dhcp_case_after"] = {
        "stdout": json.dumps({"native": {"lease": "changed"}})
    }
    assert not check(**arguments)


def test_meaningful_unsupported_classic_dns_requests_require_nonmutation() -> None:
    variables = yaml.safe_load(
        (ROOT / "tests/integration/vars/dhcp_lease_classic_fixture.yml").read_text(
            encoding="utf-8"
        )
    )
    unsupported = variables["dhcp_classic_unsupported_dns_cases"]
    assert len(unsupported) == 4
    assert all(not case["changed"] and case["failed"] for case in unsupported)
