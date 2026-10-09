"""Check ownership and literal recovery gates in the DHCP integration fixture."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

# Ansible supplies PyYAML, but its optional type-stub package is not required.
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tests/integration/vars/dhcp_lease_fixture.yml"


@pytest.fixture(name="fixture")
def fixture_functions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load maintained fixture functions with only native and runtime substitutes.

    :param tmp_path: Owned recovery workspace.
    :param monkeypatch: Scoped target argument and native replacements.
    :returns: Fixture namespace, native recorder and recovery journal.
    """
    source = yaml.safe_load(SOURCE.read_text(encoding="utf-8"))["dhcp_lease_fixture"]
    source = source[: source.index('if OPERATION == "setup":')]
    source = source.replace("assert sys.version_info[:3] == (3, 4, 4)\n", "")
    source = "\n".join(
        line
        for line in source.splitlines()
        if not line.startswith(("SOURCE =", "exec(compile("))
    )
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.call_method.return_value = {}
    monkeypatch.setattr("sys.argv", ["fixture", str(tmp_path), "cleanup"])
    namespace: dict[str, Any] = {}
    # Exercise the maintained target fixture rather than a second implementation.
    exec(compile(source, str(SOURCE), "exec"), namespace)  # pylint: disable=exec-used
    namespace["helper"] = SimpleNamespace(WmiConnection=lambda *_: connection)
    original = {
        "scopes": [],
        "records": {},
        "network": [{"ip": "protected"}],
        "services": [],
        "bindings": [],
    }
    journal = {
        "workspace": str(tmp_path),
        "scope": "192.0.2.0",
        "name": "legacy-windows-dhcp-owned",
        "original": original,
    }
    namespace["write_journal"](journal)
    return namespace, connection, journal


def _owned(journal: dict[str, Any], **changes: Any) -> dict[str, Any]:
    snapshot = dict(journal["original"])
    snapshot.update(
        scopes=[
            {"ScopeId": journal["scope"], "Name": journal["name"], "State": "Inactive"}
        ],
        records={journal["scope"]: {"leases": [], "reservations": []}},
    )
    snapshot.update(changes)
    return snapshot


def test_empty_stream_success_has_no_invented_fields(fixture: Any) -> None:
    namespace, connection, _ = fixture
    assert namespace["call"](connection, "Scope", "Get") == []
    assert connection.call_method.call_args.kwargs == {"allow_empty": True}


@pytest.mark.parametrize("mutation", ["network", "bindings", "services"])
def test_protected_changes_block_deletion_and_retain_journal(
    fixture: Any, mutation: str
) -> None:
    namespace, connection, journal = fixture
    namespace["snapshot"] = lambda: _owned(journal, **{mutation: ["changed"]})
    with pytest.raises(AssertionError):
        namespace["cleanup"](journal)
    connection.call_method.assert_not_called()
    assert Path(namespace["JOURNAL"]).exists()


@pytest.mark.parametrize("change", [{"Name": "unrelated"}, {"State": "Active"}])
def test_owned_scope_name_and_inactive_state_are_required_before_deletion(
    fixture: Any, change: dict[str, str]
) -> None:
    namespace, connection, journal = fixture
    current = _owned(journal)
    current["scopes"][0].update(change)
    namespace["snapshot"] = lambda: current
    with pytest.raises(AssertionError):
        namespace["cleanup"](journal)
    connection.call_method.assert_not_called()
    assert Path(namespace["JOURNAL"]).exists()


def test_final_literal_recovery_precedes_journal_removal(fixture: Any) -> None:
    namespace, connection, journal = fixture
    observations = iter([_owned(journal), journal["original"]])
    namespace["snapshot"] = lambda: next(observations)
    result = namespace["cleanup"](journal)
    assert result == {
        "restored": True,
        "original": journal["original"],
        "final": journal["original"],
    }
    assert not Path(namespace["JOURNAL"]).exists()
    assert connection.call_method.call_args.args[0:2] == (
        "PS_DhcpServerv4Scope",
        "Remove",
    )
    assert connection.call_method.call_args.args[3] == {
        "ScopeId": ["192.0.2.0"],
        "Force": True,
    }


@pytest.mark.parametrize("kind", ["leases", "reservations"])
@pytest.mark.parametrize(
    "record",
    [
        {"IPAddress": "192.0.2.80", "ClientId": "02-00-00-00-00-80"},
        {"IPAddress": "192.0.2.25", "ClientId": "unrelated"},
        {"IPAddress": "192.0.2.254", "ClientId": "unrelated"},
    ],
)
def test_unowned_record_prevents_force_scope_removal(
    fixture: Any, kind: str, record: dict[str, str]
) -> None:
    namespace, connection, journal = fixture
    current = _owned(journal)
    current["records"][journal["scope"]][kind].append(record)
    namespace["snapshot"] = lambda: current
    with pytest.raises(AssertionError):
        namespace["cleanup"](journal)
    connection.call_method.assert_not_called()
    assert Path(namespace["JOURNAL"]).exists()


@pytest.mark.parametrize(
    "mutation", [None, "client_id", "description", "missing_proof"]
)
def test_expired_ip_identifier_requires_journaled_original_lease(
    fixture: Any, mutation: str | None
) -> None:
    namespace, connection, journal = fixture
    original = {
        "IPAddress": "192.0.2.25",
        "ClientId": "02-00-00-00-00-25",
        "AddressState": "Active",
        "Description": "original description",
    }
    journal["owned_leases"] = [original]
    tombstone = dict(
        original, AddressState="Expired", ClientId="19-02-00-c0-00-00-00-00-00"
    )
    if mutation == "client_id":
        tombstone["ClientId"] = "19-02-00-c0-00-00-00-00-01"
    elif mutation == "description":
        tombstone["Description"] = "unrelated"
    elif mutation == "missing_proof":
        journal.pop("owned_leases")
    current = _owned(journal)
    current["records"][journal["scope"]]["leases"] = [tombstone]
    observations = iter([current, journal["original"]])
    namespace["snapshot"] = lambda: next(observations)
    if mutation:
        with pytest.raises(AssertionError):
            namespace["cleanup"](journal)
        connection.call_method.assert_not_called()
        assert Path(namespace["JOURNAL"]).exists()
    else:
        assert namespace["cleanup"](journal)["restored"]
        assert not Path(namespace["JOURNAL"]).exists()


def test_reset_journals_original_lease_before_public_removal(fixture: Any) -> None:
    namespace, _, journal = fixture
    original = {
        "IPAddress": "192.0.2.25",
        "ClientId": "02-00-00-00-00-25",
        "AddressState": "Active",
    }
    current = _owned(journal)
    current["records"][journal["scope"]]["leases"] = [original]
    namespace["remember_leases"](current, journal)
    assert journal["owned_leases"] == [original]
    assert namespace["load_journal"]()["owned_leases"] == [original]


def test_final_changed_provider_values_leave_recovery_data(fixture: Any) -> None:
    namespace, _, journal = fixture
    observations = iter(
        [_owned(journal), dict(journal["original"], scopes=["unexpected"])]
    )
    namespace["snapshot"] = lambda: next(observations)
    with pytest.raises(AssertionError):
        namespace["cleanup"](journal)
    assert Path(namespace["JOURNAL"]).exists()


def test_existing_absent_owned_scope_still_requires_whole_original_state(
    fixture: Any,
) -> None:
    namespace, connection, journal = fixture
    namespace["snapshot"] = lambda: journal["original"]
    assert namespace["cleanup"](journal)["restored"]
    connection.call_method.assert_not_called()


def test_journal_guard_rejects_wrong_workspace_before_recovery(fixture: Any) -> None:
    namespace, connection, journal = fixture
    journal["workspace"] = "unrelated"
    Path(namespace["JOURNAL"]).write_text(json.dumps(journal), encoding="utf-8")
    with pytest.raises(AssertionError):
        namespace["load_journal"]()
    connection.call_method.assert_not_called()


def test_journal_failure_occurs_before_any_scope_creation(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    namespace, connection, journal = fixture
    Path(namespace["JOURNAL"]).unlink()
    namespace["snapshot"] = lambda: journal["original"]
    monkeypatch.setattr(
        namespace["os"],
        "fsync",
        lambda _: (_ for _ in ()).throw(OSError("sync failed")),
    )
    with pytest.raises(OSError, match="sync failed"):
        namespace["setup"]()
    connection.call_method.assert_not_called()
    assert Path(namespace["JOURNAL"]).exists()
