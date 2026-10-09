"""Verify bounded DNS fixture observations and durable recovery ownership."""

# SPDX-License-Identifier: GPL-3.0-or-later
# pylint: disable=protected-access

import ctypes
import hashlib
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
import yaml  # type: ignore[import-untyped]
from jinja2.nativetypes import NativeEnvironment

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="fixture")
def load_fixture(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load the Windows-only fixture with scoped native import substitutes.

    :param monkeypatch: Environment, import and native boundary replacements.
    :returns: Imported fixture module, without executing its entry point.
    """
    monkeypatch.setenv("SystemRoot", "fixture-windows")
    monkeypatch.setitem(sys.modules, "winreg", ModuleType("winreg"))
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    monkeypatch.syspath_prepend(str(ROOT / "tests/integration/fixtures"))
    return load_module(
        ROOT / "tests/integration/fixtures/win_dns_zone.py", "dns_zone_fixture_test"
    )


def _record(path: Path) -> dict[str, Any]:
    return {
        "workspace": str(path),
        "zones": [],
        "prepared": None,
        "before": {"components": {"DNS": {"Installed": 0}}, "services": {}},
    }


def test_atomic_journal_failure_retains_original_and_removes_temporary(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "dns-zone-journal.json"
    fixture._write(str(path), {"original": True})
    monkeypatch.setattr(
        fixture.os, "replace", MagicMock(side_effect=OSError("replace denied"))
    )
    with pytest.raises(OSError, match="replace denied"):
        fixture._write(str(path), {"original": False})
    assert json.loads(path.read_text(encoding="utf-8")) == {"original": True}
    assert sorted(item.name for item in tmp_path.iterdir()) == [path.name]


def test_role_observation_failure_has_a_durable_prewrite_original_journal(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    original = {
        "components": None,
        "features": None,
        "services": {"TrustedInstaller": {"State": "Stopped"}},
    }
    monkeypatch.setattr(fixture, "_snapshot", lambda workspace, include: original)
    monkeypatch.setattr(
        fixture,
        "_components",
        MagicMock(side_effect=OSError("role enumeration failed")),
    )
    with pytest.raises(OSError, match="role enumeration failed"):
        fixture._setup(str(tmp_path))
    record = json.loads(
        (tmp_path / "dns-zone-journal.json").read_text(encoding="utf-8")
    )
    assert record["before"] == original and record["zones"] == []
    assert record["prepared"] is None and record["workspace"] == str(tmp_path)


def test_prepared_role_ownership_guard_does_not_accept_unrelated_role_mutation(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    record = _record(tmp_path)
    record["before"]["components"]["Telnet-Client"] = {"Installed": 0}
    path = tmp_path / "dns-zone-journal.json"
    fixture._write(str(path), record)
    monkeypatch.setattr(
        fixture,
        "_snapshot",
        lambda _: {
            "components": {"DNS": {"Installed": 1}, "Telnet-Client": {"Installed": 1}}
        },
    )
    with pytest.raises(AssertionError):
        fixture._prepared(str(tmp_path))
    assert fixture._read(str(path)) == record


def test_remove_role_reboot_requirement_keeps_journal_and_stops_deletion(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    record = _record(tmp_path)
    path = tmp_path / "dns-zone-journal.json"
    fixture._write(str(path), record)
    monkeypatch.setattr(fixture, "_components", lambda: {"DNS": {"Installed": 1}})
    manage = MagicMock(return_value={"success": True, "reboot_required": True})
    monkeypatch.setattr(fixture.feature_manage, "manage", manage)
    files = MagicMock()
    monkeypatch.setattr(fixture, "_files", files)
    result = fixture._cleanup(str(tmp_path))
    assert result["requires_reboot"] and not result["restored"]
    assert fixture._read(str(path))["removal_requires_reboot"]
    manage.assert_called_once()
    files.assert_not_called()


def test_cleanup_rejects_unowned_workspace_and_live_owned_zones(
    fixture: Any, tmp_path: Path
) -> None:
    path = tmp_path / "dns-zone-journal.json"
    record = _record(tmp_path)
    record["workspace"] += "-different"
    fixture._write(str(path), record)
    with pytest.raises(AssertionError):
        fixture._cleanup(str(tmp_path))
    record["workspace"] = str(tmp_path)
    record["zones"] = ["owned.invalid"]
    fixture._write(str(path), record)
    with pytest.raises(AssertionError, match="Owned zone cleanup"):
        fixture._cleanup(str(tmp_path))
    assert path.exists()


def test_empty_unjournaled_workspace_can_close_but_unknown_files_cannot(
    fixture: Any, tmp_path: Path
) -> None:
    assert fixture._cleanup(str(tmp_path)) == {"restored": True, "journal_absent": True}
    (tmp_path / "unknown.txt").write_text("protected", encoding="utf-8")
    with pytest.raises(AssertionError, match="Unjournaled workspace is not empty"):
        fixture._cleanup(str(tmp_path))


def test_metadata_qualification_is_narrow_and_keeps_duplicate_and_raw_order(
    fixture: Any,
) -> None:
    before = {
        "DNS": {
            "Installed": 0,
            "SubFeatures": ["b", "a", "a"],
            "OptionalCompanions": [{"Name": "b"}, {"Name": "a"}],
            "OtherOrder": ["b", "a"],
        }
    }
    compared = fixture.state_comparison._comparable_components(before)
    assert compared["DNS"]["SubFeatures"] == ["a", "a", "b"]
    assert before["DNS"]["SubFeatures"] == ["b", "a", "a"]
    assert compared["DNS"]["OtherOrder"] == ["b", "a"]
    assert compared["DNS"]["Installed"] == 0


def test_root_hints_are_read_from_enumerated_objects_without_reopening_paths(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = MagicMock()
    constructor = MagicMock()
    constructor.return_value.__enter__.return_value = connection
    monkeypatch.setattr(fixture.wmi, "WmiConnection", constructor)
    monkeypatch.setattr(fixture.wmi, "_query", lambda *_: ctypes.c_void_p(20))

    def _advance(
        _enum: Any, _wait: int, _count: int, instance: Any, returned: Any
    ) -> int:
        instance._obj.value = 10
        returned._obj.value = 1
        return 1

    monkeypatch.setattr(fixture.wmi, "_method", lambda *_: _advance)
    reader = MagicMock(
        return_value={
            "__CLASS": "MicrosoftDNS_AType",
            "RecordData": "127.0.0.1",
            "RootHint": "kept",
        }
    )
    monkeypatch.setattr(fixture.wmi, "_read_embedded_object", reader)
    reopen = MagicMock(side_effect=OSError("RootHints path not found"))
    monkeypatch.setattr(fixture.wmi, "_get_object", reopen)
    release = MagicMock()
    monkeypatch.setattr(fixture.wmi, "_release", release)
    result = fixture._native_dns()
    assert set(result) == {
        "MicrosoftDNS_Server",
        "MicrosoftDNS_Zone",
        "MicrosoftDNS_ResourceRecord",
    }
    assert all(rows[0]["RootHint"] == "kept" for rows in result.values())
    assert reader.call_count == 3 and release.call_count == 3
    reopen.assert_not_called()


def test_security_array_reads_actual_bounds_and_clears_native_variant(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    automation = MagicMock()
    automation.SafeArrayGetDim.return_value = 1
    automation.VariantClear.return_value = 0

    def _get(
        _object: Any, _name: str, _flags: int, value: Any, _kind: Any, _flavour: Any
    ) -> int:
        value._obj.kind = 0x2011
        value._obj.data.array = 20
        return 0

    def _bound(_array: Any, _dimension: int, output: Any, number: int) -> int:
        output._obj.value = number
        return 0

    def _element(_array: Any, index: Any, output: Any) -> int:
        ctypes.cast(output, ctypes.POINTER(ctypes.c_uint8))[0] = index._obj.value + 0x80
        return 0

    monkeypatch.setattr(fixture.wmi, "_method", lambda *_: _get)
    automation.SafeArrayGetLBound.side_effect = lambda array, dimension, output: _bound(
        array, dimension, output, 3
    )
    automation.SafeArrayGetUBound.side_effect = lambda array, dimension, output: _bound(
        array, dimension, output, 5
    )
    automation.SafeArrayGetElement.side_effect = _element
    assert fixture._security_bytes(ctypes.c_void_p(10), automation) == "838485"
    automation.VariantClear.assert_called_once()


@pytest.mark.parametrize("error_code", [0x80041013, 0x80070005])
def test_inactive_provider_load_or_access_failure_is_not_hidden_as_absence(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, error_code: int
) -> None:
    error = OSError("native provider failure")
    error.hresult = error_code  # type: ignore[attr-defined]
    connection = MagicMock()
    connection.__enter__.side_effect = error
    monkeypatch.setattr(fixture.wmi, "WmiConnection", lambda _: connection)
    monkeypatch.setattr(fixture, "_services", lambda: {})
    with pytest.raises(OSError, match="native provider failure"):
        fixture._native_dns()


def test_workspace_alias_uses_native_directory_identity_not_spelling(
    fixture: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    real = tmp_path / "actual-temp"
    real.mkdir()
    alias = tmp_path / "temp-alias"
    alias.symlink_to(real, target_is_directory=True)
    workspace = real / "legacy-windows-dns-zone-owned"
    workspace.mkdir()
    monkeypatch.setattr(
        fixture,
        "sys",
        SimpleNamespace(
            version_info=(3, 4, 4), argv=["fixture", str(workspace), "setup"]
        ),
    )
    monkeypatch.setattr(fixture.tempfile, "gettempdir", lambda: str(alias))
    setup = MagicMock(return_value={"journaled": True})
    monkeypatch.setattr(fixture, "_setup", setup)
    fixture._main()
    assert json.loads(capsys.readouterr().out) == {"journaled": True}
    setup.assert_called_once_with(str(workspace))


def test_outside_workspace_is_rejected_before_any_fixture_operation(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    expected = tmp_path / "expected-temp"
    expected.mkdir()
    outside = tmp_path / "other-temp"
    outside.mkdir()
    workspace = outside / "legacy-windows-dns-zone-owned"
    workspace.mkdir()
    monkeypatch.setattr(
        fixture,
        "sys",
        SimpleNamespace(
            version_info=(3, 4, 4), argv=["fixture", str(workspace), "setup"]
        ),
    )
    monkeypatch.setattr(fixture.tempfile, "gettempdir", lambda: str(expected))
    setup = MagicMock()
    monkeypatch.setattr(fixture, "_setup", setup)
    with pytest.raises(AssertionError):
        fixture._main()
    setup.assert_not_called()


def test_class_catalogue_order_is_not_configuration_but_definitions_are(
    fixture: Any,
) -> None:
    rows = [
        {"__CLASS": "b", "__SUPERCLASS": "a"},
        {"__CLASS": "a", "__SUPERCLASS": None},
    ]
    first: dict[str, Any] = {
        "classes": rows,
        "security": "exact",
        "children": [],
        "providers": [],
    }
    second: dict[str, Any] = dict(first, classes=list(reversed(rows)))
    assert fixture.state_comparison._class_catalogue(
        first
    ) == fixture.state_comparison._class_catalogue(second)
    assert first["classes"] == rows
    second["classes"][0] = dict(second["classes"][0], __SUPERCLASS="changed")
    assert fixture.state_comparison._class_catalogue(
        first
    ) != fixture.state_comparison._class_catalogue(second)


def test_zone_ownership_is_durable_before_the_first_zone_write(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    workspace = tmp_path / "legacy-windows-dns-zone-owned.123"
    workspace.mkdir()
    record = _record(workspace)
    record["prepared"] = {"dns": {}}
    path = workspace / "dns-zone-journal.json"
    fixture._write(str(path), record)
    connection = MagicMock()
    connection.query.return_value = []
    constructor = MagicMock()
    constructor.return_value.__enter__.return_value = connection
    monkeypatch.setattr(fixture.wmi, "WmiConnection", constructor)
    result = fixture._register_zone(str(workspace))
    name = (
        "dz" + hashlib.sha256(str(workspace).encode("utf-8")).hexdigest()[:8] + ".test"
    )
    assert result == {"name": name, "journaled": True}
    assert fixture._read(str(path))["zones"] == [result["name"]]
    assert connection.query.call_args.args == (
        "SELECT * FROM MicrosoftDNS_Zone",
        ["Name"],
    )


def _cache() -> dict[str, Any]:
    return {
        "MicrosoftDNS_Server": [{"protected": "literal"}],
        "MicrosoftDNS_Zone": [],
        "MicrosoftDNS_ResourceRecord": [
            {
                "__CLASS": "MicrosoftDNS_AType",
                "ContainerName": name,
                "OwnerName": "localhost." + name,
                "IPAddress": "127.0.0.1",
                "RecordData": "127.0.0.1",
                "TTL": 1000,
            }
            for name in ("..Cache", "..RootHints")
        ],
    }


def test_owned_cache_countdown_retains_raw_rows_and_rejects_other_changes(
    fixture: Any,
) -> None:
    before = _cache()
    after = _cache()
    for row in after["MicrosoftDNS_ResourceRecord"]:
        row["TTL"] -= 20
    changes = fixture.state_comparison._cache_countdown(before, after, True)
    assert len(changes) == 2
    assert changes[0] == {
        "before": before["MicrosoftDNS_ResourceRecord"][0],
        "after": after["MicrosoftDNS_ResourceRecord"][0],
    }
    assert before["MicrosoftDNS_ResourceRecord"][0]["TTL"] == 1000
    assert fixture.state_comparison._cache_countdown(before, before, False) == []
    with pytest.raises(AssertionError):
        fixture.state_comparison._cache_countdown(before, after, False)


@pytest.mark.parametrize("mutation", ["record", "count", "server", "delta", "increase"])
def test_owned_cache_qualification_cannot_hide_other_dns_changes(
    fixture: Any, mutation: str
) -> None:
    before, after = _cache(), _cache()
    for row in after["MicrosoftDNS_ResourceRecord"]:
        row["TTL"] -= 20
    if mutation == "record":
        after["MicrosoftDNS_ResourceRecord"][0]["IPAddress"] = "127.0.0.2"
    elif mutation == "count":
        after["MicrosoftDNS_ResourceRecord"].pop()
    elif mutation == "server":
        after["MicrosoftDNS_Server"][0]["protected"] = "changed"
    elif mutation == "delta":
        after["MicrosoftDNS_ResourceRecord"][0]["TTL"] -= 1
    else:
        for row in after["MicrosoftDNS_ResourceRecord"]:
            row["TTL"] = 1001
    with pytest.raises(AssertionError):
        fixture.state_comparison._cache_countdown(before, after, True)


def test_owned_role_initialization_is_exact_and_retains_full_server_rows(
    fixture: Any,
) -> None:
    before = [{"BootMethod": 0, "protected": "literal"}]
    after = [{"BootMethod": 3, "protected": "literal"}]
    assert fixture.state_comparison._role_initialization(before, after, True) == {
        "before": before[0],
        "after": after[0],
    }
    assert fixture.state_comparison._role_initialization(before, before, False) is None
    with pytest.raises(AssertionError):
        fixture.state_comparison._role_initialization(before, after, False)
    for changed in (
        [{"BootMethod": 2, "protected": "literal"}],
        [{"BootMethod": 3, "protected": "mutated"}],
        after * 2,
    ):
        with pytest.raises(AssertionError):
            fixture.state_comparison._role_initialization(before, changed, True)


def test_unrelated_service_deletion_cannot_be_hidden_as_servicing_reboot(
    fixture: Any,
) -> None:
    record = {
        "recovery_boot_before": "old",
        "before": {
            "identity": [{"LastBootUpTime": "old"}],
            "services": {"protected": {"NativeServiceType": 0x10}},
            "service_templates": {},
        },
    }
    after = {
        "identity": [{"LastBootUpTime": "new"}],
        "services": {},
        "service_templates": {},
    }
    with pytest.raises(AssertionError):
        fixture._qualify_servicing_boot(record, after, {}, {})


def test_register_zone_rejects_an_existing_journal_owned_zone_before_provider_calls(
    fixture: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    record = _record(tmp_path)
    record["zones"] = ["existing-owned.test"]
    record["prepared"] = {"protected": "literal"}
    journal = tmp_path / "dns-zone-journal.json"
    fixture._write(str(journal), record)
    constructor = MagicMock()
    monkeypatch.setattr(fixture.wmi, "WmiConnection", constructor)
    with pytest.raises(AssertionError):
        fixture._register_zone(str(tmp_path))
    constructor.assert_not_called()
    assert fixture._read(str(journal)) == record


@pytest.mark.parametrize("explicit", [False, True])
def test_seed_zone_preserves_the_requested_fixture_master_address(
    fixture: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    explicit: bool,
) -> None:
    record = dict(_record(tmp_path), zones=["owned.test"])
    fixture._write(str(tmp_path / "dns-zone-journal.json"), record)
    monkeypatch.setattr(fixture, "_reset_zone", MagicMock())
    arguments = ["fixture", str(tmp_path), "seed_zone", "secondary"]
    if explicit:
        arguments.append("192.0.2.53")
    monkeypatch.setattr(fixture.sys, "argv", arguments)
    manage = MagicMock(return_value={"changed": True})
    monkeypatch.setattr(fixture.dns_zone, "manage", manage)
    assert fixture._seed_zone(str(tmp_path)) == {"changed": True}
    assert manage.call_args.args[0]["dns_servers"] == [
        "192.0.2.53" if explicit else "127.0.0.1"
    ]


@pytest.mark.parametrize("changed", [False, True])
def test_finalization_rechecks_full_recovery_and_keeps_journal_on_failure(
    fixture: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    changed: bool,
) -> None:
    record = dict(_record(tmp_path), verified={"protected": "literal"})
    journal = tmp_path / "dns-zone-journal.json"
    fixture._write(str(journal), record)
    verify = MagicMock(return_value={"restored": True})
    if changed:
        verify.side_effect = AssertionError("protected configuration changed")
    monkeypatch.setattr(fixture, "_verify_recovery", verify)
    if changed:
        with pytest.raises(AssertionError, match="protected configuration changed"):
            fixture._finalize(str(tmp_path))
        assert fixture._read(str(journal)) == record
    else:
        assert fixture._finalize(str(tmp_path)) == {"finalized": True}
        assert not journal.exists()
    verify.assert_called_once_with(record, str(tmp_path))


@pytest.mark.parametrize(
    "native,released,equal",
    [
        ({"value": False}, {"value": 0}, False),
        ({"value": True}, {"value": 1}, False),
        ({"servers": ["a", "b"]}, {"servers": ["b", "a"]}, False),
        ({"paused": False, "name": "owned"}, {"name": "owned", "paused": False}, True),
    ],
)
def test_public_comparison_preserves_json_types_and_array_order(
    native: dict[str, Any], released: dict[str, Any], equal: bool
) -> None:
    document = yaml.safe_load(
        (ROOT / "tests/integration/tasks/win_dns_zone_case.yml").read_text(
            encoding="utf-8"
        )
    )
    expression = document[-1]["ansible.builtin.set_fact"]["dns_zone_comparisons"]
    environment = NativeEnvironment()
    environment.filters["to_json"] = json.dumps
    # NativeEnvironment returns structures despite the inherited str annotation.
    result: Any = environment.from_string(expression).render(
        dns_zone_comparisons=[],
        dns_zone_case={"id": "literal-json-comparison"},
        dns_zone_case_results={"native": native, "released": released},
    )
    assert result[0]["equal"] is equal
    assert result[0]["native"] == native and result[0]["released"] == released
