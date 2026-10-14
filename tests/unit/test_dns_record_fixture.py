"""Check owned DNS record setup, independent observations and workflow selection."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Fixture tests deliberately inspect its private ownership and observation boundaries.
# pylint: disable=protected-access

import json
import re
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
import yaml  # type: ignore[import-untyped]
from jinja2 import Environment
from jinja2.nativetypes import NativeEnvironment

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="fixture")
def record_fixture(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load fixture code without running native Windows entry points.

    :param monkeypatch: Scoped target helper import directory.
    :returns: Developer-runtime fixture, not Windows compatibility evidence.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    return load_module(
        ROOT / "tests/integration/fixtures/win_dns_record.py", "dns_record_fixture"
    )


def test_observer_keeps_all_selected_fields_types_and_order(fixture: Any) -> None:
    first = {"HostName": "record", "RecordType": "A", "RecordData": {"x": 1}}
    second = {"HostName": "RECORD", "RecordType": "A", "Unknown": [True, 0, None]}
    other = {"HostName": "protected", "RecordType": "A"}
    connection = MagicMock()
    connection.call_method.return_value = {
        "ReturnValue": None,
        "cmdletOutput": [first, other, second],
    }
    options = fixture._options("owned.test", {})
    assert fixture._observe(connection, options)["records"] == [first, second]
    connection.call_method.assert_called_once_with(
        "PS_DnsServerResourceRecord",
        "Get",
        ["ReturnValue", "cmdletOutput"],
        {"ZoneName": "owned.test"},
    )


def test_observer_does_not_mask_provider_errors(fixture: Any) -> None:
    connection = MagicMock()
    connection.call_method.side_effect = OSError("provider failure")
    with pytest.raises(OSError, match="provider failure"):
        fixture._observe(connection, fixture._options("owned.test", {}))


@pytest.mark.parametrize(
    "records,state,expected",
    [([{"TTL": 300}], "present", True), ([], "present", False), ([], "absent", True)],
)
def test_classic_presence_gate_returns_a_real_boolean(
    records: list[dict[str, Any]], state: str, expected: bool
) -> None:
    tasks = yaml.safe_load(
        (ROOT / "tests/integration/tasks/win_dns_record_legacy_case.yml").read_text()
    )
    condition = tasks[2]["ansible.builtin.assert"]["that"][0]
    environment: Any = NativeEnvironment()
    result = environment.from_string("{{ " + condition + " }}").render(
        dns_record_case_results={"native": {"after": {"records": records}}},
        dns_zone_case={"args": {"state": state}},
    )
    assert isinstance(result, bool) and result is expected


def _legacy_cases() -> list[dict[str, Any]]:
    integration = ROOT / "tests/integration"
    fixture = yaml.safe_load((integration / "vars/dns_record_fixture.yml").read_text())
    wrapper = yaml.safe_load((integration / "win_dns_record_legacy.yml").read_text())
    cases: list[dict[str, Any]] = (
        fixture["dns_record_cases"]
        + wrapper[1]["vars"]["dns_record_legacy_extra_cases"]
    )
    return cases


def _legacy_render_context(case: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
    environment: Any = NativeEnvironment()
    environment.filters["bool"] = bool
    environment.filters["regex_replace"] = lambda value, pattern, replacement: re.sub(
        pattern, replacement, value
    )
    args = case["args"]
    values = args.get("values", args.get("value", []))
    values = [values] if isinstance(values, str) else values
    if args["type"].upper() in ["CNAME", "NS", "PTR", "SRV"]:
        values = [value if value.endswith(".") else value + "." for value in values]
    wrapper = yaml.safe_load(
        (ROOT / "tests/integration/win_dns_record_legacy.yml").read_text()
    )
    unchanged = wrapper[1]["tasks"][0]["ansible.builtin.set_fact"][
        "dns_record_expected_unchanged"
    ]
    after = {
        "python": [3, 4, 4],
        "records": [] if args.get("state", "present").lower() == "absent" else [{}],
        "values": values,
        "ttls": [args.get("ttl", 3600)],
        "timestamps": [1 if args.get("aging", False) else 0],
    }
    context = {
        "dns_zone_case": case,
        "dns_record_expected_unchanged": unchanged,
        "dns_record_case_results": {
            "native": {
                "before": {"python": [3, 4, 4]},
                "after": after,
                "result": {
                    "failed": case.get("failed", False),
                    "changed": case["id"] not in unchanged
                    and not case.get("failed", False),
                },
            }
        },
        "dns_zone_comparisons": [],
    }
    return environment, context


@pytest.mark.parametrize("case", _legacy_cases(), ids=lambda case: case["id"])
def test_every_classic_postcondition_renders_as_boolean(case: dict[str, Any]) -> None:
    tasks = yaml.safe_load(
        (ROOT / "tests/integration/tasks/win_dns_record_legacy_case.yml").read_text()
    )
    environment, context = _legacy_render_context(case)
    for name, expression in tasks[2]["vars"].items():
        context[name] = environment.from_string(expression).render(**context)
    for task in tasks[1:3]:
        for condition in task.get("when", []):
            actual = environment.from_string("{{ " + condition + " }}").render(
                **context
            )
            assert isinstance(actual, bool)
        if task is tasks[2] and (case.get("check") or case.get("failed")):
            continue
        for condition in task["ansible.builtin.assert"]["that"]:
            actual = environment.from_string("{{ " + condition + " }}").render(
                **context
            )
            assert isinstance(actual, bool) and actual is True
    rows = environment.from_string(
        tasks[3]["ansible.builtin.set_fact"]["dns_zone_comparisons"]
    ).render(**context)
    assert isinstance(rows, list) and rows[0]["declared_behavior_verified"] is True


@pytest.mark.parametrize(
    "index,field,value",
    [
        (0, "records", []),
        (1, "values", ["wrong"]),
        (2, "ttls", [60]),
        (3, "timestamps", [1]),
    ],
)
def test_classic_postconditions_reject_incorrect_native_state(
    index: int, field: str, value: Any
) -> None:
    tasks = yaml.safe_load(
        (ROOT / "tests/integration/tasks/win_dns_record_legacy_case.yml").read_text()
    )
    environment, context = _legacy_render_context(
        {"id": "update-a-ttl", "args": {"type": "A", "value": "192.0.2.1", "ttl": 300}}
    )
    for name, expression in tasks[2]["vars"].items():
        context[name] = environment.from_string(expression).render(**context)
    context["dns_record_case_results"]["native"]["after"][field] = value
    condition = tasks[2]["ansible.builtin.assert"]["that"][index]
    actual = environment.from_string("{{ " + condition + " }}").render(**context)
    assert isinstance(actual, bool) and actual is False


@pytest.mark.parametrize("aging", [False, True])
def test_first_srv_create_rejects_default_ttl_instead_of_requested_ttl(
    aging: bool,
) -> None:
    tasks = yaml.safe_load(
        (ROOT / "tests/integration/tasks/win_dns_record_legacy_case.yml").read_text()
    )
    environment, context = _legacy_render_context(
        {
            "id": "create-srv",
            "args": {
                "type": "SRV",
                "value": "target.example.test",
                "ttl": 300,
                "aging": aging,
            },
        }
    )
    context["dns_record_case_results"]["native"]["after"]["ttls"] = [3600]
    condition = tasks[2]["ansible.builtin.assert"]["that"][2]
    assert environment.from_string("{{ " + condition + " }}").render(**context) is False


def test_seed_rejects_existing_selected_records_before_addition(
    fixture: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fixture, "_observe", lambda *_: {"records": ["existing"]})
    provider = MagicMock()
    monkeypatch.setattr(fixture.dns_record, "_Records", provider)
    with pytest.raises(AssertionError):
        fixture._seed(MagicMock(), fixture._options("owned.test", {}))
    provider.assert_not_called()


@pytest.mark.parametrize(
    "updates",
    [{"zone": "unowned.test"}, {"computer_name": "remote"}, {"zone_scope": "remote"}],
)
def test_options_cannot_redirect_fixture_writes(
    fixture: Any, updates: dict[str, Any]
) -> None:
    with pytest.raises(AssertionError):
        fixture._options("owned.test", updates)


def test_journal_must_own_exact_workspace_and_one_prepared_zone(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    workspace = tmp_path / "legacy-windows-dns-zone-unit"
    workspace.mkdir()
    monkeypatch.setattr(fixture.tempfile, "gettempdir", lambda: str(tmp_path))
    journal = workspace / "dns-zone-journal.json"
    original = {"workspace": str(workspace), "prepared": {}, "zones": ["owned.test"]}
    journal.write_text(json.dumps(original), encoding="utf-8")
    assert fixture._owned_zone(str(workspace)) == "owned.test"
    updates: list[dict[str, Any]] = [
        {"workspace": str(workspace) + "-other"},
        {"prepared": None},
        {"zones": []},
        {"zones": ["owned.test", "other.test"]},
    ]
    for update in updates:
        journal.write_text(json.dumps({**original, **update}), encoding="utf-8")
        with pytest.raises(AssertionError):
            fixture._owned_zone(str(workspace))


def test_record_workflow_override_preserves_the_default_zone_tasks() -> None:
    integration = ROOT / "tests/integration"
    current = yaml.safe_load((integration / "win_dns_zone.yml").read_text())
    included = current[0]["tasks"][2]["block"][-1]
    expression = included["ansible.builtin.include_tasks"]
    environment = Environment()
    assert environment.from_string(expression).render() == "tasks/win_dns_zone_case.yml"
    assert (
        environment.from_string(expression).render(
            dns_zone_case_tasks="tasks/win_dns_record_case.yml"
        )
        == "tasks/win_dns_record_case.yml"
    )


def test_missing_provider_override_preserves_the_default_zone_workflow() -> None:
    integration = ROOT / "tests/integration"
    wrapper = yaml.safe_load(
        (integration / "win_dns_record_unavailable.yml").read_text()
    )[0]
    current = yaml.safe_load(
        (integration / "win_dns_zone_unavailable.yml").read_text()
    )[0]
    expression = current["tasks"][3]["block"][0]["ansible.builtin.include_tasks"]
    environment = Environment()
    assert (
        environment.from_string(expression).render()
        == "tasks/win_dns_zone_unavailable_case.yml"
    )
    assert (
        environment.from_string(expression).render(**wrapper["vars"])
        == "tasks/win_dns_record_unavailable_case.yml"
    )
    prefix = current["tasks"][1]["ansible.builtin.tempfile"]["prefix"]
    assert (
        environment.from_string(prefix).render(inventory_hostname="owned")
        == "dns-zone-boundary-owned-"
    )
    assert (
        environment.from_string(prefix).render(
            inventory_hostname="owned", **wrapper["vars"]
        )
        == "dns-record-boundary-owned-"
    )


def test_embedded_fixture_preserves_sources_and_compiles() -> None:
    integration = ROOT / "tests/integration"
    data = yaml.safe_load((integration / "vars/dns_record_fixture.yml").read_text())
    environment = Environment()
    environment.filters["to_json"] = json.dumps

    def _lookup(_plugin: str, path: str, *, rstrip: bool) -> str:
        assert rstrip is False
        return Path(path).read_text(encoding="utf-8")

    source = environment.from_string(data["dns_record_fixture_program"]).render(
        lookup=_lookup, playbook_dir=str(integration)
    )
    compile(source, "dns-record-embedded-fixture", "exec")


def test_windows_fixture_hooks_use_the_target_runtime_profile() -> None:
    configuration = yaml.safe_load((ROOT / ".pre-commit-config.yaml").read_text())
    hooks = {
        hook.get("alias", hook["id"]): hook
        for repository in configuration["repos"]
        for hook in repository["hooks"]
    }
    for path in (ROOT / "tests/integration/fixtures").glob("*.py"):
        name = str(path.relative_to(ROOT))
        for alias in ("black-target", "pylint-target", "vermin"):
            assert re.search(hooks[alias]["files"], name)
        for alias in ("black-development", "pylint-development", "mypy-development"):
            assert re.search(hooks[alias]["exclude"], name)
    assert hooks["black-target"]["args"] == ["--target-version", "py34"]
    assert hooks["pylint-target"]["args"] == ["--py-version", "3.4"]
    assert hooks["vermin"]["args"] == ["-t=3.4-", "--violations"]


@pytest.mark.parametrize("aliases", [{}, {"values": ["192.0.2.1"]}])
def test_public_fixture_alias_selects_data_not_dictionary_method(
    aliases: dict[str, Any],
) -> None:
    tasks = yaml.safe_load(
        (ROOT / "tests/integration/tasks/win_dns_record_run.yml").read_text()
    )
    environment = NativeEnvironment()
    for task in tasks:
        for name in (
            "sustainablelobster.legacy_windows.win_dns_record",
            "ansible.windows.win_dns_record",
        ):
            if name in task:
                expression = task[name]["values"]
                observed = environment.from_string(expression).render(
                    dns_zone_case={"args": aliases}, omit="omitted"
                )
                assert observed == aliases.get("values", "omitted")


@pytest.mark.parametrize(
    "expected,actual", [(True, True), (False, False), (True, False), (False, True)]
)
def test_outcome_gate_retains_complete_pairs_and_rejects_wrong_expectations(
    expected: bool,
    actual: bool,
) -> None:
    integration = ROOT / "tests/integration"
    case = yaml.safe_load((integration / "tasks/win_dns_record_case.yml").read_text())
    expression = case[-1]["ansible.builtin.set_fact"]["dns_zone_comparisons"]
    environment: Any = NativeEnvironment()
    environment.filters["bool"] = bool
    environment.filters["to_json"] = json.dumps
    public = {"result": {"changed": False, "failed": actual}, "before": [], "after": []}
    rows: Any = environment.from_string(expression).render(
        dns_zone_comparisons=[],
        dns_zone_case={"failed": expected},
        dns_record_case_results={"native": public, "released": public},
    )
    assert isinstance(rows, list)
    assert rows[0]["equal"] is True
    assert rows[0]["expected"] is (expected == actual)
    # The final gate is after the play's always cleanup; the earlier gate still
    # stops immediately if a preview/validation request mutates its owned state.
    flow = yaml.safe_load((integration / "win_dns_zone.yml").read_text())[0]
    condition = next(
        item
        for task in flow["tasks"]
        for item in task.get("ansible.builtin.assert", {}).get("that", [])
        if "selectattr('expected'" in item
    )
    assert environment.from_string("{{ " + condition + " }}").render(
        dns_zone_comparisons=rows
    ) is (expected == actual)
    assert (
        environment.from_string("{{ " + condition + " }}").render(
            dns_zone_comparisons=[{"equal": True}]
        )
        is True
    )
    run = yaml.safe_load((integration / "tasks/win_dns_record_run.yml").read_text())
    assert len(run[-1]["ansible.builtin.assert"]["that"]) == 1
    assert (
        "dns_record_before.stdout == dns_record_after.stdout"
        in run[-1]["ansible.builtin.assert"]["that"][0]
    )
