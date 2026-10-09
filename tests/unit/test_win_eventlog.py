"""Exercise public classic-log results, ordered failures, and check mode."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Tests replace native boundaries to exercise the complete JSON payload contract.
# pylint: disable=protected-access

import copy
from collections import OrderedDict
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload


@pytest.fixture(name="runner")
def eventlog_runner(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> Any:
    """Run the JSON payload against deterministic native log operations.

    :param monkeypatch: Scoped native substitutes.
    :param capsys: Scoped JSON output capture.
    :returns: Runner and its observable native state.
    """
    module = load_payload("win_eventlog", monkeypatch)
    state: dict[str, Any] = {}
    monkeypatch.setattr(
        module.environment,
        "values_equal",
        lambda left, right: str(left).lower() == str(right).lower(),
    )

    def _details(name: str) -> dict[str, Any]:
        return copy.deepcopy(state.get(name, {"name": name, "exists": False}))

    def _create(name: str, source: str, resources: dict[str, Any]) -> None:
        log = state.setdefault(
            name,
            {
                "name": name,
                "exists": True,
                "entries": 0,
                "maximum_size_kb": 512,
                "overflow_action": "OverwriteOlder",
                "retention_days": 7,
                "sources": OrderedDict([(name, {})]),
            },
        )
        log["sources"][source] = {
            key: resources.get(key) for key, _ in module.eventlog.RESOURCE_VALUES
        }

    def _source(source: str) -> str | None:
        return next(
            (name for name, log in state.items() if source in log["sources"]), None
        )

    def _remove_source(name: str, source: str) -> None:
        del state[name]["sources"][source]

    def _limit(
        name: str, maximum: int | None, overflow: str | None, days: int | None
    ) -> None:
        if maximum is not None:
            state[name]["maximum_size_kb"] = maximum // 1024
        if overflow is not None:
            state[name]["overflow_action"] = overflow
            state[name]["retention_days"] = {
                "DoNotOverwrite": -1,
                "OverwriteAsNeeded": 0,
            }.get(overflow, days or 7)
        elif days:
            state[name]["retention_days"] = days

    native = SimpleNamespace(
        create_source=Mock(side_effect=_create),
        source_log=Mock(side_effect=_source),
        log_details=Mock(side_effect=_details),
        remove_source=Mock(side_effect=_remove_source),
        remove_log=Mock(side_effect=state.pop),
        clear_log=Mock(side_effect=lambda name: state[name].update(entries=0)),
        limit_log=Mock(side_effect=_limit),
        validate_limit=Mock(),
        RESOURCE_VALUES=module.eventlog.RESOURCE_VALUES,
    )
    monkeypatch.setattr(module, "eventlog", native)

    def _run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        monkeypatch.setattr(
            module, "read_arguments", lambda *_args, **_kwargs: arguments
        )
        return invoke_payload(module, capsys)

    return SimpleNamespace(run=_run, state=state, native=native, module=module)


def test_create_check_real_repeat_and_absent_results(runner: Any) -> None:
    arguments = {"name": "Owned", "sources": ["First", "Second"]}
    assert runner.run(dict(arguments, _ansible_check_mode=True)) == (
        0,
        {"changed": True, "name": "Owned", "exists": False, "sources_changed": []},
    )
    assert runner.state == {}
    code, result = runner.run(arguments)
    assert code == 0 and result["sources"] == ["Owned", "First", "Second"]
    assert result["sources_changed"] == ["First", "Second"]
    assert runner.run(arguments)[1]["changed"] is False
    before = copy.deepcopy(runner.state)
    check = runner.run(
        {"name": "Owned", "state": "absent", "_ansible_check_mode": True}
    )[1]
    assert check["exists"] is True and check["sources_changed"] == []
    assert runner.state == before
    assert runner.run({"name": "Owned", "state": "absent"}) == (
        0,
        {
            "changed": True,
            "name": "Owned",
            "exists": False,
            "sources_changed": ["Owned", "First", "Second"],
        },
    )
    assert runner.run({"name": "Owned", "state": "absent"})[1]["changed"] is False


def test_resources_recreate_and_reset_omitted_values(runner: Any) -> None:
    runner.run({"name": "Owned", "sources": ["First"]})
    arguments = {
        "name": "Owned",
        "sources": ["First"],
        "category_file": "C:\\Category.dll",
        "message_file": "C:\\Message.dll",
        "parameter_file": "C:\\Parameter.dll",
    }
    assert runner.run(dict(arguments, _ansible_check_mode=True))[1]["changed"] is True
    assert runner.native.remove_source.call_count == 0
    assert runner.run(arguments)[1]["sources_changed"] == ["First"]
    assert runner.run(arguments)[1]["changed"] is False
    assert runner.run(
        {"name": "Owned", "sources": ["First"], "message_file": "C:\\Second.dll"}
    )[1]["changed"]
    assert runner.state["Owned"]["sources"]["First"] == {
        "category_file": None,
        "message_file": "C:\\Second.dll",
        "parameter_file": None,
    }


def test_size_validation_happens_after_source_creation(runner: Any) -> None:
    code, result = runner.run(
        {"name": "Owned", "sources": ["First"], "maximum_size": "129KB"}
    )
    assert code == 1 and result == {
        "changed": True,
        "failed": True,
        "name": "Owned",
        "sources_changed": ["First"],
        "msg": "Maximum size must be divisible by 64KB",
    }
    assert "First" in runner.state["Owned"]["sources"]
    runner.native.limit_log.assert_not_called()


@pytest.mark.parametrize(
    "value,message",
    [
        ("256 MB", "Maximum size 256 MB is not properly specified"),
        ("4GB", "Maximum size must be between 64KB and 4GB"),
        ("63KB", "Maximum size must be between 64KB and 4GB"),
        ("129KB", "Maximum size must be divisible by 64KB"),
    ],
)
def test_invalid_size_retains_existing_state(
    runner: Any, value: str, message: str
) -> None:
    runner.run({"name": "Owned", "sources": ["First"]})
    before = copy.deepcopy(runner.state)
    code, result = runner.run({"name": "Owned", "maximum_size": value})
    assert code == 1 and result["changed"] is False and result["msg"] == message
    assert runner.state == before


def test_clear_check_actual_repeat_and_source_remove(runner: Any) -> None:
    runner.run({"name": "Owned", "sources": ["First"]})
    runner.state["Owned"]["entries"] = 1
    checked = runner.run(
        {"name": "Owned", "state": "clear", "_ansible_check_mode": True}
    )[1]
    assert checked["changed"] is True and checked["entries"] == 1
    assert runner.run({"name": "Owned", "state": "clear"})[1]["entries"] == 0
    assert runner.run({"name": "Owned", "state": "clear"})[1]["changed"] is False
    args = {"name": "Owned", "state": "absent", "sources": ["First"]}
    assert runner.run(dict(args, _ansible_check_mode=True))[1]["sources_changed"] == []
    assert runner.run(args)[1]["sources_changed"] == ["First"]
    assert runner.run(args)[1]["changed"] is False


def test_default_source_and_cross_log_failures(runner: Any) -> None:
    runner.run({"name": "Owned", "sources": ["First"]})
    for arguments, message in [
        (
            {"name": "Owned", "sources": ["owned"], "message_file": "C:\\Other.dll"},
            "Cannot modify default source",
        ),
        (
            {"name": "Owned", "sources": ["OWNED"], "state": "absent"},
            "Cannot remove default source",
        ),
        ({"name": "Missing", "sources": ["First"]}, "Source First already exists"),
    ]:
        code, result = runner.run(arguments)
        assert code == 1 and result["changed"] is False and message in result["msg"]
    runner.run({"name": "Other", "sources": ["OtherSource"]})
    code, result = runner.run({"name": "Other", "sources": ["First"]})
    assert (
        code == 1
        and result["msg"]
        == "Source First does not belong to log Other and cannot be modified"
    )


def test_limit_failure_retains_source_change_and_skips_final_read(runner: Any) -> None:
    runner.native.validate_limit.side_effect = ValueError("Observed limit failure")
    code, result = runner.run(
        {"name": "Owned", "sources": ["First"], "maximum_size": "2MB"}
    )
    assert (
        code == 1
        and result["sources_changed"] == ["First"]
        and result["changed"] is True
    )
    assert "exists" not in result
    assert runner.native.log_details.call_count == 1


def test_limit_check_retains_actual_result_and_zero_retention_noop(runner: Any) -> None:
    runner.run({"name": "Owned", "sources": ["First"]})
    code, result = runner.run(
        {
            "name": "Owned",
            "maximum_size": "2mb",
            "retention_days": 15,
            "_ansible_check_mode": True,
        }
    )
    assert code == 0 and result["changed"] is True and result["maximum_size_kb"] == 512
    runner.native.limit_log.assert_not_called()
    assert runner.run({"name": "Owned", "retention_days": 0})[1]["changed"] is False


def test_json_missing_name_and_missing_log_failures(runner: Any) -> None:
    code, result = runner.run({})
    assert code == 1 and result == {
        "changed": False,
        "failed": True,
        "msg": "Get-AnsibleParam: Missing required argument: name",
    }
    for args, message in [
        ({"name": "Missing"}, "You must specify one or more sources"),
        ({"name": "Missing", "state": "clear"}, "Cannot clear log Missing"),
    ]:
        code, result = runner.run(args)
        assert code == 1 and result["changed"] is False and message in result["msg"]


@pytest.mark.parametrize("check", [False, True])
def test_nested_builtin_source_is_absent_and_never_cleared_or_removed(
    runner: Any, check: bool
) -> None:
    runner.run({"name": "Application", "sources": ["Existing"]})
    runner.state["Application"]["entries"] = 17
    before = copy.deepcopy(runner.state)
    args = {"name": r"Application\Application", "_ansible_check_mode": check}
    assert runner.run(dict(args, state="absent")) == (
        0,
        {
            "name": r"Application\Application",
            "changed": False,
            "sources_changed": [],
            "exists": False,
        },
    )
    code, result = runner.run(dict(args, state="clear"))
    assert code == 1 and result["changed"] is False
    assert (
        result["msg"]
        == r"Cannot clear log Application\Application as it does not exist"
    )
    assert runner.state == before
    runner.native.clear_log.assert_not_called()
    runner.native.remove_log.assert_not_called()
