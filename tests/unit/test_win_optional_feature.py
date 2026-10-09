"""Exercise public optional-feature ordering, no-write paths and partial failures."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes establish behavior, not Windows execution support.

from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload


@pytest.fixture(name="runner")
def optional_feature_runner(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> Any:
    """Run public JSON requests with observable feature reads and batch changes.

    :param monkeypatch: Scoped payload and native substitutes.
    :param capsys: Scoped public JSON output capture.
    :returns: Runner, native calls and mutable feature state.
    """
    module = load_payload("win_optional_feature", monkeypatch)
    state = {"alpha": "Disabled", "beta": "Enabled"}
    events: list[tuple[Any, ...]] = []

    def _read(name: str) -> str | None:
        events.append(("read", name))
        return state.get(name.lower())

    def _enable(names: list[str], parents: bool, source: str | None) -> bool:
        events.append(("enable", names, parents, source))
        for name in names:
            state[name.lower()] = "Enabled"
        return False

    def _disable(names: list[str]) -> bool:
        events.append(("disable", names))
        for name in names:
            state[name.lower()] = "Disabled"
        return False

    native = SimpleNamespace(
        state=Mock(side_effect=_read),
        validate_enable=Mock(),
        enable=Mock(side_effect=_enable),
        disable=Mock(side_effect=_disable),
    )
    constructor = Mock(side_effect=lambda: nullcontext(native))
    monkeypatch.setattr(module.features, "OptionalFeatures", constructor)

    def _run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        monkeypatch.setattr(module, "read_arguments", lambda *_args: arguments)
        return invoke_payload(module, capsys)

    return SimpleNamespace(
        run=_run, state=state, events=events, native=native, constructor=constructor
    )


def test_default_present_prechecks_all_names_then_changes_one_batch(
    runner: Any,
) -> None:
    assert runner.run({"name": ["alpha", "beta"]}) == (
        0,
        {"changed": True, "reboot_required": False},
    )
    assert runner.events == [
        ("read", "alpha"),
        ("read", "beta"),
        ("enable", ["alpha"], False, None),
    ]
    assert runner.run({"name": ["alpha", "beta"]}) == (
        0,
        {"changed": False, "reboot_required": False},
    )


@pytest.mark.parametrize("check", [False, True])
def test_absent_meaningful_parent_capability_fails_before_write_or_preview(
    runner: Any,
    check: bool,
) -> None:
    runner.native.validate_enable.side_effect = ValueError("Native /All is unavailable")
    code, result = runner.run(
        {"name": "alpha", "include_parent": True, "_ansible_check_mode": check}
    )
    assert code == 1 and result["failed"] and result["changed"] is False
    assert runner.events == [("read", "alpha")]
    runner.native.enable.assert_not_called()


def test_requested_order_case_comma_and_duplicates_reach_native_batch(
    runner: Any,
) -> None:
    runner.state["beta"] = "Disabled"
    result = runner.run({"name": " BETA,Alpha,BETA ", "state": "PRESENT"})[1]
    assert result == {"changed": True, "reboot_required": False}
    assert runner.events == [
        ("read", "BETA"),
        ("read", "Alpha"),
        ("read", "BETA"),
        ("enable", ["BETA", "Alpha", "BETA"], False, None),
    ]


@pytest.mark.parametrize("names", [[], None])
def test_empty_and_null_names_still_require_native_availability(
    runner: Any, names: Any
) -> None:
    assert runner.run({"name": names}) == (
        0,
        {"changed": False, "reboot_required": False},
    )
    runner.constructor.assert_called_once_with()
    assert runner.events == []


def test_explicit_null_state_reads_names_without_changing_them(runner: Any) -> None:
    assert runner.run({"name": ["alpha", "beta"], "state": None}) == (
        0,
        {"changed": False, "reboot_required": False},
    )
    assert runner.events == [("read", "alpha"), ("read", "beta")]


@pytest.mark.parametrize("parents", [None, False, "no", True, "yes"])
def test_nullable_include_parent_and_boolean_conversion(
    runner: Any, parents: Any
) -> None:
    assert runner.run({"name": "alpha", "include_parent": parents})[0] == 0
    expected = parents in (True, "yes")
    runner.native.enable.assert_called_once_with(["alpha"], expected, None)


def test_absent_ignores_source_and_parent_setting_and_repeats(runner: Any) -> None:
    arguments = {
        "name": ["alpha", "beta"],
        "state": "ABSENT",
        "include_parent": True,
        "source": "missing-literal-source",
    }
    assert runner.run(arguments)[1] == {"changed": True, "reboot_required": False}
    assert runner.events == [
        ("read", "alpha"),
        ("read", "beta"),
        ("disable", ["beta"]),
    ]
    assert not runner.run(arguments)[1]["changed"]


@pytest.mark.parametrize("state,name", [("present", "alpha"), ("absent", "beta")])
def test_check_mode_predicts_change_without_writes(
    runner: Any, state: str, name: str
) -> None:
    before = dict(runner.state)
    assert runner.run({"name": name, "state": state, "_ansible_check_mode": True}) == (
        0,
        {"changed": True, "reboot_required": False},
    )
    assert runner.state == before
    runner.native.enable.assert_not_called()
    runner.native.disable.assert_not_called()


@pytest.mark.parametrize("check", [False, True])
def test_needed_enable_validates_source_after_all_reads(
    runner: Any, tmp_path: Path, check: bool
) -> None:
    source = str(tmp_path / "missing")
    code, result = runner.run(
        {"name": ["alpha", "beta"], "source": source, "_ansible_check_mode": check}
    )
    assert code == 1 and result == {
        "changed": False,
        "reboot_required": False,
        "failed": True,
        "msg": "Path could not be found '" + source + "'",
    }
    assert runner.events == [("read", "alpha"), ("read", "beta")]


@pytest.mark.parametrize("directory", [False, True])
def test_source_literal_file_or_directory_is_accepted(
    runner: Any, tmp_path: Path, directory: bool
) -> None:
    source = tmp_path / "literal source"
    if directory:
        source.mkdir()
    else:
        source.write_text("fixture", encoding="utf-8")
    assert runner.run({"name": "alpha", "source": str(source)})[0] == 0
    runner.native.enable.assert_called_once_with(["alpha"], False, str(source))


def test_no_needed_enable_does_not_validate_missing_source(runner: Any) -> None:
    assert runner.run({"name": "beta", "source": "missing-literal-source"}) == (
        0,
        {"changed": False, "reboot_required": False},
    )


def test_missing_later_name_fails_before_any_write_or_source_check(runner: Any) -> None:
    code, result = runner.run({"name": ["alpha", "missing"], "source": "missing"})
    assert code == 1 and result == {
        "changed": False,
        "reboot_required": False,
        "failed": True,
        "msg": "Failed to find feature 'missing'",
    }
    assert runner.events == [("read", "alpha"), ("read", "missing")]
    runner.native.enable.assert_not_called()
    runner.native.disable.assert_not_called()


@pytest.mark.parametrize("state", ["present", "absent"])
def test_reboot_flag_comes_only_from_successful_servicing(
    runner: Any, state: str
) -> None:
    action = runner.native.enable if state == "present" else runner.native.disable
    action.side_effect = None
    action.return_value = True
    name = "alpha" if state == "present" else "beta"
    assert runner.run({"name": name, "state": state}) == (
        0,
        {"changed": True, "reboot_required": True},
    )


def test_servicing_failure_preserves_upstream_unchanged_flag_despite_partial_write(
    runner: Any,
) -> None:
    runner.state["beta"] = "Disabled"

    def _partial(_names: list[str], _parents: bool, _source: str | None) -> bool:
        runner.state["alpha"] = "Enabled"
        raise OSError("native batch failed after first feature")

    runner.native.enable.side_effect = _partial
    code, result = runner.run({"name": ["alpha", "beta"]})
    assert code == 1 and result == {
        "changed": False,
        "reboot_required": False,
        "failed": True,
        "msg": "native batch failed after first feature",
    }
    assert runner.state == {"alpha": "Enabled", "beta": "Disabled"}
    runner.native.disable.assert_not_called()


@pytest.mark.parametrize(
    "desired,current,changed",
    [
        ("present", "Enabled", False),
        ("present", "EnabledPending", False),
        ("present", "Enable Pending", True),
        ("absent", "Disabled", False),
        ("absent", "Disabled with Payload Removed", False),
        ("absent", "Disable Pending", True),
    ],
)
def test_native_state_prefixes_preserve_pinned_matching_not_its_comments(
    runner: Any, desired: str, current: str, changed: bool
) -> None:
    runner.state["alpha"] = current
    result = runner.run(
        {"name": "alpha", "state": desired, "_ansible_check_mode": True}
    )[1]
    assert result == {"changed": changed, "reboot_required": False}


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({}, "missing required arguments: name"),
        ({"name": "alpha", "state": "invalid"}, "value of state must be one of:"),
        ({"name": "alpha", "include_parent": "invalid"}, "Expected a boolean"),
    ],
)
def test_argument_failures_precede_native_access(
    runner: Any, arguments: dict[str, Any], message: str
) -> None:
    code, result = runner.run(arguments)
    assert code == 1 and result["failed"] and not result["changed"]
    assert message in result["msg"] and "reboot_required" not in result
    runner.constructor.assert_not_called()


def test_unavailable_native_feature_contract_fails_even_with_empty_names(
    runner: Any,
) -> None:
    runner.constructor.side_effect = OSError("native optional features unavailable")
    code, result = runner.run({"name": []})
    assert code == 1 and result == {
        "changed": False,
        "reboot_required": False,
        "failed": True,
        "msg": "native optional features unavailable",
    }
