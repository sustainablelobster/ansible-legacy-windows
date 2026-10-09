"""Exercise capability binding, preflight, check mode and partial public results."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload


@pytest.fixture(name="runner")
def capability_runner(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> Any:
    """Run complete public requests with observable servicing substitutes.

    :param monkeypatch: Scoped payload and native replacements.
    :param capsys: JSON output capture.
    :returns: Public runner and recorded native calls.
    """
    module = load_payload("win_capability", monkeypatch)
    select = Mock(return_value=["Viewer~~~~1"])
    batch = Mock(return_value={"reboot_required": False})
    native = Mock()
    native.remove.return_value = False
    session = Mock()
    session.return_value.__enter__ = Mock(return_value=native)
    session.return_value.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(module.capability, "select", select)
    monkeypatch.setattr(module.capability, "add_batch", batch)
    monkeypatch.setattr(module.capability, "CapabilitySession", session)
    levels = Mock(return_value=("Errors", "Warnings", "WarningsInfo"))
    monkeypatch.setattr(module.capability, "logging_levels", levels)

    def _run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        monkeypatch.setattr(module, "read_arguments", lambda *_args: arguments)
        return invoke_payload(module, capsys)

    return SimpleNamespace(
        run=_run,
        module=module,
        select=select,
        batch=batch,
        session=session,
        native=native,
        levels=levels,
    )


@pytest.mark.parametrize("names", [None, []])
def test_null_or_empty_names_skip_provider_and_logging_enum(
    runner: Any, names: Any
) -> None:
    assert runner.run({"name": names, "log_level": 3}) == (
        0,
        {"changed": False, "capabilities": [], "reboot_required": False},
    )
    runner.select.assert_not_called()
    runner.batch.assert_not_called()
    runner.levels.assert_not_called()


@pytest.mark.parametrize("check", [False, True])
def test_modern_debug_level_reaches_query_and_batch_without_renumbering(
    runner: Any, check: bool
) -> None:
    runner.levels.return_value += ("Debug",)
    status, result = runner.run(
        {"name": "Viewer", "log_level": 3, "_ansible_check_mode": check}
    )
    assert status == 0 and result["changed"]
    runner.select.assert_called_once_with(["Viewer"], "present", 3, None)
    assert runner.batch.call_args.args[1]["log_level"] == 3
    assert runner.batch.call_args.args[2] is check


@pytest.mark.parametrize("level", [-1, 4])
def test_invalid_modern_enum_fails_before_any_metadata_or_servicing(
    runner: Any, level: int
) -> None:
    runner.levels.return_value += ("Debug",)
    status, result = runner.run(
        {"name": "Viewer", "log_level": level, "_ansible_check_mode": True}
    )
    assert status == 1 and result["failed"] and not result["changed"]
    assert '"Errors,Warnings,WarningsInfo,Debug".' in result["msg"]
    assert "capabilities" not in result and "reboot_required" not in result
    runner.select.assert_not_called()
    runner.batch.assert_not_called()


def test_old_provider_debug_rejection_retains_its_original_enum_names(
    runner: Any,
) -> None:
    status, result = runner.run({"name": "Viewer", "log_level": 3})
    assert status == 1 and result["failed"] and not result["changed"]
    assert '"Errors,Warnings,WarningsInfo".' in result["msg"]
    runner.select.assert_not_called()
    runner.batch.assert_not_called()


@pytest.mark.parametrize("check", [False, True])
def test_needed_additions_require_batch_even_in_check_mode(
    runner: Any, check: bool
) -> None:
    assert runner.run({"name": "Viewer", "_ansible_check_mode": check}) == (
        0,
        {"changed": True, "capabilities": ["Viewer~~~~1"], "reboot_required": False},
    )
    runner.batch.assert_called_once()
    assert runner.batch.call_args.args[0] == ["Viewer~~~~1"]
    assert runner.batch.call_args.args[2] is check
    runner.session.assert_not_called()


def test_complete_binding_retains_name_order_sources_logging_and_null_update(
    runner: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CAPABILITY_LOG_ROOT", "owned")
    assert (
        runner.run(
            {
                "name": "B,A,B",
                "source": ["first", "second"],
                "log_level": " +1 ",
                "log_path": "%CAPABILITY_LOG_ROOT%/request.log",
                "disable_windows_update": None,
                "state": "PRESENT",
            }
        )[0]
        == 0
    )
    runner.select.assert_called_once_with(
        ["B", "A", "B"], "present", 1, "owned/request.log"
    )
    assert runner.batch.call_args.args[1] == {
        "names": ["B", "A", "B"],
        "state": "present",
        "sources": ["first", "second"],
        "log_level": 1,
        "log_path": "owned/request.log",
        "disable_update": False,
    }


def test_already_desired_state_does_not_start_batch(runner: Any) -> None:
    runner.select.return_value = []
    assert runner.run({"name": "installed"})[1] == {
        "changed": False,
        "capabilities": [],
        "reboot_required": False,
    }
    runner.batch.assert_not_called()


def test_one_empty_source_is_omitted_from_installation(runner: Any) -> None:
    assert runner.run({"name": "Viewer", "source": [""]})[0] == 0
    assert runner.batch.call_args.args[1]["sources"] is None


def test_batch_startup_failure_discards_initialized_servicing_fields(
    runner: Any,
) -> None:
    runner.batch.side_effect = OSError("batch denied")
    assert runner.run({"name": "Viewer"}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "Unhandled exception while executing module: batch denied",
        },
    )


def test_missing_later_pattern_prevents_all_servicing(runner: Any) -> None:
    runner.select.side_effect = LookupError("Failed to find capability 'missing'")
    assert runner.run({"name": ["Viewer", "missing"]}) == (
        1,
        {
            "changed": False,
            "capabilities": [],
            "reboot_required": False,
            "failed": True,
            "msg": "Failed to find capability 'missing'",
        },
    )
    runner.batch.assert_not_called()
    runner.session.assert_not_called()


def test_provider_parser_failure_discards_initialized_result_like_original(
    runner: Any,
) -> None:
    runner.select.side_effect = ValueError('parsing "^[bad$" - Unterminated [] set.')
    assert runner.run({"name": "[bad"}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": (
                'Unhandled exception while executing module: parsing "^[bad$" '
                "- Unterminated [] set."
            ),
        },
    )


def test_remove_check_mode_predicts_without_batch_or_mutation(runner: Any) -> None:
    assert runner.run(
        {"name": "Viewer", "state": "absent", "_ansible_check_mode": True}
    )[1]["changed"]
    runner.batch.assert_not_called()
    runner.session.assert_not_called()


def test_remove_ignores_add_and_query_options_and_retains_duplicates(
    runner: Any,
) -> None:
    runner.select.return_value = ["B", "A", "B"]
    assert runner.run(
        {
            "name": "*",
            "state": "absent",
            "source": "unused",
            "disable_windows_update": True,
            "log_level": 1,
        }
    )[1]["capabilities"] == ["B", "A", "B"]
    runner.session.assert_called_once_with()
    assert [call.args for call in runner.native.remove.call_args_list] == [
        ("B",),
        ("A",),
        ("B",),
    ]


def test_partial_remove_keeps_reboot_but_not_successful_changed_or_names(
    runner: Any,
) -> None:
    runner.select.return_value = ["A", "B", "C"]
    runner.native.remove.side_effect = [True, OSError("blocked")]
    assert runner.run({"name": "*", "state": "absent"}) == (
        1,
        {
            "changed": False,
            "capabilities": [],
            "reboot_required": True,
            "failed": True,
            "msg": "Failed to remove capability 'B': blocked",
        },
    )
    assert runner.native.remove.call_count == 2


def test_partial_add_result_keeps_prior_reboot_and_empty_capabilities(
    runner: Any,
) -> None:
    runner.batch.return_value = {
        "reboot_required": True,
        "failure": "Failed to install capability 'B': blocked",
    }
    assert runner.run({"name": ["A", "B"]})[1] == {
        "changed": False,
        "capabilities": [],
        "reboot_required": True,
        "failed": True,
        "msg": "Failed to install capability 'B': blocked",
    }


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"name": "A", "state": "invalid"},
        {"name": "A", "log_level": 1.5},
        {"name": "A", "log_level": True},
    ],
)
def test_binding_failure_precedes_native_preflight(
    runner: Any, arguments: dict[str, Any]
) -> None:
    status, result = runner.run(arguments)
    assert status == 1 and result["failed"] and not result["changed"]
    assert "capabilities" not in result and "reboot_required" not in result
    runner.select.assert_not_called()


def test_null_state_reads_names_without_changes(runner: Any) -> None:
    runner.select.return_value = []
    assert not runner.run({"name": "A", "state": None})[1]["changed"]
    runner.select.assert_called_once_with(["A"], None, None, None)


def test_real_json_reader_rejects_unsupported_before_native_calls(
    runner: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Restore the actual binding entry point after runner's in-process substitute.
    monkeypatch.setattr(
        runner.module,
        "read_arguments",
        sys.modules["legacy_windows_module"].read_arguments,
    )
    path = tmp_path / "arguments.json"
    path.write_text(
        json.dumps({"name": "Viewer", "unsupported": True}), encoding="utf-8"
    )
    monkeypatch.setattr(sys, "argv", ["win_capability.py", str(path)])
    status, result = invoke_payload(runner.module, capsys)
    assert status == 1 and "Unsupported parameters" in result["msg"]
    runner.select.assert_not_called()
