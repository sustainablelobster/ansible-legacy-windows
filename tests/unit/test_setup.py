"""Exercise the public setup JSON interface without contacting Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload


@pytest.fixture(name="payload")
def setup_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the payload with an isolated fact-reader substitute.

    :param monkeypatch: Scoped helper substitution.
    :returns: Imported setup payload.
    """
    helper = ModuleType("legacy_windows_setup")
    helper.read_facts = Mock(return_value={"module_setup": True})  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "legacy_windows_setup", helper)
    return load_payload("setup", monkeypatch)


def _invoke(
    payload: ModuleType,
    arguments: object,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> tuple[int, dict[str, object]]:
    path = tmp_path / "arguments.json"
    path.write_text(json.dumps(arguments), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["setup.py", str(path)])
    return invoke_payload(payload, capsys)


@pytest.mark.parametrize("check", [True, False])
def test_defaults_and_check_mode(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    check: bool,
) -> None:
    expected = {"changed": False, "ansible_facts": {"module_setup": True}}
    assert _invoke(
        payload, {"_ansible_check_mode": check}, monkeypatch, tmp_path, capsys
    ) == (0, expected)
    assert payload.setup.read_facts.call_args.args == (
        {
            "gather_subset": ["all"],
            "gather_timeout": 10,
            "fact_path": None,
            "_measure_subset": False,
        },
        [],
    )


def test_gather_facts_extra_options_are_accepted(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        _invoke(
            payload,
            {"filter": "ignored*", "future_option": {"x": 1}},
            monkeypatch,
            tmp_path,
            capsys,
        )[0]
        == 0
    )


def test_private_extra_argument_is_rejected_before_collection(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, result = _invoke(
        payload, {"_future_option": {"retained": True}}, monkeypatch, tmp_path, capsys
    )
    assert code == 1 and result["failed"] is True
    assert "Unsupported parameters" in str(result["msg"])
    assert "_future_option" in str(result["msg"])
    payload.setup.read_facts.assert_not_called()


def test_explicit_null_measure_is_retained_without_enabling_measurement(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, result = _invoke(
        payload,
        {"_measure_subset": None, "_ansible_inject_invocation": True},
        monkeypatch,
        tmp_path,
        capsys,
    )
    assert code == 0
    assert payload.setup.read_facts.call_args.args[0]["_measure_subset"] is None
    assert result["invocation"]["module_args"]["_measure_subset"] is None  # type: ignore[index]


def test_controller_ignore_unknown_flag_retains_its_explicit_override(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        _invoke(
            payload,
            {"_future_option": True, "_ansible_ignore_unknown_opts": True},
            monkeypatch,
            tmp_path,
            capsys,
        )[0]
        == 0
    )
    payload.setup.read_facts.assert_called_once()


@pytest.mark.parametrize(
    "value", [True, False, 1.5, "1.5", 2**31, -(2**31) - 1, [], {}]
)
def test_invalid_timeout_fails_before_collection(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    value: object,
) -> None:
    code, result = _invoke(
        payload, {"gather_timeout": value}, monkeypatch, tmp_path, capsys
    )
    assert code == 1 and result["failed"] is True and result["changed"] is False
    payload.setup.read_facts.assert_not_called()


@pytest.mark.parametrize("case", [(0, 0), (" +12 ", 12), (None, None)])
def test_bound_timeout_retains_null_or_int(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    case: tuple[object, object],
) -> None:
    value, expected = case
    assert (
        _invoke(payload, {"gather_timeout": value}, monkeypatch, tmp_path, capsys)[0]
        == 0
    )
    assert payload.setup.read_facts.call_args.args[0]["gather_timeout"] == expected


def test_subset_list_and_warning_shape(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def _read(parameters: dict[str, object], warnings: list[str]) -> dict[str, object]:
        warnings.append("invalid value bogus specified in gather_subset")
        return {"gather_subset": parameters["gather_subset"], "module_setup": True}

    payload.setup.read_facts.side_effect = _read
    assert _invoke(
        payload, {"GATHER_SUBSET": "!all, !min,bogus"}, monkeypatch, tmp_path, capsys
    ) == (
        0,
        {
            "changed": False,
            "ansible_facts": {
                "gather_subset": ["!all", "!min", "bogus"],
                "module_setup": True,
            },
            "warnings": ["invalid value bogus specified in gather_subset"],
        },
    )


def test_invocation_keeps_extra_arguments(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, result = _invoke(
        payload,
        {"filter": "ignored", "_ansible_inject_invocation": True},
        monkeypatch,
        tmp_path,
        capsys,
    )
    assert code == 0
    assert result["invocation"] == {
        "module_args": {
            "filter": "ignored",
            "gather_subset": ["all"],
            "gather_timeout": 10,
            "fact_path": None,
            "_measure_subset": False,
        }
    }
