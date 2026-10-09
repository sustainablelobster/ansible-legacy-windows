"""Exercise the product-facts payload's public JSON contract without Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

FACTS = {
    "ansible_os_product_id": "synthetic product identifier",
    "ansible_os_product_key": "synthetic product key",
    "ansible_os_license_edition": "Windows fixture edition",
    "ansible_os_license_channel": "Volume:MAK",
    "ansible_os_license_status": "Licensed",
}


@pytest.fixture(name="payload")
def product_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the payload with an isolated native-reader substitute.

    :param monkeypatch: Scoped helper import substitution.
    :returns: Payload with deterministic product facts.
    """
    product = ModuleType("legacy_windows_product")
    monkeypatch.setattr(
        product, "read_facts", Mock(return_value=copy.deepcopy(FACTS)), raising=False
    )
    monkeypatch.setitem(sys.modules, "legacy_windows_product", product)
    return load_payload("win_product_facts", monkeypatch)


@pytest.fixture(name="invoke")
def product_invocation(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> Callable[[object], tuple[int, dict[str, Any]]]:
    """Invoke the payload through its argument file and JSON result.

    :param payload: Imported payload with a native-reader substitute.
    :param monkeypatch: Scoped command arguments.
    :param tmp_path: Isolated argument-file directory.
    :param capsys: Captured module output.
    :returns: Callable accepting the argument document.
    """

    def _invoke(arguments: object) -> tuple[int, dict[str, Any]]:
        argument_file = tmp_path / "arguments.json"
        argument_file.write_text(json.dumps(arguments), encoding="utf-8")
        monkeypatch.setattr(sys, "argv", ["win_product_facts.py", str(argument_file)])
        return invoke_payload(payload, capsys)

    return _invoke


@pytest.mark.parametrize("check", [False, True])
def test_complete_facts_repeat_including_check_mode(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    check: bool,
) -> None:
    expected = {"changed": False, "ansible_facts": FACTS}
    arguments = {"_ansible_check_mode": check, "_ansible_diff": True}
    assert invoke(arguments) == (0, expected)
    assert invoke(arguments) == (0, expected)
    assert payload.product.read_facts.call_args_list == [call([]), call([])]


@pytest.mark.parametrize(
    "value", [None, "", "Unicode fixture 雪", [], ["B", None, "A"]]
)
def test_retains_native_field_values_without_coercion(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    value: object,
) -> None:
    facts = dict.fromkeys(FACTS, value)
    payload.product.read_facts.return_value = facts
    assert invoke({}) == (0, {"changed": False, "ansible_facts": facts})


def test_named_warnings_accompany_available_facts_without_leaking_to_next_call(
    payload: ModuleType, invoke: Callable[[object], tuple[int, dict[str, Any]]]
) -> None:
    warning = "ansible_os_license_status is unavailable in this provider"
    facts = dict(FACTS, ansible_os_license_status=None)

    def _read(warnings: list[str]) -> dict[str, Any]:
        warnings.append(warning)
        return facts

    payload.product.read_facts.side_effect = _read
    assert invoke({}) == (
        0,
        {"changed": False, "ansible_facts": facts, "warnings": [warning]},
    )
    payload.product.read_facts.side_effect = None
    assert invoke({}) == (0, {"changed": False, "ansible_facts": FACTS})


@pytest.mark.parametrize(
    "error", [OSError("native read denied"), ValueError("malformed product data")]
)
def test_native_failure_discards_partial_results_and_next_read_recovers(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    error: Exception,
) -> None:
    def _fail(warnings: list[str]) -> None:
        warnings.append("partial warning")
        raise error

    payload.product.read_facts.side_effect = _fail
    assert invoke({}) == (
        1,
        {"changed": False, "failed": True, "msg": str(error)},
    )
    payload.product.read_facts.side_effect = None
    assert invoke({}) == (0, {"changed": False, "ansible_facts": FACTS})


@pytest.mark.parametrize("hresult", [0x80070005, 0x80070426])
def test_license_provider_errors_fail_without_facts_or_warnings_and_recover(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    hresult: int,
) -> None:
    message = f"IEnumWbemClassObject.Next failed (HRESULT 0x{hresult:08X})."
    error = OSError(message)
    setattr(error, "hresult", hresult)
    payload.product.read_facts.side_effect = error
    assert invoke({}) == (
        1,
        {"changed": False, "failed": True, "msg": message},
    )
    payload.product.read_facts.side_effect = None
    assert invoke({}) == (0, {"changed": False, "ansible_facts": FACTS})


def test_unexpected_failure_uses_shared_json_error_contract(
    payload: ModuleType, invoke: Callable[[object], tuple[int, dict[str, Any]]]
) -> None:
    payload.product.read_facts.side_effect = RuntimeError("unexpected reader failure")
    code, result = invoke({})
    assert code == 1 and result["failed"] is True and result["changed"] is False
    assert result["msg"] == (
        "Unhandled exception while executing module: unexpected reader failure"
    )
    assert "RuntimeError: unexpected reader failure" in result["exception"]
    assert "ansible_facts" not in result
    payload.product.read_facts.side_effect = None
    assert invoke({}) == (0, {"changed": False, "ansible_facts": FACTS})


@pytest.mark.parametrize("arguments", [{"unexpected_option": True}, {"NAME": "x"}])
def test_unknown_options_fail_before_native_reads(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    arguments: dict[str, object],
) -> None:
    assert invoke(arguments) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": (
                "Unsupported parameters for "
                "(sustainablelobster.legacy_windows.win_product_facts) module: "
                + next(iter(arguments))
                + ". Supported parameters include: "
            ),
        },
    )
    payload.product.read_facts.assert_not_called()


@pytest.mark.parametrize("arguments", [[], None, "not a mapping"])
def test_non_mapping_arguments_fail_before_native_reads(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    arguments: object,
) -> None:
    assert invoke(arguments) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "The argument file must contain a JSON object.",
        },
    )
    payload.product.read_facts.assert_not_called()


@pytest.mark.parametrize("flag", [True, "yes"])
def test_requested_invocation_contains_only_empty_public_arguments(
    invoke: Callable[[object], tuple[int, dict[str, Any]]], flag: object
) -> None:
    assert invoke({"_ANSIBLE_INJECT_INVOCATION": flag}) == (
        0,
        {
            "changed": False,
            "ansible_facts": FACTS,
            "invocation": {"module_args": {}},
        },
    )


def test_controller_ignore_unknown_options_flag_preserves_empty_invocation(
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
) -> None:
    code, result = invoke(
        {
            "unused": "not a module option",
            "_ansible_ignore_unknown_opts": True,
            "_ansible_inject_invocation": True,
        }
    )
    assert code == 0 and result["invocation"] == {"module_args": {}}
    assert result["ansible_facts"] == FACTS
