"""Check registry payload results without accessing Windows or the lab."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Direct calls exercise argument handling separately from native registry APIs.
# pylint: disable=protected-access

import json
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload


@pytest.fixture(name="payload")
def registry_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the payload with an observable, read-only registry boundary.

    :param monkeypatch: Scoped import and API substitutes.
    :returns: The payload with native registry reads replaced.
    """
    backend = ModuleType("legacy_windows_reg_stat")
    monkeypatch.setattr(
        backend, "query_key", Mock(return_value={"exists": False}), raising=False
    )
    monkeypatch.setitem(sys.modules, "legacy_windows_reg_stat", backend)
    return load_payload("win_reg_stat", monkeypatch)


@pytest.fixture(name="invoke")
def registry_invocation(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> Callable[[object], tuple[int, dict[str, Any]]]:
    """Bind argument-file setup and output capture for registry payload calls.

    :param payload: Imported payload with its native boundary replaced.
    :param monkeypatch: Scoped substitutions for the script arguments.
    :param tmp_path: Isolated directory for the argument file.
    :param capsys: Scoped stdout and stderr capture.
    :returns: Callable accepting a JSON-serializable argument document.
    """

    def _invoke(arguments: object) -> tuple[int, dict[str, Any]]:
        argument_file = tmp_path / "arguments.json"
        argument_file.write_text(json.dumps(arguments), encoding="utf-8")
        monkeypatch.setattr(sys, "argv", ["win_reg_stat.py", str(argument_file)])
        return invoke_payload(payload, capsys)

    return _invoke


@pytest.mark.parametrize("hive", ["HKCC", "HKCR", "HKCU", "HKLM", "HKU"])
@pytest.mark.parametrize("lowercase", [False, True])
@pytest.mark.parametrize("subkey", ["", r"Software\Application", r"Test Key / [&*]\雪"])
def test_path_selects_hive_without_expanding_literal_names(
    payload: ModuleType, hive: str, lowercase: bool, subkey: str
) -> None:
    prefix = hive.lower() if lowercase else hive
    assert payload._parameters({"path": prefix + ":\\" + subkey}) == {
        "hive": hive,
        "subkey": subkey,
        "name": None,
    }


@pytest.mark.parametrize(
    "path",
    [
        None,
        "",
        " ",
        "HKCU",
        "HKCU:",
        "HKCU:/Software",
        r"HKEY_CURRENT_USER:\Software",
        r"BAD:\Software",
        r" HKCU:\Software",
    ],
)
def test_invalid_path_has_upstream_validation_message(
    payload: ModuleType, path: str | None
) -> None:
    with pytest.raises(ValueError) as failed:
        payload._parameters({"path": path})
    assert str(failed.value) == (
        "path: "
        + (path or "")
        + " is not a valid registry path, see module documentation for examples."
    )
    payload.registry.query_key.assert_not_called()


@pytest.mark.parametrize("arguments", [{}, {"name": "test"}, {"unknown": "ignored"}])
def test_missing_path_has_upstream_required_argument_message(
    payload: ModuleType, arguments: dict[str, object]
) -> None:
    with pytest.raises(
        ValueError, match="^Get-AnsibleParam: Missing required argument: path$"
    ):
        payload._parameters(arguments)


@pytest.mark.parametrize(
    ("options", "hive", "subkey"),
    [
        ({"key": r"HKCU:\Alias"}, "HKCU", "Alias"),
        ({"path": r"HKCU:\Canonical", "key": r"HKLM:\Alias"}, "HKCU", "Canonical"),
        ({"path": r"HKCU:\Canonical", "key": None}, "HKCU", "Canonical"),
    ],
)
def test_path_alias_is_used_only_when_canonical_option_is_absent(
    payload: ModuleType, options: dict[str, object], hive: str, subkey: str
) -> None:
    assert payload._parameters(options) == {
        "hive": hive,
        "subkey": subkey,
        "name": None,
    }


@pytest.mark.parametrize("path", [None, ""])
def test_empty_canonical_path_does_not_fall_back_to_alias(
    payload: ModuleType, path: str | None
) -> None:
    with pytest.raises(ValueError, match="is not a valid registry path"):
        payload._parameters({"path": path, "key": r"HKCU:\Alias"})


@pytest.mark.parametrize(
    ("options", "name"),
    [
        ({}, None),
        ({"name": None}, None),
        ({"name": ""}, ""),
        ({"entry": ""}, ""),
        ({"value": ""}, ""),
        ({"entry": "alias"}, "alias"),
        ({"value": "alias"}, "alias"),
        ({"property": "ignored"}, None),
        ({"name": "canonical", "entry": "first", "value": "second"}, "canonical"),
        ({"name": None, "entry": "ignored", "value": "ignored"}, None),
        ({"entry": None, "value": "ignored"}, None),
        ({"entry": "first", "value": "second"}, "first"),
    ],
)
def test_value_name_aliases_preserve_null_and_empty_distinctions(
    payload: ModuleType, options: dict[str, object], name: str | None
) -> None:
    assert payload._parameters({"path": r"HKCU:\Application", **options}) == {
        "hive": "HKCU",
        "subkey": "Application",
        "name": name,
    }


@pytest.mark.parametrize(
    ("value", "text"),
    [
        (False, "False"),
        (True, "True"),
        (0, "0"),
        (-1, "-1"),
        (1.5, "1.5"),
        ([], "System.Object[]"),
        (["one"], "System.Object[]"),
        ({}, "System.Collections.Hashtable"),
        ({"one": "two"}, "System.Collections.Hashtable"),
    ],
)
def test_non_string_arguments_use_legacy_string_conversion(
    payload: ModuleType, value: object, text: str
) -> None:
    assert (
        payload._parameters({"path": r"HKCU:\Application", "name": value})["name"]
        == text
    )
    with pytest.raises(ValueError) as failed:
        payload._parameters({"path": value})
    assert str(failed.value).startswith(
        "path: " + text + " is not a valid registry path"
    )


@pytest.mark.parametrize(
    "case",
    [
        (None, {"exists": False}),
        (None, {"exists": True, "properties": {}, "sub_keys": []}),
        ("missing", {"exists": False}),
        ("", {"exists": True, "type": "REG_SZ", "value": "", "raw_value": ""}),
        (
            "binary",
            {
                "exists": True,
                "type": "REG_BINARY",
                "value": [0, 255],
                "raw_value": ["0x00", "0xff"],
            },
        ),
        (
            "qword",
            {
                "exists": True,
                "type": "REG_QWORD",
                "value": 18446744073709551615,
                "raw_value": 18446744073709551615,
            },
        ),
        (
            "expand",
            {
                "exists": True,
                "type": "REG_EXPAND_SZ",
                "value": r"C:\Windows\雪",
                "raw_value": r"%SystemRoot%\雪",
            },
        ),
        (
            None,
            {
                "exists": True,
                "properties": {
                    "": {"type": "REG_SZ", "value": [255], "raw_value": [255]},
                    "unsupported": None,
                },
                "sub_keys": ["Nested"],
            },
        ),
    ],
)
def test_json_result_preserves_native_shape_and_value_types(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    case: tuple[str | None, dict[str, object]],
) -> None:
    selected, native_result = case
    payload.registry.query_key.return_value = native_result
    code, result = invoke({"path": r"HKCU:\Application", "name": selected})
    assert code == 0 and result == {"changed": False, **native_result}
    payload.registry.query_key.assert_called_once_with("HKCU", "Application", selected)


@pytest.mark.parametrize("check", [False, True, "invalid but unused"])
def test_unknown_options_and_execution_metadata_do_not_change_reads(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    check: bool | str,
) -> None:
    code, result = invoke(
        {
            "KEY": r"hkcu:\Application",
            "ENTRY": "selected",
            "property": "ignored",
            "unknown": {"arbitrary": "data"},
            "state": "absent",
            "_ansible_check_mode": check,
            "_ansible_diff": True,
            "_ansible_inject_invocation": True,
            "_ansible_ignore_unknown_opts": "invalid but unused",
        },
    )
    assert code == 0 and result == {"changed": False, "exists": False}
    payload.registry.query_key.assert_called_once_with(
        "HKCU", "Application", "selected"
    )


@pytest.mark.parametrize("arguments", [None, [], "not a mapping"])
def test_invalid_argument_document_returns_json_failure_without_native_read(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    arguments: object,
) -> None:
    code, result = invoke(arguments)
    assert code == 1 and result == {
        "changed": False,
        "failed": True,
        "msg": "The argument file must contain a JSON object.",
    }
    payload.registry.query_key.assert_not_called()


def test_native_failure_does_not_return_partial_key_results_and_next_read_recovers(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
) -> None:
    payload.registry.query_key.side_effect = [
        OSError("Access is denied"),
        {"exists": True, "properties": {}, "sub_keys": []},
    ]
    arguments = {"path": r"HKCU:\Application"}
    code, result = invoke(arguments)
    assert code == 1 and result == {
        "changed": False,
        "failed": True,
        "msg": "Access is denied",
    }
    code, result = invoke(arguments)
    assert code == 0 and result == {
        "changed": False,
        "exists": True,
        "properties": {},
        "sub_keys": [],
    }
    assert payload.registry.query_key.call_count == 2
