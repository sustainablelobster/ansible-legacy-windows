"""Check environment payload results without accessing Windows or the lab."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Direct calls exercise the payload independently of its native API boundary.
# pylint: disable=protected-access

import json
import sys
from collections import OrderedDict
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import invoke_payload, load_payload


@pytest.fixture(name="native_values")
def environment_values() -> dict[tuple[str, str], str]:
    """Provide an isolated case-insensitive environment store.

    :returns: Values indexed by normalized level and variable name.
    """
    return {}


@pytest.fixture(name="payload")
def environment_payload(
    monkeypatch: pytest.MonkeyPatch, native_values: dict[tuple[str, str], str]
) -> ModuleType:
    """Replace native operations with observable reads, writes and notifications.

    :param monkeypatch: Scoped native API replacements.
    :param native_values: Storage shared with each test.
    :returns: The environment payload with its native boundary substituted.
    """
    module = load_payload("win_environment", monkeypatch)

    def set_value(name: str, value: str | None, level: str) -> None:
        key = (level, name.lower())
        if value is None:
            native_values.pop(key, None)
        else:
            native_values[key] = value

    monkeypatch.setattr(
        module.environment,
        "get_value",
        Mock(side_effect=lambda name, level: native_values.get((level, name.lower()))),
    )
    monkeypatch.setattr(module.environment, "set_value", Mock(side_effect=set_value))
    monkeypatch.setattr(module.environment, "broadcast_change", Mock())
    # Backend tests cover native Unicode mapping; this fixture needs only ASCII
    # case equivalence and must not merge the distinct ordinal names ß and ss.
    monkeypatch.setattr(
        module.environment,
        "name_key",
        Mock(
            side_effect=lambda name: name.translate(
                str.maketrans(
                    "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                )
            )
        ),
    )
    monkeypatch.setattr(
        module.environment,
        "values_equal",
        Mock(
            side_effect=lambda left, right: left is not None
            and left.lower() == right.lower()
        ),
    )
    return module


def _apply(
    payload: ModuleType,
    *,
    check: bool = False,
    diff: bool = True,
    **options: object,
) -> dict[str, Any]:
    arguments = {"level": "user", **options}
    if "name" not in arguments and "variables" not in arguments:
        arguments["name"] = "APP"
    result: dict[str, Any] = payload._environment(
        payload._parameters(arguments), check, diff
    )
    return result


def _run(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    arguments: object,
) -> tuple[int, dict[str, Any]]:
    argument_file = tmp_path / "arguments.json"
    argument_file.write_text(json.dumps(arguments), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["win_environment.py", str(argument_file)])
    return invoke_payload(payload, capsys)


@pytest.mark.parametrize("level", ["machine", "user", "process"])
def test_create_repeat_change_remove_and_repeat(
    payload: ModuleType, native_values: dict[tuple[str, str], str], level: str
) -> None:
    result = _apply(payload, level=level, value="Alpha", state="present")
    status = {"before": None, "after": "Alpha", "changed": True}
    assert result == {
        "changed": True,
        "values": {"APP": status},
        "env_values": {"APP": status},
        "before_value": None,
        "value": "Alpha",
        "diff": {"before": {level: {}}, "after": {level: {"APP": "Alpha"}}},
    }
    assert native_values == {(level, "app"): "Alpha"}
    repeated = _apply(payload, level=level, value="Alpha")
    assert repeated["changed"] is False
    assert repeated["before_value"] == repeated["value"] == "Alpha"
    assert repeated["diff"] == {
        "before": {level: {"APP": "Alpha"}},
        "after": {level: {"APP": "Alpha"}},
    }
    changed = _apply(payload, level=level, value="Beta")
    assert changed["changed"] is True and changed["before_value"] == "Alpha"
    removed = _apply(payload, level=level, state="absent")
    assert removed["changed"] is True
    assert removed["before_value"] == "Beta" and removed["value"] == ""
    assert removed["diff"] == {"before": {level: {"APP": "Beta"}}, "after": {level: {}}}
    assert _apply(payload, level=level, state="absent")["changed"] is False
    assert not native_values
    assert payload.environment.set_value.call_count == 3
    assert payload.environment.broadcast_change.call_count == 3


def test_case_only_value_change_reports_request_without_writing(
    payload: ModuleType, native_values: dict[tuple[str, str], str]
) -> None:
    native_values[("user", "app")] = "Alpha"
    result = _apply(payload, name="app", level="USER", state="PRESENT", value="alpha")
    assert result["changed"] is False
    assert result["before_value"] == "Alpha" and result["value"] == "alpha"
    assert result["diff"] == {
        "before": {"USER": {"app": "Alpha"}},
        "after": {"USER": {"app": "alpha"}},
    }
    assert native_values[("user", "app")] == "Alpha"
    payload.environment.get_value.assert_called_once_with("app", "user")
    payload.environment.set_value.assert_not_called()
    payload.environment.broadcast_change.assert_not_called()


@pytest.mark.parametrize("existing", [None, "before", ""])
@pytest.mark.parametrize("value", [None, "", "after"])
def test_check_mode_predicts_without_writing(
    payload: ModuleType,
    native_values: dict[tuple[str, str], str],
    existing: str | None,
    value: str | None,
) -> None:
    if existing is not None:
        native_values[("user", "app")] = existing
    before = dict(native_values)
    predicted = _apply(payload, value=value, check=True)
    assert native_values == before
    payload.environment.set_value.assert_not_called()
    payload.environment.broadcast_change.assert_not_called()
    assert _apply(payload, value=value) == predicted


@pytest.mark.parametrize(
    "options", [{}, {"value": None}, {"value": ""}, {"state": None}]
)
def test_inferred_removal_returns_empty_text(
    payload: ModuleType,
    native_values: dict[tuple[str, str], str],
    options: dict[str, object],
) -> None:
    native_values[("user", "app")] = "before"
    result = payload._environment(
        payload._parameters({"level": "user", "name": "APP", **options}), False, True
    )
    assert result["value"] == ""
    assert result["env_values"]["APP"] == {
        "before": "before",
        "after": "",
        "changed": True,
    }
    assert not native_values


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("existing", [None, "before"])
def test_absent_supplied_value_warns_but_preserves_requested_result(
    payload: ModuleType,
    native_values: dict[tuple[str, str], str],
    check: bool,
    existing: str | None,
) -> None:
    if existing is not None:
        native_values[("user", "app")] = existing
    result = _apply(payload, state="ABSENT", value="ignored", check=check)
    assert result["warnings"] == [
        "When removing environment variable 'APP' it should not have a value 'ignored' set"
    ]
    assert result["value"] == "ignored"
    assert result["env_values"]["APP"]["after"] == "ignored"
    assert result["changed"] == (existing is not None)
    assert result["diff"]["after"] == {"user": {"APP": "ignored"}}
    assert native_values.get(("user", "app")) == (existing if check else None)


@pytest.mark.parametrize("options", [{}, {"value": None}, {"value": ""}])
@pytest.mark.parametrize("check", [False, True])
def test_present_requires_value_and_retains_initialized_results(
    payload: ModuleType, options: dict[str, object], check: bool
) -> None:
    parameters = payload._parameters(
        {"level": "user", "name": "APP", "state": "present", **options}
    )
    assert payload._environment(parameters, check, True) == {
        "changed": False,
        "failed": True,
        "msg": payload._PRESENT_VALUE_REQUIRED,
        "values": {},
        "env_values": {},
        "diff": {"before": {"user": {}}, "after": {"user": {}}},
    }
    payload.environment.get_value.assert_not_called()
    payload.environment.set_value.assert_not_called()


@pytest.mark.parametrize("variables", [{}, "{}"])
def test_empty_mapping_is_a_successful_noop(
    payload: ModuleType, variables: object
) -> None:
    assert _apply(payload, variables=variables) == {
        "changed": False,
        "values": {},
        "env_values": {},
        "diff": {"before": {"user": {}}, "after": {"user": {}}},
    }
    payload.environment.get_value.assert_not_called()


def test_multiple_values_set_remove_and_repeat(
    payload: ModuleType, native_values: dict[tuple[str, str], str]
) -> None:
    native_values[("user", "old")] = "old"
    variables = OrderedDict(
        (name, value)
        for name, value in [
            ("NEW", "Café 雪 %SystemRoot%"),
            ("OLD", None),
            ("ABSENT", ""),
        ]
    )
    result = _apply(payload, variables=variables)
    assert result["changed"] is True
    assert result["env_values"] == {
        "NEW": {"before": None, "after": "Café 雪 %SystemRoot%", "changed": True},
        "OLD": {"before": "old", "after": "", "changed": True},
        "ABSENT": {"before": None, "after": "", "changed": False},
    }
    assert result["values"] == result["env_values"]
    assert result["before_value"] is None and result["value"] == ""
    assert result["diff"] == {
        "before": {"user": {"OLD": "old"}},
        "after": {"user": {"NEW": "Café 雪 %SystemRoot%"}},
    }
    assert _apply(payload, variables=variables)["changed"] is False
    assert native_values == {("user", "new"): "Café 雪 %SystemRoot%"}


@pytest.mark.parametrize(
    "value,expected",
    [(False, "False"), (True, "True"), (0, "0"), (42, "42"), (1.5, "1.5")],
)
def test_scalar_values_are_bound_to_nonempty_strings(
    payload: ModuleType, value: object, expected: str
) -> None:
    single = _apply(payload, value=value, check=True)
    multiple = _apply(payload, variables={"APP": value}, check=True)
    assert single == multiple
    assert single["value"] == expected and single["changed"] is True


def test_array_single_value_uses_basic_string_conversion(payload: ModuleType) -> None:
    assert (
        _apply(payload, value=["one", "two"], check=True)["value"] == "System.Object[]"
    )


def test_mapping_value_uses_powershell_string_conversion(payload: ModuleType) -> None:
    result = _apply(payload, variables={"APP": {"key": "value"}}, check=True)
    assert result["value"] == "System.Collections.Hashtable"
    assert result["changed"] is True


@pytest.mark.parametrize("values", [[], ["one"], [None], ["one", "two"]])
def test_array_dictionary_value_fails_binding(
    payload: ModuleType, values: list[object]
) -> None:
    with pytest.raises(ValueError, match="array"):
        _apply(payload, variables={"APP": values}, check=True)
    payload.environment.get_value.assert_not_called()


@pytest.mark.parametrize(
    "text,expected",
    [
        ('{"APP":"one","OLD":null}', {"APP": "one", "OLD": None}),
        ('APP="one two",OLD=', {"APP": "one two", "OLD": ""}),
        ("APP='one,two' OLD", {"APP": "one,two", "OLD": None}),
        (r"APP=one\ two,BACK=C:\\App", {"APP": "one two", "BACK": r"C:\App"}),
        ("APP=one APP=one", {"APP": "one"}),
        ("APP=one=two", {"APP": "one=two"}),
        ("APP='unterminated", {"APP": "unterminated"}),
        ("APP=value\\", {"APP": "value"}),
    ],
)
def test_dictionary_string_forms(
    payload: ModuleType, text: str, expected: dict[str, object]
) -> None:
    parameters = payload._parameters({"level": "user", "variables": text})
    assert parameters["variables"] == expected
    result = _apply(payload, variables=text, check=True)
    assert set(result["env_values"]) == set(expected)


@pytest.mark.parametrize(
    "variables", [False, [], 42, "", "invalid", "APP=one APP=two", "{bad}"]
)
def test_invalid_dictionary_arguments_fail(
    payload: ModuleType, variables: object
) -> None:
    with pytest.raises(ValueError):
        payload._parameters({"level": "user", "variables": variables})


@pytest.mark.parametrize("other", ["name", "value", "state"])
@pytest.mark.parametrize("value", [None, "", "value"])
def test_exclusive_parameters_are_checked_by_presence(
    payload: ModuleType, other: str, value: object
) -> None:
    with pytest.raises(ValueError, match="mutually exclusive: variables, " + other):
        payload._parameters({"level": "user", "variables": None, other: value})


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({"name": "APP"}, "missing required arguments: level"),
        ({"level": "user"}, "one of the following is required"),
        ({"level": "invalid", "name": "APP"}, "level must be one of"),
        ({"level": "user", "name": "APP", "state": ""}, "state must be one of"),
        ({"level": "user", "name": "APP", "state": False}, "state must be one of"),
    ],
)
def test_required_and_choice_validation(
    payload: ModuleType, arguments: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        payload._parameters(arguments)


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({"level": None, "name": "APP"}, "level must not be null"),
        ({"level": "user", "name": None}, "name must not be null"),
        ({"level": "user", "name": ""}, "name must not be empty"),
        ({"level": "user", "variables": None}, "name must not be null"),
    ],
)
def test_null_presence_passes_validation_but_execution_fails(
    payload: ModuleType, arguments: dict[str, object], message: str
) -> None:
    parameters = payload._parameters(arguments)
    with pytest.raises(ValueError, match=message):
        payload._environment(parameters, True, True)


def test_diff_is_returned_only_when_requested(payload: ModuleType) -> None:
    assert "diff" not in _apply(payload, value="value", diff=False)


def test_invalid_setter_name_can_predict_change(payload: ModuleType) -> None:
    payload.environment.set_value.side_effect = ValueError("name contains equals")
    assert _apply(payload, name="APP=BAD", value="value", check=True)["changed"] is True
    with pytest.raises(ValueError, match="name contains equals"):
        _apply(payload, name="APP=BAD", value="value")
    payload.environment.broadcast_change.assert_not_called()


def test_json_flags_invocation_and_case_insensitive_argument_names(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {
            "LEVEL": "USER",
            "NAME": "APP",
            "VALUE": "雪",
            "_ANSIBLE_CHECK_MODE": "yes",
            "_ansible_diff": "yes",
            "_ansible_inject_invocation": True,
        },
    )
    assert code == 0 and result["changed"] is True
    assert result["diff"]["after"] == {"USER": {"APP": "雪"}}
    assert result["invocation"] == {
        "module_args": {
            "level": "USER",
            "name": "APP",
            "value": "雪",
            "state": None,
            "variables": None,
        }
    }
    payload.environment.set_value.assert_not_called()


@pytest.mark.parametrize(
    "arguments", [[], {"unknown": True}, {"level": "user", "name": None}]
)
def test_json_validation_failure_has_no_partial_maps(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    arguments: object,
) -> None:
    code, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert code == 1 and result["failed"] is True and result["changed"] is False
    assert result["msg"]
    assert not {"values", "env_values", "before_value", "value", "diff"}.intersection(
        result
    )


def test_json_present_empty_failure_retains_empty_maps(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {
            "level": "user",
            "name": "APP",
            "state": "present",
            "_ansible_diff": True,
        },
    )
    assert code == 1 and result["failed"] is True
    assert result["values"] == result["env_values"] == {}
    assert result["diff"] == {"before": {"user": {}}, "after": {"user": {}}}


def test_later_binding_failure_keeps_prior_write_but_drops_partial_results(
    payload: ModuleType,
    native_values: dict[tuple[str, str], str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    arguments = {
        "level": "user",
        "variables": OrderedDict(
            [("FIRST", "one"), ("SECOND", ["invalid"]), ("THIRD", "three")]
        ),
        "_ansible_diff": True,
    }
    code, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert code == 1 and result["changed"] is False and result["failed"] is True
    assert "env_values" not in result and "diff" not in result
    assert native_values == {("user", "first"): "one"}
    assert _apply(payload, variables={"FIRST": "one"})["changed"] is False


def test_notification_failure_leaves_write_and_subsequent_request_recovers(
    payload: ModuleType,
    native_values: dict[tuple[str, str], str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload.environment.broadcast_change.side_effect = OSError("notification timeout")
    arguments = {"level": "user", "name": "APP", "value": "one", "_ansible_diff": True}
    code, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert code == 1 and result == {
        "changed": False,
        "failed": True,
        "msg": "notification timeout",
    }
    assert native_values == {("user", "app"): "one"}
    payload.environment.broadcast_change.side_effect = None
    code, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert code == 0 and result["changed"] is False
    assert result["env_values"]["APP"] == {
        "before": "one",
        "after": "one",
        "changed": False,
    }
    assert payload.environment.broadcast_change.call_count == 1


def test_native_read_failure_emits_json_without_writing(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload.environment.get_value.side_effect = OSError("access denied")
    code, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"level": "user", "name": "APP", "value": "one"},
    )
    assert code == 1 and result["msg"] == "access denied"
    assert "env_values" not in result
    payload.environment.set_value.assert_not_called()


@pytest.mark.parametrize("check", [False, True])
def test_raw_mapping_case_duplicate_fails_before_any_read_or_write(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    check: bool,
) -> None:
    code, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {
            "level": "user",
            "variables": {"APP": "one", "app": "two"},
            "_ansible_check_mode": check,
            "_ansible_diff": True,
        },
    )
    assert code == 1 and result["failed"] is True and result["changed"] is False
    assert "differ only in case" in result["msg"]
    assert "env_values" not in result and "diff" not in result
    payload.environment.get_value.assert_not_called()
    payload.environment.set_value.assert_not_called()
    payload.environment.broadcast_change.assert_not_called()


def test_case_duplicate_validation_precedes_other_argument_errors(
    payload: ModuleType,
) -> None:
    with pytest.raises(ValueError, match="differ only in case"):
        payload._parameters({"variables": {"APP": "one", "app": "two"}, "name": "APP"})


@pytest.mark.parametrize("variables", ['{"App":"one","APP":"two"}', "App=one APP=two"])
def test_dictionary_strings_keep_case_distinct_input_names(
    payload: ModuleType,
    variables: str,
) -> None:
    result = _apply(payload, variables=variables)
    assert result["changed"] is True
    assert result["env_values"] == {
        "App": {
            "before": "one",
            "after": "two",
            "changed": True,
        }
    }
    assert result["values"] == result["env_values"]
    assert result["diff"] == {
        "before": {"user": {"APP": "one"}},
        "after": {"user": {"App": "two"}},
    }
    assert payload.environment.set_value.call_args_list == [
        call("App", "one", "user"),
        call("APP", "two", "user"),
    ]


def test_linguistic_result_keys_merge_without_collapsing_writes(
    payload: ModuleType,
    native_values: dict[tuple[str, str], str],
) -> None:
    # The reference treats these names as distinct environment variables but
    # equal keys in the result hashtables. Other native pairs belong in backend tests.
    payload.environment.values_equal.side_effect = lambda left, right: (
        left is not None
        and left.lower().replace("ß", "ss") == right.lower().replace("ß", "ss")
    )
    native_values[("user", "ss")] = "old second"
    result = _apply(payload, variables=OrderedDict([("ß", "one"), ("ss", "two")]))
    assert native_values == {("user", "ß"): "one", ("user", "ss"): "two"}
    assert payload.environment.set_value.call_count == 2
    assert payload.environment.broadcast_change.call_count == 2
    assert result["env_values"] == {
        "ß": {
            "before": "old second",
            "after": "two",
            "changed": True,
        }
    }
    assert result["values"] == result["env_values"]
    assert result["diff"] == {
        "before": {"user": {"ss": "old second"}},
        "after": {"user": {"ß": "two"}},
    }
