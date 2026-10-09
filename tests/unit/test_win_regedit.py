"""Exercise registry edits, previews, partial failures, and the JSON contract."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Private module boundaries let these tests observe results without Windows.
# pylint: disable=protected-access

import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, cast
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

PATH = r"HKCU:\Software\Owned"


@pytest.fixture(name="payload")
def registry_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the payload with deterministic native string comparison.

    :param monkeypatch: Scoped target substitutes.
    :returns: Imported payload.
    """
    payload = load_payload("win_regedit", monkeypatch)
    monkeypatch.setattr(
        payload.values,
        "_strings_equal",
        lambda left, right, ignore: (
            left.lower() == right.lower() if ignore else left == right
        ),
    )
    return payload


@pytest.fixture(name="native")
def registry_boundary(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> SimpleNamespace:
    """Replace native operations with an observable registry branch.

    :param payload: Imported module.
    :param monkeypatch: Scoped native substitutions.
    :returns: Mutable fixture with call records and stored values.
    """
    key = MagicMock()
    native = SimpleNamespace(
        key=key,
        exists=True,
        stored={},
        open=Mock(),
        write=Mock(),
        delete=Mock(),
        tree=Mock(),
    )

    def _open(_hive: str, _path: str, create: bool = False) -> Any:
        if create:
            native.exists = True
        return key if native.exists else None

    def _write(_key: Any, name: str, kind: str, data: Any) -> None:
        native.stored[name] = (data, payload.registry.KINDS[kind])

    def _read(_key: Any, name: str, expand: bool = False) -> tuple[Any, Any]:
        value, kind = native.stored.get(name, (None, None))
        if expand and kind == 2:
            value = value.replace("%TEMP%", r"C:\Temp")
        return value, kind

    native.open.side_effect = _open
    native.write.side_effect = _write
    native.delete.side_effect = lambda _key, name: native.stored.pop(name)
    monkeypatch.setattr(payload.registry, "open_key", native.open)
    monkeypatch.setattr(payload.registry, "set_value", native.write)
    monkeypatch.setattr(payload.registry, "delete_value", native.delete)
    monkeypatch.setattr(payload.registry, "delete_tree", native.tree)
    monkeypatch.setattr(payload, "read_value", _read)
    return native


def _edit(payload: ModuleType, check: bool = False, **arguments: Any) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        payload._edit(payload._parameters({"path": PATH, **arguments}), check),
    )


@pytest.mark.parametrize(
    "kind,data,converted",
    [
        ("string", "text", "text"),
        ("expandstring", "%TEMP%", "%TEMP%"),
        ("multistring", ["One", "two"], ["One", "two"]),
        ("binary", "hex:be,ef", [190, 239]),
        ("none", [0, 255], [0, 255]),
        ("dword", 4294967295, -1),
        ("qword", "0xffffffffffffffff", -1),
    ],
)
def test_create_then_repeat_and_preview_change(
    payload: ModuleType, native: SimpleNamespace, kind: str, data: Any, converted: Any
) -> None:
    created = _edit(payload, name="entry", type=kind, data=data)
    assert created == {
        "changed": True,
        "data_changed": False,
        "data_type_changed": False,
        "diff": {
            "before": {PATH: {}},
            "after": {PATH: {"entry": payload.values.diff_value(kind, converted)}},
        },
    }
    native.write.assert_called_once_with(native.key, "entry", kind, converted)
    repeated = _edit(payload, name="entry", type=kind, data=data)
    assert not repeated["changed"] and not repeated["data_changed"]
    assert repeated["diff"]["before"] == repeated["diff"]["after"]
    preview = _edit(payload, True, name="entry", type="string", data="different")
    assert preview["changed"] and preview["data_changed"]
    assert preview["data_type_changed"] == (kind != "string")
    assert native.write.call_count == 1
    assert native.key.Close.call_count == 3


@pytest.mark.parametrize("check", [False, True])
def test_missing_key_prediction_stops_before_value_diff(
    payload: ModuleType, native: SimpleNamespace, check: bool
) -> None:
    native.exists = False
    result = _edit(payload, check, name="value", data="text")
    after = {} if check else {"value": {"type": "String", "value": "text"}}
    assert result["diff"] == {"before": {}, "after": {PATH: after}}
    assert result["changed"] and not result["data_changed"]
    assert native.exists is not check
    assert native.write.call_count == (0 if check else 1)


@pytest.mark.parametrize("data", [None, "", "default"])
def test_default_value_and_key_only(
    payload: ModuleType, native: SimpleNamespace, data: Any
) -> None:
    result = _edit(payload, data=data)
    assert result["changed"] == (data is not None)
    assert native.write.call_count == (0 if data is None else 1)
    if data is not None:
        assert native.stored[""] == (data, 1)


@pytest.mark.parametrize(
    "name,warning", [(None, True), ("", False), ("(Default)", False)]
)
def test_nonstring_default_requires_explicit_empty_name(
    payload: ModuleType, native: SimpleNamespace, name: Any, warning: bool
) -> None:
    result = _edit(payload, name=name, type="dword", data=42)
    assert bool(result.get("warnings")) is warning
    assert native.write.call_args.args[2] == ("string" if warning else "dword")


@pytest.mark.parametrize(
    "case",
    [
        ("One", "string", False, False),
        ("one", "string", True, False),
        ("One", "expandstring", False, True),
        (["one"], "multistring", True, True),
    ],
)
def test_existing_value_flags_are_independent(
    payload: ModuleType,
    native: SimpleNamespace,
    case: tuple[Any, str, bool, bool],
) -> None:
    data, kind, data_changed, type_changed = case
    native.stored["name"] = ("One", 1)
    result = _edit(payload, True, name="name", type=kind, data=data)
    assert result["data_changed"] is data_changed
    assert result["data_type_changed"] is type_changed
    assert result["changed"] == (data_changed or type_changed)
    native.write.assert_not_called()


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("state", ["present", "absent"])
def test_readable_legacy_kind_can_be_replaced_or_removed(
    payload: ModuleType, native: SimpleNamespace, check: bool, state: str
) -> None:
    native.stored["name"] = ([0, 0, 0, 1], 5)
    result = _edit(payload, check, name="name", state=state, type="dword", data=42)
    assert result["changed"] is True
    assert not result.get("failed")
    assert result["data_changed"] is (state == "present")
    assert result["data_type_changed"] is (state == "present")
    assert result["diff"]["before"] == {
        PATH: {"name": {"type": "Unknown", "value": [0, 0, 0, 1]}}
    }
    after = {"name": {"type": "DWord", "value": "0x0000002a"}}
    assert result["diff"]["after"] == {PATH: after if state == "present" else {}}
    assert native.write.call_count == int(not check and state == "present")
    assert native.delete.call_count == int(not check and state == "absent")
    if check:
        assert native.stored["name"] == ([0, 0, 0, 1], 5)
    elif state == "present":
        assert native.stored["name"] == (42, 4)
    else:
        assert "name" not in native.stored


def test_multistring_case_only_does_not_write(
    payload: ModuleType, native: SimpleNamespace
) -> None:
    native.stored["name"] = (["One", "TWO"], 7)
    result = _edit(payload, name="name", type="multistring", data=["one", "two"])
    assert not result["changed"]
    assert result["diff"]["after"][PATH]["name"]["value"] == ["One", "TWO"]
    native.write.assert_not_called()


@pytest.mark.parametrize(
    "case",
    [
        (exists, delete_key, name, check)
        for exists in (False, True)
        for delete_key in (False, True)
        for name in (None, "entry")
        for check in (False, True)
    ],
)
def test_absent_key_value_and_preview(
    payload: ModuleType,
    native: SimpleNamespace,
    case: tuple[bool, bool, Any, bool],
) -> None:
    exists, delete_key, name, check = case
    native.exists = exists
    native.stored[name or ""] = ("old", 1)
    result = _edit(payload, check, name=name, state="absent", delete_key=delete_key)
    assert result["changed"] is exists
    assert not result["data_changed"] and not result["data_type_changed"]
    tree = delete_key and name is None
    assert native.tree.call_count == int(exists and tree and not check)
    assert native.delete.call_count == int(exists and not tree and not check)
    if not exists:
        assert result["diff"] == {"before": "", "after": ""}
    elif tree:
        assert result["diff"] == {"before": {PATH: {}}, "after": {}}
    else:
        assert result["diff"]["after"] == {PATH: {}}


def test_absent_expand_diff_is_expanded(
    payload: ModuleType, native: SimpleNamespace
) -> None:
    native.stored["name"] = ("%TEMP%", 2)
    result = _edit(payload, True, name="name", state="absent")
    assert result["diff"]["before"][PATH]["name"] == {
        "type": "ExpandString",
        "value": r"C:\Temp",
    }


@pytest.mark.parametrize(
    "existing,key_exists", [(False, False), (False, True), (True, True)]
)
def test_write_failure_retains_partial_key_change_and_comparison_flags(
    payload: ModuleType, native: SimpleNamespace, existing: bool, key_exists: bool
) -> None:
    native.exists = key_exists
    if existing:
        native.stored["name"] = ("before", 1)
    native.write.side_effect = OSError("access denied")
    result = _edit(payload, name="name", type="expandstring", data="after")
    assert result["failed"]
    assert result["changed"] is not key_exists
    assert result["data_changed"] is existing
    assert result["data_type_changed"] is existing
    assert "access denied" in result["msg"]
    native.key.Close.assert_called_once()


@pytest.mark.parametrize("state", ["present", "absent"])
def test_explicit_data_validation_precedes_registry_access(
    payload: ModuleType, native: SimpleNamespace, state: str
) -> None:
    result = _edit(payload, name="name", type="dword", data=1.5, state=state)
    assert result["failed"] and result["data_changed"] is False
    assert result["diff"] == {"before": "", "after": ""}
    assert "remainder" in result["msg"]
    native.open.assert_not_called()


def test_aliases_overwrite_canonical_values_including_null(payload: ModuleType) -> None:
    result = payload._parameters(
        {
            "path": "wrong",
            "key": PATH,
            "name": "canonical",
            "entry": "entry",
            "value": None,
            "type": "string",
            "datatype": "DWORD",
        }
    )
    assert (
        result["path"] == PATH and result["name"] is None and result["type"] == "dword"
    )


@pytest.mark.parametrize(
    "name,value",
    [
        ("type", "unknown"),
        ("state", "unknown"),
        ("delete_key", "unknown"),
        ("hive", "bad|path"),
    ],
)
def test_validation_rejects_invalid_options(
    payload: ModuleType, name: str, value: Any
) -> None:
    with pytest.raises(ValueError):
        payload._parameters({"path": PATH, name: value})


@pytest.mark.parametrize(
    "check,fails", [(False, False), (True, False), (False, True), (True, True)]
)
def test_hive_always_unloads_after_operation(
    payload: ModuleType,
    native: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    check: bool,
    fails: bool,
) -> None:
    mount = Mock(return_value=True)
    unload = Mock()
    monkeypatch.setattr(payload, "_mount_hive", mount)
    monkeypatch.setattr(payload.registry, "unload_hive", unload)
    if fails:
        native.open.side_effect = OSError("access denied")
        with pytest.raises(OSError):
            _edit(payload, check, name="value", hive=r"C:\owned.hive")
    else:
        _edit(payload, check, name="value", hive=r"C:\owned.hive")
    mount.assert_called_once()
    unload.assert_called_once()


@pytest.mark.parametrize("diff", [False, True])
# The JSON boundary needs the argument-file, capture, and native fixtures together.
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def test_json_entrypoint_filters_diff(
    payload: ModuleType,
    native: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    diff: bool,
) -> None:
    argument_file = tmp_path / "args.json"
    argument_file.write_text(
        json.dumps(
            {"PATH": PATH, "NAME": "name", "data": "value", "_ansible_diff": diff}
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["win_regedit.py", str(argument_file)])
    code, result = invoke_payload(payload, capsys)
    assert code == 0 and result["changed"]
    assert ("diff" in result) is diff
    assert native.stored["name"] == ("value", 1)
