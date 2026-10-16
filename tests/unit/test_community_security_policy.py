"""Exercise security-policy exports, narrow imports, verification and cleanup."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Tests substitute only the native executable boundary.
# pylint: disable=protected-access

import codecs
from pathlib import Path
from types import ModuleType
from typing import Any, cast
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module


@pytest.fixture(name="payload")
def fixture_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load security policy without accessing a real Windows policy database.

    :param monkeypatch: Scoped import paths and executable lookup.
    :returns: Imported target module.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    module = load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_security_policy.py",
        "tested_community_security_policy",
    )
    existing = module.os.path.isfile
    monkeypatch.setattr(
        module.os.path,
        "isfile",
        lambda path: str(path).endswith("secedit.exe") or existing(path),
    )
    return module


@pytest.fixture(name="native")
def fixture_native(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> dict[str, Any]:
    """Provide a stateful secedit boundary which writes real Unicode INF files.

    :param payload: Imported target module.
    :param monkeypatch: Scoped command substitution.
    :returns: Policy state, calls, staged paths and configurable failure state.
    """
    state: dict[str, Any] = {
        "policy": {"MaximumPasswordAge": 42, "NewGuestName": "Guest"},
        "calls": [],
        "paths": [],
        "failure": None,
    }

    def _invoke(
        _executable: str, arguments: list[str], temporary: str
    ) -> dict[str, Any]:
        state["calls"].append(arguments)
        state["paths"].append(Path(temporary))
        result = {
            "rc": 0,
            "stdout": "native output",
            "stderr": "",
            "log": "configuration log",
        }
        if state["failure"] == arguments[0]:
            return dict(result, rc=17, stderr="native refusal")
        path = Path(arguments[arguments.index("/cfg") + 1])
        if arguments[0] == "/export":
            assert path.read_bytes().startswith(codecs.BOM_UTF16_LE)
            content = "[Unicode]\nUnicode=yes\n[System Access]\n" + "\n".join(
                f"{key} = {value}" for key, value in state["policy"].items()
            )
            path.write_text(content, encoding="utf-16")
        else:
            assert arguments[0] == "/configure"
            assert not Path(arguments[arguments.index("/db") + 1]).exists()
            imported = payload._parse(path.read_text(encoding="utf-16"))
            assert set(imported) == {"Unicode", "Version", "System Access"}
            assert len(imported["System Access"]) == 1
            state["imported"] = imported
            for key, value in imported["System Access"].items():
                if key in state["policy"]:
                    state["policy"][key] = value
        return result

    monkeypatch.setattr(payload, "_invoke", _invoke)
    return state


def test_create_repeat_case_matching_and_narrow_import(
    payload: ModuleType, native: dict[str, Any]
) -> None:
    options = {
        "section": "system access",
        "key": "MaximumPasswordAge",
        "value": "43",
        "_ansible_diff": True,
    }
    changed = payload._configure(options)
    assert changed["changed"] is True
    assert changed["import_log"] == "configuration log"
    assert (
        changed["diff"]["prepared"]
        == "[system access]\n-MaximumPasswordAge = 42\n+MaximumPasswordAge = 43"
    )
    assert native["policy"] == {"MaximumPasswordAge": 43, "NewGuestName": "Guest"}
    assert native["imported"]["System Access"] == {"MaximumPasswordAge": 43}
    assert payload._configure(options)["changed"] is False
    assert len([call for call in native["calls"] if call[0] == "/configure"]) == 1
    assert all(not path.exists() for path in native["paths"])


def test_check_mode_exports_but_never_configures(
    payload: ModuleType, native: dict[str, Any]
) -> None:
    result = payload._configure(
        {
            "section": "System Access",
            "key": "MaximumPasswordAge",
            "value": 43,
            "_ansible_check_mode": True,
        }
    )
    assert result == {
        "changed": True,
        "section": "System Access",
        "key": "MaximumPasswordAge",
        "value": 43,
    }
    assert native["policy"]["MaximumPasswordAge"] == 42
    assert [call[0] for call in native["calls"]] == ["/export"]
    assert all(not path.exists() for path in native["paths"])


@pytest.mark.parametrize("value", [42, "42", "042", "0x2a"])
def test_integer_comparison_uses_exported_policy_type(
    payload: ModuleType, native: dict[str, Any], value: Any
) -> None:
    assert (
        payload._configure(
            {"section": "System Access", "key": "MaximumPasswordAge", "value": value}
        )["changed"]
        is False
    )
    assert len(native["calls"]) == 1


def test_unicode_policy_and_result_input_type_are_retained(
    payload: ModuleType, native: dict[str, Any]
) -> None:
    options = {"section": "System Access", "key": "NewGuestName", "value": "Café 雪"}
    assert payload._configure(options)["value"] == "Café 雪"
    assert native["policy"]["NewGuestName"] == "Café 雪"
    assert payload._configure(options)["changed"] is False


def test_missing_section_is_not_imported(
    payload: ModuleType, native: dict[str, Any]
) -> None:
    result = payload._configure(
        {"section": "Not A Policy", "key": "Unknown", "value": 1}
    )
    assert result["failed"] is True and result["changed"] is False
    assert "does not exist" in result["msg"]
    assert len(native["calls"]) == 1


def test_invalid_key_is_rejected_after_native_verification(
    payload: ModuleType, native: dict[str, Any]
) -> None:
    result = payload._configure(
        {"section": "System Access", "key": "NotAPolicy", "value": 1}
    )
    assert result["failed"] is True and result["changed"] is True
    assert "not a valid key" in result["msg"]
    assert [call[0] for call in native["calls"]] == ["/export", "/configure", "/export"]
    assert all(not path.exists() for path in native["paths"])


def test_absent_key_with_empty_value_is_unchanged(
    payload: ModuleType, native: dict[str, Any]
) -> None:
    result = payload._configure(
        {"section": "System Access", "key": "NotAPolicy", "value": ""}
    )
    assert result["changed"] is False
    assert len(native["calls"]) == 1


@pytest.mark.parametrize("command,changed", [("/export", False), ("/configure", True)])
def test_command_failures_keep_native_diagnostics_and_change_state(
    payload: ModuleType, native: dict[str, Any], command: str, changed: bool
) -> None:
    native["failure"] = command
    result = payload._configure(
        {"section": "System Access", "key": "MaximumPasswordAge", "value": 43}
    )
    assert result["failed"] is True and result["changed"] is changed
    assert result["rc"] == 17 and result["stderr"] == "native refusal"
    if changed:
        assert result["import_log"] == "configuration log"
    assert all(not path.exists() for path in native["paths"])


@pytest.mark.parametrize(
    "values",
    [
        {},
        {"section": "System Access", "key": ""},
        {"section": "bad\nsection", "key": "key", "value": 0},
    ],
)
def test_invalid_arguments_fail_before_policy_access(
    payload: ModuleType, native: dict[str, Any], values: dict[str, Any]
) -> None:
    with pytest.raises(ValueError):
        payload._configure(values)
    assert not native["calls"]


def test_ini_parser_preserves_native_values_and_quotes(payload: ModuleType) -> None:
    assert payload._parse(
        '; comment\n[System Access]\nNumber = 12\nName = "Café 雪"\n'
        'Negative = -1\n[Registry Values]\nMachine\\Key=7,"a","b"'
    ) == {
        "System Access": {"Number": 12, "Name": "Café 雪", "Negative": "-1"},
        "Registry Values": {"Machine\\Key": '7,"a","b"'},
    }


def test_native_command_preserves_unicode_output_and_log(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    process = MagicMock()
    process.__enter__.return_value = process
    process.communicate.return_value = (
        codecs.BOM_UTF16_LE + "native 雪".encode("utf-16-le"),
        b"",
    )
    process.returncode = 19

    def _popen(arguments: list[str], **_keywords: Any) -> Any:
        assert arguments[:2] == ["secedit.exe", "/export"]
        assert arguments[-2] == "/log"
        Path(arguments[-1]).write_text("  log 雪\r\ncomplete\r\n", encoding="utf-16")
        return process

    monkeypatch.setattr(payload.subprocess, "Popen", _popen)
    assert payload._invoke("secedit.exe", ["/export"], str(tmp_path)) == {
        "rc": 19,
        "stdout": "native 雪",
        "stderr": "",
        "log": "log 雪\ncomplete",
    }
    process.__exit__.assert_called_once()


def test_legal_notice_workaround_removes_only_trailing_nulls(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = MagicMock()
    registry.KEY_QUERY_VALUE = 1
    registry.KEY_SET_VALUE = 2
    registry.QueryValueEx.return_value = ("Café\0middle\0\0", 1)
    monkeypatch.setattr(payload, "winreg", registry)
    payload._trim_legal_notice()
    registry.SetValueEx.assert_called_once_with(
        registry.OpenKey.return_value.__enter__.return_value,
        "LegalNoticeText",
        0,
        1,
        "Café\0middle",
    )
    registry.SetValueEx.reset_mock()
    registry.QueryValueEx.side_effect = FileNotFoundError()
    payload._trim_legal_notice()
    registry.SetValueEx.assert_not_called()


def test_policy_readback_rejects_native_coercion(
    payload: ModuleType, native: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    original = payload._invoke

    def _invoke(
        executable: str, arguments: list[str], temporary: str
    ) -> dict[str, Any]:
        result = original(executable, arguments, temporary)
        if arguments[0] == "/configure":
            native["policy"]["MaximumPasswordAge"] = 42
        return cast(dict[str, Any], result)

    monkeypatch.setattr(payload, "_invoke", Mock(side_effect=_invoke))
    result = payload._configure(
        {"section": "System Access", "key": "MaximumPasswordAge", "value": 43}
    )
    assert result["failed"] is True and result["changed"] is True
    assert "value is still 42" in result["msg"]


@pytest.mark.parametrize("access_denied", [False, True])
def test_unrelated_policy_never_reads_or_changes_existing_legal_notice(
    payload: ModuleType,
    native: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    access_denied: bool,
) -> None:
    registry = MagicMock()
    registry.QueryValueEx.return_value = ("untouched notice\0\0", 1)
    if access_denied:
        registry.OpenKey.side_effect = PermissionError("notice ACL denies access")
    monkeypatch.setattr(payload, "winreg", registry)
    result = payload._configure(
        {"section": "System Access", "key": "MaximumPasswordAge", "value": 43}
    )
    assert result["changed"] is True and not result.get("failed")
    assert native["policy"]["MaximumPasswordAge"] == 43
    registry.OpenKey.assert_not_called()
    registry.QueryValueEx.assert_not_called()
    registry.SetValueEx.assert_not_called()


@pytest.mark.parametrize("upper_case", [False, True])
def test_only_requested_legal_notice_is_normalized_after_import(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    upper_case: bool,
) -> None:
    section = "REGISTRY VALUES" if upper_case else "registry values"
    key = r"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText"
    key = key.upper() if upper_case else key.lower()
    desired = '7,"Café"'
    monkeypatch.setattr(
        payload,
        "_export",
        Mock(
            side_effect=[
                ({section: {key: '7,"old"'}}, {"rc": 0}),
                ({section: {key: desired}}, {"rc": 0}),
            ]
        ),
    )
    monkeypatch.setattr(
        payload, "_invoke", Mock(return_value={"rc": 0, "log": "configured"})
    )
    registry = MagicMock()
    registry.KEY_QUERY_VALUE, registry.KEY_SET_VALUE = 1, 2
    registry.QueryValueEx.return_value = ("Café\0\0", 1)
    monkeypatch.setattr(payload, "winreg", registry)
    result = payload._configure(
        {
            "section": section,
            "key": key,
            "value": desired,
        }
    )
    assert result["changed"] is True and not result.get("failed")
    registry.SetValueEx.assert_called_once_with(
        registry.OpenKey.return_value.__enter__.return_value,
        "LegalNoticeText",
        0,
        1,
        "Café",
    )


def test_other_registry_value_does_not_normalize_legal_notice(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    section = "Registry Values"
    key = r"MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeTextOther"
    monkeypatch.setattr(
        payload,
        "_export",
        Mock(
            side_effect=[
                ({section: {key: "1,old"}}, {"rc": 0}),
                ({section: {key: "1,new"}}, {"rc": 0}),
            ]
        ),
    )
    monkeypatch.setattr(
        payload, "_invoke", Mock(return_value={"rc": 0, "log": "configured"})
    )
    trim = Mock(side_effect=AssertionError("unrelated notice must not be read"))
    monkeypatch.setattr(payload, "_trim_legal_notice", trim)
    result = payload._configure({"section": section, "key": key, "value": "1,new"})
    assert result["changed"] is True and not result.get("failed")
    trim.assert_not_called()
