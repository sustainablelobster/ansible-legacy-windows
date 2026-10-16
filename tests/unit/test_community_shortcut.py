"""Observe shortcut state transitions while substituting native COM objects."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Private argument binders/native hotkey conversion form the request contract.
# pylint: disable=protected-access

import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module


@pytest.fixture(name="payload")
def shortcut_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load shortcut management with a stateful native boundary substitute.

    :param monkeypatch: Scoped imports and shortcut object substitution.
    :returns: Loaded shortcut frontend.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(
        str(ROOT / "legacy_community_windows/plugins/module_utils")
    )
    module = load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_shortcut.py",
        "tested_community_shortcut",
    )
    stored: dict[str, dict[str, object]] = {}

    # The private double mirrors the COM object's methods; the observable
    # transition assertions below specify its test contract.
    # pylint: disable=missing-function-docstring,missing-return-doc
    class _Shortcut:
        def __init__(self, path: str) -> None:
            self.path = path
            self.url = path.endswith(".url")
            self.values: dict[str, object] = dict(
                stored.get(
                    path,
                    {
                        "src": "",
                        "args": "",
                        "directory": "",
                        "hotkey": "",
                        "icon": ",0",
                        "description": "",
                        "windowstyle": "normal",
                        "run_as_admin": False,
                    },
                )
            )

        def __enter__(self) -> "_Shortcut":
            return self

        def __exit__(self, *_arguments: object) -> None:
            return None

        def read(self) -> dict[str, object]:
            return {"src": self.values["src"]} if self.url else dict(self.values)

        def set(self, name: str, value: object) -> None:
            self.values[name] = value

        def matches_source(self, source: str) -> bool:
            return self.values["src"] == source

        def save(self) -> None:
            stored[self.path] = dict(self.values)
            Path(self.path).write_bytes(b"native substitute")

    # pylint: enable=missing-function-docstring,missing-return-doc
    monkeypatch.setattr(module, "Shortcut", _Shortcut)
    return module


def _apply(payload: ModuleType, destination: Path, **options: object) -> dict[str, Any]:
    check_mode = options.pop("check", False)
    result: dict[str, Any] = payload._manage(
        payload._parameters({"dest": str(destination), **options}), check_mode
    )
    return result


def test_application_create_repeat_update_delete(
    payload: ModuleType, tmp_path: Path
) -> None:
    destination = tmp_path / "application.lnk"
    options = {
        "src": "C:\\Windows\\cmd.exe",
        "args": "/k echo ready",
        "directory": "C:\\Windows",
        "description": "Café 雪",
        "icon": "C:\\Windows\\cmd.exe,0",
        "hotkey": "Ctrl+Alt+F",
        "windowstyle": "maximized",
    }
    result = _apply(payload, destination, **options)
    assert result["changed"] is True
    assert destination.exists()
    for name, value in options.items():
        assert result[name] == value
    assert _apply(payload, destination, **options)["changed"] is False
    assert _apply(payload, destination, description="updated")["changed"] is True
    assert _apply(payload, destination, state="absent")["changed"] is True
    assert not destination.exists()
    assert _apply(payload, destination, state="absent")["changed"] is False


def test_url_only_manages_target(payload: ModuleType, tmp_path: Path) -> None:
    destination = tmp_path / "website.url"
    result = _apply(
        payload,
        destination,
        src="https://example.test/",
        arguments="ignored",
        run_as_admin=True,
    )
    assert result == {
        "changed": True,
        "dest": str(destination),
        "state": "present",
        "src": "https://example.test/",
    }
    assert _apply(payload, destination, src="https://example.test/")["changed"] is False


def test_shell_namespace_targets_are_compared_by_identity(
    payload: ModuleType, tmp_path: Path
) -> None:
    destination = tmp_path / "recycle.lnk"
    assert _apply(payload, destination, src="shell:RecycleBinFolder")["changed"] is True
    result = _apply(payload, destination, src="shell:RecycleBinFolder")
    assert result["changed"] is False
    assert result["src"] == "shell:RecycleBinFolder"
    assert _apply(payload, destination, src="shell:Start Menu")["changed"] is True


def test_check_mode_does_not_create_update_or_change_admin_flag(
    payload: ModuleType, tmp_path: Path
) -> None:
    destination = tmp_path / "application.lnk"
    result = _apply(payload, destination, src="C:\\application.exe", check=True)
    assert result["changed"] is True
    assert not destination.exists()
    _apply(payload, destination, src="C:\\application.exe")
    original = destination.read_bytes()
    assert (
        _apply(payload, destination, run_as_admin=True, check=True)["changed"] is True
    )
    assert destination.read_bytes() == original
    assert _apply(payload, destination)["changed"] is False
    assert _apply(payload, destination, state="absent", check=True)["changed"] is True
    assert destination.exists()


def test_admin_flag_can_be_set_repeated_and_cleared(
    payload: ModuleType, tmp_path: Path
) -> None:
    destination = tmp_path / "application.lnk"
    assert (
        _apply(payload, destination, src="C:\\application.exe", run_as_admin=True)[
            "changed"
        ]
        is True
    )
    assert _apply(payload, destination, run_as_admin=True)["changed"] is False
    assert _apply(payload, destination)["changed"] is True
    assert _apply(payload, destination)["changed"] is False


def test_environment_expansion_and_argument_alias(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SHORTCUT_FIXTURE", "C:\\Fixture")
    options = payload._parameters(
        {
            "dest": "%SHORTCUT_FIXTURE%\\file.lnk",
            "src": "%SHORTCUT_FIXTURE%\\app.exe",
            "args": "%SHORTCUT_FIXTURE%",
            "description": "%SHORTCUT_FIXTURE%",
            "directory": "%SHORTCUT_FIXTURE%",
            "icon": "%SHORTCUT_FIXTURE%\\app.exe,0",
        }
    )
    assert options["dest"] == "C:\\Fixture\\file.lnk"
    assert options["src"] == "C:\\Fixture\\app.exe"
    assert options["args"] == "C:\\Fixture"
    assert options["description"] == "C:\\Fixture"
    assert options["directory"] == "C:\\Fixture"


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({}, "dest"),
        ({"dest": "file.lnk", "state": "invalid"}, "state"),
        ({"dest": "file.lnk", "windowstyle": "invalid"}, "windowstyle"),
    ],
)
def test_invalid_arguments_fail_before_native_calls(
    payload: ModuleType, arguments: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        payload._parameters(arguments)


def test_invalid_destination_extension_is_actionable(
    payload: ModuleType, tmp_path: Path
) -> None:
    with pytest.raises(ValueError, match=".lnk or .url"):
        _apply(payload, tmp_path / "invalid.txt", src="C:\\application.exe")


@pytest.mark.parametrize(
    "value,expected",
    [
        ("", 0),
        ("Ctrl+Alt+F", ord("F") | (6 << 8)),
        ("alt+ctrl+f", ord("F") | (6 << 8)),
        ("Shift+F12", 123 | (1 << 8)),
        ("Ext+9", ord("9") | (8 << 8)),
    ],
)
@pytest.mark.usefixtures("payload")
def test_native_hotkey_word_conversion(value: str, expected: int) -> None:
    native = sys.modules["legacy_community_windows_shortcut"]
    assert native._hotkey(value) == expected
    assert native._hotkey(native._hotkey_text(expected)) == expected


@pytest.mark.parametrize("value", ["Unknown+F", "Ctrl+", "Ctrl+LongName", "F25"])
@pytest.mark.usefixtures("payload")
def test_invalid_hotkeys_fail_explicitly(value: str) -> None:
    native = sys.modules["legacy_community_windows_shortcut"]
    with pytest.raises(ValueError, match="hotkey"):
        native._hotkey(value)


@pytest.mark.usefixtures("payload")
def test_native_shell_interfaces_are_created_in_sta(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    native = sys.modules["legacy_community_windows_shortcut"]
    ole = Mock()
    ole.CoInitializeEx.return_value = 0
    ole.CoCreateInstance.return_value = 0
    monkeypatch.setattr(native, "_libraries", lambda: (ole, Mock()))
    monkeypatch.setattr(native, "_release", lambda _pointer: None)
    monkeypatch.setattr(native.Shortcut, "_interface", lambda *_arguments: None)
    with native.Shortcut(str(tmp_path / "application.lnk")):
        ole.CoInitializeEx.assert_called_once_with(None, 2)
    ole.CoUninitialize.assert_called_once_with()
