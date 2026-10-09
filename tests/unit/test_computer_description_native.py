"""Test description writes and registration access without changing Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later

from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.fixture(name="helper")
def computer_description_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the target helper with scoped sibling imports.

    :param monkeypatch: Scoped module search path.
    :returns: Fresh native helper without opening Windows resources.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    return load_module(
        ROOT / "plugins/module_utils/legacy_windows_computer_description.py",
        "tested_computer_description_native",
    )


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def _connection(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Mock:
    context = MagicMock()
    connection = Mock()
    context.__enter__.return_value = connection
    monkeypatch.setattr(helper, "WmiConnection", Mock(return_value=context))
    return connection


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.mark.parametrize("value", [None, "", "case-sensitive 雪"])
def test_reads_description_without_normalizing_provider_value(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, value: str | None
) -> None:
    connection = _connection(helper, monkeypatch)
    connection.query.return_value = [{"Description": value}]
    assert helper.read_description() == value
    connection.query.assert_called_once_with(
        "SELECT Description FROM Win32_OperatingSystem", ["Description"]
    )


# pylint: enable=duplicate-code


def test_absent_operating_system_is_actionable(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = _connection(helper, monkeypatch)
    connection.query.return_value = []
    with pytest.raises(OSError, match="no Win32_OperatingSystem"):
        helper.read_description()


@pytest.mark.parametrize("value", [None, "", "description 雪😀"])
def test_updates_only_the_locatable_description_property(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, value: str | None
) -> None:
    connection = _connection(helper, monkeypatch)
    connection.query.return_value = [{"__PATH": "Win32_OperatingSystem=@"}]
    helper.write_description(value)
    connection.set_string_property.assert_called_once_with(
        "Win32_OperatingSystem=@", "Description", value
    )


@pytest.mark.parametrize("rows", [[], [{"__PATH": None}], [{"__PATH": ""}]])
def test_missing_description_identity_never_updates_provider(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, rows: list[dict[str, object]]
) -> None:
    connection = _connection(helper, monkeypatch)
    connection.query.return_value = rows
    with pytest.raises(OSError, match="no locatable"):
        helper.write_description("new")
    connection.set_string_property.assert_not_called()


@pytest.fixture(name="registry")
def native_registry(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> SimpleNamespace:
    """Replace registry boundaries with observable native-view operations.

    :param helper: Fresh target helper.
    :param monkeypatch: Scoped native module replacement.
    :returns: Mock registry constants, open key, getter, and setter.
    """
    key = MagicMock()
    key.__enter__.return_value = 71
    registry = SimpleNamespace(
        HKEY_LOCAL_MACHINE=0x80000002,
        KEY_QUERY_VALUE=1,
        KEY_SET_VALUE=2,
        KEY_WOW64_64KEY=0x100,
        REG_SZ=1,
        OpenKey=Mock(return_value=key),
        QueryValueEx=Mock(return_value=("original", 1)),
        SetValueEx=Mock(),
    )
    monkeypatch.setattr(helper, "winreg", registry)
    return registry


def test_registration_reads_native_view_and_preserves_case(
    helper: ModuleType, registry: SimpleNamespace
) -> None:
    assert helper.read_registration("RegisteredOwner") == "original"
    registry.OpenKey.assert_called_once_with(
        registry.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        0,
        0x101,
    )
    registry.QueryValueEx.assert_called_once_with(71, "RegisteredOwner")


@pytest.mark.parametrize("name", ["RegisteredOwner", "RegisteredOrganization"])
def test_missing_registration_matches_measured_failure(
    helper: ModuleType, registry: SimpleNamespace, name: str
) -> None:
    error = FileNotFoundError("missing")
    setattr(error, "winerror", 2)
    registry.QueryValueEx.side_effect = error
    with pytest.raises(ValueError) as raised:
        helper.read_registration(name)
    assert str(raised.value) == (
        f"Unhandled exception while executing module: Property {name} does not "
        "exist at path HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\"
        "CurrentVersion\\."
    )
    registry.SetValueEx.assert_not_called()


def test_registration_read_access_error_is_not_treated_as_absence(
    helper: ModuleType, registry: SimpleNamespace
) -> None:
    error = PermissionError(13, "denied")
    registry.QueryValueEx.side_effect = error
    with pytest.raises(PermissionError):
        helper.read_registration("RegisteredOwner")


def test_registration_write_uses_native_view_and_string_kind(
    helper: ModuleType, registry: SimpleNamespace
) -> None:
    helper.write_registration("RegisteredOrganization", "organization 雪")
    registry.OpenKey.assert_called_once_with(
        registry.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        0,
        0x102,
    )
    registry.SetValueEx.assert_called_once_with(
        71, "RegisteredOrganization", 0, registry.REG_SZ, "organization 雪"
    )


def test_registration_requires_windows(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper, "winreg", None)
    with pytest.raises(OSError, match="requires a Windows target"):
        helper.read_registration("RegisteredOwner")
    with pytest.raises(OSError, match="requires a Windows target"):
        helper.write_registration("RegisteredOwner", "new")
