"""Exercise native hostname reads and rename requests without a Windows host."""

# SPDX-License-Identifier: GPL-3.0-or-later

from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import ROOT, load_module

ACTIVE = "Active-Dns-Name"
OBJECT_PATH = r'\\ACTIVE-NETBIOS\ROOT\CIMV2:Win32_ComputerSystem.Name="ACTIVE-NETBIOS"'
EMPTY_NAME = (
    "Cannot validate argument on parameter 'NewName'. The argument is null or "
    "empty. Provide an argument that is not null or empty, and then try the "
    "command again."
)


@pytest.fixture(name="helper")
def hostname_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Import the standalone target helper without making native calls.

    :param monkeypatch: Scoped adjacent-helper import path.
    :returns: Fresh target helper loaded by the development interpreter.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    return load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_hostname.py",
        "tested_hostname_native",
    )


@pytest.fixture(name="native")
def hostname_boundaries(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Record provider ownership and native hostname/error requests.

    :param helper: Imported target helper.
    :param monkeypatch: Scoped Windows, Winsock, and WMI substitutes.
    :returns: Configurable native results and call recorders.
    """
    connection = Mock()
    connection.query.return_value = [{"DNSHostName": ACTIVE, "__PATH": OBJECT_PATH}]
    connection.call_method.return_value = {"ReturnValue": 0}
    context = MagicMock()
    context.__enter__.return_value = connection
    context.__exit__.return_value = False
    native = SimpleNamespace(
        connection=connection,
        context=context,
        open=Mock(return_value=context),
        version=Mock(return_value=SimpleNamespace(major=10, minor=0)),
        hostname=Mock(return_value=ACTIVE),
        format_error=Mock(return_value="Access is denied.\r\n"),
    )
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        helper, "sys", SimpleNamespace(getwindowsversion=native.version)
    )
    monkeypatch.setattr(helper, "socket", SimpleNamespace(gethostname=native.hostname))
    monkeypatch.setattr(
        helper, "ctypes", SimpleNamespace(FormatError=native.format_error)
    )
    monkeypatch.setattr(helper, "WmiConnection", native.open)
    return native


@pytest.mark.parametrize("version", [(5, 2), (6, 0), (6, 1), (10, 0)])
def test_read_uses_provider_spelling_on_server_2003_and_newer(
    helper: ModuleType, native: Any, version: tuple[int, int]
) -> None:
    native.version.return_value = SimpleNamespace(major=version[0], minor=version[1])
    native.connection.query.return_value = [{"DNSHostName": "Mixed-Case-Provider"}]
    assert helper.read_hostname() == "Mixed-Case-Provider"
    native.connection.query.assert_called_once_with(
        "SELECT DNSHostName FROM Win32_ComputerSystem", ["DNSHostName"]
    )
    native.context.__exit__.assert_called_once_with(None, None, None)
    native.hostname.assert_not_called()
    native.connection.call_method.assert_not_called()


def test_xp_uses_native_dns_name_without_unsupported_wmi_property(
    helper: ModuleType, native: Any
) -> None:
    native.version.return_value = SimpleNamespace(major=5, minor=1)
    native.hostname.return_value = "xp-Lowercase-Dns"
    assert helper.read_hostname() == "xp-Lowercase-Dns"
    native.hostname.assert_called_once_with()
    native.open.assert_not_called()


def test_xp_native_read_failure_is_not_hidden(helper: ModuleType, native: Any) -> None:
    native.version.return_value = SimpleNamespace(major=5, minor=1)
    error = OSError("Winsock hostname failed")
    native.hostname.side_effect = error
    with pytest.raises(OSError) as raised:
        helper.read_hostname()
    assert raised.value is error
    native.open.assert_not_called()


def test_non_windows_read_fails_before_native_operations(
    helper: ModuleType, native: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="posix"))
    with pytest.raises(OSError, match="require a Windows target"):
        helper.read_hostname()
    native.version.assert_not_called()
    native.hostname.assert_not_called()
    native.open.assert_not_called()


@pytest.mark.parametrize("rows", [[], [{"DNSHostName": None}], [{"DNSHostName": 7}]])
def test_missing_provider_hostname_closes_connection_without_fallback(
    helper: ModuleType, native: Any, rows: list[dict[str, Any]]
) -> None:
    native.connection.query.return_value = rows
    with pytest.raises(OSError, match="no Win32_ComputerSystem DNS hostname"):
        helper.read_hostname()
    native.context.__exit__.assert_called_once_with(None, None, None)
    native.hostname.assert_not_called()
    native.connection.call_method.assert_not_called()


def test_provider_read_failure_releases_connection_and_allows_retry(
    helper: ModuleType, native: Any
) -> None:
    error = OSError("IEnumWbemClassObject.Next failed (HRESULT 0x80041017).")
    native.connection.query.side_effect = error
    with pytest.raises(OSError) as raised:
        helper.read_hostname()
    assert raised.value is error
    assert native.context.__exit__.call_args.args[:2] == (OSError, error)
    native.hostname.assert_not_called()
    native.connection.query.side_effect = None
    assert helper.read_hostname() == ACTIVE
    assert native.context.__exit__.call_count == 2


@pytest.mark.parametrize("name", [None, ""])
@pytest.mark.parametrize("check_mode", [False, True])
def test_null_and_empty_names_fail_before_any_native_operation(
    helper: ModuleType, native: Any, name: str | None, check_mode: bool
) -> None:
    with pytest.raises(ValueError) as raised:
        helper.rename_hostname(name, check_mode=check_mode)
    assert str(raised.value) == EMPTY_NAME
    native.hostname.assert_not_called()
    native.open.assert_not_called()
    native.format_error.assert_not_called()


@pytest.mark.parametrize(
    "name", ["Normal-Name", "invalid/name", "12345", " ", "a.b", "雪", "a\0b", "a" * 64]
)
def test_check_mode_accepts_nonempty_names_without_provider_validation(
    helper: ModuleType, native: Any, name: str
) -> None:
    assert helper.rename_hostname(name, check_mode=True) is None
    native.hostname.assert_not_called()
    native.open.assert_not_called()
    native.format_error.assert_not_called()


@pytest.mark.parametrize(
    "name", [ACTIVE, "Pending-Name", "12345", "invalid/name", "a" * 64]
)
def test_real_rename_passes_exact_name_and_null_credentials_to_provider(
    helper: ModuleType, native: Any, name: str
) -> None:
    assert helper.rename_hostname(name) is None
    native.connection.query.assert_called_once_with(
        "SELECT Name FROM Win32_ComputerSystem", ["__PATH"]
    )
    native.connection.call_method.assert_called_once_with(
        OBJECT_PATH,
        "Rename",
        ["ReturnValue"],
        {"Name": name, "UserName": None, "Password": None},
    )
    native.context.__exit__.assert_called_once_with(None, None, None)
    native.format_error.assert_not_called()


@pytest.mark.parametrize("rows", [[], [{"__PATH": None}], [{"__PATH": ""}]])
def test_missing_rename_target_closes_connection_without_method_call(
    helper: ModuleType, native: Any, rows: list[dict[str, Any]]
) -> None:
    native.connection.query.return_value = rows
    with pytest.raises(OSError, match="no locatable Win32_ComputerSystem instance"):
        helper.rename_hostname("NEW")
    assert native.context.__exit__.call_count == 1
    native.connection.call_method.assert_not_called()
    native.format_error.assert_not_called()


@pytest.mark.parametrize(
    ("code", "message", "expected"),
    [
        (5, "Access is denied.\r\n", "Access is denied."),
        (87, "The parameter is incorrect", "The parameter is incorrect."),
        (1355, "Domaine indisponible 雪... ", "Domaine indisponible 雪."),
    ],
)
def test_provider_rejection_reports_active_name_and_normalizes_error_punctuation(
    helper: ModuleType, native: Any, code: int, message: str, expected: str
) -> None:
    native.connection.call_method.return_value = {"ReturnValue": code}
    native.format_error.return_value = message
    with pytest.raises(OSError) as raised:
        helper.rename_hostname("NEW")
    assert str(raised.value) == (
        "Fail to rename computer 'Active-Dns-Name' to 'NEW' due to the following "
        "exception: " + expected
    )
    native.format_error.assert_called_once_with(code)
    native.context.__exit__.assert_called_once_with(None, None, None)
    native.connection.call_method.return_value = {"ReturnValue": 0}
    assert helper.rename_hostname("NEW") is None
    assert native.context.__exit__.call_count == 2


@pytest.mark.parametrize("operation", ["query", "call_method"])
def test_rename_provider_exception_releases_connection_and_allows_retry(
    helper: ModuleType, native: Any, operation: str
) -> None:
    error = OSError("Native provider failed (HRESULT 0x80041003).")
    boundary = getattr(native.connection, operation)
    boundary.side_effect = error
    with pytest.raises(OSError) as raised:
        helper.rename_hostname("NEW")
    assert raised.value is error
    assert native.context.__exit__.call_args.args[:2] == (OSError, error)
    if operation == "query":
        native.connection.call_method.assert_not_called()
    native.format_error.assert_not_called()
    boundary.side_effect = None
    assert helper.rename_hostname("NEW") is None
    assert native.context.__exit__.call_count == 2


def test_active_name_read_failure_prevents_rename(
    helper: ModuleType, native: Any
) -> None:
    error = OSError("Winsock hostname failed")
    native.hostname.side_effect = error
    with pytest.raises(OSError) as raised:
        helper.rename_hostname("NEW")
    assert raised.value is error
    native.open.assert_not_called()
