"""Exercise native timezone commands and legacy Windows rules without a host."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native-boundary tests inspect the helper's ctypes structures and API seams.
# pylint: disable=protected-access

import ctypes
import ntpath
import struct
from collections import OrderedDict
from contextlib import contextmanager
from types import ModuleType, SimpleNamespace
from typing import Any, Iterator
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import ROOT, load_module, native_error

CATALOGUE = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones"
TOOL = r"C:\Windows\System32\tzutil.exe"
STANDARD_DATE = (0, 11, 0, 1, 2, 0, 0, 0)
DAYLIGHT_DATE = (0, 3, 0, 2, 2, 0, 0, 0)


def _entry(standard: str = "Localized standard 雪", bias: int = -345) -> dict[str, Any]:
    return {
        "Std": standard,
        "Dlt": "Localized daylight 雪",
        "TZI": struct.pack("<lll16H", bias, 17, -43, *STANDARD_DATE, *DAYLIGHT_DATE),
    }


def _name(value: str) -> Any:
    return (ctypes.c_uint16 * 32).from_buffer_copy(
        value.encode("utf-16-le").ljust(64, b"\0")
    )


@pytest.fixture(name="helper")
def timezone_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Import target code with adjacent helpers and deterministic ID comparison.

    :param monkeypatch: Scoped helper imports and native-collation substitute.
    :returns: Imported timezone helper without executing native operations.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    helper = load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_timezone.py",
        "tested_timezone_native",
    )
    monkeypatch.setattr(
        helper, "values_equal", lambda left, right: left.lower() == right.lower()
    )
    monkeypatch.setattr(ctypes, "WinError", native_error, raising=False)
    return helper


@pytest.fixture(name="modern")
def modern_timezone(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Capture subprocess requests while prohibiting legacy timezone operations.

    :param helper: Imported helper.
    :param monkeypatch: Scoped process, utility, and console-codepage substitutes.
    :returns: Configurable utility process and native-library recorder.
    """
    state = SimpleNamespace(process=MagicMock(), kernel=Mock(), legacy=Mock())
    state.process.__enter__.return_value = state.process
    state.process.returncode = 0
    state.process.communicate.return_value = (b"Canonical Time_dstoff\r\n", b"")
    state.kernel.GetOEMCP.return_value = 437
    monkeypatch.setattr(helper, "_tzutil", lambda: TOOL)
    state.launch = Mock(return_value=state.process)
    monkeypatch.setattr(helper.subprocess, "Popen", state.launch)
    monkeypatch.setattr(
        ctypes, "WinDLL", Mock(return_value=state.kernel), raising=False
    )
    for name in ("_catalogue", "_native_zone", "ownership_privileges"):
        operation = getattr(state.legacy, name)
        operation.side_effect = AssertionError(
            "The utility must own modern timezone operations"
        )
        monkeypatch.setattr(helper, name, operation)
    return state


def test_current_timezone_uses_native_utility_without_legacy_reads_or_writes(
    helper: ModuleType, modern: Any
) -> None:
    assert helper.get_timezone() == "Canonical Time_dstoff"
    modern.launch.assert_called_once_with(
        [TOOL, "/g"], stdout=helper.subprocess.PIPE, stderr=helper.subprocess.PIPE
    )
    modern.process.communicate.assert_called_once_with()
    modern.process.__exit__.assert_called_once()
    assert modern.legacy.mock_calls == []


def test_available_utility_lines_preserve_labels_blank_lines_and_oem_text(
    helper: ModuleType, modern: Any
) -> None:
    modern.process.communicate.return_value = (
        b"(UTC+01:00) R\x82sum\x82\r\nCanonical Time\r\n\r\nAnother Time\r\n",
        b"",
    )
    assert helper.available_timezones() == [
        "(UTC+01:00) Résumé",
        "Canonical Time",
        "",
        "Another Time",
    ]
    assert modern.launch.call_args.args == ([TOOL, "/l"],)
    assert modern.legacy.mock_calls == []


def test_set_utility_receives_requested_spelling_as_one_literal_argument(
    helper: ModuleType, modern: Any
) -> None:
    requested = 'Literal "timezone" & name_DSTOFF'
    assert helper.set_timezone(requested) is None
    modern.launch.assert_called_once_with(
        [TOOL, "/s", requested],
        stdout=helper.subprocess.PIPE,
        stderr=helper.subprocess.PIPE,
    )
    assert modern.legacy.mock_calls == []


def test_empty_timezone_omits_native_argument_and_preserves_utility_failure(
    helper: ModuleType, modern: Any
) -> None:
    modern.process.returncode = 87
    modern.process.communicate.return_value = (b"Missing timezone argument\r\n", b"")
    with pytest.raises(helper.TimeZoneCommandError) as raised:
        helper.set_timezone("")
    modern.launch.assert_called_once_with(
        [TOOL, "/s"], stdout=helper.subprocess.PIPE, stderr=helper.subprocess.PIPE
    )
    error = raised.value
    assert (error.action, error.stdout, error.stderr, error.rc) == (
        "setting the specified timezone",
        "Missing timezone argument",
        "",
        87,
    )
    modern.process.__exit__.assert_called_once()
    assert modern.legacy.mock_calls == []


@pytest.mark.parametrize(
    "operation,action",
    [
        ("get_timezone", "getting the current machine's timezone setting"),
        ("available_timezones", "listing the available timezones"),
        ("set_timezone", "setting the specified timezone"),
    ],
)
def test_utility_failure_keeps_both_streams_and_return_code_and_recovers(
    helper: ModuleType, modern: Any, operation: str, action: str
) -> None:
    modern.process.returncode = 87
    modern.process.communicate.return_value = (
        b"first\r\n\r\nlast\r\n",
        b"failure\r\nsecond line\r\n",
    )
    arguments = ("Canonical Time",) if operation == "set_timezone" else ()
    with pytest.raises(helper.TimeZoneCommandError) as raised:
        getattr(helper, operation)(*arguments)
    error = raised.value
    assert (error.action, error.stdout, error.stderr, error.rc) == (
        action,
        "first\n\nlast",
        "failure\nsecond line",
        87,
    )
    assert str(error) == f"An error occurred when {action}."
    modern.process.__exit__.assert_called_once()
    assert modern.legacy.mock_calls == []
    modern.process.returncode = 0
    getattr(helper, operation)(*arguments)
    assert modern.launch.call_count == 2


def test_utility_start_failure_never_falls_back_to_legacy_mutation(
    helper: ModuleType, modern: Any
) -> None:
    modern.launch.side_effect = native_error(5)
    with pytest.raises(OSError) as raised:
        helper.set_timezone("Canonical Time")
    assert raised.value.errno == 5
    modern.process.communicate.assert_not_called()
    assert modern.legacy.mock_calls == []


@pytest.mark.parametrize(
    "major,present", [(5, False), (6, True), (10, True), (10, False)]
)
def test_utility_discovery_only_allows_legacy_fallback_before_vista(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, major: int, present: bool
) -> None:
    isfile = Mock(return_value=present)
    monkeypatch.setattr(
        helper,
        "os",
        SimpleNamespace(
            name="nt",
            environ={"SystemRoot": r"C:\Windows"},
            path=SimpleNamespace(join=ntpath.join, isfile=isfile),
        ),
    )
    monkeypatch.setattr(
        helper,
        "sys",
        SimpleNamespace(getwindowsversion=lambda: SimpleNamespace(major=major)),
    )
    if major >= 6 and not present:
        with pytest.raises(OSError, match="tzutil.exe is required"):
            helper._tzutil()
    else:
        assert helper._tzutil() == (TOOL if present else None)
    isfile.assert_called_once_with(TOOL)


@pytest.fixture(name="legacy")
def legacy_timezone(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Provide installed registry rules, native current state, and scoped writes.

    :param helper: Imported helper.
    :param monkeypatch: Scoped native API, registry, and privilege replacements.
    :returns: Mutable native machine state with observed reads and writes.
    """
    state = SimpleNamespace(
        kernel=Mock(),
        registry=Mock(),
        error=5,
        status=2,
        events=[],
        entries=OrderedDict(
            [
                ("Canonical Time", _entry()),
                ("Other Time", _entry("Another standard name", 300)),
            ]
        ),
        opened=[],
        closed=[],
        writes=[],
        privileged=False,
    )
    state.zone = helper._TimeZoneInformation(
        -345,
        _name("Localized standard 雪"),
        helper._SystemTime(*STANDARD_DATE),
        17,
        _name("Localized daylight 雪"),
        helper._SystemTime(*DAYLIGHT_DATE),
        -43,
    )
    state.registry.HKEY_LOCAL_MACHINE = 0x80000002
    state.registry.KEY_READ = 0x20019
    state.registry.KEY_WOW64_64KEY = 0x100

    def _open(root: Any, name: str, *arguments: Any) -> Any:
        if root == state.registry.HKEY_LOCAL_MACHINE:
            assert name == CATALOGUE
            assert arguments == (0, 0x20119)
            handle = "catalogue"
        else:
            assert root == "catalogue"
            assert name in state.entries
            assert not arguments
            handle = name
        state.opened.append(handle)
        context = MagicMock()
        context.__enter__.return_value = handle
        context.__exit__.side_effect = lambda *_args: state.closed.append(handle)
        return context

    def _query(key: str, field: str) -> tuple[Any, int]:
        return state.entries[key][field], 3 if field == "TZI" else 1

    def _get(pointer: Any) -> int:
        ctypes.memmove(pointer, ctypes.byref(state.zone), ctypes.sizeof(state.zone))
        return int(state.status)

    def _set(pointer: Any) -> int:
        assert state.privileged
        state.events.append("write")
        state.writes.append(helper._TimeZoneInformation.from_buffer_copy(pointer._obj))
        return 1

    @contextmanager
    def _privileges(names: tuple[str, ...]) -> Iterator[None]:
        assert names == ("SeSystemtimePrivilege",)
        state.events.append("enable")
        state.privileged = True
        try:
            yield
        finally:
            state.privileged = False
            state.events.append("restore")

    state.registry.OpenKey.side_effect = _open
    state.registry.QueryInfoKey.side_effect = lambda _parent: (len(state.entries), 0, 0)
    state.registry.EnumKey.side_effect = lambda _parent, index: list(state.entries)[
        index
    ]
    state.registry.QueryValueEx.side_effect = _query
    state.kernel.GetTimeZoneInformation.side_effect = _get
    state.kernel.SetTimeZoneInformation.side_effect = _set
    monkeypatch.setattr(helper, "_tzutil", lambda: None)
    monkeypatch.setattr(helper, "_kernel", lambda: state.kernel)
    monkeypatch.setattr(helper, "winreg", state.registry)
    monkeypatch.setattr(helper, "ownership_privileges", _privileges)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: state.error, raising=False)
    return state


def test_legacy_catalogue_reads_installed_ids_and_closes_every_key_without_writes(
    helper: ModuleType, legacy: Any
) -> None:
    assert helper.available_timezones() == ["Canonical Time", "Other Time"]
    assert legacy.opened == ["catalogue", "Canonical Time", "Other Time"]
    assert legacy.closed == ["Canonical Time", "Other Time", "catalogue"]
    legacy.kernel.GetTimeZoneInformation.assert_not_called()
    legacy.kernel.SetTimeZoneInformation.assert_not_called()
    legacy.registry.SetValueEx.assert_not_called()
    assert legacy.events == []


@pytest.mark.parametrize("disabled", [False, True])
def test_legacy_current_zone_returns_canonical_id_and_disabled_dst_suffix(
    helper: ModuleType, legacy: Any, disabled: bool
) -> None:
    if disabled:
        legacy.zone.standard_date = helper._SystemTime()
        legacy.zone.daylight_date = helper._SystemTime()
    assert helper.get_timezone() == "Canonical Time" + ("_dstoff" if disabled else "")
    legacy.kernel.SetTimeZoneInformation.assert_not_called()
    legacy.registry.SetValueEx.assert_not_called()
    assert legacy.events == []
    assert sorted(legacy.closed) == sorted(legacy.opened)


def test_legacy_timezone_without_installed_dst_does_not_gain_disabled_suffix(
    helper: ModuleType, legacy: Any
) -> None:
    legacy.entries["Canonical Time"]["TZI"] = struct.pack(
        "<lll16H", -345, 17, -43, *([0] * 16)
    )
    legacy.zone.standard_date = helper._SystemTime()
    legacy.zone.daylight_date = helper._SystemTime()
    assert helper.get_timezone() == "Canonical Time"


@pytest.mark.parametrize("mismatch", ["name", "bias"])
def test_unmatched_current_timezone_fails_without_guessing_or_writing(
    helper: ModuleType, legacy: Any, mismatch: str
) -> None:
    if mismatch == "name":
        legacy.zone.standard_name = _name("Uninstalled timezone")
    else:
        legacy.zone.bias += 1
    with pytest.raises(OSError, match="no matching installed ID"):
        helper.get_timezone()
    assert legacy.events == []
    legacy.kernel.SetTimeZoneInformation.assert_not_called()


def test_native_get_failure_preserves_error_before_reading_catalogue(
    helper: ModuleType, legacy: Any
) -> None:
    legacy.status = 0xFFFFFFFF
    legacy.error = 1314
    with pytest.raises(OSError) as raised:
        helper.get_timezone()
    assert raised.value.errno == 1314
    legacy.registry.OpenKey.assert_not_called()
    legacy.kernel.SetTimeZoneInformation.assert_not_called()
    assert legacy.events == []


@pytest.mark.parametrize("requested", ["canonical time", "Canonical Time_DSTOFF"])
def test_legacy_set_preserves_installed_offsets_names_and_requested_dst_mode(
    helper: ModuleType, legacy: Any, requested: str
) -> None:
    helper.set_timezone(requested)
    assert legacy.events == ["enable", "write", "restore"]
    assert legacy.privileged is False
    assert len(legacy.writes) == 1
    zone = legacy.writes[0]
    assert (zone.bias, zone.standard_bias, zone.daylight_bias) == (-345, 17, -43)
    assert (
        bytes(zone.standard_name).decode("utf-16-le").rstrip("\0")
        == "Localized standard 雪"
    )
    assert (
        bytes(zone.daylight_name).decode("utf-16-le").rstrip("\0")
        == "Localized daylight 雪"
    )
    disabled = requested.endswith("_DSTOFF")
    assert bytes(zone.standard_date) == (
        b"\0" * 16 if disabled else struct.pack("<8H", *STANDARD_DATE)
    )
    assert bytes(zone.daylight_date) == (
        b"\0" * 16 if disabled else struct.pack("<8H", *DAYLIGHT_DATE)
    )
    legacy.registry.SetValueEx.assert_not_called()


@pytest.mark.parametrize(
    "requested", ["unknown", "Canonical Time_dstoff_dstoff", "Canonical Time ", ""]
)
def test_invalid_legacy_id_fails_before_privilege_or_write(
    helper: ModuleType, legacy: Any, requested: str
) -> None:
    with pytest.raises(ValueError, match="not an installed timezone ID"):
        helper.set_timezone(requested)
    assert legacy.events == []
    legacy.kernel.SetTimeZoneInformation.assert_not_called()


@pytest.mark.parametrize("invalid", [b"short", b"\0" * 45, bytearray(44), "not binary"])
def test_malformed_installed_rule_fails_before_privilege_or_write(
    helper: ModuleType, legacy: Any, invalid: Any
) -> None:
    legacy.entries["Canonical Time"]["TZI"] = invalid
    with pytest.raises(ValueError, match="44 binary bytes"):
        helper.set_timezone("Canonical Time")
    assert legacy.events == []
    legacy.kernel.SetTimeZoneInformation.assert_not_called()
    assert sorted(legacy.closed) == sorted(legacy.opened)


def test_installed_names_must_fit_native_utf16_capacity_before_write(
    helper: ModuleType, legacy: Any
) -> None:
    legacy.entries["Canonical Time"]["Std"] = "😀" * 16
    with pytest.raises(ValueError, match="31 UTF-16 units"):
        helper.set_timezone("Canonical Time")
    assert legacy.events == []
    legacy.kernel.SetTimeZoneInformation.assert_not_called()


def test_legacy_write_failure_restores_privileges_and_can_be_retried(
    helper: ModuleType, legacy: Any
) -> None:
    original = legacy.kernel.SetTimeZoneInformation.side_effect

    def _failed_write(pointer: Any) -> int:
        original(pointer)
        return 0

    legacy.kernel.SetTimeZoneInformation.side_effect = _failed_write
    legacy.error = 1314
    with pytest.raises(OSError) as raised:
        helper.set_timezone("Canonical Time")
    assert raised.value.errno == 1314
    assert legacy.privileged is False
    assert legacy.events == ["enable", "write", "restore"]
    legacy.kernel.SetTimeZoneInformation.side_effect = original
    helper.set_timezone("Canonical Time")
    assert legacy.events == ["enable", "write", "restore"] * 2


def test_privilege_failure_prevents_timezone_write(
    helper: ModuleType, legacy: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        helper, "ownership_privileges", Mock(side_effect=native_error(1314))
    )
    with pytest.raises(OSError) as raised:
        helper.set_timezone("Canonical Time")
    assert raised.value.errno == 1314
    legacy.kernel.SetTimeZoneInformation.assert_not_called()
    legacy.registry.SetValueEx.assert_not_called()


def test_registry_read_failure_closes_keys_and_does_not_change_timezone(
    helper: ModuleType, legacy: Any
) -> None:
    legacy.registry.QueryValueEx.side_effect = native_error(5)
    with pytest.raises(OSError) as raised:
        helper.available_timezones()
    assert raised.value.errno == 5
    assert legacy.closed == ["Canonical Time", "catalogue"]
    assert legacy.events == []
    legacy.kernel.SetTimeZoneInformation.assert_not_called()
