"""Observe native event arguments and nonmutating validation/check behavior."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

# Direct calls test validation independently of the JSON/native boundaries.
# pylint: disable=protected-access

from types import ModuleType
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module


@pytest.fixture(name="payload")
def entry_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Substitute the native registry and event-writing boundaries.

    :param monkeypatch: Scoped boundary replacements.
    :returns: Imported event entry payload.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    module = load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_eventlog_entry.py",
        "tested_community_eventlog_entry",
    )
    monkeypatch.setattr(
        module.eventlog, "log_details", Mock(return_value={"exists": True})
    )
    monkeypatch.setattr(module.eventlog, "source_log", Mock(return_value="TestLog"))
    monkeypatch.setattr(module, "_write", Mock())
    return module


def _arguments(**changes: object) -> dict[str, object]:
    arguments = {
        "log": "TestLog",
        "source": "TestSource",
        "event_id": 42,
        "message": "héllo",
    }
    arguments.update(changes)
    return arguments


def test_defaults_write_information_without_raw_bytes(payload: ModuleType) -> None:
    assert payload._entry(_arguments()) == {  # pylint: disable=protected-access
        "changed": True,
        "msg": "Entry added to log TestLog from source TestSource",
    }
    payload._write.assert_called_once_with(
        "TestSource", 42, "héllo", 4, 0, b""
    )  # pylint: disable=protected-access


def test_explicit_event_fields_and_signed_category(payload: ModuleType) -> None:
    payload._entry(
        _arguments(entry_type="warning", category=-1, raw_data="0, 10,255")
    )  # pylint: disable=protected-access
    payload._write.assert_called_once_with(
        "TestSource", 42, "héllo", 2, 65535, b"\x00\x0a\xff"
    )  # pylint: disable=protected-access


def test_check_mode_validates_source_without_writing(payload: ModuleType) -> None:
    result = payload._entry(
        _arguments(_ansible_check_mode=True)
    )  # pylint: disable=protected-access
    assert result["changed"] is True
    payload._write.assert_not_called()  # pylint: disable=protected-access


@pytest.mark.parametrize(
    "changes",
    [
        {"log": ""},
        {"source": None},
        {"message": ""},
        {"event_id": -1},
        {"event_id": 65536},
        {"event_id": None},
        {"entry_type": "invalid"},
        {"category": 32768},
        {"raw_data": "-1"},
        {"raw_data": "256"},
        {"raw_data": "text"},
    ],
)
def test_invalid_values_never_write(
    payload: ModuleType, changes: dict[str, object]
) -> None:
    with pytest.raises(ValueError):
        payload._entry(_arguments(**changes))  # pylint: disable=protected-access
    payload._write.assert_not_called()  # pylint: disable=protected-access


@pytest.mark.parametrize("source_log", [None, "OtherLog"])
def test_missing_or_differently_registered_source_is_rejected(
    payload: ModuleType, source_log: str | None
) -> None:
    payload.eventlog.source_log.return_value = source_log
    with pytest.raises(ValueError):
        payload._entry(_arguments())  # pylint: disable=protected-access
    payload._write.assert_not_called()  # pylint: disable=protected-access


def test_missing_log_never_falls_back_to_application(payload: ModuleType) -> None:
    payload.eventlog.log_details.return_value = {"exists": False}
    with pytest.raises(ValueError, match="does not exist"):
        payload._entry(_arguments())  # pylint: disable=protected-access
    payload._write.assert_not_called()  # pylint: disable=protected-access
