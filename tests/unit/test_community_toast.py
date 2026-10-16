"""Exercise public notification behavior independently of native UI delivery."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import datetime
from types import SimpleNamespace
from typing import Any

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module


@pytest.fixture(name="desktop")
def desktop_fixture(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Load native helpers but replace only actual desktop and clock operations.

    :param monkeypatch: Scoped native boundary substitutions.
    :returns: Maintained payload with independently observed notification requests.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(
        str(ROOT / "legacy_community_windows/plugins/module_utils")
    )
    payload = load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_toast.py",
        "community_toast",
    )
    state = SimpleNamespace(
        payload=payload, explorer=True, available=True, sends=[], sleeps=[]
    )

    def available() -> None:
        """Independently model whether the target actually exports WinRT.

        :raises OSError: The selected fixture has no notification runtime.
        """
        if not state.available:
            raise OSError("Windows Runtime toast notification APIs are unavailable")

    def send(
        parameters: dict[str, Any], expires: datetime.datetime, check_mode: bool
    ) -> None:
        """Observe an actual payload request at the native Show boundary.

        :param parameters: Converted literal message options.
        :param expires: Requested native expiration timestamp.
        :param check_mode: Whether to validate without showing.
        """
        state.sends.append((parameters, expires, check_mode))

    monkeypatch.setattr(payload.native, "available", available)
    monkeypatch.setattr(payload.native, "has_explorer", lambda: state.explorer)
    monkeypatch.setattr(payload.native, "send", send)
    monkeypatch.setattr(
        payload.native, "format_time", lambda value, **_flags: value.isoformat()
    )
    monkeypatch.setattr(payload.time, "sleep", state.sleeps.append)
    return state


def test_actual_send_retains_parameters_and_released_unchanged_flag(
    desktop: SimpleNamespace,
) -> None:
    arguments = {
        "title": "Title <&> \U0001f41e",
        "msg": "Line one\nline two",
        "tag": "unique",
        "group": "group",
        "popup": False,
        "expire": 3,
    }
    result = getattr(desktop.payload, "_execute")(arguments)
    parameters, expires, check = desktop.sends[0]
    assert parameters == {
        name: arguments[name] for name in ("title", "msg", "tag", "group", "popup")
    }
    assert check is False and expires.tzinfo == datetime.timezone.utc
    assert desktop.sleeps == [3]
    assert result["toast_sent"] is True and result["changed"] is False
    assert isinstance(result["time_taken"], float)
    assert all(
        result[name] for name in ("expire_at", "expire_at_utc", "sent_localtime")
    )


def test_check_mode_validates_without_showing_or_waiting(
    desktop: SimpleNamespace,
) -> None:
    result = getattr(desktop.payload, "_execute")(
        {"expire": 3, "_ansible_check_mode": True}
    )
    assert len(desktop.sends) == 1 and desktop.sends[0][2] is True
    assert desktop.sleeps == []
    assert result["toast_sent"] is False and result["changed"] is False


def test_no_explorer_is_a_successful_noop(desktop: SimpleNamespace) -> None:
    desktop.explorer = False
    result = getattr(desktop.payload, "_execute")({})
    assert result["toast_sent"] is False and result["changed"] is False
    assert result["no_toast_sent_reason"] == "No logged in users to notify"
    assert desktop.sends == [] and desktop.sleeps == []


def test_missing_actual_runtime_fails_before_desktop_send(
    desktop: SimpleNamespace,
) -> None:
    desktop.available = False
    with pytest.raises(OSError, match="APIs are unavailable"):
        getattr(desktop.payload, "_execute")({})
    assert desktop.sends == []


@pytest.mark.parametrize("expire", [-1, "not a number", None])
def test_invalid_expiration_never_sends(desktop: SimpleNamespace, expire: Any) -> None:
    with pytest.raises(ValueError, match="expire must"):
        getattr(desktop.payload, "_execute")({"expire": expire})
    assert desktop.sends == []


def test_installed_notification_failure_is_not_reported_as_delivery(
    desktop: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(parameters: Any, expires: Any, check_mode: Any) -> None:
        """Supply an independent concrete notification HRESULT failure.

        :param parameters: Ignored native message options.
        :param expires: Ignored native expiration time.
        :param check_mode: Ignored notification preview flag.
        :raises OSError: The native notifier rejected the message.
        """
        raise OSError("ToastNotifier.Show failed with HRESULT 0x80070490")

    monkeypatch.setattr(desktop.payload.native, "send", fail)
    with pytest.raises(OSError, match="0x80070490"):
        getattr(desktop.payload, "_execute")({"expire": 0})
    assert desktop.sleeps == []


def test_default_message_matches_released_runtime_not_its_conflicting_prose(
    desktop: SimpleNamespace,
) -> None:
    getattr(desktop.payload, "_execute")({"expire": 0})
    parameters = desktop.sends[0][0]
    assert parameters["msg"] == "Hello world!"
    assert parameters["title"].startswith("Notification: ")
    assert parameters["group"] == "Powershell" and parameters["tag"] == "Ansible"
