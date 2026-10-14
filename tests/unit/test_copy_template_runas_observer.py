"""Check the uniquely owned observer's temporary token privilege scope."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ctypes
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from scripts import verify_copy_template_runas_capture as verifier
from tests.unit.payload_support import ROOT, load_module
from tests.unit.test_copy_template_runas import _debug_snapshot


@pytest.mark.parametrize("failure", [None, "observation", "interrupt", "readiness"])
def test_system_observer_restores_existing_privilege_and_closes_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    # These pointer outputs/private calls are the exact native ownership boundary.
    # pylint: disable=protected-access
    observer = verifier._OBSERVER  # pylint: disable=protected-access
    monkeypatch.setitem(sys.modules, "legacy_windows_account", ModuleType("account"))
    monkeypatch.setitem(sys.modules, "legacy_windows_s4u", ModuleType("s4u"))
    helper = load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_runas_token.py",
        "observer_token",
    )
    monkeypatch.setitem(sys.modules, "legacy_windows_runas_token", helper)
    attributes = [0]

    def adjust(
        _token: Any, _all: bool, change: Any, _size: int, previous: Any, _needed: Any
    ) -> bool:
        """Mock exact adjustment and restoration performed by the maintained context.

        :param change: By-reference native requested privilege attributes.
        :param previous: By-reference native output for the old privilege state.
        :returns: True after applying the requested privilege attributes.
        """
        if previous is not None:
            previous._obj.count = 1  # pylint: disable=protected-access
            previous._obj.privilege.attributes = attributes[
                0
            ]  # pylint: disable=protected-access
        attributes[0] = (
            change._obj.privilege.attributes
        )  # pylint: disable=protected-access
        return True

    security = SimpleNamespace(
        OpenProcessToken=Mock(return_value=True),
        LookupPrivilegeValueW=Mock(return_value=True),
        AdjustTokenPrivileges=adjust,
    )
    kernel = SimpleNamespace(
        GetCurrentProcess=lambda: 5, CloseHandle=Mock(return_value=True)
    )
    monkeypatch.setattr(helper, "_libraries", lambda: (security, kernel, None))
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 0, raising=False)
    monkeypatch.setattr(
        observer, "_debug_state", lambda *_args: _debug_snapshot(attributes[0])
    )

    def collect(*_args: Any) -> dict[str, Any]:
        """Finish after enablement, or simulate an interrupted owned observer.

        :param _args: Unused collector context in this native API substitute.
        :returns: Literal retained observation outcome.
        :raises KeyboardInterrupt: For the explicit interruption case.
        """
        assert attributes[0] == 2
        if failure == "interrupt":
            raise KeyboardInterrupt("owned interruption")
        return {
            "failure": (
                "retained observation failure" if failure == "observation" else None
            )
        }

    monkeypatch.setattr(observer, "_collect", collect)
    write = observer._write  # pylint: disable=protected-access

    def owned_write(path: str, value: Any) -> None:
        if failure == "readiness" and path.endswith("-ready.json"):
            raise OSError("owned readiness failure")
        write(path, value)

    monkeypatch.setattr(observer, "_write", owned_write)
    prefix = str(tmp_path / "observer-native-12")
    if failure in ("interrupt", "readiness"):
        with pytest.raises(KeyboardInterrupt if failure == "interrupt" else OSError):
            observer._system_collect(
                None, {}, {}, prefix
            )  # pylint: disable=protected-access
    else:
        result = observer._system_collect(
            None, {}, {}, prefix
        )  # pylint: disable=protected-access
        assert result["failure"] == (
            "retained observation failure" if failure else None
        )
    state = json.loads(Path(prefix + "-privilege.json").read_text(encoding="utf-8"))
    assert state == {
        "before": _debug_snapshot(0),
        "enabled": _debug_snapshot(2),
        "after": _debug_snapshot(0),
        "token_closed": True,
    }
    assert attributes == [0]
    kernel.CloseHandle.assert_called_once()
