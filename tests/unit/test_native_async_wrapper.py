"""Check exact watchdog ownership and failure recovery at the async frontend."""

# SPDX-License-Identifier: GPL-3.0-or-later
# The private frontend boundary is supplied by Ansible's async invocation ABI.
# pylint: disable=protected-access

from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import HELPER, load_module


@pytest.fixture(name="frontend")
def frontend_fixture(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    """Supply a retained watchdog handle and real protocol/cache files.

    :param monkeypatch: Scoped native launch boundary substitutes.
    :param tmp_path: Isolated task directory and async cache.
    :returns: Frontend module, native kernel mock and owned paths.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    wrapper = load_module(
        HELPER.parent / "legacy_windows_async_wrapper.py", "tested_async_frontend"
    )
    request = str(tmp_path / "request.json")
    cache = str(tmp_path / "j1.2")
    kernel = SimpleNamespace(
        WaitForSingleObject=Mock(side_effect=[258, 0]),
        TerminateProcess=Mock(return_value=True),
        CloseHandle=Mock(),
    )
    monkeypatch.setattr(
        wrapper, "_request", lambda *_args: (str(tmp_path), request, cache, "j1.2")
    )
    monkeypatch.setattr(wrapper, "launch_watchdog", Mock(return_value=(kernel, 21, 23)))
    return wrapper, kernel, request, cache


def test_success_uses_the_pinned_launch_handle_and_complete_handshake(
    frontend: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    wrapper, kernel, request, cache = frontend

    def _startup(api: Any, handle: int, pid: int, path: str, timeout: int) -> None:
        assert (api, handle, pid, path, timeout) == (kernel, 21, 23, request, 5)
        metadata = wrapper.read_json(cache)
        assert metadata == wrapper.read_json(request + ".release")
        assert metadata["ansible_async_watchdog_pid"] == pid

    monkeypatch.setattr(wrapper, "_await_startup", _startup)
    result = wrapper.launch(["core", "arguments"], 5)
    assert result == dict(
        wrapper.read_json(cache), _ansible_suppress_tmpdir_delete=True
    )
    assert result["started"] and not result["finished"]
    assert "_ansible_suppress_tmpdir_delete" not in wrapper.read_json(cache)
    kernel.CloseHandle.assert_called_once_with(21)
    kernel.TerminateProcess.assert_not_called()


@pytest.mark.parametrize("alive", [False, True])
def test_startup_failure_stops_only_owned_worker_and_removes_its_cache(
    frontend: Any, monkeypatch: pytest.MonkeyPatch, alive: bool
) -> None:
    wrapper, kernel, _request, cache = frontend
    kernel.WaitForSingleObject.side_effect = [258, 0] if alive else [0]
    monkeypatch.setattr(
        wrapper, "_await_startup", Mock(side_effect=OSError("startup failed"))
    )
    with pytest.raises(OSError, match="startup failed"):
        wrapper.launch(["core", "arguments"], 5)
    assert not Path(cache).exists()
    if alive:
        kernel.TerminateProcess.assert_called_once_with(21, 1)
    else:
        kernel.TerminateProcess.assert_not_called()
    kernel.CloseHandle.assert_called_once_with(21)
    wrapper.launch_watchdog.assert_called_once()


def test_frontend_cannot_fallback_after_a_native_launch_failure(
    frontend: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    wrapper, kernel, _request, cache = frontend
    monkeypatch.setattr(wrapper, "launch_watchdog", Mock(side_effect=OSError("denied")))
    with pytest.raises(OSError, match="denied"):
        wrapper.launch(["core", "arguments"], 5)
    assert not Path(cache).exists()
    wrapper.launch_watchdog.assert_called_once()
    kernel.CloseHandle.assert_not_called()
