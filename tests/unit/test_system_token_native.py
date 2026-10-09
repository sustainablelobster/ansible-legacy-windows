"""Exercise the one-shot SYSTEM handoff's authentication and recovery."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These tests deliberately exercise the fixed native ownership boundaries.
# pylint: disable=protected-access

import ctypes
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module, native_error


@pytest.fixture(name="helper")
def system_helper(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Import the target code without loading workstation Windows libraries.

    :param monkeypatch: Scoped native-error replacement.
    :returns: The fixed-purpose SYSTEM token helper.
    """
    result = load_module(
        ROOT / "plugins/module_utils/legacy_windows_system_token.py",
        "tested_system_token",
    )
    monkeypatch.setattr(ctypes, "WinError", native_error, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 1008, raising=False)
    return result


@pytest.mark.parametrize("previous", [False, True])
@pytest.mark.parametrize("failure", [None, "identity", "duplicate", "restore"])
def test_peer_identity_token_access_and_caller_restoration(
    helper: Any, monkeypatch: pytest.MonkeyPatch, previous: bool, failure: str | None
) -> None:
    calls: list[tuple[Any, ...]] = []

    def _open(thread: Any, access: int, as_self: bool, output: Any) -> bool:
        calls.append((thread, access, as_self))
        if access == 0xC:
            output._obj.value = 10 if previous else None
            return previous
        output._obj.value = 20
        return True

    def _duplicate(*args: Any) -> bool:
        assert args[1:5] == (0x02000000, None, 2, 1)
        if failure == "duplicate":
            return False
        args[-1]._obj.value = 30
        return True

    security = SimpleNamespace(
        OpenThreadToken=Mock(side_effect=_open),
        ImpersonateNamedPipeClient=Mock(return_value=True),
        DuplicateTokenEx=Mock(side_effect=_duplicate),
        RevertToSelf=Mock(return_value=failure != "restore"),
        SetThreadToken=Mock(return_value=failure != "restore"),
    )
    kernel = SimpleNamespace(GetCurrentThread=lambda: 1, CloseHandle=Mock())
    monkeypatch.setattr(
        helper,
        "_sid",
        lambda *_args: "other-sid" if failure == "identity" else "S-1-5-18",
    )
    if failure:
        with pytest.raises((OSError, ValueError)):
            helper._duplicate_client(security, kernel, 7)
    else:
        assert helper._duplicate_client(security, kernel, 7).value == 30
    assert calls == [(1, 0xC, True), (1, 0xF, False)]
    assert security.DuplicateTokenEx.call_count == (failure != "identity")
    assert security.SetThreadToken.call_count == previous
    assert security.RevertToSelf.call_count == (not previous)
    closed = [call.args[0].value for call in kernel.CloseHandle.call_args_list]
    assert closed == [20] + ([10] if previous else []) + (
        [30] if failure == "restore" else []
    )


@pytest.mark.parametrize("message", [b"nonce", b"other", None])
@pytest.mark.parametrize("pipe_error", [232, 233, 536])
def test_handoff_rejects_wrong_message_and_has_a_real_deadline(
    helper: Any,
    monkeypatch: pytest.MonkeyPatch,
    message: bytes | None,
    pipe_error: int,
) -> None:
    def _read(_pipe: Any, buffer: Any, _size: Any, count: Any, _overlap: Any) -> bool:
        if message is None:
            return False
        ctypes.memmove(buffer, message, len(message))
        count._obj.value = len(message)
        return True

    kernel = SimpleNamespace(ReadFile=Mock(side_effect=_read))
    ticks = iter([1.0, 2.0])
    monkeypatch.setattr(helper.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(helper.time, "sleep", lambda _delay: None)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: pipe_error, raising=False)
    if message == b"nonce":
        helper._read_message(kernel, 7, b"nonce", 1.5)
    else:
        with pytest.raises(ValueError, match="Unexpected|Timed out"):
            helper._read_message(kernel, 7, b"nonce", 1.5)
    kernel.ReadFile.assert_called_once()


def test_private_descriptor_grants_only_system_and_the_caller(
    helper: Any,
) -> None:
    def _convert(sddl: str, _revision: Any, output: Any, _size: Any) -> bool:
        assert sddl == "D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;S-1-5-21-1-2-3-4)"
        output._obj.value = 77
        return True

    security = SimpleNamespace(
        ConvertStringSecurityDescriptorToSecurityDescriptorW=Mock(side_effect=_convert)
    )
    kernel = SimpleNamespace(LocalFree=Mock())
    with helper._attributes(
        security, kernel, "S-1-5-21-1-2-3-4", children=True
    ) as value:
        assert value.descriptor == 77 and not value.inherit
    assert kernel.LocalFree.call_args.args[0].value == 77


@pytest.mark.parametrize("error", [1052, 1061, 1062])
@pytest.mark.parametrize("states", [(4, 1), (4, 3, 1), (4, 4, 3, 1), (3, 1)])
def test_self_completing_service_stop_race_requires_stopped_state(
    helper: Any, monkeypatch: pytest.MonkeyPatch, error: int, states: tuple[int, ...]
) -> None:
    security = SimpleNamespace(ControlService=Mock(return_value=False))
    kernel = SimpleNamespace(WaitForSingleObject=Mock(return_value=0))
    observations = iter(SimpleNamespace(state=state) for state in states)
    monkeypatch.setattr(helper, "_status", lambda *_args: next(observations))
    monkeypatch.setattr(ctypes, "get_last_error", lambda: error, raising=False)
    monkeypatch.setattr(helper.time, "sleep", lambda _delay: None)
    helper._stop_and_wait(security, kernel, {"service": 13, "process": 14})
    assert security.ControlService.call_count == (states[0] == 4)
    kernel.WaitForSingleObject.assert_called_once()


@pytest.mark.parametrize("error", [1052, 1061, 1062])
def test_rejected_stop_never_accepts_a_service_that_remains_active(
    helper: Any, monkeypatch: pytest.MonkeyPatch, error: int
) -> None:
    security = SimpleNamespace(ControlService=Mock(return_value=False))
    kernel = SimpleNamespace(WaitForSingleObject=Mock())
    monkeypatch.setattr(helper, "_status", lambda *_args: SimpleNamespace(state=4))
    monkeypatch.setattr(ctypes, "get_last_error", lambda: error, raising=False)
    ticks = iter([0.0, 1.0, 16.0])
    monkeypatch.setattr(helper.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(helper.time, "sleep", lambda _delay: None)
    with pytest.raises(ValueError, match="did not stop"):
        helper._stop_and_wait(security, kernel, {"service": 13, "process": 14})
    kernel.WaitForSingleObject.assert_not_called()


@pytest.mark.parametrize("failure", [None, "start", "handshake", "ack", "cleanup"])
def test_owned_resources_and_acquired_tokens_recover_on_each_failure(
    helper: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str | None
) -> None:
    def _open(_process: Any, _access: Any, output: Any) -> bool:
        output._obj.value = 9
        return True

    def _directory(path: str, _attributes: Any) -> bool:
        Path(path).mkdir()
        return True

    security = SimpleNamespace(
        OpenProcessToken=Mock(side_effect=_open),
        OpenSCManagerW=Mock(return_value=12),
        CreateServiceW=Mock(return_value=13),
        StartServiceW=Mock(return_value=failure != "start"),
        ControlService=Mock(return_value=True),
        DeleteService=Mock(return_value=failure != "cleanup"),
        CloseServiceHandle=Mock(return_value=True),
    )
    kernel = SimpleNamespace(
        GetCurrentProcess=lambda: 1,
        CreateDirectoryW=Mock(side_effect=_directory),
        CreateNamedPipeW=Mock(return_value=11),
        ConnectNamedPipe=Mock(return_value=True),
        OpenProcess=Mock(return_value=14),
        WaitForSingleObject=Mock(return_value=0),
        CloseHandle=Mock(return_value=True),
    )
    monkeypatch.setattr(helper, "_libraries", lambda: (security, kernel))
    monkeypatch.setattr(helper, "_sid", lambda *_args: "caller-sid")
    monkeypatch.setattr(
        helper,
        "_attributes",
        lambda *_args, **_kwargs: nullcontext(helper._Attributes()),
    )
    monkeypatch.setattr(helper.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(
        helper, "_status", lambda *_args: SimpleNamespace(state=1, pid=99)
    )
    monkeypatch.setattr(helper, "_duplicate_client", lambda *_args: ctypes.c_void_p(15))

    def _message(*_args: Any) -> None:
        if failure == "handshake":
            raise ValueError("Rejected handshake")

    def _ack(*_args: Any) -> None:
        if failure == "ack":
            raise ValueError("Rejected acknowledgement")

    monkeypatch.setattr(helper, "_read_message", _message)
    monkeypatch.setattr(helper, "_write_message", _ack)
    if failure:
        with pytest.raises((ValueError, OSError)):
            helper.acquire_token()
    else:
        assert helper.acquire_token().value == 15
    security.DeleteService.assert_called_once_with(13)
    assert [call.args[0] for call in security.CloseServiceHandle.call_args_list] == [
        13,
        12,
    ]
    closed = [
        (
            call.args[0].value
            if isinstance(call.args[0], ctypes.c_void_p)
            else call.args[0]
        )
        for call in kernel.CloseHandle.call_args_list
    ]
    assert 9 in closed and 11 in closed
    assert (15 in closed) == (failure in ("ack", "cleanup"))
    assert bool(list(tmp_path.iterdir())) == (failure == "cleanup")
    command = security.CreateServiceW.call_args.args
    assert command[4:7] == (0x10, 3, 1) and command[-2:] == (None, None)
