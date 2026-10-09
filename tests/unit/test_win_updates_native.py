"""Exercise native WUA Automation ownership and callback failure boundaries."""

# SPDX-License-Identifier: GPL-3.0-or-later
# ABI substitutes are controller-only evidence, not Windows availability.
# pylint: disable=protected-access

import ctypes
import threading
from contextlib import ExitStack
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="helper")
def native_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load native WUA without executing Windows APIs.

    :param monkeypatch: Scoped target-helper path and callback calling convention.
    :returns: Fresh native helper.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    monkeypatch.setattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE, raising=False)
    return load_module(
        ROOT / "plugins/module_utils/legacy_windows_updates_native.py",
        "tested_updates_native",
    )


@pytest.mark.parametrize("status", [0, 1, 0x00240005])
def test_success_statuses_do_not_raise(helper: ModuleType, status: int) -> None:
    helper._check(status, "native test")


@pytest.mark.parametrize("status", [-2145124322, 0x8024000B, -2147467259])
def test_hresult_failure_is_unsigned_and_actionable(
    helper: ModuleType, status: int
) -> None:
    with pytest.raises(helper.WuaError) as raised:
        helper._check(status, "native test")
    assert raised.value.hresult == status & 0xFFFFFFFF
    assert f"0x{status & 0xFFFFFFFF:08X}" in str(raised.value)


@pytest.mark.parametrize("hresult", [0x80070005, -2147024891])
def test_system_hresult_description_uses_safe_unsigned_native_lookup(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, hresult: int
) -> None:
    # This local callback mirrors the seven-argument ABI and checks it below;
    # repeating that contract in parameter/return docstrings adds no clarity.
    # pylint: disable=too-many-arguments,too-many-positional-arguments
    # pylint: disable=missing-return-doc
    def format_message(
        flags: int,
        source: Any,
        code: int,
        language: int,
        buffer: Any,
        size: int,
        arguments: Any,
    ) -> int:
        assert flags == 0x1200 and source is arguments is None
        assert code == 0x80070005 and language == 0 and size == len(buffer)
        buffer.value = "Access is denied.\r\n"
        return len(buffer.value)

    # pylint: enable=too-many-arguments,too-many-positional-arguments
    # pylint: enable=missing-return-doc

    kernel = SimpleNamespace(FormatMessageW=Mock(side_effect=format_message))
    factory = Mock(return_value=kernel)
    monkeypatch.setattr(ctypes, "WinDLL", factory, raising=False)
    assert helper.hresult_description(hresult) == "Access is denied."
    factory.assert_called_once_with("kernel32", use_last_error=True)
    assert kernel.FormatMessageW.restype is ctypes.c_uint32


def test_unknown_hresult_has_no_invented_description(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    kernel = SimpleNamespace(FormatMessageW=Mock(return_value=0))
    monkeypatch.setattr(ctypes, "WinDLL", Mock(return_value=kernel), raising=False)
    assert helper.hresult_description(0xDEADBEEF) is None


@pytest.mark.parametrize("value", ["", "snow 雪", "nul\x00tail", "\ud800"])
def test_bstr_length_not_null_termination_preserves_text(
    helper: ModuleType, value: str
) -> None:
    raw = value.encode("utf-16-le", "surrogatepass")
    buffer = ctypes.create_string_buffer(raw)
    automation = SimpleNamespace(SysStringLen=lambda _pointer: len(raw) // 2)
    assert helper._string(automation, ctypes.addressof(buffer)) == value
    assert helper._string(automation, None) == ""


@pytest.mark.parametrize(
    "value,kind,field,expected",
    [
        (None, 0, None, None),
        (True, 11, "signed16", -1),
        (False, 11, "signed16", 0),
        (-(2**31), 3, "signed32", -(2**31)),
        (2**31 - 1, 3, "signed32", 2**31 - 1),
    ],
)
def test_input_variant_scalar_layout(
    helper: ModuleType, value: Any, kind: int, field: str | None, expected: Any
) -> None:
    agent = helper.UpdateAgent()
    variant = helper._Variant()
    agent._input(variant, value)
    assert variant.kind == kind
    if field:
        assert getattr(variant.data, field) == expected


@pytest.mark.parametrize("value", [-(2**31) - 1, 2**31, [], {}, 1.5])
def test_unsupported_or_overflowing_inputs_fail_before_native_dispatch(
    helper: ModuleType, value: Any
) -> None:
    with pytest.raises(ValueError):
        helper.UpdateAgent()._input(helper._Variant(), value)


def test_unicode_input_counts_utf16_units_and_reports_allocation_failure(
    helper: ModuleType,
) -> None:
    agent = helper.UpdateAgent()
    agent._automation = SimpleNamespace(SysAllocStringLen=Mock(return_value=42))
    variant = helper._Variant()
    agent._input(variant, "雪😀\x00")
    agent._automation.SysAllocStringLen.assert_called_once_with("雪😀\x00", 4)
    assert variant.kind == 8 and variant.data.bstr == 42
    agent._automation.SysAllocStringLen.return_value = None
    with pytest.raises(MemoryError, match="allocate WUA"):
        agent._input(helper._Variant(), "text")


@pytest.mark.parametrize(
    "kind,field,value,expected",
    [
        (0, "integer", 0, None),
        (1, "integer", 0, None),
        (2, "signed16", -2, -2),
        (3, "signed32", -2145124322, -2145124322),
        (11, "signed16", -1, True),
        (11, "signed16", 0, False),
        (19, "unsigned32", 4294967295, 4294967295),
        (20, "integer", -4, -4),
        (21, "integer", -1, 18446744073709551615),
    ],
)
def test_output_scalar_types_keep_full_hresult_and_byte_counts(
    helper: ModuleType, kind: int, field: str, value: int, expected: Any
) -> None:
    variant = helper._Variant(kind=kind)
    setattr(variant.data, field, value)
    assert helper.UpdateAgent()._output(variant) == expected


@pytest.mark.parametrize(
    "magnitude,scale,negative,expected",
    [(2**80, 0, False, 2**80), (12, 1, False, 1.2), (12, 1, True, -1.2)],
)
def test_decimal_output_uses_native_overlay_and_preserves_integral_magnitude(
    helper: ModuleType, magnitude: int, scale: int, negative: bool, expected: Any
) -> None:
    raw = (
        b"\x0e\x00"
        + bytes([scale, 0x80 if negative else 0])
        + (magnitude >> 64).to_bytes(4, "little")
        + (magnitude & (2**64 - 1)).to_bytes(8, "little")
    )
    variant = helper._Variant()
    ctypes.memmove(ctypes.byref(variant), raw, 16)
    assert helper.UpdateAgent()._output(variant) == expected


def test_null_interface_and_unknown_variant_are_distinct(helper: ModuleType) -> None:
    assert helper.UpdateAgent()._output(helper._Variant(kind=9)) is None
    with pytest.raises(ValueError, match="VARIANT type 77"):
        helper.UpdateAgent()._output(helper._Variant(kind=77))


def test_callback_hresult_boundary_does_not_leak_python_exceptions(
    helper: ModuleType,
) -> None:
    error = ValueError("consumer failed")
    callback = helper._Callback(
        helper._CALLBACK_IDS["Search"][1], Mock(side_effect=error)
    )
    assert callback._receive(None, 4, 5) == -2147467259
    assert callback.error is error
    assert callback.references == 1
    assert callback._add_reference(None) == 2
    assert callback._drop_reference(None) == 1


def test_callback_query_interface_accepts_only_iunknown_and_own_iid(
    helper: ModuleType,
) -> None:
    callback = helper._Callback(helper._CALLBACK_IDS["Search"][1], Mock())
    output = ctypes.c_void_p(999)
    identifier = helper._guid(helper._UNKNOWN)
    assert (
        callback._query_interface(123, ctypes.byref(identifier), ctypes.pointer(output))
        == 0
    )
    assert output.value == 123 and callback.references == 2
    identifier = helper._guid(helper._DISPATCH)
    assert (
        callback._query_interface(123, ctypes.byref(identifier), ctypes.pointer(output))
        == -2147467262
    )
    assert getattr(output, "value") is None and callback.references == 2


@pytest.mark.parametrize(
    "ending_error,cleanup_error",
    [
        (None, None),
        (ValueError("end failed"), None),
        (None, OSError("cleanup failed")),
        (ValueError("end failed"), OSError("cleanup failed")),
    ],
)
def test_async_end_and_cleanup_preserve_primary_error_and_callback_storage(
    helper: ModuleType, ending_error: Exception | None, cleanup_error: Exception | None
) -> None:
    agent, target, job = helper.UpdateAgent(), Mock(), Mock()
    result = object()

    def _call(name: str, *values: Any) -> Any:
        if name == "BeginSearch":
            values[1]._receive(None, None, None)
            return job
        if ending_error:
            raise ending_error
        return result

    target.call.side_effect = _call
    job.call.side_effect = cleanup_error
    if ending_error or cleanup_error:
        expected = ending_error or cleanup_error
        assert isinstance(expected, Exception)
        with pytest.raises(type(expected)) as raised:
            agent.operation(target, "Search", "criteria", lambda: False, None)
        assert raised.value is (ending_error or cleanup_error)
        if ending_error and cleanup_error:
            assert getattr(ending_error, "cleanup_error") == "cleanup failed"
    else:
        assert (
            agent.operation(target, "Search", "criteria", lambda: False, None) is result
        )
    job.call.assert_called_once_with("CleanUp")
    assert bool(helper._RETAINED_CALLBACKS) == bool(cleanup_error)


def test_advisory_abort_failure_still_waits_for_completion_and_cleans_once(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    event = Mock()
    event.wait.side_effect = [False, False, True]
    monkeypatch.setattr(threading, "Event", lambda: event)
    target, job = Mock(), Mock()
    target.call.side_effect = [job, "completed"]
    job.call.side_effect = [helper.WuaError("cannot cancel", 0x8024000A), None]
    assert (
        helper.UpdateAgent().operation(target, "Search", "criteria", lambda: True, None)
        == "completed"
    )
    assert [call.args[0] for call in job.call.call_args_list] == [
        "RequestAbort",
        "CleanUp",
    ]
    assert event.wait.call_count == 3


def test_long_native_operation_repeats_source_power_request_without_cancelling(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    event = Mock()
    event.wait.side_effect = [False, False, False, True]
    monkeypatch.setattr(threading, "Event", lambda: event)
    clock = iter([0, 59, 60, 60, 120, 120])
    monkeypatch.setattr(helper.time, "monotonic", lambda: next(clock))
    keep_awake = Mock()
    monkeypatch.setattr(helper, "_keep_awake", keep_awake)
    target, job = Mock(), Mock()
    target.call.side_effect = [job, "completed"]
    assert (
        helper.UpdateAgent().operation(
            target, "Search", "criteria", lambda: False, None
        )
        == "completed"
    )
    assert keep_awake.call_count == 2
    job.call.assert_called_once_with("CleanUp")


def test_power_request_uses_native_flags_and_ignores_rejected_request(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    kernel = SimpleNamespace(SetThreadExecutionState=Mock(return_value=0))
    monkeypatch.setattr(
        ctypes, "WinDLL", lambda *_args, **_kwargs: kernel, raising=False
    )
    helper._keep_awake()
    kernel.SetThreadExecutionState.assert_called_once_with(0x80000001)


def test_com_session_is_created_only_after_initial_system_info_read(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    ole = SimpleNamespace(CoInitializeEx=Mock(return_value=0), CoUninitialize=Mock())
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(helper, "_libraries", lambda: (ole, object()))
    agent = helper.UpdateAgent()
    monkeypatch.setattr(agent, "create", Mock(return_value=Mock()))
    with agent:
        agent.create.assert_not_called()
        agent.reboot_required()
        agent.create_session()
        assert [call.args[0] for call in agent.create.call_args_list] == [
            "c01b9ba0-bea7-41ba-b604-d0a36f469133",
            "4cb43d7f-7eee-4906-8698-60da1c38f2fe",
        ]
    ole.CoUninitialize.assert_called_once_with()


def test_failed_com_initialization_does_not_uninitialize(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    ole = SimpleNamespace(
        CoInitializeEx=Mock(return_value=-2147417850), CoUninitialize=Mock()
    )
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(helper, "_libraries", lambda: (ole, object()))
    with pytest.raises(helper.WuaError):
        with helper.UpdateAgent():
            pytest.fail("failed initialization entered")
    ole.CoUninitialize.assert_not_called()


def test_failed_create_releases_any_partial_native_pointer(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = helper.UpdateAgent()

    def _create(*values: Any) -> int:
        values[-1]._obj.value = 123
        return -2147467259

    agent._ole = SimpleNamespace(CoCreateInstance=_create)
    release = Mock()
    monkeypatch.setattr(helper, "_release", release)
    with pytest.raises(helper.WuaError):
        agent.create("4cb43d7f-7eee-4906-8698-60da1c38f2fe")
    assert release.call_args.args[0].value == 123


def test_input_failure_clears_allocated_variants_before_dispatch(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = helper.UpdateAgent()
    agent._cleanup = ExitStack()
    monkeypatch.setattr(helper, "_release", Mock())
    monkeypatch.setattr(helper, "_method", lambda *_args: lambda *_values: 0)
    clear = Mock()
    monkeypatch.setattr(agent, "_clear", clear)

    def partial(variant: Any, _value: Any) -> None:
        variant.kind = 8
        variant.data.bstr = 123
        raise MemoryError("partial input")

    monkeypatch.setattr(agent, "_input", partial)
    with pytest.raises(MemoryError, match="partial input"):
        helper._UpdateObject(agent, 99).call("test", "text")
    assert clear.call_args.args[0]._obj.data.bstr == 123
    agent._cleanup.close()
