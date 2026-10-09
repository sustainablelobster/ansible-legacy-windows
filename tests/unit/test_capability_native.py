"""Exercise DISM metadata, buffer ownership, filtering and failure cleanup."""

# SPDX-License-Identifier: GPL-3.0-or-later
# ctypes by-reference substitutes must fill the original native output records.
# This file alone accesses their backing objects and the helper's private ABI.
# pylint: disable=protected-access

import ctypes
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.fixture(name="provider")
def native_capability(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Supply a native-buffer provider while retaining actual metadata parsing.

    :param monkeypatch: Scoped imports and library replacement.
    :returns: Helper, library and native storage that outlives each call.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    module = load_module(
        ROOT / "plugins/module_utils/legacy_windows_capability.py", "capability_tested"
    )
    records = (module._Capability * 3)(  # pylint: disable=protected-access
        ("Second", 0), ("First", 4), ("Third", 4)
    )
    buffers: list[Any] = [records]
    events: list[tuple[Any, ...]] = []

    def _open(_image: str, _windows: Any, _system: Any, output: Any) -> int:
        output._obj.value = 23
        return 0

    def _catalogue(_session: Any, output: Any, count: Any) -> int:
        output._obj.contents = records[0]
        count._obj.value = 3
        return 0

    def _info(_session: Any, name: str, output: Any) -> int:
        events.append(("info", name))
        record = module._CapabilityInfo(  # pylint: disable=protected-access
            name, 4, "display " + name, "description " + name, 2**32 - 1, 19
        )
        buffers.append(record)
        output._obj.contents = record
        return 0

    def _delete(pointer: Any) -> int:
        events.append(("delete", ctypes.addressof(pointer.contents)))
        return 0

    library = SimpleNamespace(
        DismInitialize=Mock(return_value=0),
        DismOpenSession=Mock(side_effect=_open),
        DismGetCapabilities=Mock(side_effect=_catalogue),
        DismGetCapabilityInfo=Mock(side_effect=_info),
        DismGetLastErrorMessage=Mock(return_value=1),
        DismDelete=Mock(side_effect=_delete),
        DismCloseSession=Mock(return_value=0),
        DismShutdown=Mock(return_value=0),
    )
    monkeypatch.setattr(module, "_library", lambda: library)
    return SimpleNamespace(
        module=module, library=library, buffers=buffers, events=events, records=records
    )


# pylint: enable=duplicate-code


def test_catalogue_order_full_fields_unsigned_sizes_and_buffer_release(
    provider: Any,
) -> None:
    result = provider.module.capabilities()
    assert [entry["name"] for entry in result] == ["Second", "First", "Third"]
    assert result[0] == {
        "name": "Second",
        "state": "Installed",
        "display_name": "display Second",
        "description": "description Second",
        "download_size": 2**32 - 1,
        "install_size": 19,
    }
    assert len([event for event in provider.events if event[0] == "delete"]) == 4
    provider.library.DismCloseSession.assert_called_once()
    provider.library.DismShutdown.assert_called_once_with()


def test_filtering_is_lazy_preserves_native_order_and_queries_only_matches(
    provider: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    matches = Mock(side_effect=lambda name, _patterns: name != "Second")
    monkeypatch.setattr(provider.module.matching, "matches", matches)
    result = provider.module.capabilities(["pattern", "[bad"])
    assert [entry["name"] for entry in result] == ["First", "Third"]
    assert [event for event in provider.events if event[0] == "info"] == [
        ("info", "First"),
        ("info", "Third"),
    ]
    assert all(call.args[1] == ["pattern", "[bad"] for call in matches.call_args_list)


@pytest.mark.parametrize("level,path", [(None, None), (0, ""), (3, "owned.log")])
def test_logging_false_values_use_pinned_source_defaults(
    provider: Any, level: Any, path: Any
) -> None:
    provider.module.capabilities(log_level=level, log_path=path)
    provider.library.DismInitialize.assert_called_once_with(
        level or 2, path or None, None
    )


@pytest.mark.parametrize("operation", ["DismGetCapabilities", "DismGetCapabilityInfo"])
def test_metadata_failure_preserves_hresult_and_releases_open_session(
    provider: Any, operation: str
) -> None:
    function = getattr(provider.library, operation)
    function.side_effect = None
    function.return_value = -2147024891
    with pytest.raises(OSError, match=operation + r" failed .*0x80070005"):
        provider.module.capabilities()
    provider.library.DismCloseSession.assert_called_once()
    provider.library.DismShutdown.assert_called_once_with()
    if operation == "DismGetCapabilityInfo":
        assert provider.events == [("delete", ctypes.addressof(provider.records))]


def test_invalid_reached_pattern_also_releases_every_native_resource(
    provider: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        provider.module.matching,
        "matches",
        Mock(side_effect=ValueError("bad wildcard")),
    )
    with pytest.raises(ValueError, match="bad wildcard"):
        provider.module.capabilities(["[bad"])
    assert provider.events == [("delete", ctypes.addressof(provider.records))]
    provider.library.DismCloseSession.assert_called_once()
    provider.library.DismShutdown.assert_called_once_with()


def test_failed_initialize_does_not_close_or_shutdown_uninitialized_provider(
    provider: Any,
) -> None:
    provider.library.DismInitialize.return_value = -2147024891
    with pytest.raises(OSError, match="DismInitialize"):
        provider.module.capabilities()
    provider.library.DismOpenSession.assert_not_called()
    provider.library.DismCloseSession.assert_not_called()
    provider.library.DismShutdown.assert_not_called()


def test_failed_open_shuts_down_without_closing_an_unopened_session(
    provider: Any,
) -> None:
    provider.library.DismOpenSession.side_effect = None
    provider.library.DismOpenSession.return_value = -2147024891
    with pytest.raises(OSError, match="DismOpenSession"):
        provider.module.capabilities()
    provider.library.DismCloseSession.assert_not_called()
    provider.library.DismShutdown.assert_called_once_with()


def test_missing_catalogue_buffer_does_not_dereference_null_pointer(
    provider: Any,
) -> None:
    def _missing(_session: Any, _output: Any, count: Any) -> int:
        count._obj.value = 3
        return 0

    provider.library.DismGetCapabilities.side_effect = _missing
    with pytest.raises(OSError, match="count without a capability array"):
        provider.module.capabilities()
    provider.library.DismCloseSession.assert_called_once()
    provider.library.DismShutdown.assert_called_once_with()


def test_empty_catalogue_is_successful_and_releases_the_open_session(
    provider: Any,
) -> None:
    provider.library.DismGetCapabilities.side_effect = None
    provider.library.DismGetCapabilities.return_value = 0
    assert provider.module.capabilities() == []
    provider.library.DismGetCapabilityInfo.assert_not_called()
    provider.library.DismCloseSession.assert_called_once()
    provider.library.DismShutdown.assert_called_once_with()


def test_missing_information_buffer_is_actionable_and_catalogue_is_released(
    provider: Any,
) -> None:
    provider.library.DismGetCapabilityInfo.side_effect = None
    provider.library.DismGetCapabilityInfo.return_value = 0
    with pytest.raises(OSError, match="no capability information"):
        provider.module.capabilities()
    assert provider.events == [("delete", ctypes.addressof(provider.records))]
    provider.library.DismCloseSession.assert_called_once()
    provider.library.DismShutdown.assert_called_once_with()


@pytest.mark.parametrize("operation", ["DismCloseSession", "DismShutdown"])
def test_native_cleanup_failure_is_not_hidden_by_a_successful_metadata_read(
    provider: Any, operation: str
) -> None:
    getattr(provider.library, operation).return_value = -2147024891
    with pytest.raises(OSError, match=operation):
        provider.module.capabilities()
    provider.library.DismShutdown.assert_called_once_with()


def test_native_error_detail_is_copied_then_freed(provider: Any) -> None:
    detail = provider.module._DismString(
        "native diagnostic\r\n"
    )  # pylint: disable=protected-access

    def _message(output: Any) -> int:
        output._obj.contents = detail
        return 0

    provider.library.DismGetLastErrorMessage.side_effect = _message
    provider.library.DismInitialize.return_value = -2147024891
    with pytest.raises(OSError, match="native diagnostic"):
        provider.module.capabilities()
    assert provider.events == [("delete", ctypes.addressof(detail))]


def test_non_windows_target_fails_without_loading_a_library(
    provider: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Exercise the real platform boundary with an independently loaded helper.
    module: ModuleType = load_module(
        ROOT / "plugins/module_utils/legacy_windows_capability.py",
        "capability_boundary",
    )
    monkeypatch.setattr(module.os, "name", "posix")
    with pytest.raises(ValueError, match="Windows target"):
        module.capabilities()
    provider.library.DismInitialize.assert_not_called()
