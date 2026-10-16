"""Observe pagefile contracts, provider writes, native ownership and recovery."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Native providers are boundary substitutes; routine checks never contact hosts.
# pylint: disable=protected-access

import copy
import ctypes
from contextlib import ExitStack
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module

_DIRECTORY = ROOT / "legacy_community_windows/plugins/module_utils"
_NAME = "C:\\pagefile.sys"


def _row(name: str = _NAME, initial: int = 2048, maximum: int = 4096) -> dict[str, Any]:
    return {
        "__PATH": "Win32_PageFileSetting.Name=" + name,
        "Name": name,
        "InitialSize": initial,
        "MaximumSize": maximum,
        "Caption": "native caption",
        "Description": "native description",
    }


# The fake mirrors only the native pagefile operations used by the public module.
# pylint: disable=missing-function-docstring,missing-return-doc
class _Provider:
    def __init__(self) -> None:
        self.rows = [_row()]
        self.mode: bool | None = False
        self.automatic_supported = True
        self.writes: list[Any] = []
        self.size_error = False
        self.create_error = False

    def __enter__(self) -> "_Provider":
        return self

    def __exit__(self, *_arguments: Any) -> None:
        return None

    def records(self) -> list[dict[str, Any]]:
        return self.rows

    def automatic(self) -> bool | None:
        return self.mode

    def set_automatic(self, enabled: bool) -> None:
        self.writes.append(("automatic", enabled))
        self.mode = enabled

    def delete(self, record: dict[str, Any]) -> None:
        self.writes.append(("delete", record["Name"]))
        self.rows.remove(record)

    def create(self, name: str) -> dict[str, Any]:
        self.writes.append(("create", name))
        if self.create_error:
            raise OSError("controlled creation failure")
        result = _row(name, 0, 0)
        self.rows.append(result)
        return result

    def set_sizes(self, record: dict[str, Any], initial: int, maximum: int) -> None:
        self.writes.append(("sizes", record["Name"], initial, maximum))
        if self.size_error:
            raise OSError("controlled provider size failure")
        record.update(InitialSize=initial, MaximumSize=maximum)


# pylint: enable=missing-function-docstring,missing-return-doc


@pytest.fixture(name="pagefiles")
def fixture_pagefiles(monkeypatch: pytest.MonkeyPatch) -> tuple[ModuleType, _Provider]:
    """Load real argument and management code around an in-memory provider.

    :param monkeypatch: Scoped helper paths and native provider substitution.
    :returns: Imported payload and its native boundary substitute.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(str(_DIRECTORY))
    module = load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_pagefile.py",
        "tested_community_pagefile",
    )
    provider = _Provider()
    monkeypatch.setattr(module, "Pagefiles", lambda: provider)
    monkeypatch.setattr(module.os.path, "isdir", lambda _path: True)
    return module, provider


def test_query_keeps_native_fields_and_filters_drive(
    pagefiles: tuple[ModuleType, _Provider],
) -> None:
    module, provider = pagefiles
    result = module._manage({"drive": "c"})
    assert result == {
        "changed": False,
        "automatic_managed_pagefiles": False,
        "pagefiles": [
            {
                "name": _NAME,
                "caption": "native caption",
                "description": "native description",
                "initial_size": 2048,
                "maximum_size": 4096,
            }
        ],
    }
    assert module._manage({"drive": "d"})["pagefiles"] == []
    assert not provider.writes


def test_missing_automatic_field_is_null_with_warning(
    pagefiles: tuple[ModuleType, _Provider],
) -> None:
    module, provider = pagefiles
    provider.mode, provider.automatic_supported = None, False
    result = module._manage({})
    assert result["automatic_managed_pagefiles"] is None
    assert "does not expose" in result["warnings"][0]
    result = module._manage({"automatic": False, "remove_all": True})
    assert result["failed"] is True and result["changed"] is False
    assert not provider.writes


def test_fixed_sizes_update_repeat_query_and_restore(
    pagefiles: tuple[ModuleType, _Provider],
) -> None:
    module, provider = pagefiles
    options = {
        "drive": "C",
        "initial_size": 32,
        "maximum_size": 64,
        "state": "present",
        "override": False,
    }
    assert module._manage(options) == {"changed": True}
    assert module._manage(options) == {"changed": False}
    assert module._manage({"drive": "C"})["pagefiles"][0]["initial_size"] == 32
    assert (
        module._manage(dict(options, initial_size=2048, maximum_size=4096))["changed"]
        is True
    )
    assert provider.rows == [_row()]


def test_default_override_replaces_existing_each_time(
    pagefiles: tuple[ModuleType, _Provider],
) -> None:
    module, provider = pagefiles
    options = {"drive": "C", "state": "present", "system_managed": True}
    assert module._manage(options)["changed"] is True
    assert module._manage(options)["changed"] is True
    assert [write[0] for write in provider.writes] == [
        "delete",
        "create",
        "delete",
        "create",
    ]
    assert provider.rows[0]["InitialSize"] == 0


def test_override_false_preserves_system_managed_existing_file(
    pagefiles: tuple[ModuleType, _Provider],
) -> None:
    module, provider = pagefiles
    provider.rows = [_row(initial=0, maximum=0)]
    assert (
        module._manage(
            {
                "drive": "C",
                "state": "present",
                "override": False,
                "initial_size": 32,
                "maximum_size": 64,
            }
        )["changed"]
        is False
    )
    assert not provider.writes


@pytest.mark.parametrize(
    "options",
    [
        {
            "drive": "C",
            "state": "present",
            "override": False,
            "initial_size": 32,
            "maximum_size": 64,
        },
        {"drive": "D", "state": "present", "system_managed": True},
        {"drive": "C", "state": "absent"},
        {"remove_all": True},
        {"automatic": True},
    ],
)
def test_check_mode_predicts_without_any_native_write(
    pagefiles: tuple[ModuleType, _Provider], options: dict[str, Any]
) -> None:
    module, provider = pagefiles
    original = copy.deepcopy(provider.rows)
    assert module._manage(dict(options, _ansible_check_mode=True))["changed"] is True
    assert provider.rows == original and provider.mode is False
    assert not provider.writes


def test_remove_all_and_global_mode_query_reflect_real_state(
    pagefiles: tuple[ModuleType, _Provider],
) -> None:
    module, provider = pagefiles
    result = module._manage({"remove_all": True, "automatic": True})
    assert result == {
        "changed": True,
        "automatic_managed_pagefiles": True,
        "pagefiles": [],
    }
    assert module._manage({"remove_all": True, "automatic": True})["changed"] is False
    assert provider.writes == [("delete", _NAME), ("automatic", True)]


def test_absence_is_case_insensitive_and_idempotent(
    pagefiles: tuple[ModuleType, _Provider],
) -> None:
    module, provider = pagefiles
    assert module._manage({"drive": "c", "state": "absent"}) == {"changed": True}
    assert module._manage({"drive": "C", "state": "absent"}) == {"changed": False}
    assert provider.rows == []


def test_size_rejection_uses_released_registry_workaround(
    pagefiles: tuple[ModuleType, _Provider], monkeypatch: pytest.MonkeyPatch
) -> None:
    module, provider = pagefiles
    provider.size_error = True
    fallback = Mock()
    monkeypatch.setattr(module, "registry_sizes", fallback)
    result = module._manage(
        {
            "drive": "C",
            "state": "present",
            "override": False,
            "initial_size": 32,
            "maximum_size": 64,
        }
    )
    assert result == {"changed": True}
    assert provider.writes == [("sizes", _NAME, 32, 64), ("delete", _NAME)]
    fallback.assert_called_once_with(_NAME, 32, 64)


def test_failed_replacement_reports_already_removed_configuration(
    pagefiles: tuple[ModuleType, _Provider],
) -> None:
    module, provider = pagefiles
    provider.create_error = True
    result = module._manage({"drive": "C", "state": "present"})
    assert result["changed"] is True and result["failed"] is True
    assert "creation failure" in result["msg"]
    assert provider.rows == []


@pytest.mark.parametrize(
    "options",
    [
        {"state": "invalid"},
        {"state": "present"},
        {"drive": "C:"},
        {"initial_size": -1},
        {"maximum_size": "bad"},
    ],
)
def test_invalid_inputs_fail_before_provider_writes(
    pagefiles: tuple[ModuleType, _Provider], options: dict[str, Any]
) -> None:
    module, provider = pagefiles
    with pytest.raises(ValueError):
        module._manage(options)
    assert not provider.writes


def _native(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.syspath_prepend(str(HELPER.parent))
    return load_module(
        _DIRECTORY / "legacy_community_windows_pagefile_native.py",
        "tested_pagefile_native",
    )


@pytest.mark.parametrize(
    "hresult,unavailable", [(0x80041002, True), (0x80070005, False)]
)
def test_automatic_capability_catches_only_absent_native_property(
    monkeypatch: pytest.MonkeyPatch, hresult: int, unavailable: bool
) -> None:
    native = _native(monkeypatch)
    error = OSError("native error")
    setattr(error, "hresult", hresult)
    connection = Mock()
    connection.query.side_effect = error
    monkeypatch.setattr(native, "WmiConnection", lambda: connection)
    provider = native.Pagefiles()
    if unavailable:
        assert provider.automatic() is None
        assert provider.automatic_supported is False
    else:
        with pytest.raises(OSError):
            provider.automatic()
        assert provider.automatic_supported is True


def test_registry_workaround_preserves_unrelated_and_replaces_exact_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = _native(monkeypatch)
    registry = MagicMock()
    registry.KEY_QUERY_VALUE, registry.KEY_SET_VALUE, registry.REG_MULTI_SZ = 1, 2, 7
    registry.QueryValueEx.return_value = (
        [
            r'"c:\pagefile.sys" 2048 4096',
            r"D:\pagefile.sys 64 128",
            r"C:\pagefile.sys.old 32 64",
        ],
        7,
    )
    monkeypatch.setattr(native, "winreg", registry)
    native.registry_sizes(_NAME, 32, 64)
    registry.SetValueEx.assert_called_once_with(
        registry.OpenKey.return_value.__enter__.return_value,
        "PagingFiles",
        0,
        7,
        [
            r"D:\pagefile.sys 64 128",
            r"C:\pagefile.sys.old 32 64",
            r"C:\pagefile.sys 32 64",
        ],
    )


def test_native_spawn_owns_reference_and_saves_create_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = _native(monkeypatch)
    connection = SimpleNamespace(_services=100, _automation=200)
    monkeypatch.setattr(native, "WmiConnection", lambda: connection)
    monkeypatch.setattr(native, "_get_object", lambda *_arguments: 300)
    writes: list[Any] = []
    released: list[Any] = []

    def _method(_pointer: Any, slot: int, _result: Any, _types: Any) -> Any:
        assert slot == 15

        def _spawn(_self: Any, flags: int, output: Any) -> int:
            assert flags == 0
            ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p)).contents.value = 400
            return 0

        return _spawn

    monkeypatch.setattr(native, "_method", _method)
    monkeypatch.setattr(
        native,
        "_put_string",
        lambda _pointer, _automation, name, value: writes.append((name, value)),
    )
    monkeypatch.setattr(
        native,
        "_save",
        lambda _connection, pointer, flags: writes.append((pointer.value, flags)),
    )
    monkeypatch.setattr(native, "_release", released.append)
    provider = native.Pagefiles()
    monkeypatch.setattr(provider, "records", lambda: [_row()])
    assert provider.create(_NAME)["Name"] == _NAME
    assert writes == [("Name", _NAME), (400, 2)]
    assert released[0].value == 400


def test_native_delete_uses_synchronous_deleteinstance_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = _native(monkeypatch)
    connection = SimpleNamespace(_services=100, _automation=200)
    monkeypatch.setattr(native, "WmiConnection", lambda: connection)
    monkeypatch.setattr(native, "_bstr", lambda _automation, _cleanup, value: value)
    calls: list[Any] = []

    def _method(pointer: Any, slot: int, _result: Any, types: Any) -> Any:
        assert pointer == 100 and slot == 16
        assert len(types) == 4

        def _delete(*values: Any) -> int:
            calls.append(values)
            return 0

        return _delete

    monkeypatch.setattr(native, "_method", _method)
    native.Pagefiles().delete(_row())
    assert calls == [(100, _row()["__PATH"], 0, None, None)]


def test_global_automatic_write_passes_only_its_partial_update_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = _native(monkeypatch)
    connection = SimpleNamespace(_services=100, _automation=200)
    monkeypatch.setattr(native, "WmiConnection", lambda: connection)
    monkeypatch.setattr(native, "_get_object", lambda *_arguments: 300)
    context = object()
    monkeypatch.setattr(native, "_automatic_context", lambda *_arguments: context)
    put, save = Mock(), Mock()
    monkeypatch.setattr(native, "_put_boolean", put)
    monkeypatch.setattr(native, "_save", save)
    provider = native.Pagefiles()
    provider.computer = {"__PATH": "the actual computer instance"}
    provider.set_automatic(False)
    put.assert_called_once_with(300, 200, "AutomaticManagedPagefile", False)
    save.assert_called_once_with(connection, 300, 1, context)


@pytest.mark.parametrize("context", [None, 700])
def test_native_save_passes_the_selected_context_without_changing_flags(
    monkeypatch: pytest.MonkeyPatch, context: int | None
) -> None:
    native = _native(monkeypatch)
    connection = SimpleNamespace(_services=100)
    put = Mock(return_value=0)

    def _method(pointer: Any, slot: int, _result: Any, types: Any) -> Any:
        assert pointer == 100 and slot == 14 and len(types) == 4
        return put

    monkeypatch.setattr(native, "_method", _method)
    native._save(connection, 300, 1, context)
    put.assert_called_once_with(100, 300, 1, context, None)


@pytest.mark.parametrize(
    "failure",
    [None, "create", "marker", "allocate", "array_element", "properties"],
)
def test_partial_automatic_context_owns_native_values_on_success_and_failure(
    monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    native = _native(monkeypatch)
    released: list[Any] = []
    markers: list[tuple[str, int, int]] = []
    ole, automation = Mock(), Mock()
    automation.SafeArrayCreateVector.return_value = 0 if failure == "allocate" else 400
    automation.SafeArrayPutElement.return_value = (
        0x80070057 if failure == "array_element" else 0
    )
    automation.VariantClear.return_value = 0

    def _create(*arguments: Any) -> int:
        ctypes.cast(arguments[4], ctypes.POINTER(ctypes.c_void_p)).contents.value = 700
        return 0x80070005 if failure == "create" else 0

    def _set_value(_context: Any, name: str, flags: int, pointer: Any) -> int:
        assert flags == 0
        variant = ctypes.cast(pointer, ctypes.POINTER(native._Variant)).contents
        markers.append((name, variant.kind, variant.data.signed16))
        if failure == "marker" and name == "__PUT_EXTENSIONS":
            return 0x80041003
        if failure == "properties" and name == "__PUT_EXT_PROPERTIES":
            return 0x80041001
        return 0

    def _method(_context: Any, slot: int, _result: Any, types: Any) -> Any:
        assert slot == 8 and len(types) == 3
        return _set_value

    ole.CoCreateInstance.side_effect = _create
    monkeypatch.setattr(native, "_libraries", lambda: (ole, automation))
    monkeypatch.setattr(native, "_release", released.append)
    monkeypatch.setattr(native, "_method", _method)
    bstr = Mock(return_value=800)
    monkeypatch.setattr(native, "_bstr", bstr)
    connection = SimpleNamespace(_automation=automation)

    def _run() -> None:
        with ExitStack() as cleanup:
            context = native._automatic_context(connection, cleanup)
            assert context.value == 700

    if failure:
        with pytest.raises(MemoryError if failure == "allocate" else OSError):
            _run()
    else:
        _run()
        assert markers == [
            ("__PUT_EXTENSIONS", 11, -1),
            ("__PUT_EXT_CLIENT_REQUEST", 11, -1),
            ("__PUT_EXT_PROPERTIES", 0x2008, 400),
        ]
        automation.SafeArrayCreateVector.assert_called_once_with(8, 0, 1)
        assert bstr.call_args.args[-1] == "AutomaticManagedPagefile"
        assert automation.SafeArrayPutElement.call_args.args[-1] == 800
    assert len(released) == 1 and released[0].value == 700
    assert automation.VariantClear.call_count == (
        0 if failure in ("create", "marker") else 1
    )
