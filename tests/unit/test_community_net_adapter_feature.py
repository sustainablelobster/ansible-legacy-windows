"""Observe adapter-binding contracts, native transactions and cleanup."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Native boundaries are substitutes; controller checks never contact lab hosts.
# pylint: disable=protected-access

import ctypes
from contextlib import ExitStack
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module

_DIRECTORY = ROOT / "legacy_community_windows/plugins/module_utils"


# The fake stages changes until Apply and cancels them on context exit.
# pylint: disable=missing-function-docstring,missing-return-doc
class _Bindings:
    def __init__(self) -> None:
        self.writable: bool | None = None
        self.names = {"Ethernet Café": "first", "Wireless": "second"}
        self.components = {
            "ms_pacer": {
                "Ethernet Café": [{"pointer": 1, "enabled": True}],
                "Wireless": [{"pointer": 2, "enabled": False}],
            },
            "ms_msclient": {
                "Ethernet Café": [
                    {"pointer": 3, "enabled": True},
                    {"pointer": 4, "enabled": False},
                ],
                "Wireless": [],
            },
        }
        self.pending: list[tuple[dict[str, Any], bool]] = []
        self.applied: list[list[tuple[dict[str, Any], bool]]] = []
        self.reboot = False
        self.apply_error = False

    def __call__(self, writable: bool) -> "_Bindings":
        self.writable = writable
        return self

    def __enter__(self) -> "_Bindings":
        return self

    def __exit__(self, *_arguments: Any) -> None:
        self.pending.clear()

    def adapters(self) -> dict[str, str]:
        return dict(self.names)

    def paths(
        self, component: str, adapters: dict[str, str]
    ) -> dict[str, list[dict[str, Any]]]:
        if component.lower() not in self.components:
            raise ValueError("Invalid componentID: " + component)
        return {
            name: self.components[component.lower()][name]
            for name in self.names
            if name in adapters
        }

    def enable(self, path: dict[str, Any], enabled: bool) -> None:
        self.pending.append((path, enabled))

    def apply(self) -> bool:
        if self.apply_error:
            raise OSError("controlled apply failure")
        self.applied.append(list(self.pending))
        for path, enabled in self.pending:
            path["enabled"] = enabled
        self.pending.clear()
        return self.reboot


# pylint: enable=missing-function-docstring,missing-return-doc


@pytest.fixture(name="bindings")
def fixture_bindings(monkeypatch: pytest.MonkeyPatch) -> tuple[ModuleType, _Bindings]:
    """Load the public module with a transactional native boundary substitute.

    :param monkeypatch: Scoped helper paths and native factory replacement.
    :returns: Imported payload and mutable binding-state substitute.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(str(_DIRECTORY))
    module = load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_net_adapter_feature.py",
        "tested_community_net_adapter_feature",
    )
    native = _Bindings()
    monkeypatch.setattr(module, "NetworkBindings", native)
    return module, native


def test_case_insensitive_scalar_lifecycle_is_idempotent(
    bindings: tuple[ModuleType, _Bindings],
) -> None:
    module, native = bindings
    arguments = {
        "interface": "ethernet café",
        "component_id": "MS_PACER",
        "state": "disabled",
    }
    assert module._manage(arguments) == {"changed": True}
    assert len(native.applied) == 1
    assert module._manage(arguments) == {"changed": False}
    assert len(native.applied) == 1
    assert native.components["ms_pacer"]["Wireless"][0]["enabled"] is False
    assert native.writable is True
    assert module._manage(dict(arguments, state="enabled")) == {"changed": True}


def test_wildcard_enables_only_paths_that_differ(
    bindings: tuple[ModuleType, _Bindings],
) -> None:
    module, native = bindings
    assert module._manage({"interface": "*", "component_id": ["ms_pacer"]}) == {
        "changed": True
    }
    assert [path["pointer"] for path, _enabled in native.applied[0]] == [2]
    assert module._manage({"interface": "*", "component_id": "ms_pacer"}) == {
        "changed": False
    }


def test_every_native_path_to_one_adapter_is_updated(
    bindings: tuple[ModuleType, _Bindings],
) -> None:
    module, native = bindings
    arguments = {"interface": "Ethernet Café", "component_id": "ms_msclient"}
    assert module._manage(arguments) == {"changed": True}
    assert [path["pointer"] for path, _enabled in native.applied[0]] == [4]
    assert module._manage(arguments) == {"changed": False}
    assert module._manage(dict(arguments, state="disabled")) == {"changed": True}
    assert len(native.applied[-1]) == 2


def test_check_mode_does_not_acquire_lock_or_stage_writes(
    bindings: tuple[ModuleType, _Bindings],
) -> None:
    module, native = bindings
    assert module._manage(
        {"interface": "*", "component_id": "ms_pacer", "_ansible_check_mode": True}
    ) == {"changed": True}
    assert native.writable is False
    assert not native.pending and not native.applied
    assert native.components["ms_pacer"]["Wireless"][0]["enabled"] is False


@pytest.mark.parametrize(
    "arguments, message",
    [
        ({}, "required"),
        ({"interface": "Ethernet Café"}, "required"),
        ({"component_id": "ms_pacer"}, "required"),
        (
            {"interface": "Ethernet Café", "component_id": "ms_pacer", "state": "up"},
            "state must be",
        ),
        (
            {"interface": ["Ethernet Café", "missing"], "component_id": "ms_pacer"},
            "Invalid network adapter name",
        ),
        (
            {"interface": "Eth*", "component_id": "ms_pacer"},
            "Invalid network adapter name",
        ),
        (
            {"interface": "Ethernet Café", "component_id": ["ms_pacer", "missing"]},
            "Invalid componentID",
        ),
        (
            {"interface": "*", "component_id": ["ms_pacer", "ms_msclient"]},
            "has no binding on adapter Wireless",
        ),
    ],
)
def test_invalid_requests_fail_before_any_binding_is_staged(
    bindings: tuple[ModuleType, _Bindings], arguments: dict[str, Any], message: str
) -> None:
    module, native = bindings
    with pytest.raises(ValueError, match=message):
        module._manage(dict(arguments, state=arguments.get("state", "disabled")))
    assert not native.applied and not native.pending


def test_native_restart_requirement_is_reported_without_restarting(
    bindings: tuple[ModuleType, _Bindings],
) -> None:
    module, native = bindings
    native.reboot = True
    result = module._manage({"interface": "*", "component_id": "ms_pacer"})
    assert result["changed"] is True
    assert "require a restart" in result["warnings"][0]


def test_staging_failure_cancels_pending_changes(
    bindings: tuple[ModuleType, _Bindings],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, native = bindings
    monkeypatch.setattr(native, "enable", Mock(side_effect=OSError("staging failure")))
    with pytest.raises(OSError, match="staging failure"):
        module._manage({"interface": "*", "component_id": "ms_pacer"})
    assert not native.applied and not native.pending


def test_apply_failure_reports_attempted_change_and_actionable_error(
    bindings: tuple[ModuleType, _Bindings],
) -> None:
    module, native = bindings
    native.apply_error = True
    assert module._manage({"interface": "*", "component_id": "ms_pacer"}) == {
        "changed": True,
        "failed": True,
        "msg": "controlled apply failure",
    }
    assert not native.pending


def _native(monkeypatch: pytest.MonkeyPatch) -> tuple[ModuleType, Any]:
    monkeypatch.syspath_prepend(str(HELPER.parent))
    module = load_module(
        _DIRECTORY / "legacy_community_windows_net_adapter_feature_native.py",
        "tested_community_net_adapter_feature_native",
    )
    native = module.NetworkBindings(True)
    native.cleanup = ExitStack()
    native.ole = Mock()
    native.configuration = ctypes.c_void_p(10)
    return module, native


def test_native_guids_keep_published_little_endian_layout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, _bindings = _native(monkeypatch)
    assert bytes(module._guid("4d36e972-e325-11ce-bfc1-08002be10318")) == bytes.fromhex(
        "72e9364d25e3ce11bfc108002be10318"
    )


def test_native_path_state_uses_boolean_and_commits_synchronously(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _module, native = _native(monkeypatch)
    calls: list[tuple[Any, ...]] = []

    def call(*arguments: Any) -> int:
        """Record native arguments and return Windows' successful reboot code.

        :param arguments: Native interface, slot and typed arguments.
        :returns: Successful HRESULT.
        """
        calls.append(arguments)
        return 0x0004A020 if arguments[1] == 5 else 0

    native._call = call
    native.enable({"pointer": 30}, False)
    assert native.pending is True
    assert calls == [(30, 6, [ctypes.c_int32], 0)]
    assert native.apply() is True
    assert calls[-1] == (native.configuration, 5, ())
    assert native.pending is False


def test_native_read_only_cannot_stage_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, _bindings = _native(monkeypatch)
    with pytest.raises(ValueError, match="read-only"):
        module.NetworkBindings(False).enable({"pointer": 30}, True)


def test_native_context_cancels_before_releasing_pointers_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _module, native = _native(monkeypatch)
    events: list[Any] = []
    native.pending = True
    native._call = lambda *arguments: events.append(arguments)
    native.cleanup.callback(events.append, "released")
    native.__exit__(None, None, None)
    assert events == [(native.configuration, 6, ()), "released"]


def test_native_lock_contention_frees_owner_without_initializing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _module, native = _native(monkeypatch)
    native._call = Mock(return_value=1)
    with pytest.raises(OSError, match="locked by another application"):
        native._acquire_lock()
    native.ole.CoTaskMemFree.assert_called_once()
    assert native._call.call_args.args[1] == 3


def test_native_enumerator_next_uses_fetched_count_and_owns_pointer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module, native = _native(monkeypatch)
    released: list[int | None] = []
    monkeypatch.setattr(module, "_release", lambda value: released.append(value.value))
    slots: list[int] = []

    def call(_pointer: Any, slot: int, _types: Any, *_arguments: Any) -> int:
        """Return one owned element and then the end-of-enumeration HRESULT.

        :param slot: Native enumerator method index.
        :param _arguments: Native count, output pointer and fetched-count pointer.
        :returns: S_OK followed by S_FALSE.
        """
        slots.append(slot)
        if len(slots) == 1:
            ctypes.cast(_arguments[1], ctypes.POINTER(ctypes.c_void_p))[0] = 99
            ctypes.cast(_arguments[2], ctypes.POINTER(ctypes.c_uint32))[0] = 1
            return 0
        return 1

    native._call = call
    assert [pointer.value for pointer in native._enumerate(20)] == [99]
    native.cleanup.close()
    assert slots == [3, 3]
    assert released == [None, 99]


def test_native_strings_are_cotaskmem_freed_even_on_getter_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _module, native = _native(monkeypatch)
    native._call = Mock(side_effect=OSError("getter failed"))
    with pytest.raises(OSError, match="getter failed"):
        native._string(10, 6)
    native.ole.CoTaskMemFree.assert_called_once()


def test_native_paths_match_adapter_instance_not_display_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _module, native = _native(monkeypatch)
    objects = {
        (10, 8): 11,
        (11, 0): 12,
        (12, 8): 13,
        (14, 10): 15,
        (16, 5): 17,
        (18, 5): 19,
        (20, 10): 21,
        (22, 5): 23,
    }
    enumerations = {13: [14, 20], 15: [16, 18], 21: [22]}
    native.configuration = 10
    native._object = lambda pointer, slot, *_arguments: objects[pointer, slot]
    native._enumerate = lambda pointer: iter(enumerations[pointer])
    native._instance_id = lambda pointer: {17: "transport", 19: "NIC", 23: "other"}[
        pointer
    ]
    native._call = Mock(return_value=1)
    assert native.paths("ms_pacer", {"Ethernet Café": "nic"}) == {
        "Ethernet Café": [{"pointer": 14, "enabled": False}]
    }
    native._call.assert_called_once_with(14, 5, ())


def test_native_missing_component_fails_without_binding_enumeration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _module, native = _native(monkeypatch)
    native._object = Mock(return_value=ctypes.c_void_p())
    with pytest.raises(ValueError, match="Invalid componentID: missing"):
        native.paths("missing", {"Ethernet": "nic"})
    native._object.assert_called_once()
