"""Verify the independent integration launcher's exact native name and ownership."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Native ABI substitutions keep this routine check away from Windows hosts.
# pylint: disable=protected-access

import ctypes
from types import ModuleType
from typing import Any
from unittest.mock import Mock
from uuid import UUID

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="runner")
def fixture_runner() -> ModuleType:
    """Load the self-contained Task1 integration launcher.

    :returns: Imported launcher without touching Windows.
    """
    return load_module(
        ROOT / "tests/integration/fixtures/community_scheduled_task_run.py",
        "tested_community_task_runner",
    )


@pytest.mark.parametrize("name", ["dotted.task", "public.task.job"])
@pytest.mark.parametrize("failure", [None, "activate", "run"])
def test_independent_launch_uses_exact_filename_and_releases_references(
    runner: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    failure: str | None,
) -> None:
    ole = Mock()
    ole.CoInitializeEx.return_value = 0
    released: list[int] = []
    calls: list[int] = []

    def _create(
        class_id: Any, _outer: Any, context: int, interface: Any, output: Any
    ) -> int:
        assert (
            str(UUID(bytes_le=ctypes.string_at(class_id, 16)))
            == "148bd52a-a2ab-11ce-b11f-00aa00530503"
        )
        assert (
            str(UUID(bytes_le=ctypes.string_at(interface, 16)))
            == "148bd527-a2ab-11ce-b11f-00aa00530503"
        )
        assert context == 1
        ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p)).contents.value = 100
        return 0

    def _method(pointer: Any, slot: int, _result: Any, _arguments: Any) -> Any:
        calls.append(slot)

        def _invoke(_pointer: Any, *values: Any) -> int:
            if slot == 6:
                assert pointer.value == 100
                assert values[0] == name + ".job"
                assert (
                    str(UUID(bytes_le=ctypes.string_at(values[1], 16)))
                    == "148bd524-a2ab-11ce-b11f-00aa00530503"
                )
                if failure == "activate":
                    return 0x80070057
                ctypes.cast(
                    values[2], ctypes.POINTER(ctypes.c_void_p)
                ).contents.value = 200
            elif slot == 12:
                assert pointer.value == 200
                if failure == "run":
                    return 0x80070005
            return 0

        return _invoke

    ole.CoCreateInstance.side_effect = _create
    monkeypatch.setattr(runner.ctypes, "WinDLL", lambda _library: ole, raising=False)
    monkeypatch.setattr(runner, "_method", _method)
    monkeypatch.setattr(
        runner,
        "_release",
        lambda pointer: released.append(pointer.value) if pointer else None,
    )
    if failure:
        with pytest.raises(OSError, match="HRESULT"):
            runner.run_task(name)
    else:
        assert runner.run_task(name) == {
            "started": True,
            "name": name,
            "launcher": "ITask.Run",
        }
    assert released == ([100] if failure == "activate" else [200, 100])
    assert calls == ([6] if failure == "activate" else [6, 12])
    ole.CoUninitialize.assert_called_once_with()
