"""Check durable regional journals, exact restoration, and failed-cleanup retention."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import copy
import ctypes
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

# PyYAML is supplied by the pinned development environment without type stubs.
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


@pytest.fixture(name="fixture")
def region_fixture(tmp_path: Path) -> Any:
    """Load actual journal and recovery functions without Windows initialization.

    :param tmp_path: Disposable controller-only recovery workspace.
    :returns: Real journal/recovery functions with recorded native boundaries.
    """
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/region_fixture.yml").read_text()
    )["region_fixture"]
    source = source.replace("{{ region_helper_sources | to_json | to_json }}", "'{}'")
    names = {"read_journal", "backup", "restore_locale", "cleanup", "verify"}
    # Select real Region journal functions independently of other recovery fixtures.
    # pylint: disable=duplicate-code
    definitions: list[ast.stmt] = [
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    # pylint: enable=duplicate-code
    initial = {
        "registry": {"HKCU\\International": {"raw": "original"}},
        "user_locale": "en-US",
        "system_locale": "en-US",
        "location": 244,
        "python": [3, 4, 4],
    }
    state = SimpleNamespace(
        initial=initial,
        current=copy.deepcopy(initial),
        path=tmp_path / "region-recovery.json",
    )
    namespace: dict[str, Any] = {
        "json": json,
        "os": os,
        "WORKSPACE": str(tmp_path),
        "JOURNAL": str(state.path),
        "ROOTS": [("HKCU", "International")],
        "observe": Mock(side_effect=lambda: copy.deepcopy(state.current)),
        "mount": Mock(),
        "winreg": SimpleNamespace(UnloadKey=Mock(), HKEY_USERS=3),
        "ADVAPI": SimpleNamespace(RegUnLoadKeyW=Mock(return_value=0)),
        "check": Mock(),
        "MOUNT": "LEGACY_REGION_FIXTURE",
        "locale_name": Mock(return_value="en-US"),
    }

    def _restore(hive: str, path: str, original: Any) -> None:
        state.current["registry"][hive + "\\" + path] = copy.deepcopy(original)
        state.current["user_locale"] = state.initial["user_locale"]

    namespace["restore_tree"] = Mock(side_effect=_restore)
    # Only journal and recovery contracts run; native DLLs and main do not.
    # pylint: disable-next=exec-used
    exec(
        compile(
            ast.Module(body=definitions, type_ignores=[]), "<region fixture>", "exec"
        ),
        namespace,
    )
    state.functions = namespace
    return state


def test_durable_journal_precedes_any_registry_write(fixture: Any) -> None:
    state = fixture.functions["backup"]()
    assert state == {"workspace": str(fixture.path.parent), "initial": fixture.initial}
    assert json.loads(fixture.path.read_text()) == state
    fixture.functions["restore_tree"].assert_not_called()


def test_existing_journal_is_not_overwritten(fixture: Any) -> None:
    fixture.path.write_text("earlier original backup")
    with pytest.raises(AssertionError, match="already exists"):
        fixture.functions["backup"]()
    assert fixture.path.read_text() == "earlier original backup"
    fixture.functions["observe"].assert_not_called()


def test_cleanup_restores_exact_state_before_claiming_success(fixture: Any) -> None:
    state = fixture.functions["backup"]()
    fixture.current["registry"]["HKCU\\International"] = {"raw": "changed"}
    fixture.current["user_locale"] = "en-GB"
    assert fixture.functions["cleanup"](state) == {"restoration_attempted": True}
    result = fixture.functions["verify"](state)
    assert result == {
        "restored": True,
        "initial": fixture.initial,
        "final": fixture.initial,
    }
    assert fixture.path.exists()
    fixture.functions["ADVAPI"].RegUnLoadKeyW.assert_called_once_with(
        3, "LEGACY_REGION_FIXTURE"
    )


def test_failed_cleanup_retains_journal_and_unloads_hive(fixture: Any) -> None:
    state = fixture.functions["backup"]()
    fixture.current["registry"]["HKCU\\International"] = {"raw": "changed"}
    restore = fixture.functions["restore_tree"]
    fixture.functions["restore_tree"] = Mock(side_effect=OSError("write denied"))
    with pytest.raises(OSError, match="write denied"):
        fixture.functions["cleanup"](state)
    assert json.loads(fixture.path.read_text()) == state
    fixture.functions["ADVAPI"].RegUnLoadKeyW.assert_called_once()
    fixture.functions["restore_tree"] = restore
    assert fixture.functions["cleanup"](state)["restoration_attempted"]
    assert fixture.functions["verify"](state)["restored"]


def test_cleanup_republishes_active_locale_after_restoring_pending_defaults(
    fixture: Any,
) -> None:
    state = fixture.functions["backup"]()
    fixture.current["system_locale"] = "en-GB"
    fixture.functions["locale_name"].return_value = "en-GB"
    calls: list[tuple[str, int]] = []

    def _set_locale(name: str, flags: int) -> int:
        calls.append((name, flags))
        if len(calls) == 2:
            fixture.current["system_locale"] = name
        return 0

    library = SimpleNamespace(IntlUpdateSystemLocale=Mock(side_effect=_set_locale))
    fixture.functions["ctypes"] = SimpleNamespace(
        WinDLL=Mock(return_value=library),
        c_wchar_p=ctypes.c_wchar_p,
        c_int32=ctypes.c_int32,
    )
    assert fixture.functions["cleanup"](state)["restoration_attempted"]
    assert fixture.current["system_locale"] == "en-GB"
    assert fixture.functions["restore_locale"](state)["locale_restoration_attempted"]
    assert calls == [("en-US", 2), ("en-US", 2)]
    assert fixture.functions["verify"](state)["restored"]
    assert fixture.path.exists()


def test_final_verification_detects_native_state_mismatch(fixture: Any) -> None:
    state = fixture.functions["backup"]()
    fixture.current["location"] = 12
    with pytest.raises(AssertionError, match="Original regional settings differ"):
        fixture.functions["verify"](state)
    assert json.loads(fixture.path.read_text()) == state


def test_journal_identity_and_root_set_are_checked_before_mutation(
    fixture: Any,
) -> None:
    state = fixture.functions["backup"]()
    state["workspace"] = str(fixture.path.parent / "unrelated")
    with pytest.raises(AssertionError):
        fixture.functions["cleanup"](state)
    fixture.functions["mount"].assert_not_called()
    fixture.functions["restore_tree"].assert_not_called()


def test_fixture_uses_only_python34_syntax() -> None:
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/region_fixture.yml").read_text()
    )["region_fixture"]
    source = source.replace("{{ region_helper_sources | to_json | to_json }}", "'{}'")
    ast.parse(source, feature_version=(3, 4))
