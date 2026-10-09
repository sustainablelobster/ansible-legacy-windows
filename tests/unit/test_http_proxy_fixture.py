"""Verify proxy fixture journaling and exact recovery without Windows access."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import copy
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock, call

import pytest

# The pinned Nix environment supplies PyYAML without its optional typing stubs.
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


@pytest.fixture(name="fixture")
def http_proxy_fixture(tmp_path: Path) -> Any:
    """Load real recovery contracts with native proxy operations replaced.

    :param tmp_path: Disposable controller-only journal directory.
    :returns: Recovery functions and stateful native-operation stand-ins.
    """
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/http_proxy_fixture.yml").read_text()
    )["http_proxy_fixture"]
    names = {
        "backup",
        "cleanup",
        "prepare_ie",
        "read_allocated",
        "read_ie",
        "read_journal",
        "read_winhttp",
        "save_journal",
        "setup",
    }
    definitions: list[ast.stmt] = [
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    initial = {
        "winhttp": {
            "access_type": 3,
            "proxy": "original-proxy:8080",
            "bypass": "OriginalBypass;<local>",
        },
        "ie": {
            "auto_detect": False,
            "auto_config_url": None,
            "proxy": None,
            "bypass": None,
        },
        "lan": {
            "flags": 1,
            "auto_config_url": None,
            "proxy": "disabled-original-proxy",
            "bypass": None,
        },
        "registry": {
            "": {
                "exists": True,
                "security": "original descriptor",
                "values": {
                    "ProxyEnable": {"exists": False},
                    "ProxyServer": {"exists": True, "type": 3, "data": "AP8="},
                },
            },
            "Connections": {"exists": False},
        },
    }
    api = SimpleNamespace(
        initial=copy.deepcopy(initial),
        current=copy.deepcopy(initial),
        journal=tmp_path / "http-proxy-recovery.json",
    )

    def _write_winhttp(values: dict[str, Any]) -> None:
        assert api.journal.exists()
        api.current["winhttp"] = copy.deepcopy(values)

    def _write_lan(values: dict[str, Any]) -> None:
        assert api.journal.exists()
        api.current["lan"] = copy.deepcopy(values)
        api.current["ie"] = {
            "proxy": values["proxy"] if values["flags"] & 2 else None,
            "bypass": values["bypass"] if values["flags"] & 2 else None,
            "auto_config_url": (
                values["auto_config_url"] if values["flags"] & 4 else None
            ),
            "auto_detect": bool(values["flags"] & 8),
        }
        api.current["registry"] = {"modified": "native connection counter"}

    def _restore_registry(values: dict[str, Any]) -> None:
        api.current["registry"] = copy.deepcopy(values)

    namespace = {
        "os": os,
        "json": json,
        "JOURNAL": str(api.journal),
        "IE_PATH": r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "DIRECT": {"access_type": 1, "proxy": None, "bypass": None},
        "IE_STATIC": {
            "flags": 15,
            "proxy": "fixture-proxy.invalid:8181",
            "bypass": "fixture-bypass.invalid;<local>",
            "auto_config_url": "http://pac.invalid/fixture.pac",
        },
        "observe": lambda: copy.deepcopy(api.current),
        "read_winhttp": lambda: copy.deepcopy(api.current["winhttp"]),
        "read_ie": lambda: copy.deepcopy(api.current["ie"]),
        "read_lan": lambda: copy.deepcopy(api.current["lan"]),
        "registry_snapshot": lambda: copy.deepcopy(api.current["registry"]),
        "write_winhttp": Mock(side_effect=_write_winhttp),
        "write_lan": Mock(side_effect=_write_lan),
        "restore_registry": Mock(side_effect=_restore_registry),
        "refresh_ie": Mock(),
    }
    # Only journal contracts execute; DLL loading and target main never run.
    # pylint: disable-next=exec-used
    exec(
        compile(
            ast.Module(body=definitions, type_ignores=[]),
            "<http proxy fixture>",
            "exec",
        ),
        namespace,
    )
    api.native_readers = {name: namespace[name] for name in ("read_ie", "read_winhttp")}
    namespace["read_ie"] = lambda: copy.deepcopy(api.current["ie"])
    namespace["read_winhttp"] = lambda: copy.deepcopy(api.current["winhttp"])
    api.functions = namespace
    return api


def test_backup_preserves_native_and_raw_registry_state_before_any_write(
    fixture: Any,
) -> None:
    state = fixture.functions["backup"]()
    assert state["initial"] == fixture.initial
    assert state["restored"] is False
    assert json.loads(fixture.journal.read_text()) == state
    for operation in ("write_winhttp", "write_lan", "restore_registry"):
        fixture.functions[operation].assert_not_called()


def test_existing_recovery_journal_cannot_be_overwritten(fixture: Any) -> None:
    fixture.journal.write_text("earlier recovery")
    with pytest.raises(AssertionError, match="already exists"):
        fixture.functions["backup"]()
    assert fixture.journal.read_text() == "earlier recovery"
    assert fixture.current == fixture.initial


def test_failed_journal_write_never_changes_proxy_settings(fixture: Any) -> None:
    fixture.functions["save_journal"] = Mock(side_effect=OSError("disk full"))
    with pytest.raises(OSError, match="disk full"):
        fixture.functions["backup"]()
    assert fixture.current == fixture.initial
    fixture.functions["write_winhttp"].assert_not_called()
    fixture.functions["write_lan"].assert_not_called()


def test_baseline_and_ie_changes_keep_the_original_recovery_authority(
    fixture: Any,
) -> None:
    state = fixture.functions["backup"]()
    original_journal = fixture.journal.read_bytes()
    fixture.functions["setup"](state)
    assert fixture.current["winhttp"] == fixture.functions["DIRECT"]
    for operation in ("ie_static", "ie_auto"):
        fixture.functions["prepare_ie"](state, operation)
        assert fixture.current["ie"]["auto_detect"] is True
        assert fixture.current["ie"]["auto_config_url"] == (
            "http://pac.invalid/fixture.pac"
        )
        assert fixture.journal.read_bytes() == original_journal
    assert fixture.current["ie"]["proxy"] is None
    fixture.functions["cleanup"](fixture.functions["read_journal"]())
    assert fixture.current == fixture.initial
    assert json.loads(fixture.journal.read_text())["restored"] is True


def test_partial_ie_write_failure_is_recoverable_from_original_journal(
    fixture: Any,
) -> None:
    state = fixture.functions["backup"]()
    fixture.functions["setup"](state)
    write = fixture.functions["write_lan"].side_effect

    def _partial_write(values: dict[str, Any]) -> None:
        write(values)
        raise OSError("refresh failed")

    fixture.functions["write_lan"].side_effect = _partial_write
    with pytest.raises(OSError, match="refresh failed"):
        fixture.functions["prepare_ie"](state, "ie_static")
    assert json.loads(fixture.journal.read_text()) == state
    fixture.functions["write_lan"].side_effect = write
    fixture.functions["cleanup"](fixture.functions["read_journal"]())
    assert fixture.current == fixture.initial


def test_raw_registry_restoration_failure_preserves_journal_for_retry(
    fixture: Any,
) -> None:
    state = fixture.functions["backup"]()
    fixture.functions["prepare_ie"](state, "ie_static")
    restore = fixture.functions["restore_registry"].side_effect
    fixture.functions["restore_registry"].side_effect = OSError("registry denied")
    with pytest.raises(OSError, match="registry denied"):
        fixture.functions["cleanup"](state)
    assert fixture.current["lan"] == fixture.initial["lan"]
    assert fixture.current["registry"] != fixture.initial["registry"]
    assert json.loads(fixture.journal.read_text()) == state
    fixture.functions["restore_registry"].side_effect = restore
    fixture.functions["cleanup"](fixture.functions["read_journal"]())
    assert fixture.current == fixture.initial


def test_matching_original_settings_are_not_rewritten(fixture: Any) -> None:
    fixture.functions["cleanup"](fixture.functions["backup"]())
    for operation in ("write_winhttp", "write_lan", "restore_registry", "refresh_ie"):
        fixture.functions[operation].assert_not_called()


def test_refresh_counter_rewrite_precedes_final_raw_restore_and_is_not_repeated(
    fixture: Any,
) -> None:
    state = fixture.functions["backup"]()
    fixture.current["registry"] = {"modified": "old refresh counter"}

    def _refresh() -> None:
        fixture.current["registry"] = {"modified": "incremented refresh counter"}

    fixture.functions["refresh_ie"].side_effect = _refresh
    operations = Mock()
    operations.attach_mock(fixture.functions["refresh_ie"], "refresh")
    operations.attach_mock(fixture.functions["restore_registry"], "restore")
    fixture.functions["cleanup"](fixture.functions["read_journal"]())
    assert fixture.current == fixture.initial
    expected = [call.refresh(), call.restore(state["initial"]["registry"])]
    assert operations.mock_calls == expected
    fixture.functions["cleanup"](fixture.functions["read_journal"]())
    assert operations.mock_calls == expected
    assert fixture.current == fixture.initial


def test_failed_native_verification_does_not_mark_the_journal_restored(
    fixture: Any,
) -> None:
    state = fixture.functions["backup"]()
    fixture.current["ie"]["proxy"] = "unexpected proxy"
    with pytest.raises(AssertionError, match="Original WinHTTP or IE settings differ"):
        fixture.functions["cleanup"](state)
    assert json.loads(fixture.journal.read_text()) == state
    assert state["restored"] is False


def test_foreign_registry_path_in_journal_is_rejected(fixture: Any) -> None:
    state = fixture.functions["backup"]()
    state["ie_path"] = "another registry key"
    fixture.journal.write_text(json.dumps(state))
    with pytest.raises(AssertionError, match="another IE key"):
        fixture.functions["read_journal"]()
    assert fixture.current == fixture.initial


@pytest.mark.parametrize("reader", ["read_winhttp", "read_ie"])
def test_failed_native_reads_release_every_partial_string_allocation(
    fixture: Any, reader: str
) -> None:
    pointers = SimpleNamespace(
        proxy=11, bypass=22, auto_config_url=33, access_type=3, auto_detect=0
    )
    free = Mock()
    fixture.functions.update(
        {
            "ctypes": SimpleNamespace(byref=lambda value: value, wstring_at=Mock()),
            "ProxyInfo": lambda: pointers,
            "IEConfig": lambda: pointers,
            "get_proxy": Mock(return_value=False),
            "get_ie": Mock(return_value=False),
            "require": Mock(side_effect=OSError("native read failed")),
            "free": free,
        }
    )
    with pytest.raises(OSError, match="native read failed"):
        fixture.native_readers[reader]()
    expected = [call(11), call(22)]
    if reader == "read_ie":
        expected.append(call(33))
    assert free.call_args_list == expected
    fixture.functions["ctypes"].wstring_at.assert_not_called()
