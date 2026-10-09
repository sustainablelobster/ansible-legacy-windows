"""Check independent WinINet fixture ABI and recovery without Windows access."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import copy
import ctypes
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


def fixture_definitions(names: set[str], namespace: dict[str, Any]) -> None:
    """Load selected fixture contracts without native DLL loading or main.

    :param names: Function and structure definitions required by the test.
    :param namespace: Explicit stand-ins for native calls and fixture state.
    """
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/inet_proxy_fixture.yml").read_text()
    )["inet_proxy_fixture"]
    definitions: list[ast.stmt] = [
        node
        for node in ast.parse(source).body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names
    ]
    # Only selected contracts execute; DLL loading and target main never run.
    # pylint: disable-next=exec-used
    exec(
        compile(
            ast.Module(body=definitions, type_ignores=[]), "<inet fixture>", "exec"
        ),
        namespace,
    )


@pytest.mark.parametrize(
    ("name", "size"), [("RasEntry", 5616), ("RasEntryName", 1048), ("RasDevice", 296)]
)
def test_ras_abi_uses_windows_wide_characters_and_xp_structure_tail(
    name: str, size: int
) -> None:
    native = SimpleNamespace(**vars(ctypes))
    native.c_wchar = ctypes.c_uint16
    namespace: dict[str, Any] = {"ctypes": native, "DWORD": ctypes.c_uint32}
    fixture_definitions({name}, namespace)
    assert ctypes.sizeof(namespace[name]) == size
    assert ctypes.alignment(namespace[name]) == 4


def test_inactive_native_strings_are_not_reported_as_effective_settings() -> None:
    namespace: dict[str, Any] = {}
    fixture_definitions({"effective"}, namespace)
    values = {
        "flags": 9,
        "proxy": "disabled original proxy",
        "bypass": "disabled original bypass",
        "auto_config_url": "http://disabled.invalid/fixture.pac",
    }
    assert namespace["effective"](values) == {
        "auto_detect": True,
        "proxy": None,
        "bypass": None,
        "auto_config_url": None,
    }
    assert values["proxy"] == "disabled original proxy"


def test_legacy_option_fallback_frees_partial_strings_before_retry() -> None:
    native = SimpleNamespace(**vars(ctypes))
    native.get_last_error = lambda: 87
    free = Mock()
    namespace: dict[str, Any] = {
        "ctypes": native,
        "DWORD": ctypes.c_uint32,
        "POINTER": ctypes.c_void_p,
        "free": free,
    }
    fixture_definitions(
        {
            "OptionValue",
            "ConnectionOption",
            "ConnectionOptions",
            "connection_options",
            "read_connection",
        },
        namespace,
    )
    buffers = [ctypes.create_unicode_buffer(value) for value in ("partial", "proxy")]
    addresses = [ctypes.addressof(buffer) for buffer in buffers]
    options_seen = []

    def _query(_handle: Any, option: int, pointer: Any, _size: Any) -> bool:
        assert option == 75
        listing = pointer._obj  # pylint: disable=protected-access
        assert listing.connection == "Owned disconnected connection"
        options = listing.options
        flag_option = options[0].option
        options_seen.append(flag_option)
        if flag_option == 10:
            options[1].value.text = addresses[0]
            return False
        assert free.call_args_list == [call(addresses[0])]
        options[0].value.number = 3
        options[1].value.text = addresses[1]
        return True

    namespace["query_option"] = _query
    assert namespace["read_connection"]("Owned disconnected connection") == {
        "flags": 3,
        "proxy": "proxy",
        "bypass": None,
        "auto_config_url": None,
    }
    assert options_seen == [10, 1]
    assert free.call_args_list == [call(addresses[0]), call(addresses[1])]


@pytest.fixture(name="fixture")
def inet_proxy_fixture(tmp_path: Path) -> Any:
    """Load journal contracts with stateful native entry and proxy stand-ins.

    :param tmp_path: Disposable controller-only recovery workspace.
    :returns: Native-operation stand-ins and real journal/recovery functions.
    """
    connection = "LegacyWinINet-owned"
    baseline = {"flags": 9, "proxy": None, "bypass": None, "auto_config_url": None}
    namespace: dict[str, Any] = {}
    fixture_definitions({"effective"}, namespace)
    initial = {
        "winhttp": {"access_type": 1, "proxy": None, "bypass": None},
        "ie": namespace["effective"](baseline),
        "lan": copy.deepcopy(baseline),
        "lan_values": namespace["effective"](baseline),
        "connection": None,
        "connection_values": None,
        "connection_exists": False,
        "registry": {
            "": {"security": "unchanged root security"},
            "Connections": {
                "security": "unchanged connection security",
                "values": {
                    connection: {"exists": False},
                    "SavedLegacySettings": {"exists": True, "data": "original"},
                },
            },
        },
        "other_entries": [{"name": "Unrelated entry", "properties": "original"}],
    }
    api = SimpleNamespace(
        initial=copy.deepcopy(initial),
        current=copy.deepcopy(initial),
        journal=tmp_path / "inet-proxy-recovery.json",
    )

    def _create(_path: Any, name: str, entry: Any, *_args: Any) -> int:
        assert json.loads(api.journal.read_text())["connection"] == name == connection
        assert not api.current["connection_exists"]
        assert entry.device_type == "pppoe"
        api.current["connection_exists"] = True
        return 0

    def _delete(_path: Any, name: str) -> int:
        assert name == connection
        api.current.update(
            connection_exists=False, connection=None, connection_values=None
        )
        return 0

    def _write(values: dict[str, Any], name: str | None = None) -> None:
        assert name in (None, connection)
        field = "lan" if name is None else "connection"
        api.current[field] = copy.deepcopy(values)
        api.current[field + "_values"] = namespace["effective"](values)
        if name is None:
            api.current["ie"] = namespace["effective"](values)
        api.current["registry"]["Connections"]["values"]["SavedLegacySettings"] = {
            "exists": True,
            "data": "native write counter",
        }

    def _restore_registry(values: dict[str, Any]) -> None:
        api.current["registry"] = copy.deepcopy(values)

    namespace.update(
        {
            "ctypes": SimpleNamespace(sizeof=lambda _value: 5616, byref=lambda x: x),
            "json": json,
            "os": os,
            "JOURNAL": str(api.journal),
            "CONNECTION": connection,
            "BASELINE": baseline,
            "RasEntry": SimpleNamespace,
            "observe": lambda: copy.deepcopy(api.current),
            "validate_entry": Mock(
                side_effect=lambda *_args: (
                    183 if api.current["connection_exists"] else 0
                )
            ),
            "ras_devices": lambda: [{"kind": "pppoe", "name": "PPPoE fixture"}],
            "phonebook_files": lambda: {"original.pbk": {"exists": True}},
            "cleanup_phonebooks": Mock(),
            "create_entry": Mock(side_effect=_create),
            "delete_entry": Mock(side_effect=_delete),
            "write_connection": Mock(side_effect=_write),
            "read_connection": lambda: copy.deepcopy(api.current["lan"]),
            "registry_snapshot": lambda: copy.deepcopy(api.current["registry"]),
            "restore_registry": Mock(side_effect=_restore_registry),
            "refresh_ie": Mock(),
            "require_status": lambda status: (
                None if status == 0 else pytest.fail("Unexpected native error")
            ),
        }
    )
    fixture_definitions(
        {"backup", "save_journal", "read_journal", "setup", "cleanup"}, namespace
    )
    api.functions = namespace
    return api


def test_original_state_is_flushed_before_owned_entry_creation(fixture: Any) -> None:
    state = fixture.functions["backup"]()
    original_journal = fixture.journal.read_bytes()
    assert state["initial"] == fixture.initial
    fixture.functions["create_entry"].assert_not_called()
    fixture.functions["setup"](state)
    assert fixture.journal.read_bytes() == original_journal
    assert fixture.current["other_entries"] == fixture.initial["other_entries"]
    fixture.functions["cleanup"](fixture.functions["read_journal"]())
    assert fixture.current == fixture.initial
    assert json.loads(fixture.journal.read_text())["restored"] is True


def test_existing_entry_collision_is_never_journaled_or_deleted(fixture: Any) -> None:
    fixture.current["connection_exists"] = True
    with pytest.raises(AssertionError, match="name is not free"):
        fixture.functions["backup"]()
    assert not fixture.journal.exists()
    fixture.functions["create_entry"].assert_not_called()
    fixture.functions["delete_entry"].assert_not_called()


def test_journal_failure_never_creates_or_changes_settings(fixture: Any) -> None:
    fixture.functions["save_journal"] = Mock(side_effect=OSError("disk full"))
    with pytest.raises(OSError, match="disk full"):
        fixture.functions["backup"]()
    assert fixture.current == fixture.initial
    fixture.functions["create_entry"].assert_not_called()
    fixture.functions["write_connection"].assert_not_called()


def test_partial_setup_failure_retains_ownership_for_cleanup(fixture: Any) -> None:
    state = fixture.functions["backup"]()
    fixture.functions["write_connection"].side_effect = OSError("proxy write failed")
    with pytest.raises(OSError, match="proxy write failed"):
        fixture.functions["setup"](state)
    assert fixture.current["connection_exists"]
    assert json.loads(fixture.journal.read_text()) == state
    fixture.functions["cleanup"](fixture.functions["read_journal"]())
    assert fixture.current == fixture.initial


def test_failed_entry_deletion_preserves_journal_and_retry_only_deletes_owned_name(
    fixture: Any,
) -> None:
    state = fixture.functions["backup"]()
    fixture.functions["setup"](state)
    delete = fixture.functions["delete_entry"].side_effect
    fixture.functions["delete_entry"].side_effect = OSError("entry busy")
    with pytest.raises(OSError, match="entry busy"):
        fixture.functions["cleanup"](state)
    assert json.loads(fixture.journal.read_text()) == state
    fixture.functions["delete_entry"].side_effect = delete
    fixture.functions["cleanup"](fixture.functions["read_journal"]())
    fixture.functions["delete_entry"].assert_called_with(None, state["connection"])
    assert fixture.current == fixture.initial


def test_cleanup_restores_raw_values_after_refresh_and_is_idempotent(
    fixture: Any,
) -> None:
    state = fixture.functions["backup"]()
    fixture.functions["setup"](state)

    def _refresh() -> None:
        fixture.current["registry"] = {"refresh": "changed legacy counter"}

    fixture.functions["refresh_ie"].side_effect = _refresh
    fixture.functions["cleanup"](state)
    assert fixture.current == fixture.initial
    calls = fixture.functions["delete_entry"].call_count
    fixture.functions["cleanup"](fixture.functions["read_journal"]())
    assert fixture.functions["delete_entry"].call_count == calls
    assert fixture.functions["refresh_ie"].call_count == 1
    assert fixture.current == fixture.initial


def test_changed_unrelated_entry_prevents_successful_cleanup_verification(
    fixture: Any,
) -> None:
    state = fixture.functions["backup"]()
    fixture.current["other_entries"][0]["properties"] = "unexpected change"
    with pytest.raises(AssertionError, match="Original IE or phonebook settings"):
        fixture.functions["cleanup"](state)
    assert json.loads(fixture.journal.read_text()) == state


def test_generated_empty_phonebook_cleanup_preserves_existing_files(
    tmp_path: Path,
) -> None:
    user_directory = tmp_path / "user" / "Network" / "Connections" / "Pbk"
    user_directory.mkdir(parents=True)
    generated = user_directory / "rasphone.pbk"
    generated.write_bytes(b"empty generated phonebook")
    shared_directory = tmp_path / "all-users" / "Pbk"
    shared_directory.mkdir(parents=True)
    shared = shared_directory / "sharedaccess.ini"
    shared.write_bytes(b"original shared access")
    shared_phonebook = shared_directory / "rasphone.pbk"
    shared_phonebook.write_bytes(b"original phonebook")
    namespace: dict[str, Any] = {"os": os, "phonebook_entries": lambda: []}
    fixture_definitions({"cleanup_phonebooks"}, namespace)
    files = {
        str(generated): {
            "exists": False,
            "missing_dirs": [
                str(user_directory),
                str(user_directory.parent),
                str(user_directory.parent.parent),
            ],
        },
        str(shared_phonebook): {"exists": True, "missing_dirs": []},
    }
    namespace["cleanup_phonebooks"](files)
    assert not generated.exists()
    assert not user_directory.parent.parent.exists()
    assert shared.read_bytes() == b"original shared access"
    assert shared_phonebook.read_bytes() == b"original phonebook"
    namespace["cleanup_phonebooks"](files)


def test_generated_phonebook_with_unexpected_entry_is_not_deleted(
    tmp_path: Path,
) -> None:
    phonebook = tmp_path / "rasphone.pbk"
    phonebook.write_bytes(b"unexpected entry")
    namespace: dict[str, Any] = {
        "os": os,
        "phonebook_entries": lambda: [{"path": str(phonebook), "name": "Other"}],
    }
    fixture_definitions({"cleanup_phonebooks"}, namespace)
    with pytest.raises(AssertionError, match="unexpected entries"):
        namespace["cleanup_phonebooks"](
            {str(phonebook): {"exists": False, "missing_dirs": []}}
        )
    assert phonebook.read_bytes() == b"unexpected entry"
