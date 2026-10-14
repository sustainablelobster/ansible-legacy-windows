"""Exercise native GPO-link writes and public results against independent state."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Pytest boundary fixtures and input/output cases remain explicit.
# pylint: disable=too-many-arguments,too-many-positional-arguments
# Repeated JSON invocations are independent behavior cases, not duplicated logic.
# pylint: disable=duplicate-code

import ctypes
import importlib
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.ad_account_support import invoke_account as _run
from tests.unit.test_ad_policy_support import GPO_PATH, GUIDS, TARGET, Directory
from tests.unit.test_ad_policy_support import payload as load_payload
from tests.unit.test_ad_policy_support import state


def _link(number: int, flags: int = 0) -> bytes:
    return (
        "[LDAP://CN={" + GUIDS[number - 1] + "}," + GPO_PATH + ";" + str(flags) + "]"
    ).encode()


@pytest.fixture(name="directory")
def _directory() -> Directory:
    return Directory()


@pytest.fixture(name="payload")
def _payload(monkeypatch: pytest.MonkeyPatch, directory: Directory) -> ModuleType:
    return load_payload("gpo", monkeypatch, directory)


def test_link_creation_defaults_append_and_match_upstream_create_diff(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory.objects[TARGET]["gPLink"] = [_link(1)]
    arguments = {"name": "Policy 2", "target": TARGET, "_ansible_diff": True}
    status, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0 and result == {
        "changed": True,
        "diff": {
            "before": {},
            "after": {"enabled": True, "enforced": False, "order": None},
        },
    }
    assert directory.objects[TARGET]["gPLink"] == [_link(2) + _link(1)]
    assert directory.objects[TARGET]["gPOptions"] == [b"1"]
    directory.writes.clear()
    status, repeated = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0 and repeated == {
        "changed": False,
        "diff": {
            "before": {"enabled": True, "enforced": False, "order": 2},
            "after": {"enabled": True, "enforced": False, "order": 2},
        },
    }
    assert not directory.writes


@pytest.mark.parametrize("flags", [0, 1, 2, 3])
def test_flag_updates_preserve_unrelated_links_and_unspecified_settings(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    flags: int,
) -> None:
    directory.objects[TARGET]["gPLink"] = [_link(1, 5) + _link(2, flags) + _link(3, 2)]
    request = {
        "guid": GUIDS[1],
        "target": TARGET,
        "enabled": False,
        "_ansible_diff": True,
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, request)
    assert status == 0 and result["changed"] is (not bool(flags & 1))
    assert directory.objects[TARGET]["gPLink"] == [
        _link(1, 5) + _link(2, flags | 1) + _link(3, 2)
    ]
    assert result["diff"]["after"] == {
        "enabled": False,
        "enforced": bool(flags & 2),
        "order": 2,
    }


@pytest.mark.parametrize("check", [False, True])
def test_order_update_moves_only_the_selected_link(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    check: bool,
) -> None:
    directory.objects[TARGET]["gPLink"] = [_link(1) + _link(2, 3) + _link(3)]
    before = state(directory)
    status, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {
            "name": "Policy 2",
            "target": TARGET,
            "order": 1,
            "_ansible_check_mode": check,
            "_ansible_diff": True,
        },
    )
    assert status == 0 and result["changed"]
    assert result["diff"]["before"]["order"] == 2
    assert result["diff"]["after"]["order"] == 1
    if check:
        assert state(directory) == before and not directory.writes
    else:
        assert directory.objects[TARGET]["gPLink"] == [
            _link(1) + _link(3) + _link(2, 3)
        ]


@pytest.mark.parametrize("number,order", [(1, 3), (2, 2), (3, 1)])
def test_existing_link_order_matches_group_policy_not_ldap_string_position(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    number: int,
    order: int,
) -> None:
    original = _link(1) + _link(2, 3) + _link(3)
    directory.objects[TARGET]["gPLink"] = [original]
    arguments = {
        "guid": GUIDS[number - 1],
        "target": TARGET,
        "order": order,
        "_ansible_diff": True,
    }
    status, result = _run(payload, monkeypatch, tmp_path, capsys, arguments)
    assert status == 0 and not result["changed"]
    assert result["diff"]["before"]["order"] == order
    assert result["diff"]["after"]["order"] == order
    assert directory.objects[TARGET]["gPLink"] == [original]
    assert not directory.writes


def test_explicit_creation_order_enabled_and_enforced_are_applied_together(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory.objects[TARGET]["gPLink"] = [_link(1) + _link(3)]
    status, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {
            "guid": GUIDS[1],
            "target": TARGET,
            "order": 2,
            "enabled": False,
            "enforced": True,
            "_ansible_diff": True,
        },
    )
    assert status == 0 and result["changed"]
    assert directory.objects[TARGET]["gPLink"] == [_link(1) + _link(2, 3) + _link(3)]
    assert result["diff"]["after"] == {"enabled": False, "enforced": True, "order": 2}


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("check", [False, True])
def test_remove_is_idempotent_and_does_not_delete_gpo_or_other_links(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    existing: bool,
    check: bool,
) -> None:
    directory.objects[TARGET]["gPLink"] = [
        _link(1) + (_link(2, 3) if existing else b"") + _link(3)
    ]
    before = state(directory)
    status, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {
            "name": "Policy 2",
            "target": TARGET,
            "state": "absent",
            "_ansible_check_mode": check,
            "_ansible_diff": True,
        },
    )
    assert (
        status == 0 and result["changed"] is existing and result["diff"]["after"] == {}
    )
    if check:
        assert state(directory) == before and not directory.writes
    else:
        assert directory.objects[TARGET]["gPLink"] == [_link(1) + _link(3)]
    assert "CN={" + GUIDS[1] + "}," + GPO_PATH in directory.objects


def test_last_link_removal_deletes_attribute_without_changing_blocked_inheritance(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory.objects[TARGET]["gPLink"] = [_link(1)]
    status, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"name": "Policy 1", "target": TARGET, "state": "absent"},
    )
    assert status == 0 and result["changed"]
    assert "gPLink" not in directory.objects[TARGET]
    assert directory.objects[TARGET]["gPOptions"] == [b"1"]


@pytest.mark.parametrize("order", [0, -1, 4])
def test_out_of_range_order_is_rejected_before_write(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    order: int,
) -> None:
    directory.objects[TARGET]["gPLink"] = [_link(1) + _link(2)]
    before = state(directory)
    status, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"name": "Policy 2", "target": TARGET, "order": order},
    )
    assert (
        status == 1
        and not result["changed"]
        and state(directory) == before
        and not directory.writes
    )


@pytest.mark.parametrize(
    "arguments",
    [
        {"target": TARGET},
        {"name": "Policy 1"},
        {"name": "Policy 1", "guid": GUIDS[0], "target": TARGET},
        {"guid": "not-a-guid", "target": TARGET},
        {"name": "Policy 1", "target": TARGET, "state": "bad"},
        {"name": "Missing", "target": TARGET, "state": "absent"},
    ],
)
def test_invalid_or_missing_gpo_requests_fail_without_mutating_links(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    arguments: dict[str, Any],
) -> None:
    assert _run(payload, monkeypatch, tmp_path, capsys, arguments)[0] == 1
    assert not directory.writes


def test_duplicate_display_names_fail_instead_of_selecting_arbitrary_gpo(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory.objects["CN={" + GUIDS[1] + "}," + GPO_PATH]["displayName"] = [
        b"Policy 1"
    ]
    status, result = _run(
        payload, monkeypatch, tmp_path, capsys, {"name": "Policy 1", "target": TARGET}
    )
    assert status == 1 and "exactly one" in result["msg"] and not directory.writes


def test_malformed_existing_link_data_is_never_overwritten(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory.objects[TARGET]["gPLink"] = [b"[LDAP://broken;bad]"]
    before = state(directory)
    status, result = _run(
        payload, monkeypatch, tmp_path, capsys, {"name": "Policy 1", "target": TARGET}
    )
    assert (
        status == 1
        and "malformed" in result["msg"]
        and state(directory) == before
        and not directory.writes
    )


def test_denied_write_has_no_directory_effect_and_returns_failure(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory.fail_action = "modify"
    before = state(directory)
    status, result = _run(
        payload, monkeypatch, tmp_path, capsys, {"name": "Policy 1", "target": TARGET}
    )
    assert status == 1 and result["failed"] and result["changed"]
    assert state(directory) == before and not directory.writes


def test_omitted_server_uses_pdc_discovery_but_explicit_server_does_not(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    helper = importlib.import_module("legacy_ad_policy_gpo")
    _run(payload, monkeypatch, tmp_path, capsys, {"name": "Policy 1", "target": TARGET})
    helper._pdc.assert_called_once_with()  # pylint: disable=protected-access
    helper.LDAPConnection.assert_called_with("dc.example.test")
    helper._pdc.reset_mock()  # pylint: disable=protected-access
    _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"name": "Policy 1", "target": TARGET, "domain_server": "other.example.test"},
    )
    helper._pdc.assert_not_called()  # pylint: disable=protected-access
    helper.LDAPConnection.assert_called_with("other.example.test")
    assert directory.closed


def test_native_pdc_discovery_requires_the_pdc_and_copies_name_before_freeing(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del payload
    # Only the native ABI boundary is substituted; the resolver itself runs.
    # pylint: disable=protected-access
    helper = importlib.import_module("legacy_ad_policy_gpo")
    helper = importlib.reload(helper)
    api = Mock()
    information = helper._DomainController(controller=r"\\dc.example.test")

    def _discover(
        _computer: Any, domain: Any, _guid: Any, _site: Any, flags: int, output: Any
    ) -> int:
        assert domain is None and flags == 0x40000011
        ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(
            information
        )
        return 0

    api.DsGetDcNameW.side_effect = _discover
    monkeypatch.setattr(helper.os, "name", "nt")
    monkeypatch.setattr(ctypes, "WinDLL", Mock(return_value=api), raising=False)
    assert helper._pdc() == "dc.example.test"
    api.NetApiBufferFree.assert_called_once()
    assert api.NetApiBufferFree.call_args.args[0].value == ctypes.addressof(information)


def test_gpo_display_name_is_escaped_as_a_literal_ldap_assertion(
    payload: ModuleType,
    directory: Directory,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory.objects["CN={" + GUIDS[0] + "}," + GPO_PATH]["displayName"] = [
        b"Policy *(literal)"
    ]
    status, result = _run(
        payload,
        monkeypatch,
        tmp_path,
        capsys,
        {"name": "Policy *(literal)", "target": TARGET},
    )
    assert status == 0 and result["changed"]
    assert directory.objects[TARGET]["gPLink"] == [_link(1)]
