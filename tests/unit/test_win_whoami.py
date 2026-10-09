"""Exercise the whoami payload's public JSON contract without Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

ACCOUNT = {
    "sid": "S-1-5-21-1-2-3-1000",
    "account_name": "reader",
    "domain_name": "FIXTURE",
    "type": "User",
}
TOKEN = {
    "groups": [
        {
            "sid": "S-1-5-32-544",
            "account_name": "Administrators",
            "domain_name": "BUILTIN",
            "type": "Alias",
            "attributes": ["Mandatory", "Enabled by default", "Enabled", "Owner"],
        }
    ],
    "privileges": {"SeChangeNotifyPrivilege": "enabled-by-default"},
    "label": {
        "sid": "S-1-16-12288",
        "account_name": "High Mandatory Level",
        "domain_name": "Mandatory Label",
        "type": "Label",
    },
    "token_type": "TokenPrimary",
    "impersonation_level": "SecurityAnonymous",
}
SESSION = {
    "account": ACCOUNT,
    "logon_id": (1 << 64) - 1,
    "login_domain": "FIXTURE",
    "authentication_package": "Negotiate",
    "logon_type": "Interactive",
    "login_time": "2026-09-29T12:00:00.1234567+00:00",
    "logon_server": "FIXTURE",
    "dns_domain_name": "",
    "upn": None,
    "user_flags": [],
}
ENABLED_GROUPS = ["S-1-5-32-544", "S-1-5-5-1-2"]
RIGHTS = ["SeInteractiveLogonRight", "SeNetworkLogonRight"]


@pytest.fixture(name="payload")
def whoami_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the public payload with isolated native-reader substitutes.

    :param monkeypatch: Scoped helper imports.
    :returns: Payload with deterministic token and logon responses.
    """
    token = ModuleType("legacy_windows_token")
    monkeypatch.setattr(
        token,
        "token_information",
        Mock(
            return_value=(
                copy.deepcopy(TOKEN),
                SESSION["logon_id"],
                ENABLED_GROUPS,
                True,
            )
        ),
        raising=False,
    )
    logon = ModuleType("legacy_windows_logon")
    monkeypatch.setattr(
        logon, "logon_session", Mock(return_value=copy.deepcopy(SESSION)), raising=False
    )
    monkeypatch.setattr(
        logon, "logon_rights", Mock(return_value=list(RIGHTS)), raising=False
    )
    monkeypatch.setitem(sys.modules, "legacy_windows_token", token)
    monkeypatch.setitem(sys.modules, "legacy_windows_logon", logon)
    return load_payload("win_whoami", monkeypatch)


@pytest.fixture(name="invoke")
def whoami_invocation(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> Callable[[object], tuple[int, dict[str, Any]]]:
    """Invoke the payload through its argument file and JSON result.

    :param payload: Imported payload.
    :param monkeypatch: Scoped command arguments.
    :param tmp_path: Isolated argument-file directory.
    :param capsys: Captured module output.
    :returns: Callable accepting the argument document.
    """

    def _invoke(arguments: object) -> tuple[int, dict[str, Any]]:
        argument_file = tmp_path / "arguments.json"
        argument_file.write_text(json.dumps(arguments), encoding="utf-8")
        monkeypatch.setattr(sys, "argv", ["win_whoami.py", str(argument_file)])
        return invoke_payload(payload, capsys)

    return _invoke


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("administrator", [False, True])
def test_complete_results_repeat_including_check_mode_and_non_admin_rights(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    check: bool,
    administrator: bool,
) -> None:
    payload.token.token_information.return_value = (
        copy.deepcopy(TOKEN),
        SESSION["logon_id"],
        ENABLED_GROUPS,
        administrator,
    )
    expected = dict(
        SESSION, **TOKEN, changed=False, rights=RIGHTS if administrator else []
    )
    arguments = {"_ansible_check_mode": check, "_ansible_diff": True}
    assert invoke(arguments) == (0, expected)
    assert invoke(arguments) == (0, expected)
    assert payload.logon.logon_session.call_args_list == [
        call(SESSION["logon_id"], []),
        call(SESSION["logon_id"], []),
    ]
    assert payload.logon.logon_rights.call_args_list == (
        [call(ENABLED_GROUPS), call(ENABLED_GROUPS)] if administrator else []
    )


def test_legacy_null_fields_keep_available_information_and_named_warnings(
    payload: ModuleType, invoke: Callable[[object], tuple[int, dict[str, Any]]]
) -> None:
    def _token(warnings: list[str]) -> tuple[dict[str, Any], int, list[str], bool]:
        warnings.append("label is unavailable on this Windows version")
        return dict(TOKEN, label=None), 42, ENABLED_GROUPS, True

    def _session(identifier: int, warnings: list[str]) -> dict[str, Any]:
        assert identifier == 42
        warnings.append("user_flags is unavailable in this logon record")
        return dict(SESSION, logon_id=42, user_flags=None)

    payload.token.token_information.side_effect = _token
    payload.logon.logon_session.side_effect = _session
    code, result = invoke({})
    assert code == 0
    assert result["account"] == ACCOUNT
    assert result["label"] is None and result["user_flags"] is None
    assert result["rights"] == RIGHTS
    assert result["warnings"] == [
        "label is unavailable on this Windows version",
        "user_flags is unavailable in this logon record",
    ]


@pytest.mark.parametrize("phase", ["token", "session", "rights"])
def test_native_failure_discards_partial_results_and_next_read_recovers(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    phase: str,
) -> None:
    failing = {
        "token": payload.token.token_information,
        "session": payload.logon.logon_session,
        "rights": payload.logon.logon_rights,
    }[phase]
    failing.side_effect = OSError("native read denied")
    code, result = invoke({})
    assert code == 1 and result["failed"] is True and result["changed"] is False
    assert "native read denied" in result["msg"]
    assert not set(SESSION).intersection(result)
    assert not set(TOKEN).intersection(result)
    failing.side_effect = None
    assert invoke({}) == (0, dict(SESSION, **TOKEN, changed=False, rights=RIGHTS))


@pytest.mark.parametrize("arguments", [{"unexpected_option": True}, []])
def test_bad_arguments_fail_before_reading_native_identity(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    arguments: object,
) -> None:
    code, result = invoke(arguments)
    assert code == 1 and result["failed"] is True and result["changed"] is False
    payload.token.token_information.assert_not_called()
    payload.logon.logon_session.assert_not_called()
    payload.logon.logon_rights.assert_not_called()


def test_requested_invocation_contains_only_the_empty_public_arguments(
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
) -> None:
    code, result = invoke({"_ansible_inject_invocation": True})
    assert code == 0
    assert result["invocation"] == {"module_args": {}}
