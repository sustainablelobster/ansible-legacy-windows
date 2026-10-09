"""Exercise access-rule decisions and JSON results without contacting Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes verify the public workflow, not Windows runtime support.
# pylint: disable=protected-access

import json
import sys
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import Any, Iterator
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

_PATH = r"C:\Café 雪 [literal] 'file' % ! &.txt"
_SID = "S-1-5-32-545"
_RULE = b"requested explicit access rule"


@pytest.fixture(name="payload")
def acl_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the public payload against an isolated, writable ACL boundary.

    :param monkeypatch: Scoped imports and native boundary replacements.
    :returns: Payload with a mock native backend and an empty initial ACL.
    """
    native = Mock()
    certificates = Mock()
    monkeypatch.setitem(sys.modules, "legacy_windows_acl", native)
    monkeypatch.setitem(sys.modules, "legacy_windows_certificate_acl", certificates)
    module = load_payload("win_acl", monkeypatch)
    target = {"path": _PATH, "kind": "file", "container": False}
    stored: dict[str, Any] = {**target, "rules": []}
    writer = Mock(side_effect=stored.update)
    events: list[str] = []

    @contextmanager
    def _privileges() -> Iterator[None]:
        events.append("privileges enabled")
        try:
            yield
        finally:
            events.append("privileges restored")

    @contextmanager
    def _open_acl(_target: dict[str, Any]) -> Iterator[tuple[dict[str, Any], Mock]]:
        events.append("ACL opened")
        try:
            yield {**stored, "rules": list(stored["rules"])}, writer
        finally:
            events.append("ACL closed")

    native.resolve_target.return_value = target
    certificates.resolve_target.return_value = target
    native.resolve_user.return_value = _SID
    native.acl_privileges.side_effect = _privileges
    native.open_acl.side_effect = _open_acl
    certificates.open_acl.side_effect = _open_acl
    native.make_rule.return_value = _RULE
    native.has_rule.side_effect = lambda snapshot, rule: rule in snapshot["rules"]
    native.add_rule.side_effect = lambda snapshot, rule: {
        **snapshot,
        "rules": snapshot["rules"] + [rule],
    }
    native.remove_rule.side_effect = lambda snapshot, rule: {
        **snapshot,
        "rules": [entry for entry in snapshot["rules"] if entry != rule],
    }
    module.__dict__.update(test_stored=stored, test_writer=writer, test_events=events)
    return module


def _manage(
    payload: ModuleType, *, check_mode: bool = False, **options: object
) -> dict[str, Any]:
    return payload._manage(  # type: ignore[no-any-return]
        payload._parameters(
            {"path": _PATH, "user": _SID, "rights": "Read", "type": "allow", **options}
        ),
        check_mode,
    )


@pytest.mark.parametrize("kind", ["file", "registry", "certificate"])
@pytest.mark.parametrize("matched", [False, True])
@pytest.mark.parametrize("state", ["absent", "present"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_changes_idempotence_and_check_mode(
    payload: ModuleType, kind: str, matched: bool, state: str, check_mode: bool
) -> None:
    path = {
        "file": _PATH,
        "registry": r"HKCU:\Software\Café 雪 [literal]",
        "certificate": "Cert:\\CurrentUser\\My\\" + "A" * 40,
    }[kind]
    target = payload.acl.resolve_target.return_value
    target.update(path=path, kind=kind, container=kind == "registry")
    payload.test_stored.update(target, rules=[_RULE] if matched else [])
    changed = matched != (state == "present")
    result = _manage(payload, path=path, state=state, check_mode=check_mode)
    assert result["changed"] is changed
    assert not result.get("failed")
    assert "diff" not in result
    assert "msg" not in result
    assert payload.test_writer.call_count == int(changed and not check_mode)
    assert bool(payload.test_stored["rules"]) is (
        matched if check_mode else state == "present"
    )
    assert payload.acl.add_rule.call_count == int(
        changed and not check_mode and state == "present"
    )
    assert payload.acl.remove_rule.call_count == int(
        changed and state == "absent" and (not check_mode or kind == "certificate")
    )
    assert payload.test_events == [
        "privileges enabled",
        "ACL opened",
        "ACL closed",
        "privileges restored",
    ]
    if kind == "certificate":
        payload.certificate.resolve_target.assert_called_once_with(path)
        payload.acl.resolve_target.assert_not_called()
    else:
        payload.acl.resolve_target.assert_called_once_with(path, False)
        payload.certificate.resolve_target.assert_not_called()
    if not check_mode:
        assert _manage(payload, path=path, state=state)["changed"] is False


@pytest.mark.parametrize("follow", [False, True])
def test_literal_path_and_follow_are_passed_to_native_resolution(
    payload: ModuleType, follow: bool
) -> None:
    _manage(payload, path=r"%TEMP%\literal", follow=follow)
    payload.acl.resolve_target.assert_called_once_with(r"%TEMP%\literal", follow)


def test_missing_path_precedes_user_resolution(payload: ModuleType) -> None:
    payload.acl.resolve_target.return_value = None
    assert _manage(payload, user="unresolvable") == {
        "changed": False,
        "failed": True,
        "msg": _PATH + " file or directory does not exist on the host",
    }
    payload.acl.resolve_user.assert_not_called()
    payload.acl.acl_privileges.assert_not_called()


@pytest.mark.parametrize("path", [None, ""])
def test_empty_or_null_path_matches_the_measured_binding_failure(
    payload: ModuleType, path: str | None
) -> None:
    ending = "null" if path is None else "an empty string"
    assert _manage(payload, path=path) == {
        "changed": False,
        "failed": True,
        "msg": "Unhandled exception while executing module: Cannot bind argument "
        "to parameter 'Path' because it is " + ending + ".",
    }
    payload.acl.resolve_target.assert_not_called()
    payload.acl.resolve_user.assert_not_called()


@pytest.mark.parametrize("user", [None, ""])
def test_empty_or_null_user_fails_after_existence_and_before_rule_validation(
    payload: ModuleType, user: str | None
) -> None:
    assert _manage(payload, user=user, rights="invalid") == {
        "changed": False,
        "failed": True,
        "msg": 'Unhandled exception while executing module: Exception calling ".ctor" '
        'with "1" argument(s): "String cannot be of zero length.\r\nParameter name: name"',
    }
    payload.acl.resolve_target.assert_called_once()
    payload.acl.resolve_user.assert_not_called()
    payload.acl.make_rule.assert_not_called()


def test_unknown_account_matches_the_measured_translation_failure(
    payload: ModuleType,
) -> None:
    error = OSError("No mapping between account names and security IDs was done.")
    setattr(error, "winerror", 1332)
    payload.acl.resolve_user.side_effect = error
    result = _manage(payload, user="missing")
    assert result == {
        "changed": False,
        "failed": True,
        "msg": "account_name missing is not a valid account, cannot get SID: Exception "
        'calling "Translate" with "1" argument(s): "Some or all identity references '
        'could not be translated."',
    }
    payload.acl.make_rule.assert_not_called()
    payload.acl.open_acl.assert_not_called()


@pytest.mark.parametrize(
    "failure", [None, ValueError("identity could not be translated")]
)
def test_user_failure_precedes_rule_validation_and_acl_reads(
    payload: ModuleType, failure: ValueError | None
) -> None:
    payload.acl.resolve_user.return_value = None
    payload.acl.resolve_user.side_effect = failure
    result = _manage(payload, user="missing", rights="invalid rights")
    assert result["failed"] and not result["changed"]
    assert result["msg"] == (
        "identity could not be translated"
        if failure
        else "missing is not a valid user or group on the host machine or domain"
    )
    payload.acl.make_rule.assert_not_called()
    payload.acl.open_acl.assert_not_called()
    payload.acl.acl_privileges.assert_not_called()


def test_rule_validation_precedes_filesystem_acl_read(payload: ModuleType) -> None:
    payload.acl.make_rule.side_effect = ValueError("invalid enum value")
    result = _manage(payload, rights="broken", state="PRESENT")
    assert result["failed"] and not result["changed"]
    assert result["msg"] == (
        "an error occurred when attempting to PRESENT broken permission(s) on "
        + _PATH
        + " for "
        + _SID
        + " - invalid enum value"
    )
    payload.acl.open_acl.assert_not_called()
    assert payload.test_events == ["privileges enabled", "privileges restored"]


@pytest.mark.parametrize("stage", ["privilege", "read", "modify", "write"])
@pytest.mark.parametrize("state", ["present", "absent"])
def test_operation_failures_close_resources_and_allow_recovery(
    payload: ModuleType, stage: str, state: str
) -> None:
    payload.test_stored["rules"] = [] if state == "present" else [_RULE]
    operation = payload.acl.add_rule if state == "present" else payload.acl.remove_rule
    boundary = {
        "privilege": payload.acl.acl_privileges,
        "read": payload.acl.open_acl,
        "modify": operation,
        "write": payload.test_writer,
    }[stage]
    previous = boundary.side_effect
    boundary.side_effect = OSError("access denied")
    result = _manage(payload, state=state)
    assert result["failed"] and not result["changed"]
    if stage in ("modify", "write"):
        verb = "adding" if state == "present" else "removing"
        assert (
            result["msg"]
            == "an exception occurred when "
            + verb
            + " the specified rule - access denied"
        )
        assert payload.test_events[-2:] == ["ACL closed", "privileges restored"]
    else:
        assert result["msg"].startswith("an error occurred when attempting to " + state)
    boundary.side_effect = previous
    assert _manage(payload, state=state) == {"changed": True}


@pytest.mark.parametrize("state", ["present", "absent"])
def test_check_mode_skips_rule_modification_and_its_canonicality_failures(
    payload: ModuleType, state: str
) -> None:
    payload.test_stored["rules"] = [] if state == "present" else [_RULE]
    payload.acl.add_rule.side_effect = ValueError("ACL is not canonical")
    payload.acl.remove_rule.side_effect = ValueError("ACL is not canonical")
    assert _manage(payload, state=state, check_mode=True) == {"changed": True}
    payload.acl.add_rule.assert_not_called()
    payload.acl.remove_rule.assert_not_called()
    payload.test_writer.assert_not_called()


def test_malformed_acl_insertion_fails_before_writing(payload: ModuleType) -> None:
    message = "The ACL contains a malformed ACE SID."
    payload.acl.add_rule.side_effect = ValueError(message)
    result = _manage(payload)
    assert result == {
        "changed": False,
        "failed": True,
        "msg": "an exception occurred when adding the specified rule - " + message,
    }
    payload.test_writer.assert_not_called()
    assert payload.test_stored["rules"] == []
    assert payload.test_events[-2:] == ["ACL closed", "privileges restored"]


@pytest.mark.parametrize("name", ["path", "user", "rights", "type"])
def test_missing_required_argument_names_follow_upstream_order(
    payload: ModuleType, name: str
) -> None:
    arguments: dict[str, object] = {
        "path": _PATH,
        "user": _SID,
        "rights": "Read",
        "type": "allow",
    }
    del arguments[name]
    with pytest.raises(
        ValueError, match="^Get-AnsibleParam: Missing required argument: " + name + "$"
    ):
        payload._parameters(arguments)


def test_optional_defaults_and_explicit_required_nulls(payload: ModuleType) -> None:
    assert payload._parameters(
        {"path": None, "user": None, "rights": None, "type": "ALLOW"}
    ) == {
        "path": None,
        "user": None,
        "rights": None,
        "type": "allow",
        "state": "present",
        "inherit": None,
        "propagation": "None",
        "follow": False,
    }


@pytest.mark.parametrize(
    "name, value, choices",
    [
        ("type", "grant", "allow,deny"),
        ("state", None, "absent,present"),
        ("propagation", "invalid", "InheritOnly,None,NoPropagateInherit"),
    ],
)
def test_legacy_choices_validate_explicit_values(
    payload: ModuleType, name: str, value: object, choices: str
) -> None:
    with pytest.raises(ValueError) as caught:
        payload._parameters(
            {
                "path": _PATH,
                "user": _SID,
                "rights": "Read",
                "type": "allow",
                name: value,
            }
        )
    assert str(caught.value) == (
        "Get-AnsibleParam: Argument "
        + name
        + " needs to be one of "
        + choices
        + " but was "
        + ("" if value is None else str(value))
        + "."
    )


@pytest.mark.parametrize(
    "value", [None, False, "false", "invalid", " yes ", "y", "t", 0, 1.0]
)
def test_legacy_follow_false_values(payload: ModuleType, value: object) -> None:
    assert payload._legacy_bool(value) is False


@pytest.mark.parametrize("value", [True, "TRUE", "yes", "ON", "1", 1])
def test_legacy_follow_true_values(payload: ModuleType, value: object) -> None:
    assert payload._legacy_bool(value) is True


def test_json_entry_point_ignores_unknown_arguments_and_does_not_report_diff(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    arguments = tmp_path / "arguments.json"
    arguments.write_text(
        json.dumps(
            {
                "PATH": _PATH,
                "USER": _SID,
                "RIGHTS": "Read",
                "TYPE": "ALLOW",
                "unknown": "ignored",
                "_ansible_check_mode": True,
                "_ansible_diff": True,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["win_acl.py", str(arguments)])
    status, result = invoke_payload(payload, capsys)
    assert status == 0 and result == {"changed": True}
    payload.test_writer.assert_not_called()
