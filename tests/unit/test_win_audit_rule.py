"""Exercise public audit-rule binding, failure order, and stored-state results."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes establish public workflow, not Windows runtime support.
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

_PATH = r"C:\Café 雪 [literal] % &.txt"
_SID = "S-1-1-0"


@pytest.fixture(name="payload")
def audit_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load a payload with independently observable stored audit rules.

    :param monkeypatch: Scoped imports and native boundary substitutes.
    :returns: Payload with writable audit backend and a deterministic target.
    """
    native, paths = Mock(), Mock()
    monkeypatch.setitem(sys.modules, "legacy_windows_audit_rule", native)
    monkeypatch.setitem(sys.modules, "legacy_windows_acl", paths)
    payload = load_payload("win_audit_rule", monkeypatch)
    target = {"path": _PATH, "kind": "file", "container": True}
    stored: dict[str, Any] = {**target, "rules": []}
    events: list[str] = []

    @contextmanager
    def _privileges() -> Iterator[None]:
        events.append("enabled")
        try:
            yield
        finally:
            events.append("restored")

    paths.resolve_target.return_value = target
    paths.resolve_user.return_value = _SID
    native.audit_targets.side_effect = lambda _target: [target]
    native.audit_write_targets.side_effect = lambda _target: [
        {name: stored[name] for name in ("path", "kind", "container")}
    ]
    native.audit_privileges.side_effect = _privileges
    native.read_sacl.side_effect = lambda _target: {
        **stored,
        "rules": list(stored["rules"]),
    }
    native.current_rules.side_effect = lambda snapshot: (
        snapshot["rules"][0] if len(snapshot["rules"]) == 1 else snapshot["rules"] or {}
    )
    native.make_rule.return_value = {"user": "Everyone", "rights": "Read"}
    native.translate_rule_user.side_effect = lambda rule, _user: rule
    native.has_rule.side_effect = lambda snapshot, rule: rule in snapshot["rules"]
    native.has_user.side_effect = lambda snapshot, _sid: bool(snapshot["rules"])
    native.add_rule.side_effect = lambda snapshot, rule: dict(
        snapshot, rules=snapshot["rules"] + [rule]
    )
    native.remove_user.side_effect = lambda snapshot, _sid: dict(snapshot, rules=[])
    native.write_sacl.side_effect = stored.update
    payload.__dict__.update(test_stored=stored, test_events=events)
    return payload


def _manage(payload: ModuleType, check: bool = False, **options: Any) -> dict[str, Any]:
    parameters = payload._parameters(
        {"path": _PATH, "user": _SID, "rights": ["Read"], **options}
    )
    result: dict[str, Any] = {"changed": False}
    payload._manage(parameters, result, check)
    return result


@pytest.mark.parametrize("count", [0, 2])
@pytest.mark.parametrize("state", ["present", "absent"])
@pytest.mark.parametrize("check", [False, True])
def test_null_and_array_binding_failures_preserve_complete_results(
    payload: ModuleType, count: int, state: str, check: bool
) -> None:
    target = payload.acl.resolve_target.return_value
    payload.audit.audit_targets.side_effect = lambda _target: [target] * count
    result = _manage(payload, check, state=state)
    expected: dict[str, Any] = {
        "changed": False,
        "failed": True,
        "exception": "(traceback unavailable)",
    }
    if state == "absent":
        expected["msg"] = (
            "Unhandled exception while executing module: "
            "You cannot call a method on a null-valued expression."
        )
    else:
        expected["path_type"] = "directory"
        if not count and not check:
            expected["msg"] = (
                "Failed to set the audit rule: "
                "You cannot call a method on a null-valued expression."
            )
        else:
            expected["current_audit_rules"] = {}
            expected["msg"] = "Failed to apply audit change: " + (
                "AclObject"
                if count
                else "Cannot bind argument to parameter 'AclObject' because it is null."
            )
    assert result == expected
    payload.audit.write_sacl.assert_not_called()
    assert payload.test_stored["rules"] == []


@pytest.mark.parametrize("state", ["present", "absent"])
@pytest.mark.parametrize("check", [False, True])
def test_multiple_matching_rules_can_exit_before_array_binding(
    payload: ModuleType, state: str, check: bool
) -> None:
    target = payload.acl.resolve_target.return_value
    rule = payload.audit.make_rule.return_value
    payload.test_stored["rules"] = [rule]
    payload.audit.audit_targets.side_effect = lambda _target: [target, target]
    result = _manage(payload, check, state=state)
    expected = {
        "changed": False,
        "path_type": "directory",
        "current_audit_rules": [rule, rule],
    }
    if state == "absent":
        expected.update(
            failed=True,
            exception="(traceback unavailable)",
            msg="Failed to apply audit change: AclObject",
        )
    assert result == expected
    payload.audit.write_sacl.assert_not_called()
    assert payload.test_stored["rules"] == [rule]


def test_single_match_writes_selected_sibling_but_keeps_literal_kind(
    payload: ModuleType,
) -> None:
    sibling = {"path": r"C:\matched_file", "kind": "file", "container": False}
    payload.test_stored.update(sibling)
    payload.audit.audit_targets.side_effect = lambda _target: [sibling]
    result = _manage(payload)
    assert result["path_type"] == "directory"
    assert result["changed"]
    assert payload.audit.write_sacl.call_args.args[0]["path"] == sibling["path"]
    assert (
        payload.audit.make_rule.call_args.args[0]
        == payload.acl.resolve_target.return_value
    )


@pytest.mark.parametrize("check", [True, False])
def test_escaped_request_reads_one_object_but_writes_another(
    payload: ModuleType, check: bool
) -> None:
    destination = {"path": r"C:\matched_file", "kind": "file", "container": False}
    payload.audit.audit_write_targets.side_effect = lambda _target: [destination]
    payload.audit.write_sacl.side_effect = None
    expected = {"changed": True, "path_type": "directory", "current_audit_rules": {}}
    assert _manage(payload, check) == expected
    assert _manage(payload, check) == expected
    assert payload.audit.write_sacl.call_count == (0 if check else 2)
    if check:
        payload.audit.audit_write_targets.assert_not_called()
    else:
        assert payload.audit.write_sacl.call_args.args[0]["path"] == destination["path"]
    assert payload.test_stored["rules"] == []


def test_pattern_read_failure_precedes_constructor_and_retains_literal_kind(
    payload: ModuleType,
) -> None:
    detail = "The specified wildcard character pattern is not valid: owned["
    payload.audit.audit_targets.side_effect = ValueError(detail)
    assert _manage(payload) == {
        "changed": False,
        "failed": True,
        "exception": "(traceback unavailable)",
        "path_type": "directory",
        "msg": "Unable to retrieve the ACL on " + _PATH + ": " + detail,
    }
    payload.audit.make_rule.assert_not_called()
    payload.audit.write_sacl.assert_not_called()


@pytest.mark.parametrize(
    "kind,container,label",
    [
        ("file", True, "directory"),
        ("file", False, "file"),
        ("registry", True, "registry"),
    ],
)
@pytest.mark.parametrize("state", ["present", "absent"])
@pytest.mark.parametrize("matched", [False, True])
@pytest.mark.parametrize("check", [False, True])
# Keep the independent lifecycle dimensions visible in this public matrix.
def test_stored_rules_check_mode_and_idempotence(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    payload: ModuleType,
    kind: str,
    container: bool,
    label: str,
    state: str,
    matched: bool,
    check: bool,
) -> None:
    target = payload.acl.resolve_target.return_value
    target.update(kind=kind, container=container)
    rule = payload.audit.make_rule.return_value
    payload.test_stored.update(target, rules=[rule] if matched else [])
    result = _manage(payload, check, state=state, inheritance_flags=["None"])
    changed = matched != (state == "present")
    stored_after = matched if check else state == "present"
    assert result == {
        "changed": changed,
        "path_type": label,
        "current_audit_rules": rule if stored_after else {},
    }
    assert payload.audit.write_sacl.call_count == int(changed and not check)
    assert payload.audit.add_rule.call_count == int(
        changed and not check and state == "present"
    )
    assert payload.audit.remove_user.call_count == int(changed and state == "absent")
    assert payload.test_events == ["enabled", "restored"]


def test_defaults_case_preservation_and_alias_precedence(payload: ModuleType) -> None:
    result = payload._parameters(
        {
            "path": "canonical",
            "destination": "first",
            "dest": "last",
            "user": _SID,
            "rights": "Read, Write",
            "state": "PRESENT",
            "audit_flags": "Success, FAILURE",
        }
    )
    assert result == {
        "path": "last",
        "destination": "first",
        "dest": "last",
        "user": _SID,
        "rights": ["Read", "Write"],
        "state": "PRESENT",
        "inheritance_flags": ["ContainerInherit", "ObjectInherit"],
        "propagation_flags": "None",
        "audit_flags": ["Success", "FAILURE"],
    }


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({"user": _SID}, "missing required arguments: path"),
        ({"path": _PATH}, "missing required arguments: user"),
        (
            {"path": _PATH, "user": _SID},
            "state is present but all of the following are missing: rights",
        ),
        (
            {"path": _PATH, "user": _SID, "rights": ["Read"], "audit_flags": ["bogus"]},
            "value of audit_flags must be one of: failure, success. Got no match for: bogus",
        ),
    ],
)
def test_public_binding_failures(
    payload: ModuleType, arguments: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValueError, match="^" + message + "$"):
        payload._parameters(arguments)
    payload.acl.resolve_target.assert_not_called()


def test_missing_path_precedes_identity_and_privilege_lookup(
    payload: ModuleType,
) -> None:
    payload.acl.resolve_target.return_value = None
    assert _manage(payload) == {
        "changed": False,
        "failed": True,
        "msg": "defined path (" + _PATH + ") is not found/invalid",
    }
    payload.acl.resolve_user.assert_not_called()
    payload.audit.audit_privileges.assert_not_called()


def test_file_right_validation_precedes_inheritance_failure(
    payload: ModuleType,
) -> None:
    payload.acl.resolve_target.return_value["container"] = False
    result = _manage(payload)
    assert result == {
        "changed": False,
        "failed": True,
        "path_type": "file",
        "msg": "The target type is a file. inheritance_flags must be changed to 'none'",
    }
    payload.audit.validate_rights.assert_called_once()
    payload.audit.make_rule.assert_not_called()
    payload.audit.write_sacl.assert_not_called()
    assert payload.test_events == ["enabled", "restored"]


def test_null_file_inheritance_fails_before_constructor(payload: ModuleType) -> None:
    payload.acl.resolve_target.return_value["container"] = False
    result = _manage(payload, True, inheritance_flags=None)
    assert result["failed"]
    assert result["path_type"] == "file"
    assert result["msg"] == (
        "The target type is a file. inheritance_flags must be changed to 'none'"
    )
    payload.audit.make_rule.assert_not_called()
    payload.audit.write_sacl.assert_not_called()


def test_unknown_identity_keeps_the_pinned_lookup_failure(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    error = OSError("unknown account")
    setattr(error, "winerror", 1332)
    payload.acl.resolve_user.side_effect = error
    monkeypatch.setattr(
        payload,
        "read_arguments",
        lambda *_args: {
            "path": _PATH,
            "user": "unknown",
            "rights": ["Read"],
            "_ansible_check_mode": True,
        },
    )
    assert payload._response() == {
        "changed": False,
        "failed": True,
        "msg": (
            "Failed to lookup the identity (unknown): The term 'Fail-Json' is not "
            "recognized as the name of a cmdlet, function, script file, or operable "
            "program. Check the spelling of the name, or if a path was included, "
            "verify that the path is correct and try again."
        ),
    }
    payload.audit.audit_privileges.assert_not_called()
    payload.audit.read_sacl.assert_not_called()


@pytest.mark.parametrize("check", [False, True])
def test_constructor_failure_discards_the_partially_populated_result(
    payload: ModuleType, check: bool
) -> None:
    payload.audit.make_rule.side_effect = ValueError("constructor diagnostic")
    assert _manage(payload, check) == {
        "changed": False,
        "failed": True,
        "msg": "Unhandled exception while executing module: constructor diagnostic",
    }
    payload.audit.write_sacl.assert_not_called()
    assert payload.test_events == ["enabled", "restored"]


@pytest.mark.parametrize(
    "check,matched", [(True, False), (False, True), (False, False)]
)
def test_sid_string_translation_only_for_unmatched_actual_add(
    payload: ModuleType, check: bool, matched: bool
) -> None:
    rule = payload.audit.make_rule.return_value
    payload.test_stored["rules"] = [rule] if matched else []
    error = OSError("unmapped")
    setattr(error, "winerror", 1332)
    payload.audit.translate_rule_user.side_effect = error
    result = _manage(payload, check)
    if not matched and not check:
        assert result == {
            "changed": False,
            "failed": True,
            "path_type": "directory",
            "exception": "(traceback unavailable)",
            "msg": (
                'Failed to set the audit rule: Exception calling "AddAuditRule" '
                'with "1" argument(s): "Some or all identity references could '
                'not be translated."'
            ),
        }
    else:
        assert result["changed"] is not matched
        assert not result.get("failed")
        payload.audit.translate_rule_user.assert_not_called()
    payload.audit.write_sacl.assert_not_called()


@pytest.mark.parametrize(
    "operation,prefix,current",
    [
        ("read_sacl", "Unable to retrieve the ACL on " + _PATH + ": ", False),
        ("add_rule", "Failed to set the audit rule: ", False),
        ("write_sacl", "Failed to apply audit change: ", True),
        ("remove_user", "Failed to remove audit rule: ", True),
    ],
)
def test_failure_boundaries_keep_upstream_result_fields(
    payload: ModuleType, operation: str, prefix: str, current: bool
) -> None:
    if operation == "remove_user":
        payload.test_stored["rules"] = [payload.audit.make_rule.return_value]
    getattr(payload.audit, operation).side_effect = OSError("denied")
    result = _manage(
        payload, state="absent" if operation == "remove_user" else "present"
    )
    assert result["msg"] == prefix + "denied"
    assert result["failed"] is True and result["changed"] is False
    assert ("current_audit_rules" in result) is current
    assert payload.test_events == ["enabled", "restored"]


def test_final_read_failure_returns_error_string_without_losing_changed(
    payload: ModuleType,
) -> None:
    payload.audit.read_sacl.side_effect = [dict(payload.test_stored), OSError("denied")]
    result = _manage(payload)
    assert result["changed"] is True
    assert result["current_audit_rules"] == "Unable to retrieve the ACL on " + _PATH


def test_json_entrypoint_retains_bound_invocation(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    arguments = tmp_path / "arguments.json"
    arguments.write_text(
        json.dumps(
            {
                "path": _PATH,
                "user": _SID,
                "rights": ["Read"],
                "_ansible_check_mode": True,
                "_ansible_inject_invocation": True,
            }
        )
    )
    monkeypatch.setattr(sys, "argv", [payload.__file__, str(arguments)])
    code, result = invoke_payload(payload, capsys)
    assert code == 0 and result["changed"] is True
    assert result["current_audit_rules"] == {}
    assert result["invocation"]["module_args"] == payload._parameters(
        {"path": _PATH, "user": _SID, "rights": ["Read"]}
    )
