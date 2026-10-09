"""Exercise exact public parity, opaque ACE retention and recovery evidence."""

# SPDX-License-Identifier: GPL-3.0-or-later
# The tests deliberately decode raw binary observations at the private boundary.
# pylint: disable=protected-access

import base64
import copy
import json
import struct
from typing import Any

import pytest

from tests.unit.payload_support import ROOT, load_module

COMPARATOR = load_module(
    ROOT / "tests/integration/files/mixed_acl_compare.py", "tested_mixed_acl_compare"
)


def _command(value: Any) -> dict[str, Any]:
    return {"rc": 0, "stdout": json.dumps(value), "stderr": ""}


def _identity(*parts: int) -> bytes:
    return (
        bytes([1, len(parts)])
        + b"\x00\x00\x00\x00\x00\x05"
        + struct.pack("<" + "I" * len(parts), *parts)
    )


def _ace(kind: int, flags: int, sid: bytes, mask: int, data: bytes = b"") -> bytes:
    body = struct.pack("<I", mask) + sid + data
    return struct.pack("<BBH", kind, flags, len(body) + 4) + body


def _acl(*entries: bytes, revision: int = 4) -> str:
    body = b"".join(entries)
    return base64.b64encode(
        struct.pack("<BBHHH", revision, 0, len(body) + 8, len(entries), 0) + body
    ).decode("ascii")


def _rule(user: str) -> dict[str, str]:
    return {
        "user": user,
        "rights": "ReadData",
        "audit_flags": "Success",
        "is_inherited": "False",
        "inheritance_flags": "None",
        "propagation_flags": "None",
    }


@pytest.fixture(name="capture")
def mixed_capture() -> dict[str, Any]:
    """Create an exact ordinary-add capture beside one opaque callback ACE.

    :returns: Complete independently encoded public and binary observations.
    """
    callback = _ace(13, 64, _identity(20), 1, b"\x00" * 4)
    ordinary = _ace(2, 64, _identity(32, 546), 1)
    original = {
        "owner": "owner",
        "group": "group",
        "dacl": _acl(_ace(0, 0, _identity(18), 2032127), revision=2),
        "sacl": _acl(revision=2),
        "control": 0xBC14,
    }
    baseline = {
        role: copy.deepcopy(original) for role in ("workspace", "file", "registry")
    }
    before = copy.deepcopy(baseline)
    before["file"]["sacl"] = _acl(callback)
    after = copy.deepcopy(before)
    after["file"]["sacl"] = _acl(callback, ordinary)
    rules = [_rule(r"NT AUTHORITY\NETWORK SERVICE"), _rule(r"BUILTIN\Guests")]
    result = {
        "changed": True,
        "failed": False,
        "path_type": "file",
        "current_audit_rules": rules,
    }
    prepare = {
        "snapshot": before["file"],
        "unusual": base64.b64encode(callback).decode("ascii"),
    }
    record = {
        "case": {
            "name": "File callback audit insertion",
            "module": "audit",
            "role": "file",
            "ace_type": 13,
        },
        "before_native": _command(prepare),
        "before_all_native": _command(before),
        "after_native": _command(after),
        "native": result,
        "native_repeat": dict(result, changed=False),
        "after_native_repeat": _command(after),
        "before_original": _command(prepare),
        "before_all_original": _command(before),
        "after_original": _command(after),
        "original": copy.deepcopy(result),
    }
    return {
        "setup": _command(
            {
                "runtime": [3, 4, 4],
                "baseline": baseline,
                "principal": r"BUILTIN\Guests",
                "unusual_principal": r"NT AUTHORITY\NETWORK SERVICE",
            }
        ),
        "results": [record],
        "restore": _command({"snapshots": baseline}),
        "readback": _command(baseline),
        "cleanup": _command(
            {"restored": True, "journal_absent": True, "snapshots": baseline}
        ),
        "absence": _command(
            {
                "file_absent": True,
                "registry_absent": True,
                "journal_absent": True,
                "workspace_empty": True,
            }
        ),
        "workspace_absent": True,
        "staging_before": _command(["existing-staging"]),
        "staging_after": _command(["existing-staging"]),
    }


def test_exact_callback_add_and_repeat_capture_passes(capture: dict[str, Any]) -> None:
    assert COMPARATOR.verify_capture(capture, paired=True) == {
        "cases": 1,
        "paired": True,
        "running": False,
    }


@pytest.mark.parametrize("state", ["present", "absent"])
@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("partial", [False, True])
def test_conditional_matching_removal_and_partial_rights_capture(
    capture: dict[str, Any], state: str, check: bool, partial: bool
) -> None:
    record = capture["results"][0]
    baseline = json.loads(capture["setup"]["stdout"])["baseline"]
    before = copy.deepcopy(baseline)
    mask = 0x100003 if partial else 0x100001
    callback = _ace(9, 0, _identity(20), mask, b"artx\x01\x02\x03\x04")
    ordinary = _ace(0, 0, _identity(20), 0x100001)
    stored = COMPARATOR._aces(before["file"]["dacl"])
    before["file"]["dacl"] = _acl(callback, *stored, *([ordinary] if partial else []))
    after = copy.deepcopy(before)
    if state == "absent" and not check:
        remaining = [_ace(9, 0, _identity(20), 2, callback[20:])] if partial else []
        after["file"]["dacl"] = _acl(*stored, *remaining)
    record["case"] = {
        "name": "Conditional request",
        "module": "access",
        "role": "file",
        "ace_type": 9,
        "mask": mask,
        "use_unusual_principal": True,
        "condition": "1 == 1",
        "state": state,
        "check": check,
        **(
            {"seed_common": True, "seed_common_mask": 0x100001, "remaining_mask": 2}
            if partial
            else {}
        ),
    }
    prepare = {
        "snapshot": before["file"],
        "unusual": base64.b64encode(callback).decode("ascii"),
    }
    result = {"changed": state == "absent", "failed": False}
    record.update(
        before_native=_command(prepare),
        before_original=_command(prepare),
        before_all_native=_command(before),
        before_all_original=_command(before),
        after_native=_command(after),
        after_original=_command(after),
        native=result,
        original=copy.deepcopy(result),
        native_repeat=dict(result, changed=False),
        original_repeat=dict(result, changed=False),
        after_native_repeat=_command(after),
        after_original_repeat=_command(after),
    )
    assert COMPARATOR.verify_capture(capture, paired=True)["cases"] == 1


@pytest.mark.parametrize(
    "name,value",
    [("changed", 1), ("failed", True), ("path_type", "registry"), ("unexpected", None)],
)
def test_rejects_wrong_or_additional_public_fields(
    capture: dict[str, Any], name: str, value: Any
) -> None:
    capture["results"][0]["native"][name] = value
    with pytest.raises(AssertionError):
        COMPARATOR.verify_capture(capture, paired=True)


@pytest.mark.parametrize("role", ["registry", "workspace"])
@pytest.mark.parametrize("field", ["owner", "group", "dacl", "sacl", "control"])
def test_rejects_changes_to_unrelated_object(
    capture: dict[str, Any], role: str, field: str
) -> None:
    after = json.loads(capture["results"][0]["after_native"]["stdout"])
    after[role][field] = "changed"
    capture["results"][0]["after_native"] = _command(after)
    with pytest.raises(AssertionError):
        COMPARATOR.verify_capture(capture, paired=True)


@pytest.mark.parametrize(
    "damage", ["condition", "mask", "sid", "drop", "duplicate", "order"]
)
def test_rejects_opaque_or_new_rule_damage(
    capture: dict[str, Any], damage: str
) -> None:
    after = json.loads(capture["results"][0]["after_native"]["stdout"])
    entries = COMPARATOR._aces(after["file"]["sacl"])
    if damage == "condition":
        entries[0] = entries[0][:-1] + b"\x01"
    elif damage == "mask":
        entries[1] = entries[1][:4] + struct.pack("<I", 2) + entries[1][8:]
    elif damage == "sid":
        entries[1] = entries[1][:-4] + struct.pack("<I", 545)
    elif damage == "drop":
        entries.pop(0)
    elif damage == "duplicate":
        entries.append(entries[0])
    else:
        entries[0] = bytes([7]) + entries[0][1:]
    after["file"]["sacl"] = _acl(*entries)
    capture["results"][0]["after_native"] = _command(after)
    with pytest.raises(AssertionError):
        COMPARATOR.verify_capture(capture, paired=True)


@pytest.mark.parametrize(
    "key", ["before_all_original", "after_original", "after_native_repeat", "readback"]
)
def test_rejects_pair_repeat_or_recovery_descriptor_differences(
    capture: dict[str, Any], key: str
) -> None:
    result = capture[key] if key == "readback" else capture["results"][0][key]
    observed = json.loads(result["stdout"])
    observed["file"]["control"] ^= 0x800
    result["stdout"] = json.dumps(observed)
    with pytest.raises(AssertionError):
        COMPARATOR.verify_capture(capture, paired=True)


def test_rejects_changed_repeat_even_with_unchanged_descriptor(
    capture: dict[str, Any],
) -> None:
    capture["results"][0]["native_repeat"]["changed"] = True
    with pytest.raises(AssertionError):
        COMPARATOR.verify_capture(capture, paired=True)


@pytest.mark.parametrize("damage", ["workspace", "staging", "absence"])
def test_rejects_incomplete_resource_or_staging_recovery(
    capture: dict[str, Any], damage: str
) -> None:
    if damage == "workspace":
        capture["workspace_absent"] = False
    elif damage == "staging":
        capture["staging_after"] = _command(["extra-staging"])
    else:
        proof = json.loads(capture["absence"]["stdout"])
        proof["registry_absent"] = False
        capture["absence"] = _command(proof)
    with pytest.raises(AssertionError):
        COMPARATOR.verify_capture(capture, paired=True)
