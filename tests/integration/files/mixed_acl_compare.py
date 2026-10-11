"""Verify raw mixed ACL results, unchanged opaque entries and exact recovery."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import json
import struct
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def _literal(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _stdout(result: dict[str, Any]) -> Any:
    assert result["rc"] == 0 and result["stderr"] == "", result
    return json.loads(result["stdout"])


def _public(result: dict[str, Any]) -> dict[str, Any]:
    return {
        name: value
        for name, value in result.items()
        if not name.startswith("_ansible_")
        and name not in ("invocation", "exception", "changed_when_result")
    }


def _sid(*subauthorities: int) -> bytes:
    return (
        bytes([1, len(subauthorities)])
        + b"\x00\x00\x00\x00\x00\x05"
        + struct.pack("<" + "I" * len(subauthorities), *subauthorities)
    )


def _aces(encoded: str | None) -> list[bytes]:
    if encoded is None:
        return []
    raw = base64.b64decode(encoded)
    revision, _, size, count, _ = struct.unpack_from("<BBHHH", raw)
    assert revision in (2, 4) and size == len(raw)
    offset, result = 8, []
    for _ in range(count):
        length = struct.unpack_from("<H", raw, offset + 2)[0]
        assert length >= 4 and offset + length <= len(raw)
        result.append(raw[offset : offset + length])
        offset += length
    assert offset == len(raw)
    return result


def _new_rule(case: dict[str, Any]) -> bytes:
    if case["module"] == "audit":
        kind, mask, flags = 2, 1, 64
    else:
        kind = int(case.get("type", "allow") == "deny")
        mask = 1 | (0x100000 if case["role"] == "file" and not kind else 0)
        flags = 0
    identity = _sid(20) if case.get("use_unusual_principal") else _sid(32, 546)
    return struct.pack("<BBHI", kind, flags, len(identity) + 8, mask) + identity


def _changed(case: dict[str, Any]) -> bool:
    if case["module"] == "access" and case.get("use_unusual_principal"):
        matched = (
            case["ace_type"] in (9, 10)
            and not case.get("inherited")
            and int(case.get("type", "allow") == "deny") == case["ace_type"] - 9
            and case.get("mask", 1) == struct.unpack_from("<I", _new_rule(case), 4)[0]
        )
        matched = matched or (
            bool(case.get("seed_common"))
            and case.get("seed_common_mask", case.get("mask", 1))
            == struct.unpack_from("<I", _new_rule(case), 4)[0]
        )
        return bool(matched) == bool(case.get("state", "present") == "absent")
    if case.get("state", "present") == "absent":
        return bool(
            case.get("use_unusual_principal")
            and (case["ace_type"] == 13 or case.get("seed_common"))
        )
    return not (case.get("use_unusual_principal") and case["ace_type"] == 13)


def _audit_public(user: str, role: str) -> dict[str, str]:
    return {
        "user": user,
        "rights": "QueryValues" if role == "registry" else "ReadData",
        "audit_flags": "Success",
        "is_inherited": "False",
        "inheritance_flags": "None",
        "propagation_flags": "None",
    }


def _expected_public(
    case: dict[str, Any], setup: dict[str, Any], *, repeat: bool = False
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "changed": False if repeat else _changed(case),
        "failed": False,
    }
    if case["module"] != "audit":
        return result
    rules = []
    removed = case.get("state", "present") == "absent" and _changed(case)
    if not removed and case["ace_type"] == 13:
        rules.append(_audit_public(setup["unusual_principal"], case["role"]))
    if not removed and case.get("seed_common"):
        rules.append(_audit_public(setup["unusual_principal"], case["role"]))
    if (
        case.get("state", "present") == "present"
        and not case.get("check")
        and _changed(case)
    ):
        rules.append(_audit_public(setup["principal"], case["role"]))
    result.update(
        path_type="file" if case["role"] == "file" else "registry",
        current_audit_rules=rules[0] if len(rules) == 1 else rules or {},
    )
    return result


def _check_public(
    actual: dict[str, Any], expected: dict[str, Any], warnings: Any
) -> None:
    if warnings is not None:
        expected = dict(expected, warnings=warnings)
    assert _literal(_public(actual)) == _literal(expected), (actual, expected)


def _canonical(entries: list[bytes], *, audit: bool) -> None:
    priority = (
        {2: 0, 13: 0, 7: 1, 15: 1}
        if audit
        else {1: 0, 10: 0, 6: 1, 12: 1, 0: 2, 9: 2, 5: 3, 11: 3}
    )
    groups = [4 if ace[1] & 16 else priority[ace[0]] for ace in entries]
    assert groups == sorted(groups), entries


def _check_effects(record: dict[str, Any]) -> None:
    case, role = record["case"], record["case"]["role"]
    before = _stdout(record["before_all_native"])
    after = _stdout(record["after_native"])
    assert before[role] == _stdout(record["before_native"])["snapshot"]
    assert set(before) == set(after)
    for other in before:
        if other != role:
            assert _literal(before[other]) == _literal(after[other]), other
    if case.get("check") or not _changed(case):
        assert _literal(before) == _literal(after)
        return
    field = "sacl" if case["module"] == "audit" else "dacl"
    untouched = "dacl" if field == "sacl" else "sacl"
    for name in ("owner", "group", untouched):
        assert before[role][name] == after[role][name], (name, before, after)
    assert before[role]["control"] & 0x3000 == after[role]["control"] & 0x3000
    existing = _aces(before[role][field])
    actual = _aces(after[role][field])
    unusual = base64.b64decode(_stdout(record["before_native"])["unusual"])
    assert existing.count(unusual) == 1
    if case.get("state", "present") == "absent":
        expected = [
            ace for ace in existing if ace != unusual and ace != _new_rule(case)
        ]
        if case.get("remaining_mask"):
            remaining = (
                unusual[:4] + struct.pack("<I", case["remaining_mask"]) + unusual[8:]
            )
            expected.insert(existing.index(unusual), remaining)
    else:
        expected = existing + [_new_rule(case)]
    assert Counter(actual) == Counter(expected), (actual, expected)
    if case["module"] == "access" and case.get("state", "present") == "absent":
        if all(ace[1] & 16 or ace[0] in (0, 1, 9, 10) for ace in expected):

            def _access_order(ace: bytes) -> tuple[Any, ...]:
                if ace[1] & 16:
                    return (2, existing.index(ace))
                identity = ace[8 : 16 + 4 * ace[9]]
                return (
                    0 if ace[0] in (1, 10) else 1,
                    identity[2:8],
                    identity[1],
                    struct.unpack("<" + "I" * identity[1], identity[8:]),
                )

            expected.sort(key=_access_order)
        assert actual == expected
    assert [ace for ace in actual if ace[1] & 16] == [
        ace for ace in existing if ace[1] & 16
    ]
    _canonical(actual, audit=field == "sacl")


def verify_capture(
    capture: dict[str, Any], *, paired: bool, running: bool = False
) -> dict[str, Any]:
    """Validate exact public values, binary descriptors and complete recovery.

    :param capture: Unmodified observations from the integration playbook.
    :param paired: Also compare untouched upstream execution and starting state.
    :param running: Verify completed cases before the final recovery stage.
    :returns: Number of validated cases and whether paired evidence was checked.
    """
    setup = _stdout(capture["setup"])
    assert setup["runtime"] == [3, 4, 4]
    for record in capture["results"]:
        case = record["case"]
        warnings = record["native"].get("warnings")
        _check_public(record["native"], _expected_public(case, setup), warnings)
        _check_effects(record)
        if not case.get("check"):
            _check_public(
                record["native_repeat"],
                _expected_public(case, setup, repeat=True),
                warnings,
            )
            assert _literal(_stdout(record["after_native_repeat"])) == _literal(
                _stdout(record["after_native"])
            )
        if paired:
            assert _literal(_public(record["native"])) == _literal(
                _public(record["original"])
            )
            assert _literal(_stdout(record["before_all_native"])) == _literal(
                _stdout(record["before_all_original"])
            )
            assert _literal(_stdout(record["before_native"])) == _literal(
                _stdout(record["before_original"])
            )
            assert _literal(_stdout(record["after_native"])) == _literal(
                _stdout(record["after_original"])
            )
            if case.get("condition") and not case.get("check"):
                assert _literal(_public(record["native_repeat"])) == _literal(
                    _public(record["original_repeat"])
                )
                assert _literal(_stdout(record["after_original"])) == _literal(
                    _stdout(record["after_original_repeat"])
                )
    if not running:
        assert _literal(_stdout(capture["restore"])["snapshots"]) == _literal(
            setup["baseline"]
        )
        assert _literal(_stdout(capture["readback"])) == _literal(setup["baseline"])
        cleanup = _stdout(capture["cleanup"])
        assert cleanup["restored"] is True and cleanup["journal_absent"] is True
        assert _literal(cleanup["snapshots"]) == _literal(setup["baseline"])
        assert _stdout(capture["absence"]) == {
            "file_absent": True,
            "registry_absent": True,
            "journal_absent": True,
            "workspace_empty": True,
        }
        assert capture["workspace_absent"] is True
        assert _literal(_stdout(capture["staging_before"])) == _literal(
            _stdout(capture["staging_after"])
        )
    return {"cases": len(capture["results"]), "paired": paired, "running": running}


if __name__ == "__main__":
    with Path(sys.argv[1]).open(encoding="utf-8") as stream:
        data = json.load(stream)
    print(
        json.dumps(
            verify_capture(
                data, paired=sys.argv[2] == "paired", running="--running" in sys.argv
            )
        )
    )
