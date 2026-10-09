"""Check whole child-wait results, real trees and individually bounded receipts."""

# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import base64
import calendar
import copy
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any


def literal(value: object) -> str:
    """Serialize every typed field for a stable literal comparison.

    :param value: Complete observable value.
    :returns: Canonical JSON without field omissions.
    """
    return json.dumps(value, sort_keys=True)


def public(value: dict[str, Any]) -> dict[str, Any]:
    """Keep all public fields except Ansible invocation/exception metadata.

    :param value: Complete module result.
    :returns: Complete public result.
    """
    return {
        key: item
        for key, item in value.items()
        if key not in ("invocation", "exception")
    }


def state(value: dict[str, Any]) -> dict[str, Any]:
    """Separate operation clocks and tree observations from protected state.

    :param value: Complete native observation.
    :returns: Literal registry, service, pending and file state.
    """
    result = copy.deepcopy(value)
    for key in ("utc", "started", "preparation_started_utc", "receipts", "running"):
        result.pop(key, None)
    return result


def protected(
    value: dict[str, Any], baseline: dict[str, Any], identifier: str
) -> dict[str, Any]:
    """Keep the literal boundary outside the single disposable product.

    :param value: Full native observation.
    :param baseline: Operation's exact protected baseline.
    :param identifier: Journal-owned registry product name.
    :returns: Every field outside the explicitly owned product and output.
    """
    result = state(value)
    result.pop("outputs")
    for location, branch in result["registry"].items():
        if branch is None:
            continue
        branch["children"] = [
            row for row in branch["children"] if row["name"] != identifier
        ]
        if baseline["registry"][location] is None:
            assert branch == {"values": [], "children": []}
            result["registry"][location] = None
    return result


def creation_seconds(value: str) -> float:
    """Interpret the native CIM creation timestamp without dropping precision.

    :param value: Raw Win32_Process CreationDate.
    :returns: UTC seconds including microseconds and timezone offset.
    """
    match = re.fullmatch(r"(\d{14})\.(\d{6})([+-])(\d{3})", value)
    assert match, value
    offset = int(match[4]) * 60 * (1 if match[3] == "+" else -1)
    return (
        calendar.timegm(time.strptime(match[1], "%Y%m%d%H%M%S"))
        + int(match[2]) / 1e6
        - offset
    )


def portable_receipts(
    after: dict[str, Any], before: dict[str, Any], expected: dict[str, Any]
) -> dict[str, Any]:
    """Validate the real graph and qualify only generated, bounded identities.

    :param after: Full after-operation native observation.
    :param before: Full before-operation native observation.
    :param expected: Explicit execution, root-code and pending-tree contract.
    :returns: Complete receipts with precisely qualified generated fields.
    """
    records = after["receipts"]
    assert set(records) == (
        {"parent", "child", "grandchild"} if expected.get("executed") else set()
    )
    roles = {value["data"]["pid"]: role for role, value in records.items()}
    assert len(roles) == len(records)
    if records:
        assert records["parent"]["data"]["child"] == records["child"]["data"]["pid"]
        assert records["child"]["data"]["parent"] == records["parent"]["data"]["pid"]
        assert records["child"]["data"]["child"] == records["grandchild"]["data"]["pid"]
        assert (
            records["grandchild"]["data"]["parent"] == records["child"]["data"]["pid"]
        )
    result: dict[str, Any] = copy.deepcopy(records)
    for role, record in result.items():
        data, file = record["data"], record["file"]
        assert data["role"] == role
        assert data["code"] == (
            expected.get("code", 0)
            if role == "parent"
            else 19 if role == "child" else 29
        )
        assert before["utc"] <= data["utc"] <= after["utc"]
        assert before["utc"] <= file["mtime"] / 1e9 <= after["utc"]
        raw = base64.b64decode(file["bytes"]["raw_bytes"])
        assert raw == json.dumps(data, sort_keys=True).encode("utf-8")
        assert hashlib.sha256(raw).hexdigest() == file["sha256"] and file[
            "length"
        ] == len(raw)
        for field in ("pid", "parent", "child"):
            if field in data:
                assert isinstance(data[field], int) and not isinstance(
                    data[field], bool
                )
                if field != "parent" or role != "parent":
                    data[field] = "<owned-" + roles[data[field]] + ">"
        data["utc"] = "<individually-bounded-receipt-clock>"
        # Qualify only these individually verified generated fields, not a
        # protected file's mtime/bytes or arbitrary unknown receipt properties.
        file["mtime"] = "<individually-bounded-receipt-mtime>"
        file["bytes"] = {"verified_generated_data": copy.deepcopy(data)}
        file["sha256"] = "<verified-raw-receipt-sha256>"
        file["length"] = "<verified-raw-receipt-length>"
    active = after["running"]
    assert bool(active) is expected.get("pending", False)
    for process in active:
        assert process["ProcessId"] in roles and process["ParentProcessId"] in roles
        role = roles[process["ProcessId"]]
        assert role != "parent"
        assert (
            before["utc"]
            <= creation_seconds(process["CreationDate"])
            <= records[role]["data"]["utc"]
        )
        assert records[role]["data"]["workspace"] in process["CommandLine"]
    return result


def verify_side(row: dict[str, Any], side: str, identifier: str) -> dict[str, Any]:
    """Check all literal protected effects and each new output's time bounds.

    :param row: Complete retained paired operation.
    :param side: Native or untouched original.
    :param identifier: Exact journal-owned product ID.
    :returns: Literal effects plus narrowly qualified generated receipts.
    """
    expected = row["expected"]
    before = json.loads(
        row["before" if side == "native" else "before_original"]["stdout"]
    )
    after = json.loads(row["after_" + side]["stdout"])
    assert before["utc"] <= after["utc"]
    assert literal(protected(before, before, identifier)) == literal(
        protected(after, before, identifier)
    )
    if expected.get("check") or not expected.get("executed"):
        assert literal(state(before)) == literal(state(after))
    keys = [
        (location, child)
        for location, branch in after["registry"].items()
        if branch is not None
        for child in branch["children"]
        if child["name"] == identifier
    ]
    assert len(keys) == int(expected.get("installed", False))
    assert set(after["outputs"]) == (
        {"installed.json"} if expected.get("installed") else set()
    )
    if keys:
        assert keys[0][0] == "HKCU/native"
        output = after["outputs"]["installed.json"]
        assert json.loads(base64.b64decode(output["bytes"]["raw_bytes"])) == {
            "identifier": identifier,
            "location": "HKCU/native",
        }
        lower = (
            before["preparation_started_utc"]
            if "installed.json" in before["outputs"]
            else before["utc"]
        )
        assert lower <= output["mtime"] / 1e9 <= after["utc"]
    portable = state(after)
    for file in portable["outputs"].values():
        file["mtime"] = "<individually-bounded-new-output-mtime>"
    initial = state(before)
    for file in initial["outputs"].values():
        assert before["preparation_started_utc"] <= file["mtime"] / 1e9 <= before["utc"]
        file["mtime"] = "<individually-bounded-prepared-output-mtime>"
    return {
        "before": initial,
        "after": portable,
        "receipts": portable_receipts(after, before, expected),
    }


def verify_capture(
    capture: dict[str, Any], paired: bool, growing: bool = False
) -> dict[str, Any]:
    """Validate the complete public matrix and strict owned-process recovery.

    :param capture: Full retained fixture outcomes.
    :param paired: Require the original released module's whole result/effects.
    :param growing: The last raw observation has not yet been marked validated.
    :returns: Literal comparison result and only precisely qualified generated fields.
    :raises AssertionError: Public fields, real tree, timestamps or recovery differ.
    """
    assert capture["results"], "No complete observed public case was retained"
    identifier = json.loads(capture["setup"]["stdout"])["identifier"]
    for index, row in enumerate(capture["results"]):
        expected = row["expected"]
        if not growing or index < len(capture["results"]) - 1:
            assert row["validated"] is True
        effects = []
        for side in ("native", "original") if paired else ("native",):
            result = row[side]
            assert result["changed"] is expected.get("changed", False)
            assert bool(result.get("failed", False)) is expected.get("failed", False)
            assert result["reboot_required"] is expected.get("reboot", False)
            assert result["rc"] == (
                expected.get("code", 0) if expected.get("executed") else 0
            )
            effects.append(verify_side(row, side, identifier))
        if paired:
            assert literal(public(row["native"])) == literal(
                public(row["original"])
            ), row["name"]
            assert literal(effects[0]) == literal(effects[1]), row["name"]
    if not growing:
        assert capture["workspace_absent"] is True
        assert json.loads(capture["staging_before"]["stdout"]) == json.loads(
            capture["staging_after"]["stdout"]
        )
        recovery = json.loads(capture["recovery"]["stdout"])
        assert (
            recovery["restored"] is True
            and recovery["process_tree_absent"] is True
            and recovery["receipt_files_absent"] is True
        )
        assert literal(state(recovery["before"])) == literal(state(recovery["after"]))
    return {
        "verified": True,
        "paired": paired,
        "growing": growing,
        "cases": len(capture["results"]),
        "qualifications": (
            "Only newly generated receipt PID links/clock/serialization/filemtime "
            "and installed-output mtimes are qualified after exact graph/raw "
            "serialization/hash/individual bounds checks. Protected source/runtime "
            "bytes, hashes, mtimes, attributes, ACL and registry/service/pending "
            "fields remain literal; raw values remain retained."
        ),
    }


def rewrite_owned(value: Any, root: str, identifier: str) -> Any:
    """Replace only this capture's separately allocated owned identities.

    :param value: Complete typed public/request/effect value.
    :param root: Proven journal-owned workspace.
    :param identifier: Proven disposable uninstall entry name.
    :returns: Same typed value with just these concrete identities replaced.
    """
    if isinstance(value, str):
        return value.replace(identifier, "<owned-product>").replace(
            root, "<owned-workspace>"
        )
    if isinstance(value, list):
        return [rewrite_owned(item, root, identifier) for item in value]
    if isinstance(value, dict):
        return {
            rewrite_owned(key, root, identifier): rewrite_owned(item, root, identifier)
            for key, item in value.items()
        }
    return value


def _mapped_effect(
    effect: dict[str, Any], root: str, identifier: str
) -> dict[str, Any]:
    # Host registry/service/runtime/ACL fields never compare across different
    # Windows installations. Each remains literal against its own baseline.
    # Project only the exact owned product, output data and validated tree.
    result: dict[str, Any] = {
        "receipts": {
            role: {
                "data": receipt["data"],
                "attributes": receipt["file"]["attributes"],
            }
            for role, receipt in effect["receipts"].items()
        }
    }
    for side in ("before", "after"):
        value = effect[side]
        result[side] = {
            "outputs": {
                name: json.loads(base64.b64decode(file["bytes"]["raw_bytes"]))
                for name, file in value["outputs"].items()
            },
            "product": [
                child
                for branch in value["registry"].values()
                if branch is not None
                for child in branch["children"]
                if child["name"] == identifier
            ],
        }
    mapped: dict[str, Any] = rewrite_owned(result, root, identifier)
    return mapped


def verify_reference(
    capture: dict[str, Any], references: list[dict[str, Any]], growing: bool = False
) -> dict[str, Any]:
    """Map legacy execution to identical-input whole released modern results.

    :param capture: Native legacy observations and exact recovery.
    :param references: Healthy paired modern cohorts, retaining each source root.
    :param growing: The final legacy row has not yet been marked validated.
    :returns: Count of complete public requests and owned effects compared.
    """
    verify_capture(capture, False, growing)
    for reference in references:
        verify_capture(reference, True)
    native_setup = json.loads(capture["setup"]["stdout"])
    root = capture["results"][0]["request"]["chdir"]
    identifier = native_setup["identifier"]
    assert identifier.endswith(root.rsplit("\\", 1)[-1])
    originals = {
        row["name"]: (row, json.loads(reference["setup"]["stdout"]))
        for reference in references
        for row in reference["results"]
    }
    assert len(originals) == sum(len(reference["results"]) for reference in references)
    for row in capture["results"]:
        original, source_setup = originals[row["name"]]
        assert native_setup["sha256"] == source_setup["sha256"]
        source_root = original["request"]["chdir"]
        source_identifier = source_setup["identifier"]
        assert source_identifier.endswith(source_root.rsplit("\\", 1)[-1])
        assert literal(row["expected"]) == literal(original["expected"])
        assert literal(rewrite_owned(row["request"], root, identifier)) == literal(
            rewrite_owned(original["request"], source_root, source_identifier)
        )
        assert literal(
            rewrite_owned(public(row["native"]), root, identifier)
        ) == literal(
            rewrite_owned(public(original["original"]), source_root, source_identifier)
        ), row[
            "name"
        ]
        native_effect = verify_side(row, "native", identifier)
        source_effect = verify_side(original, "original", source_identifier)
        assert literal(_mapped_effect(native_effect, root, identifier)) == literal(
            _mapped_effect(source_effect, source_root, source_identifier)
        ), row["name"]
    return {"mapped": True, "cases": len(capture["results"]), "same_input_hashes": True}


def main() -> None:
    """Validate retained evidence without contacting Windows."""
    parser = argparse.ArgumentParser()
    parser.add_argument("capture", type=Path)
    parser.add_argument("mode", choices=("paired", "native"))
    parser.add_argument("--growing", action="store_true")
    parser.add_argument("--reference", type=Path, action="append")
    args = parser.parse_args()
    capture = json.loads(args.capture.read_bytes())
    print(
        json.dumps(
            verify_reference(
                capture,
                [json.loads(path.read_bytes()) for path in args.reference],
                args.growing,
            ),
            sort_keys=True,
        )
        if args.reference
        else json.dumps(
            verify_capture(capture, args.mode == "paired", args.growing),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
