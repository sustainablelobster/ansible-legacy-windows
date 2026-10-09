"""Verify complete registry-package results and individually bounded file clocks."""

# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import base64
import copy
import json
from pathlib import Path
from typing import Any


def _literal(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True)


def _state(observation: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(observation)
    value.pop("utc")
    value.pop("preparation_started_utc", None)
    return value


def _portable(observation: dict[str, Any]) -> dict[str, Any]:
    value = _state(observation)
    # Only newly written fixture-output clocks differ across independent runs.
    # Their raw values remain captured and must pass the operation-bound checks.
    for output in value["outputs"].values():
        output.pop("mtime")
    return value


def _protected(
    value: dict[str, Any], baseline: dict[str, Any], identifier: str
) -> dict[str, Any]:
    result = _state(value)
    result.pop("outputs")
    for label, branch in result["registry"].items():
        if branch is None:
            continue
        branch["children"] = [
            row for row in branch["children"] if row["name"] != identifier
        ]
        if baseline["registry"][label] is None:
            assert branch == {"values": [], "children": []}
            result["registry"][label] = None
    return result


def _verify_timestamps(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    assert before["utc"] <= after["utc"]
    qualified = []
    for name, output in before["outputs"].items():
        assert (
            before["preparation_started_utc"] <= output["mtime"] / 1e9 <= before["utc"]
        )
        qualified.append("before.outputs." + name + ".mtime")
    for name, output in after["outputs"].items():
        if (
            name in before["outputs"]
            and output["mtime"] == before["outputs"][name]["mtime"]
        ):
            continue
        assert before["utc"] <= output["mtime"] / 1e9 <= after["utc"]
        qualified.append("after.outputs." + name + ".mtime")
    return qualified


def _verify_side(
    record: dict[str, Any], side: str, identifier: str, workspace: str | None
) -> tuple[dict[str, Any], list[str]]:
    expected = record["expected"]
    before = json.loads(
        record["before" if side == "native" else "before_original"]["stdout"]
    )
    after = json.loads(record["after_" + side]["stdout"])
    qualified = _verify_timestamps(before, after)
    assert _literal(_protected(before, before, identifier)) == _literal(
        _protected(after, before, identifier)
    )
    logged_uninstall = "uninstall_arguments" in expected
    if expected.get("check") or expected.get("failed"):
        unchanged = copy.deepcopy(after)
        if logged_uninstall and not expected.get("check"):
            unchanged["outputs"].pop("uninstall-arguments.json", None)
        assert _literal(_state(before)) == _literal(_state(unchanged))
    keys = [
        (location, row)
        for location, branch in after["registry"].items()
        if branch is not None
        for row in branch["children"]
        if row["name"] == identifier
    ]
    assert len(keys) == int(expected.get("installed", False))
    assert set(after["outputs"]) == (
        ({"installed.json"} if expected.get("installed", False) else set())
        | ({"uninstall-arguments.json"} if logged_uninstall else set())
    )
    if logged_uninstall:
        assert workspace is not None
        content = after["outputs"]["uninstall-arguments.json"]["bytes"]["raw_bytes"]
        assert json.loads(base64.b64decode(content).decode("utf-8")) == {
            "identifier": identifier,
            "invocations": [
                {
                    "executable": workspace + r"\registry installer.exe",
                    "arguments": expected["uninstall_arguments"],
                    "operation": expected.get("uninstall_operation", "remove"),
                }
            ],
        }
    if keys:
        assert keys[0][0] == expected["hive"] + "/" + expected["branch"]
        content = after["outputs"]["installed.json"]["bytes"]["raw_bytes"]
        assert json.loads(base64.b64decode(content).decode("utf-8")) == {
            "identifier": identifier,
            "location": expected["hive"] + "/" + expected["branch"],
        }
    return {"before": _portable(before), "after": _portable(after)}, qualified


def _public(result: dict[str, Any]) -> dict[str, Any]:
    value = {
        key: value
        for key, value in result.items()
        if key not in ("invocation", "exception")
    }
    # The contract replaces the collection's fully qualified name, not any
    # other diagnostic text. Retain each complete raw message in the capture.
    prefix = "Unsupported parameters for (ansible.windows.win_package)"
    if value.get("msg", "").startswith(prefix):
        value["msg"] = value["msg"].replace(
            prefix,
            "Unsupported parameters for (sustainablelobster.legacy_windows.win_package)",
            1,
        )
    return value


def _verify_repeat(record: dict[str, Any]) -> None:
    expected = {
        "changed": False,
        "failed": False,
        "rc": 0,
        "reboot_required": False,
    }
    if "warnings" in record["native"]:
        expected["warnings"] = record["native"]["warnings"]
    assert _literal(_public(record["native_repeat"])) == _literal(expected)
    repeated = json.loads(record["after_native_repeat"]["stdout"])
    assert _literal(_state(repeated)) == _literal(
        _state(json.loads(record["after_native"]["stdout"]))
    )


def verify_capture(
    capture: dict[str, Any], *, paired: bool, running: bool = False
) -> dict[str, Any]:
    """Compare all public values and effects, qualifying only measured clocks.

    :param capture: Complete raw registry-executable fixture evidence.
    :param paired: Require a released source counterpart for every request.
    :param running: Validate a growing capture before final cleanup exists.
    :returns: Checked cases and exact qualified output-clock paths.
    :raises AssertionError: A public value, effect, clock or cleanup differs.
    """
    setup = json.loads(capture["setup"]["stdout"])
    identifier = setup["identifier"]
    reports = []
    for index, record in enumerate(capture["results"]):
        expected = record["expected"]
        native = record["native"]
        assert bool(native.get("failed", False)) == bool(expected.get("failed", False))
        assert native["changed"] is bool(expected.get("changed", False))
        assert native.get("reboot_required", False) is False
        if not running or index < len(capture["results"]) - 1:
            assert record["validated"] is True
        effects: dict[str, dict[str, Any]] = {}
        qualified: dict[str, list[str]] = {}
        for side in ("native", "original") if paired else ("native",):
            effects[side], qualified[side] = _verify_side(
                record, side, identifier, setup.get("workspace")
            )
        if expected.get("repeat"):
            _verify_repeat(record)
        if paired:
            assert _literal(_public(native)) == _literal(
                _public(record["original"])
            ), record["name"]
            assert qualified["native"] == qualified["original"]
            assert _literal(effects["native"]) == _literal(effects["original"])
        reports.append({"case": record["name"], "qualified_clock_paths": qualified})
    assert reports
    if not running:
        assert capture["workspace_absent"] is True
        assert json.loads(capture["staging_before"]["stdout"]) == json.loads(
            capture["staging_after"]["stdout"]
        )
        recovery = json.loads(capture["recovery"]["stdout"])
        assert recovery["restored"] is True
        if not recovery.get("journal_absent"):
            assert _literal(_state(recovery["before"])) == _literal(
                _state(recovery["after"])
            )
    return {"verified": True, "paired": paired, "running": running, "cases": reports}


def main() -> None:
    """Validate retained evidence locally without contacting Windows.

    :raises AssertionError: Raw public behavior, effects or recovery differ.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("mode", choices=("paired", "native"))
    parser.add_argument("--running", action="store_true")
    args = parser.parse_args()
    capture = json.loads(args.capture.read_text(encoding="utf-8"))
    print(
        json.dumps(
            verify_capture(capture, paired=args.mode == "paired", running=args.running),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
