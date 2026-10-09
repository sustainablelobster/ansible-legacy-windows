"""Verify whole synchronous Copy/Template Runas results and owned effects."""

# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import base64
import copy
import importlib.util
import itertools
import json
import math
from pathlib import Path
from typing import Any, cast

_OBSERVER_SPEC = importlib.util.spec_from_file_location(
    "owned_copy_observer_selection",
    Path(__file__).resolve().parents[1]
    / "tests/integration/fixtures/copy_template_runas_observer.py",
)
assert _OBSERVER_SPEC is not None and _OBSERVER_SPEC.loader is not None
_OBSERVER = importlib.util.module_from_spec(_OBSERVER_SPEC)
_OBSERVER_SPEC.loader.exec_module(_OBSERVER)


def _literal(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)


def _observed(record: dict[str, Any]) -> Any:
    assert isinstance(record["rc"], int) and not isinstance(record["rc"], bool)
    assert record["rc"] == 0, record
    return json.loads(record["stdout"])


def _public(row: dict[str, Any], side: str, root: str) -> dict[str, Any]:
    result = dict(row[side])
    result.pop("invocation", None)
    result.pop("exception", None)
    assert result.get("failed", False) is False, (row["case"], side, result)
    assert isinstance(result["changed"], bool)
    assert result["changed"] is (row["case"][2] in ("create", "check_new"))
    if row["case"][1] == "template":
        # Only this source allocation differs: retain both raw values and prove
        # exact owner-private scope/basename/absence immediately after return.
        source, directory = Path(result["src"]), Path(root)
        assert directory.is_absolute() and source.is_absolute()
        assert directory.name.startswith("copy-template-runas-local-")
        assert source.resolve().is_relative_to(directory.resolve())
        assert source.name == "basic.j2"
        assert row["rendered_" + side]["stat"]["exists"] is False
        assert not source.exists()
        result["src"] = "<owned-rendered-source>/basic.j2"
    return result


def _staging(
    row: dict[str, Any],
    side: str,
    before: dict[str, Any],
    after: dict[str, Any],
    retained_complete: bool,
) -> None:
    if retained_complete and "staging_inventory" not in before:
        # The immutable original's accepted file/archive pairs recorded names
        # and final root absence, not scratch contents or ownership. Keep that
        # historical qualification explicit; new captures require inventory.
        assert row["case"][1] != "template"
        assert before["staging"] == after["staging"]
        return
    previous, current = before["staging_inventory"], after["staging_inventory"]
    for observed in (before, after):
        assert sorted(
            {name.split("/")[0] for name in observed["staging_inventory"]}
        ) == (observed["staging"])
        assert all(
            name not in (".", "..") and "/" not in name and "\\" not in name
            for name in observed["staging"]
        )
    assert all(
        _literal(current[name]) == _literal(entry) for name, entry in previous.items()
    )
    if (
        side == "native"
        or row["case"][1] != "template"
        or row["case"][2] in ("repeat", "check_existing")
    ):
        assert _literal(previous) == _literal(current)
        assert before["staging"] == after["staging"]
    else:
        # Released Template create/check_new retains one task-owned directory;
        # measured repeat/check_existing preserves the complete prior inventory.
        # Retain the allocation rather than emulate it in production.
        additions = set(after["staging"]) - set(before["staging"])
        assert len(additions) == 1
        child = additions.pop()
        assert child.startswith("ansible-tmp-")
        assert current[child]["metadata"]["attributes"] & 16
        assert all(
            name == child or name.startswith(child + "/")
            for name in set(current) - set(previous)
        )


def _expected_content(workflow: str) -> dict[str, bytes]:
    return {
        "file": {"single.bin": bytes(range(256)) * 4},
        "archive": {
            "nested/payload.bin": bytes(range(256)) * 4,
            "Café 雪 [x].txt": b"Public fixture % ! &\r\n",
        },
        "template": {
            "basic.txt": "Header % ! &\r\nCafé 雪 \\path % ! &\r\n".encode(),
        },
    }[workflow]


def _output_schema(output: dict[str, Any], workflow: str, populated: bool) -> None:
    assert isinstance(output, dict)
    files = set(_expected_content(workflow)) if populated else set()
    directories = {"nested", "empty"} if populated and workflow == "archive" else set()
    assert set(output) == files | directories
    for name, entry in output.items():
        assert isinstance(entry, dict)
        assert set(entry) == {"metadata", "security"} | (
            {"base64"} if name in files else set()
        )
        metadata, security = entry["metadata"], entry["security"]
        assert isinstance(metadata, dict) and isinstance(security, dict)
        assert set(metadata) == {"attributes", "modification_time"}
        assert set(security) == {"owner", "sddl"}
        for value in metadata.values():
            assert isinstance(value, int) and not isinstance(value, bool) and value >= 0
        assert bool(metadata["attributes"] & 16) is (name in directories)
        assert isinstance(security["owner"], str) and security["owner"].startswith(
            "S-1-"
        )
        assert isinstance(security["sddl"], str) and security["sddl"].startswith("O:")
        if name in files:
            assert isinstance(entry["base64"], str)
            base64.b64decode(entry["base64"], validate=True)


def _output(row: dict[str, Any], side: str, retained_complete: bool) -> dict[str, Any]:
    before = _observed(row["before_" + side])
    after = _observed(row["after_" + side])
    _staging(row, side, before, after, retained_complete)
    for observed in (before, after):
        assert isinstance(observed["time"], float) and math.isfinite(observed["time"])
    assert before["time"] <= after["time"]
    for field in ("source", "sentinel", "global"):
        assert _literal(before[field]) == _literal(after[field]), (row["case"], field)
    _output_schema(
        before["output"], row["case"][1], row["case"][2] in ("repeat", "check_existing")
    )
    _output_schema(after["output"], row["case"][1], row["case"][2] != "check_new")
    result = cast(dict[str, Any], copy.deepcopy(after["output"]))
    if row["case"][2] != "create":
        assert _literal(before["output"]) == _literal(after["output"]), row["case"]
    else:
        assert before["output"] == {}
        for name, entry in result.items():
            # Owner/SDDL remain literal between implementations. The measured
            # Administrators default owner is not the worker's token user SID.
            # ZIP file dates come from the literal fixed controller sources;
            # newly created directories and single/rendered files use call time.
            if row["case"][1] != "archive" or "base64" not in entry:
                ticks = entry["metadata"].pop("modification_time")
                assert isinstance(ticks, int) and not isinstance(ticks, bool)
                stamp = ticks / 10000000 - 11644473600
                assert before["time"] <= stamp <= after["time"], (row["case"], name)
    return result


def _worker(
    record: dict[str, Any], start: dict[str, Any], finished: float
) -> tuple[int, int]:
    identity, parent = record["identity"], record["parent_identity"]
    assert isinstance(record["observed_epoch"], float)
    assert math.isfinite(record["observed_epoch"])
    assert identity["alive"] is True and parent["alive"] is True
    for value in (identity, parent):
        assert all(
            isinstance(value[field], int)
            and not isinstance(value[field], bool)
            and value[field] > 0
            for field in ("pid", "created")
        )
    assert record["process"]["ProcessId"] == identity["pid"]
    assert record["process"]["ParentProcessId"] == parent["pid"]
    assert record["parent_process"]["ProcessId"] == parent["pid"]
    # Reuse the pure selector; loading it never invokes Windows APIs.
    assert _OBSERVER._selected(  # pylint: disable=protected-access
        record["process"], start["workspace"], start["side"]
    )
    stamp = identity["created"] / 10000000 - 11644473600
    assert start["started_epoch"] <= stamp <= record["observed_epoch"] <= finished
    assert parent["created"] <= identity["created"]
    assert start["started_epoch"] <= parent["created"] / 10000000 - 11644473600
    assert not any(
        item["identity"]
        and item["identity"]["pid"] == identity["pid"]
        and item["identity"]["created"] == identity["created"]
        for item in start["baseline"]
    )
    return parent["pid"], parent["created"]


def _privilege_restored(start: dict[str, Any], stop: dict[str, Any]) -> None:
    privilege = stop["debug_privilege"]
    assert privilege["token_closed"] is True
    before, enabled = privilege["before"], privilege["enabled"]
    assert _literal(before) == _literal(privilege["after"])
    assert _literal(start["debug_privilege"]) == _literal(
        {"before": before, "enabled": enabled}
    )
    assert isinstance(before["debug_attributes"], int)
    assert not isinstance(before["debug_attributes"], bool)
    assert isinstance(enabled["debug_attributes"], int)
    assert not isinstance(enabled["debug_attributes"], bool)
    assert enabled["debug_attributes"] == before["debug_attributes"] | 2
    assert enabled["debug_luid"] == before["debug_luid"]
    expected = copy.deepcopy(before["privileges"])
    matching = [item for item in expected if item["luid"] == before["debug_luid"]]
    assert len(matching) == 1
    assert matching[0]["attributes"] == before["debug_attributes"]
    matching[0]["attributes"] = enabled["debug_attributes"]
    assert _literal(expected) == _literal(enabled["privileges"])


def _tokens(row: dict[str, Any], side: str, document: dict[str, Any]) -> None:
    start = _observed(row[side + "_observer_start"])
    stop = _observed(row[side + "_observer_stop"])
    for value in (start["started_epoch"], stop["finished_epoch"]):
        assert isinstance(value, float) and math.isfinite(value)
    assert start["started_epoch"] <= stop["finished_epoch"]
    assert _literal(start) == _literal(stop["ready"])
    assert stop["valid"] is True and stop["observer_closed"] is True
    assert stop["failure"] is None and stop["races"] == []
    assert start["workspace"] == document["workspace"]["path"]
    assert start["side"] == side and start["python"] == [3, 4, 4]
    assert _literal(start["observer"]) == _literal(stop["observer"])
    expected_sid = (
        "S-1-5-18"
        if row["case"][0] == "system"
        else document["identity"]["account"]["sid"]
    )
    expected_count = 2 if row["case"][2] == "create" else 1
    assert start["observer_sid"] == document["identity"]["account"]["sid"]
    if row["case"][0] == "system":
        _privilege_restored(start, stop)
    records = stop["records"]
    assert stop["expected_sid"] == expected_sid
    assert stop["expected_workers"] == len(records) == expected_count
    parents = set()
    for record in records:
        assert record["sid"] == expected_sid
        parents.add(_worker(record, start, stop["finished_epoch"]))
    assert len(parents) == expected_count


def _pair(
    row: dict[str, Any],
    document: dict[str, Any],
    setup: dict[str, Any],
    retained_complete: bool,
) -> None:
    case = row["case"]
    assert _literal(_public(row, "native", document["controller_temp_root"])) == (
        _literal(_public(row, "original", document["controller_temp_root"]))
    ), (case, "whole public")
    outputs = [_output(row, side, retained_complete) for side in ("native", "original")]
    assert _literal(outputs[0]) == _literal(outputs[1]), (case, "whole output")
    expected = _expected_content(case[1])
    actual = {
        name: base64.b64decode(entry["base64"], validate=True)
        for name, entry in outputs[0].items()
        if "base64" in entry
    }
    assert actual == ({} if case[2] == "check_new" else expected), case
    for side in ("native", "original"):
        before = _observed(row["before_" + side])
        for field in ("source", "sentinel", "global"):
            assert _literal(before[field]) == _literal(setup[field]), (case, field)


def _account(result: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in result.items()
        if key not in ("invocation", "exception")
    }


def _user_prefix(document: dict[str, Any], indices: list[int]) -> None:
    # The frozen first SYSTEM viewer failed access checks after these complete
    # user pairs. Adjudicate only that exact prefix; do not manufacture rows.
    assert indices == [0, 4, 5, 6, 8, 9, 10, 11]
    assert _literal(document["case_indices"]) == _literal(
        indices + [12, 16, 17, 18, 20, 21, 22, 23]
    )
    failed = document["latest_native_observer_stop"]
    assert _literal(failed["rc"]) == _literal(3) and failed["failed"] is True
    observation = json.loads(failed["stdout"])
    assert observation["valid"] is False and observation["observer_closed"] is True
    assert observation["expected_sid"] == "S-1-5-18"
    assert _literal(observation["expected_workers"]) == _literal(2)
    assert observation["records"] == observation["races"] == []
    assert observation["failure"] == "PermissionError(13, 'Access is denied.', None, 5)"


def _recovered(document: dict[str, Any], setup: dict[str, Any]) -> None:
    recovery = _observed(document["recovery"])
    assert recovery["workspace_absent"] is True
    final = _observed(document["results"][-1]["after_original"])
    assert recovery["staging"] == final["staging"]
    if "staging_inventory" in recovery:
        assert _literal(recovery["staging_inventory"]) == _literal(
            final["staging_inventory"]
        )
    for field in ("source", "sentinel", "global"):
        assert _literal(recovery[field]) == _literal(setup[field]), field
    assert _observed(document["controller_before"]) == _observed(
        document["controller_after"]
    )
    assert not Path(document["controller_workspace"]["path"]).exists()
    assert _observed(document["staging_before"]) == _observed(document["staging_after"])
    assert _literal(_account(document["identity"])) == _literal(
        _account(document["final_identity"])
    )


def verify_capture(
    document: dict[str, Any],
    case_indices: list[int] | None = None,
    *,
    retained_complete: bool = False,
    retained_user_prefix: bool = False,
) -> int:
    """Compare explicit paired workflows and literal protected/recovery records.

    :param document: Raw source/native results and complete observer records.
    :param case_indices: Ordered unique indices in the fixed 24-case matrix.
    :param retained_complete: Check all old identities, adjudicating only indices.
    :param retained_user_prefix: Adjudicate the frozen failed-SYSTEM run's user pairs.
    :returns: Number of verified whole public and content/ownership pairs.
    :raises AssertionError: A result, allocation, effect or recovery differs.
    """
    complete_cases = list(
        itertools.product(
            ("user", "system"),
            ("file", "archive", "template"),
            ("create", "repeat", "check_existing", "check_new"),
        )
    )
    indices = list(range(24)) if case_indices is None else case_indices
    assert not (retained_complete and retained_user_prefix)
    assert indices and all(
        isinstance(index, int) and not isinstance(index, bool) and 0 <= index < 24
        for index in indices
    )
    assert indices == sorted(set(indices))
    cases = [complete_cases[index] for index in indices]
    rows = document["results"]
    if retained_complete:
        # Read the unchanged complete raw capture; never compose synthetic rows.
        assert len(rows) == 24
        assert [row["case"] for row in rows] == [list(case) for case in complete_cases]
        rows = [rows[index] for index in indices]
    else:
        assert len(rows) == len(cases)
        if retained_user_prefix:
            _user_prefix(document, indices)
        elif "case_indices" in document:
            assert _literal(document["case_indices"]) == _literal(indices)
    setup = _observed(document["setup"])
    assert _literal(setup["global"]["python"]) == _literal([3, 4, 4])
    if not retained_complete:
        assert setup["staging"] == [] and setup["staging_inventory"] == {}
        staging = setup["staging_inventory"]
    for row, case in zip(rows, cases):
        assert row["case"] == list(case)
        if not retained_complete:
            assert _literal(_observed(row["before_native"])["staging_inventory"]) == (
                _literal(staging)
            )
            assert _literal(_observed(row["before_original"])["staging_inventory"]) == (
                _literal(_observed(row["after_native"])["staging_inventory"])
            )
            staging = _observed(row["after_original"])["staging_inventory"]
            for side in ("native", "original"):
                _tokens(row, side, document)
        _pair(row, document, setup, retained_complete)
    _recovered(document, setup)
    return len(rows)


def main() -> None:
    """Check one retained capture without accessing a Windows host."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--case-indices", type=int, nargs="+")
    parser.add_argument("--retained-complete", action="store_true")
    parser.add_argument("--retained-user-prefix", action="store_true")
    args = parser.parse_args()
    count = verify_capture(
        json.loads(args.capture.read_text(encoding="utf-8")),
        args.case_indices,
        retained_complete=args.retained_complete,
        retained_user_prefix=args.retained_user_prefix,
    )
    print(f"PASS: {count} whole public/content/ownership/recovery Runas pairs")


if __name__ == "__main__":
    main()
