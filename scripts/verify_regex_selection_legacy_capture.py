"""Verify legacy native category availability, not cross-host source parity."""

# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import json
import math
import ntpath
import sys
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

# The supported standalone CLI must also work outside the source checkout.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
# Reuse the accepted typed comparisons after standalone CLI setup.
# pylint: disable-next=wrong-import-position
from scripts.verify_regex_selection_capture import _public, _same


def _cases() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    path = (
        Path(__file__).resolve().parents[1]
        / "tests/integration/vars/regex_selection.yml"
    )
    values = yaml.safe_load(path.read_text(encoding="utf-8"))
    find = values["regex_selection_find_cases"]
    find = find + [
        {
            "id": "literal-caret",
            "pattern": r"^[\p{L}^_]+[.]txt$",
            "names": find[0]["names"],
        }
    ]
    return find, values["regex_selection_wait_cases"]


def _file_types(row: dict[str, Any]) -> None:
    expected = {
        "path": str,
        "filename": str,
        "attributes": str,
        "owner": str,
        "exists": bool,
        "isarchive": bool,
        "isdir": bool,
        "ishidden": bool,
        "isreadonly": bool,
        "isreg": bool,
        "islnk": bool,
        "isjunction": bool,
        "isshared": bool,
        "sharename": type(None),
        "extension": str,
        "size": int,
        "checksum": type(None),
        "nlink": int,
        "hlnk_targets": list,
        "lnk_source": type(None),
        "lnk_target": type(None),
    }
    assert row.keys() == expected.keys() | {
        "creationtime",
        "lastaccesstime",
        "lastwritetime",
    }
    for key, kind in expected.items():
        # Boolean integers and missing/null properties are different JSON types.
        # pylint: disable-next=unidiomatic-typecheck
        assert type(row[key]) is kind


def _successful(result: dict[str, Any]) -> None:
    assert result["failed"] is False and result["changed"] is False


def _timestamps(rows: list[dict[str, Any]], prepared: dict[str, Any]) -> None:
    for row in rows:
        seed = prepared["files"][row["filename"]]["mtime"]
        for field in ("creationtime", "lastaccesstime", "lastwritetime"):
            value = row[field]
            # Native Find preserves fractional seconds and projects integral
            # values to JSON integers. Never rewrite the retained public value.
            assert type(value) in (int, float) and math.isfinite(value)
            expected = int if value == int(value) else float
            # A Boolean or an integral float is a different observable type.
            # pylint: disable-next=unidiomatic-typecheck
            assert type(value) is expected
            if field != "lastaccesstime":
                # Local-wall projection preserves the seeded fraction. On XP,
                # preparing the protection journal reads files and updates their
                # access times, so access is not assumed to retain the seed.
                assert value % 1 == seed % 1


def _find_results(capture: dict[str, Any], prepared: dict[str, Any]) -> None:
    cases = {case["id"]: case for case in capture["find_cases"]}
    assert len(cases) == 10 and "literal-caret" in cases
    results = capture["find"]["results"]
    assert len(results) == 20
    normal: dict[str, dict[str, Any]] = {}
    seen: set[tuple[str, bool]] = set()
    for result in results:
        case, check = result["item"]
        _same(case, cases[case["id"]])
        _same(check, bool(check))
        identity = case["id"]
        assert (identity, check) not in seen
        seen.add((identity, check))
        assert result["ansible_loop_var"] == "item"
        _successful(result)
        _same(result["examined"], 10)
        _same(result["matched"], len(case["names"]))
        rows = result["files"]
        assert len(rows) == result["matched"]
        names = {row["filename"] for row in rows}
        assert len(names) == len(rows)
        assert names == set(case["names"])
        _timestamps(rows, prepared)
        for row in rows:
            _file_types(row)
            name = row["filename"]
            _same(row["path"], ntpath.join(prepared["root"], "files", name))
            _same(row["size"], len(prepared["files"][name]["bytes"]))
            assert row["exists"] is True and row["isreg"] is True
            assert row["isdir"] is False and row["islnk"] is False
            assert row["isjunction"] is False
        public = _public(result)
        # Loop input is retained and validated above; its check Boolean is the
        # sole intentional difference between the two same-host module calls.
        public.pop("item")
        if not check:
            assert identity not in normal
            normal[identity] = public
        else:
            assert identity in normal
            _same(normal.pop(identity), public)
    assert not normal
    assert seen == {(identity, check) for identity in cases for check in (False, True)}


def _wait_results(capture: dict[str, Any]) -> None:
    cases = capture["wait_cases"]
    results = capture["wait"]["results"]
    assert len(cases) == len(results) == 5
    assert len({case["id"] for case in cases}) == 5
    before, after = capture["clock_before"], capture["clock_after"]
    assert before["rc"] == after["rc"] == 0
    bound = float(after["stdout"]) - float(before["stdout"])
    assert math.isfinite(bound) and 0 < bound < 120
    for case, result in zip(cases, results):
        _same(result["item"], case)
        assert result["ansible_loop_var"] == "item"
        _successful(result)
        _same(result["wait_attempts"], 1)
        elapsed = result["elapsed"]
        # A JSON integer is not the released elapsed type, even when equal.
        # pylint: disable-next=unidiomatic-typecheck
        assert type(elapsed) is float
        assert math.isfinite(elapsed) and 0 <= elapsed <= bound


def verify(capture: dict[str, Any]) -> None:
    """Check retained native results and their same-host protection baseline.

    :param capture: Complete literal capture from regex_selection_legacy.yml.
    :raises AssertionError: Required inputs, results, types or closure differ.
    """
    assert capture["mode"] == "legacy-native"
    expected_find, expected_wait = _cases()
    _same(capture["find_cases"], expected_find)
    _same(capture["wait_cases"], expected_wait)
    assert capture["expected_windows"] in ([5, 1], [5, 2])
    before, after = capture["before"], capture["after"]
    assert before["rc"] == after["rc"] == 0
    identity = json.loads(before["stdout"])
    _same(identity, json.loads(after["stdout"]))
    _same(identity["python"], [3, 4, 4])
    _same(identity["bits"], 32)
    _same(identity["windows"], capture["expected_windows"])
    assert capture["expected_mac"] in [
        row["MACAddress"] for row in identity["protected"]["network"]
    ]
    assert capture["prepare"]["rc"] == 0
    prepared = json.loads(capture["prepare"]["stdout"])
    _same(prepared["root"], capture["workspace"]["path"])
    _find_results(capture, prepared)
    _wait_results(capture)
    cleanup = capture["cleanup"]
    assert cleanup["rc"] == 0 and cleanup["failed"] is False
    recovered = json.loads(cleanup["stdout"])
    assert recovered["absent"] is True
    _same(prepared, recovered["before"])
    _same(
        json.loads(capture["staging_before"]["stdout"]),
        json.loads(capture["staging_after"]["stdout"]),
    )


def main() -> None:
    """Validate one private capture using the standalone development CLI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    arguments = parser.parse_args()
    verify(json.loads(arguments.capture.read_text(encoding="utf-8")))
    print(
        "PASS:20 typed native Find requests,5 Wait requests and literal legacy closure"
    )


if __name__ == "__main__":
    main()
