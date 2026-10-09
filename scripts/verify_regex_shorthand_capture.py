"""Check whole public shorthand results, exact memberships and owned recovery."""

# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import importlib.util
import json
import math
import ntpath
import sys
from pathlib import Path
from typing import Any

# Development tooling supplies PyYAML without optional typing metadata.
import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# Reuse the independently reviewed comparisons and lifecycle, not new models.
# pylint: disable-next=wrong-import-position
from scripts.verify_regex_selection_capture import _public, _same, _timestamps

# The unchanged native/source file schema includes security and link fields.
# pylint: disable-next=wrong-import-position
from scripts.verify_regex_selection_legacy_capture import _file_types

# The ordinary UTF16 verifier supplies the same bounded clock/closure contract.
# pylint: disable-next=wrong-import-position
from scripts.verify_regex_utf16_capture import _clock_bound, _closure


def _find_pairs(
    capture: dict[str, Any], cases: list[dict[str, Any]], filenames: tuple[str, ...]
) -> None:
    _same(capture["prepare"]["rc"], 0)
    prepared = json.loads(capture["prepare"]["stdout"])
    _same(prepared["root"], capture["workspace"]["path"])
    assert set(prepared["files"]) == set(filenames)
    expected = [(case, check) for case in cases for check in (False, True)]
    assert len(capture["find"]) == len(expected) == 16
    normal: dict[str, Any] = {}
    for pair, (case, check) in zip(capture["find"], expected):
        _same(pair["case"], case)
        _same(pair["check"], check)
        native, source = _public(pair["native"]), _public(pair["source"])
        _same(native, source)
        assert native["failed"] is False and native["changed"] is False
        _same(native["examined"], len(filenames))
        _same(native["matched"], len(case["names"]))
        names = [entry["filename"] for entry in native["files"]]
        assert len(names) == len(set(names)) == len(case["names"])
        assert sorted(names) == sorted(case["names"])
        for entry in native["files"]:
            _file_types(entry)
            name = entry["filename"]
            _same(entry["path"], ntpath.join(prepared["root"], "files", name))
            _same(entry["size"], len(prepared["files"][name]["bytes"]))
            assert entry["exists"] is True and entry["isreg"] is True
        _timestamps(native["files"])
        if check:
            _same(normal[case["id"]], native)
        else:
            normal[case["id"]] = native


def verify(capture: dict[str, Any]) -> None:
    """Require every selected complete public pair and literal fixture closure.

    :param capture: Unmodified JSON capture from the accepted lifecycle tasks.
    :raises AssertionError: Inputs, results, memberships, clocks or recovery differ.
    """
    cases = yaml.safe_load(
        (ROOT / "tests/integration/vars/regex_shorthand.yml").read_text(
            encoding="utf-8"
        )
    )
    spec = importlib.util.spec_from_file_location(
        "owned_shorthand_names", ROOT / "tests/integration/fixtures/regex_shorthand.py"
    )
    assert spec is not None and spec.loader is not None
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    _find_pairs(capture, cases["regex_shorthand_find_cases"], fixture.FILES)
    assert len(capture["wait"]) == len(cases["regex_shorthand_wait_cases"]) == 5
    for pair, case in zip(capture["wait"], cases["regex_shorthand_wait_cases"]):
        _same(pair["case"], case)
        bound = _clock_bound(pair["before"], pair["after"])
        native, source = _public(pair["native"]), _public(pair["source"])
        for result in (native, source):
            assert result["failed"] is False and result["changed"] is False
            elapsed = result.pop("elapsed")
            # Preserve the released float field rather than integer coercion.
            # pylint: disable-next=unidiomatic-typecheck
            assert type(elapsed) is float
            assert math.isfinite(elapsed) and 0 <= elapsed <= bound
            _same(result["wait_attempts"], 1)
        _same(native, source)
    _same(capture["cleanup"]["rc"], 0)
    _closure(capture)


def main() -> None:
    """Verify retained JSON without contacting Windows or lab infrastructure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    arguments = parser.parse_args()
    verify(json.loads(arguments.capture.read_text(encoding="utf-8")))
    print("PASS:16 typed shorthand Find pairs,5 bounded Wait pairs and literal closure")


if __name__ == "__main__":
    main()
