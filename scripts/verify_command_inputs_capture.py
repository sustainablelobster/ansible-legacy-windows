"""Verify actual command input failures and unchanged runtime/staging observations."""

# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import json
from pathlib import Path
from typing import Any


# This standalone verifier keeps its own literal result and cleanup gates.
# pylint: disable=duplicate-code
def _literal(value: Any) -> str:
    # JSON distinguishes False from 0 and keeps array order; object order is irrelevant.
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)


# pylint: enable=duplicate-code


# This standalone verifier keeps its own literal result and cleanup gates.
# pylint: disable=duplicate-code
def _public(result: dict[str, Any]) -> dict[str, Any]:
    metadata = {
        "invocation",
        "exception",
        "item",
        "ansible_loop_var",
        "_ansible_no_log",
        "_ansible_item_label",
    }
    return {key: value for key, value in result.items() if key not in metadata}


# pylint: enable=duplicate-code


# This standalone verifier keeps its own literal result and cleanup gates.
# pylint: disable=duplicate-code
def _runtime(document: dict[str, Any]) -> None:
    observations = []
    for field in ("before", "after"):
        record = document[field]
        return_code = record["rc"]
        assert isinstance(return_code, int) and not isinstance(return_code, bool), field
        assert return_code == 0, field
        value = json.loads(record["stdout"])
        assert _literal(value["python"]) == "[3, 4, 4]", field
        assert _literal(value["windows_version"]) == _literal(
            document["expected_windows_version"]
        ), field
        assert isinstance(value["mac"], str) and value["mac"].strip(), field
        assert isinstance(value["staging"], list), field
        observations.append(value)
    assert _literal(observations[0]) == _literal(observations[1]), "runtime/staging"


# pylint: enable=duplicate-code


def verify_capture(
    document: dict[str, Any], reference: dict[str, Any] | None = None
) -> int:
    """Verify twelve complete input failures against actual released execution.

    :param document: Unmodified paired or native-only public fixture capture.
    :param reference: Paired modern capture required for native-only legacy runs.
    :returns: Number of complete, literally matching public failure results.
    :raises AssertionError: If input, runtime, result or recovery evidence differs.
    """
    assert document["mode"] in ("paired", "native")
    _runtime(document)
    cases = document["cases"]
    assert len(cases) == 12 and len({case["name"] for case in cases}) == 12
    if document["mode"] == "paired":
        assert reference is None, "paired captures do not need another reference"
        source_document = document
    else:
        assert reference is not None and reference["mode"] == "paired"
        verify_capture(reference)
        assert _literal(cases) == _literal(reference["cases"]), "reference inputs"
        source_document = reference
    native = document["native"]["results"]
    source = source_document["source"]["results"]
    assert len(native) == len(source) == len(cases)
    for case, first, second in zip(cases, native, source):
        assert _literal(first["item"]) == _literal(second["item"]) == _literal(case)
        for result in (first, second):
            assert result["changed"] is False and result["failed"] is True, case["name"]
            assert result.get("cmd") != "System.Collections.Hashtable", case["name"]
        assert _literal(_public(first)) == _literal(_public(second)), case["name"]
    return len(cases)


def main() -> None:
    """Verify a retained capture locally without connecting to Windows."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--reference", type=Path)
    args = parser.parse_args()
    document = json.loads(args.capture.read_text(encoding="utf-8"))
    reference = (
        json.loads(args.reference.read_text(encoding="utf-8"))
        if args.reference
        else None
    )
    count = verify_capture(document, reference)
    print(f"PASS: {count} literal typed input failures and runtime/staging recovery")


if __name__ == "__main__":
    main()
