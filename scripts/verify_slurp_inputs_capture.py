"""Verify complete Slurp input results and literal owned-resource recovery."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from pathlib import Path
from typing import Any


def _literal(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)


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


def _recovery(document: dict[str, Any]) -> dict[str, Any]:
    observations: list[dict[str, Any]] = []
    for field in ("before", "after"):
        record = document[field]
        assert isinstance(record["rc"], int) and not isinstance(record["rc"], bool)
        assert record["rc"] == 0, field
        value = json.loads(record["stdout"])
        assert _literal(value["runtime"]["python"]) == "[3, 4, 4]", field
        assert _literal(value["runtime"]["windows_version"]) == _literal(
            document["expected_windows_version"]
        ), field
        mac = document["expected_mac"].replace(":", "-").upper()
        assert mac in value["runtime"]["mac"].upper(), field
        observations.append(value)
    before = observations[0]
    after = observations[1]
    assert after["root_absent"] is True, "owned workspace absence"
    for key in ("root", "runtime", "files"):
        assert _literal(before[key]) == _literal(after[key]), key
    return before


def verify_capture(document: dict[str, Any]) -> int:
    """Compare every public field and protected file observation.

    :param document: Unmodified paired public fixture capture.
    :returns: Number of complete normal/check results matching the source.
    :raises AssertionError: If identity, inputs, public fields or closure differ.
    """
    before = _recovery(document)
    cases = document["cases"]
    assert len(cases) == 16
    assert all(isinstance(case["check"], bool) for case in cases)
    assert all(isinstance(case["success"], bool) for case in cases)
    assert len({(case["name"], case["check"]) for case in cases}) == 16
    assert {case["check"] for case in cases} == {False, True}
    native = document["native"]["results"]
    source = document["source"]["results"]
    assert len(native) == len(source) == len(cases)
    for case, first, second in zip(cases, native, source):
        assert _literal(first["item"]) == _literal(second["item"]) == _literal(case)
        for result in (first, second):
            assert result["changed"] is False, case["name"]
            if case["success"]:
                assert result.get("failed", False) is False, case["name"]
                assert result["encoding"] == "base64", case["name"]
                expected = before["files"][case["src"].rsplit("\\", 1)[1]]["bytes"]
                assert result["content"] == expected, case["name"]
            else:
                assert result["failed"] is True, case["name"]
        assert _literal(_public(first)) == _literal(_public(second)), case["name"]
    return len(cases)


def main() -> None:
    """Validate a retained capture locally, without any Windows connection."""
    document = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    print(f"PASS: {verify_capture(document)} complete typed Slurp pairs and recovery")


if __name__ == "__main__":
    main()
