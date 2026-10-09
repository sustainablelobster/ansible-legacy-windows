"""Verify complete paired HTTP timeout observations and exact owned recovery."""

# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import json
import math
from pathlib import Path
from typing import Any


def _literal_json(value: Any) -> str:
    # JSON object keys are unordered, but array order and boolean/integer/float
    # distinctions are observable; Python equality alone treats False as 0.
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False)


def _observation(record: dict[str, Any], field: str) -> dict[str, Any]:
    value = record[field]
    assert value["rc"] == 0, (record["name"], field, value)
    observed = json.loads(value["stdout"])
    assert isinstance(observed, dict), (record["name"], field)
    return observed


def _public(record: dict[str, Any]) -> dict[str, Any]:
    result = dict(record["result"])
    # These are controller invocation/traceback wrappers, not module fields.
    result.pop("invocation", None)
    result.pop("exception", None)
    if "elapsed" in result:
        elapsed = result.pop("elapsed")
        assert isinstance(elapsed, float) and math.isfinite(elapsed) and elapsed >= 0
        before, after = _observation(record, "before"), _observation(record, "after")
        assert elapsed <= after["time"] - before["time"], record["name"]
    return result


def _files(record: dict[str, Any]) -> dict[str, Any]:
    before, after = _observation(record, "before"), _observation(record, "after")
    for name in ("sentinel", "source"):
        assert before[name] == after[name], (record["name"], name)
    output: dict[str, Any] = after["output"]
    if record["result"].get("changed") and not record["check"]:
        assert record["module"] == "get_url", record["name"]
        output = json.loads(json.dumps(output))
        for name, entry in output["children"].items():
            assert name == "result.bin", (record["name"], name)
            clock = entry.pop("mtime")
            assert isinstance(clock, float) and math.isfinite(clock)
            assert before["time"] <= clock <= after["time"], record["name"]
    else:
        assert output == before["output"], record["name"]
    return output


def verify_capture(document: dict[str, Any]) -> int:
    """Compare all public fields and literal requests, bounding only call clocks.

    :param document: Complete paired capture with original protected journal.
    :returns: Number of complete, verified native/released pairs.
    :raises AssertionError: If public/wire fields, clocks or recovery differ.
    """
    assert document["mode"] == "paired"
    cases, results = document["cases"], document["results"]
    assert len(results) == len(cases) * 2
    assert len({case["name"] for case in cases}) == len(cases)
    for index, case in enumerate(cases):
        native, source = results[index * 2 : index * 2 + 2]
        assert native["name"] == source["name"] == case["name"]
        assert native["side"] == "native" and source["side"] == "original"
        for name in ("module", "params", "check"):
            assert native[name] == source[name], (case["name"], name)
        assert ("elapsed" in native["result"]) == ("elapsed" in source["result"]), case[
            "name"
        ]
        assert _literal_json(_public(native)) == _literal_json(_public(source)), (
            case["name"],
            "public",
            _public(native),
            _public(source),
        )
        assert _literal_json(_files(native)) == _literal_json(_files(source)), (
            case["name"],
            "files",
        )
        assert _literal_json(
            _observation(native, "after")["requests"]
        ) == _literal_json(_observation(source, "after")["requests"]), (
            case["name"],
            "wire",
            _observation(native, "after")["requests"],
            _observation(source, "after")["requests"],
        )
    setup = json.loads(document["setup"]["stdout"])
    recovery = document["recovery"]
    assert recovery["rc"] == 0
    recovered = json.loads(recovery["stdout"])
    assert recovered["restored"] is True and recovered["server_stopped"] is True
    assert recovered["before"]["process"] == setup["before"]["process"]
    assert setup["server"]["pid"] == setup["before"]["process"]["pid"]
    assert setup["server"]["creation"] == setup["before"]["process"]["creation"]
    for name in ("source", "sentinel"):
        assert recovered[name] == setup["before"][name]
    assert document["workspace_absent"] is True
    for field in ("staging_before", "staging_after"):
        assert document[field]["rc"] == 0
    assert json.loads(document["staging_before"]["stdout"]) == json.loads(
        document["staging_after"]["stdout"]
    )
    return len(cases)


def main() -> None:
    """Validate one retained capture without contacting a Windows system."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    arguments = parser.parse_args()
    count = verify_capture(json.loads(arguments.capture.read_text(encoding="utf-8")))
    print(f"PASS: {count} complete timeout pairs, literal wire and owned recovery")


if __name__ == "__main__":
    main()
