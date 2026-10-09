"""Verify four length-bearing FTP transfers and their exact owned closure."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import math
import sys
from pathlib import Path
from typing import Any

CASES = (
    "length_150_unread",
    "length_150_consumed",
    "length_125_unread",
    "length_125_consumed",
)
PAYLOAD = b"legacy download fixture\x00\xff\n"


def _literal(left: Any, right: Any) -> bool:
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


# This standalone verifier keeps its own literal result and cleanup gates.
# pylint: disable=duplicate-code
def _operation(row: dict[str, Any], side: str) -> dict[str, Any]:
    observation = row["observations"][side]
    result, before, after = (observation[key] for key in ("result", "before", "after"))
    assert result["changed"] is False and result["failed"] is False
    elapsed = result["elapsed"]
    for value in (elapsed, before["time"], after["time"]):
        assert isinstance(value, (int, float)) and not isinstance(value, bool)
        assert math.isfinite(value)
    duration = after["time"] - before["time"]
    assert math.isfinite(duration) and 0 <= elapsed <= duration
    assert elapsed < 120
    assert result["content_length"] == len(PAYLOAD)
    assert isinstance(result["content_length"], int)
    assert not isinstance(result["content_length"], bool)
    status = 125 if "125" in row["name"] else 150
    assert result["status_code"] == status
    assert result["content_type"] is None and result["headers"] == []
    if row["name"].endswith("consumed"):
        assert result["content"] == PAYLOAD.decode("utf-8", "replace")
        assert row["params"]["status_code"] == [226]
    else:
        assert "content" not in result
        assert row["params"]["status_code"] == [status]
    for field in ("sentinel", "source", "output"):
        assert _literal(before[field], after[field])
    assert after["requests"] == []
    wire = observation["wire"]["wire"]
    requests = [event for event in wire if event.get("command") == "RETR"]
    filename = f"length-{status}.bin"
    assert len(requests) == 1
    assert requests[0]["argument"] == (
        filename if side == "original" else "/" + filename
    )
    assert all(
        event["command"] in ("USER", "PASS", "OPTS", "PWD", "TYPE", "PASV", "RETR")
        for event in wire
        if event["kind"] == "command"
    )
    replies = [event["response"] for event in wire if event["kind"] == "reply"]
    assert result["status_description"] in replies
    assert result["status_description"].startswith(str(status) + " ")
    assert result["status_description"].endswith(" (26 bytes).\r\n")
    assert all(event["port"] == 2122 for event in wire if event["kind"] == "passive")
    if row["name"].endswith("consumed"):
        assert any(reply.startswith("226 ") for reply in replies)
    return {
        key: value
        for key, value in result.items()
        if key not in ("invocation", "exception", "elapsed")
    }


# pylint: enable=duplicate-code


# This standalone verifier keeps its own literal result and cleanup gates.
# pylint: disable=duplicate-code
def verify(capture: dict[str, Any]) -> dict[str, Any]:
    """Require the whole typed results, literal files, wire and owned cleanup.

    :param capture: Unmodified maintained FTP play's raw observations.
    :returns: Pair count and explicit elapsed/protocol qualifications.
    :raises AssertionError: If public, clock, file, wire or closure differs.
    """
    assert (
        "BC-24-11-3E-87-91" in json.loads(capture["identity"]["stdout"])["mac"].upper()
    )
    assert tuple(row["name"] for row in capture["results"]) == CASES
    for row in capture["results"]:
        assert row["validated"] is True
        assert set(row["observations"]) == {"native", "original"}
        assert _literal(_operation(row, "native"), _operation(row, "original"))
        native, original = (
            row["observations"][side] for side in ("native", "original")
        )
        assert type(native["result"]["elapsed"]) is type(original["result"]["elapsed"])
        assert _literal(native["wire"]["protected"], original["wire"]["protected"])
        assert _literal(native["before"]["output"], original["before"]["output"])
    for field in ("recovery", "controller_recovery"):
        restored = json.loads(capture[field]["stdout"])
        assert restored["restored"] is True and restored["server_stopped"] is True
    assert json.loads(capture["unforward"]["stdout"])["forwards_cancelled"] is True
    assert (
        json.loads(capture["guest_closed"]["stdout"])["guest_forward_ports_closed"]
        is True
    )
    assert capture["controller_absence"]["stat"]["exists"] is False
    before, after = (
        json.loads(capture[field]["stdout"])
        for field in ("staging_before", "staging_after")
    )
    assert _literal(before["staging"], after["staging"])
    assert after["workspace_absent"] is True
    return {
        "pairs": len(CASES),
        "whole_typed_public": True,
        "recovery": True,
        "qualifications": [
            "Elapsed is type-matched and bounded by recorded target-clock "
            "observations without tolerance.",
            "Raw FTP negotiation and relative/absolute resource arguments "
            "differ; not wire-byte parity.",
        ],
    }


# pylint: enable=duplicate-code


# This standalone verifier keeps its own literal result and cleanup gates.
# pylint: disable=duplicate-code
def main() -> None:
    """Read one retained capture without guest calls or resource allocation."""
    print(
        json.dumps(
            verify(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))),
            sort_keys=True,
        )
    )


# pylint: enable=duplicate-code


# This standalone verifier keeps its own literal result and cleanup gates.
# pylint: disable=duplicate-code
if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
