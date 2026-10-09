"""Verify five complete FTP rejection responses and exact owned closure offline."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import math
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

CASES = (
    "size_rejected",
    "size_accepted_error",
    "missing_rejected",
    "missing_accepted_error",
    "login_rejected",
)


def _literal(left: Any, right: Any) -> bool:
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


def _require_elapsed(
    result: dict[str, Any], before: dict[str, Any], after: dict[str, Any]
) -> None:
    elapsed = result["elapsed"]
    for value in (elapsed, before["time"], after["time"]):
        assert isinstance(value, (int, float)) and not isinstance(value, bool)
        assert math.isfinite(value)
    duration = after["time"] - before["time"]
    assert math.isfinite(duration)
    assert 0 <= elapsed < 120
    # Target-clock observations bracket the entire request; no tolerance is needed.
    assert elapsed <= duration
    if result["failed"]:
        assert isinstance(elapsed, int) and elapsed == 0


def _operation(row: dict[str, Any], side: str) -> dict[str, Any]:
    observed = row["observations"][side]
    result = observed["result"]
    assert result["changed"] is False
    assert result["failed"] is row["case"].get("failed", False)
    before, after = observed["before"], observed["after"]
    _require_elapsed(result, before, after)
    for field in ("sentinel", "source", "output"):
        assert _literal(before[field], after[field]), (row["name"], side, field)
    assert after["requests"] == []
    commands = [
        event for event in observed["wire"]["wire"] if event["kind"] == "command"
    ]
    assert all(
        event["command"]
        in ("USER", "PASS", "OPTS", "PWD", "TYPE", "PASV", "SIZE", "RETR")
        for event in commands
    )
    requests = [
        event for event in commands if event["command"] == row["params"]["url_method"]
    ]
    if row["name"] == "login_rejected":
        assert requests == []
        assert not any(event["command"] == "TYPE" for event in commands)
    else:
        filename = urlsplit(row["params"]["url"]).path
        assert len(requests) == 1
        assert requests[0]["argument"] == (
            filename.lstrip("/") if side == "original" else filename
        )
        if row["params"]["url_method"] == "SIZE":
            assert not any(event["command"] == "TYPE" for event in commands)
    replies = [
        event["response"]
        for event in observed["wire"]["wire"]
        if event["kind"] == "reply"
    ]
    assert result["banner_message"] in replies
    assert result["status_description"] in replies
    if result["welcome_message"]:
        assert result["welcome_message"] in replies
    assert result["status_code"] == (530 if row["name"] == "login_rejected" else 550)
    assert result["content_length"] == 0 and not isinstance(
        result["content_length"], bool
    )
    assert result["content_type"] is None and result["headers"] == []
    assert result["content"] == ""
    return {
        key: value
        for key, value in result.items()
        if key not in ("invocation", "exception", "elapsed")
    }


def verify(capture: dict[str, Any]) -> dict[str, Any]:
    """Require whole typed public pairs, actual protocol and owned cleanup.

    :param capture: Unmodified maintained play's complete raw observations.
    :returns: Pair count and explicit scope of equality qualifications.
    :raises AssertionError: If a public, wire, file, identity or closure gate fails.
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
            row["observations"]["native"],
            row["observations"]["original"],
        )
        assert type(native["result"]["elapsed"]) is type(original["result"]["elapsed"])
        assert _literal(native["before"]["output"], original["before"]["output"])
        assert _literal(native["wire"]["protected"], original["wire"]["protected"])
    for field in ("recovery", "controller_recovery"):
        restored = json.loads(capture[field]["stdout"])
        assert restored["restored"] is True and restored["server_stopped"] is True
    # This standalone verifier keeps its own literal result and cleanup gates.
    # pylint: disable=duplicate-code
    assert json.loads(capture["unforward"]["stdout"])["forwards_cancelled"] is True
    assert (
        json.loads(capture["guest_closed"]["stdout"])["guest_forward_ports_closed"]
        is True
    )
    assert capture["controller_absence"]["stat"]["exists"] is False
    # pylint: enable=duplicate-code
    before = json.loads(capture["staging_before"]["stdout"])
    after = json.loads(capture["staging_after"]["stdout"])
    assert after["workspace_absent"] is True
    assert _literal(before["staging"], after["staging"])
    return {
        "pairs": len(CASES),
        "whole_typed_public": True,
        "recovery": True,
        "qualifications": [
            "Only invocation/exception diagnostics and independently bounded elapsed differ.",
            (
                "Raw login negotiation and relative/absolute resource arguments "
                "are retained, not byte-equal."
            ),
        ],
    }


def main() -> None:
    """Inspect one retained capture without starting any server or guest call."""
    print(
        json.dumps(
            verify(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
