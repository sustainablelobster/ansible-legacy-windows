"""Validate complete FTP URI evidence without contacting a Windows host."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from pathlib import Path
from typing import Any

CASES = (
    "preliminary_response",
    "completed_download",
    "unaccepted_final_status",
    "destination_download",
    "repeated_destination",
    "check_destination",
    "preliminary_125",
    "file_timestamp",
    "working_directory",
)


def _literal(left: Any, right: Any) -> bool:
    return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)


def _operation(
    row: dict[str, Any], name: str, observed: dict[str, Any]
) -> dict[str, Any]:
    result = observed["result"]
    assert result["changed"] is row["case"].get("changed", False)
    assert result["failed"] is row["case"].get("failed", False)
    assert isinstance(result["elapsed"], (int, float))
    assert not isinstance(result["elapsed"], bool)
    assert 0 <= result["elapsed"] < 120
    if result["failed"]:
        assert isinstance(result["elapsed"], int) and result["elapsed"] == 0
    public = {
        key: value
        for key, value in result.items()
        if key not in ("invocation", "exception", "elapsed")
    }
    before, after = observed["before"], observed["after"]
    assert _literal(before["sentinel"], after["sentinel"])
    assert _literal(before["source"], after["source"])
    assert after["requests"] == []
    if not result["changed"] or row["case"].get("check", False):
        assert _literal(before["output"], after["output"])
    else:
        assert after["modified_in_request"] is True
    wire = observed["wire"]["wire"]
    commands = [event for event in wire if event["kind"] == "command"]
    method = row["params"]["url_method"]
    wanted = (
        "preliminary-125.bin" if row["name"] == "preliminary_125" else "payload.bin"
    )
    requests = [event for event in commands if event["command"] == method]
    # Source includes a login PWD; the explicit PWD request is the last.
    if method == "PWD":
        assert requests[-1]["argument"] == ""
    else:
        assert len(requests) == 1
        assert requests[0]["argument"] == (
            wanted if name == "original" else "/" + wanted
        )
    assert all(
        event["command"]
        in ("USER", "PASS", "OPTS", "PWD", "TYPE", "PASV", "RETR", "MDTM")
        for event in commands
    )
    replies = [event["response"] for event in wire if event["kind"] == "reply"]
    assert result["banner_message"] in replies
    assert result["welcome_message"] in replies
    assert result["status_description"] in replies
    assert all(
        event["response"].endswith("\r\n") for event in wire if event["kind"] == "reply"
    )
    assert all(event["port"] == 2122 for event in wire if event["kind"] == "passive")
    return public


def verify(capture: dict[str, Any]) -> dict[str, Any]:
    """Require complete public results, protected material and owned recovery.

    :param capture: Maintained fixture's raw evidence document.
    :returns: Counts and the explicitly bounded comparison qualifications.
    :raises AssertionError: If any public, file, wire or recovery gate fails.
    """
    identity = json.loads(capture["identity"]["stdout"])
    assert "BC-24-11-3E-87-91" in identity["mac"].upper()
    rows = capture["results"]
    assert tuple(row["name"] for row in rows) == CASES
    for row in rows:
        operations = row["observations"]
        assert set(operations) == {"native", "original"}
        public = {
            name: _operation(row, name, observed)
            for name, observed in operations.items()
        }
        assert _literal(public["native"], public["original"])
        assert type(operations["native"]["result"]["elapsed"]) is type(
            operations["original"]["result"]["elapsed"]
        )
        assert _literal(
            operations["native"]["before"]["output"],
            operations["original"]["before"]["output"],
        )
        assert _literal(
            operations["native"]["after"]["portable_output"],
            operations["original"]["after"]["portable_output"],
        )
        assert _literal(
            operations["native"]["wire"]["protected"],
            operations["original"]["wire"]["protected"],
        )
    target = json.loads(capture["recovery"]["stdout"])
    controller = json.loads(capture["controller_recovery"]["stdout"])
    assert target["restored"] is True and target["server_stopped"] is True
    assert controller["restored"] is True and controller["server_stopped"] is True
    assert json.loads(capture["unforward"]["stdout"])["forwards_cancelled"] is True
    assert (
        json.loads(capture["guest_closed"]["stdout"])["guest_forward_ports_closed"]
        is True
    )
    assert capture["controller_absence"]["stat"]["exists"] is False
    before_staging = json.loads(capture["staging_before"]["stdout"])
    after_staging = json.loads(capture["staging_after"]["stdout"])
    assert after_staging["workspace_absent"] is True
    assert _literal(before_staging["staging"], after_staging["staging"])
    return {
        "pairs": len(rows),
        "whole_typed_public": True,
        "recovery": True,
        "qualifications": [
            (
                "Elapsed is independently sampled, type-matched and bounded; "
                "failure is exact integer zero."
            ),
            (
                "FTP initialization commands and relative/absolute owned filenames "
                "differ; all raw wire is retained, not declared byte-equal."
            ),
            (
                "New output mtimes are individually operation-bounded; protected "
                "bytes, attributes and mtimes remain literal."
            ),
        ],
    }


if __name__ == "__main__":
    print(
        json.dumps(
            verify(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))),
            sort_keys=True,
        )
    )
