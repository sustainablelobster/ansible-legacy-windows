"""Verify one actual noninstalling WUA search without discarding public fields."""

# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import base64
import hashlib
import json
import math
import re
import uuid
from pathlib import Path
from typing import Any

# Exact JSON types distinguish target counters/PIDs from Booleans throughout.
# pylint: disable=unidiomatic-typecheck
INPUTS = {
    "state": "searched",
    "server_selection": "windows_update",
    "category_names": ["*"],
    "reject_list": [".*"],
}


def _same(left: Any, right: Any) -> None:
    # JSON preserves Boolean/integer/float distinctions and list order; sorting
    # object keys changes no public value. Nonfinite numeric evidence is invalid.
    assert json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(
        right, sort_keys=True, allow_nan=False
    )


def _observed(record: dict[str, Any], name: str) -> Any:
    row = record[name]
    assert row["rc"] == 0 and type(row["rc"]) is int
    return json.loads(row["stdout"])


def _public(result: dict[str, Any]) -> dict[str, Any]:
    assert result.get("failed", False) is False
    assert result.get("unreachable", False) is False
    assert result["changed"] is result["rebooted"] is False
    assert type(result["reboot_required"]) is bool
    for name in ("found_update_count", "installed_update_count", "failed_update_count"):
        assert type(result[name]) is int and result[name] == 0
    assert result["updates"] == {}
    assert type(result["filtered_updates"]) is dict
    for identifier, row in result["filtered_updates"].items():
        assert str(uuid.UUID(identifier)) == identifier and row["id"] == identifier
        assert set(row) == {
            "id",
            "title",
            "categories",
            "kb",
            "downloaded",
            "installed",
            "filtered_reasons",
        }
        assert type(row["title"]) is str and row["title"]
        assert type(row["downloaded"]) is bool and row["installed"] is False
        for name in ("categories", "kb", "filtered_reasons"):
            assert type(row[name]) is list
            assert all(type(value) is str for value in row[name])
        assert "reject_list" in row["filtered_reasons"]
    # Only Ansible invocation/traceback and its private no_log wrapper are not
    # module public output. Every other field, including warnings, stays literal.
    return {
        name: value
        for name, value in result.items()
        if name not in ("invocation", "exception", "_ansible_no_log")
    }


def _catalogue(row: dict[str, Any]) -> dict[str, dict[str, Any]]:
    assert row["python"] == [3, 4, 4]
    assert row["criteria"] == "IsInstalled = 0"
    assert row["online"] is False and type(row["server_selection"]) is int
    assert row["server_selection"] == 2
    assert type(row["result_code"]) is int and row["result_code"] in (2, 3)
    assert type(row["elapsed"]) is float and math.isfinite(row["elapsed"])
    assert 0 <= row["elapsed"] <= 180
    assert type(row["updates"]) is list
    result = {}
    for update in row["updates"]:
        assert set(update) == {
            "id",
            "revision",
            "title",
            "eula_accepted",
            "downloaded",
            "installed",
        }
        assert str(uuid.UUID(update["id"])) == update["id"]
        assert update["id"] not in result
        assert type(update["revision"]) is int and update["revision"] >= 0
        assert type(update["title"]) is str and update["title"]
        assert type(update["eula_accepted"]) is bool
        assert type(update["downloaded"]) is bool and update["installed"] is False
        result[update["id"]] = update
    return result


def _closed(expected: dict[str, Any], actual: Any) -> None:
    assert type(expected["pid"]) is int and expected["pid"] > 0
    assert type(expected["created"]) is int and expected["created"] > 0
    assert expected["alive"] is True
    if actual is not None:
        assert actual["pid"] == expected["pid"]
        assert type(actual["created"]) is int and actual["created"] > 0
        assert type(actual["alive"]) is bool
        assert actual["created"] != expected["created"] or actual["alive"] is False


def _logs(record: dict[str, Any], count: int) -> None:
    diagnostics = _observed(record, "diagnostics")
    _same(diagnostics["workspace"], record["workspace"]["path"])
    _same(diagnostics["protected"], _observed(record, "protected"))
    protected = diagnostics["protected"]
    assert set(protected) == {"sha256", "attributes", "mtime_ns", "security"}
    assert re.fullmatch(r"[0-9a-f]{64}", protected["sha256"])
    assert type(protected["attributes"]) is int
    assert type(protected["mtime_ns"]) is int and protected["mtime_ns"] > 0
    assert base64.b64decode(protected["security"], validate=True)
    for name in ("native.log", "original.log"):
        log = diagnostics["logs"][name]
        text = base64.b64decode(log["body_base64"], validate=True).decode("utf-8-sig")
        _same(text, log["text"])
        assert "Searching for updates to install with query 'IsInstalled = 0'" in text
        assert re.findall(r"Found ([0-9]+) updates", text) == [str(count)]
        assert "Accepting EULA" not in text
        assert "Downloading updates" not in text and "Installing updates" not in text


def _backends(record: dict[str, Any]) -> int:
    monitor = _observed(record, "monitor")
    assert [row["Sid"] for row in monitor["owners"]] == ["S-1-5-18"] * 2
    stopped = _observed(record, "monitor_closed")
    _same(monitor["identity"], stopped["monitor_identity"])
    _closed(stopped["monitor_identity"], stopped["monitor_final"])
    records, closed = stopped["records"], stopped["backends_closed"]
    assert len(records) == len(closed) and len(records) >= 2
    assert {row["side"] for row in records} == {"native", "original"}
    births: set[tuple[int, int]] = set()
    for row, closure in zip(records, closed):
        assert type(row["time"]) is float and math.isfinite(row["time"])
        assert type(row["sid"]) is str and row["sid"].startswith("S-1-")
        _same(row["identity"], closure["expected"])
        _closed(closure["expected"], closure["actual"])
        birth = (row["identity"]["pid"], row["identity"]["created"])
        # A side label cannot turn the same observed worker into another birth.
        assert birth not in births
        births.add(birth)
    return len(births)


def _retained_baseline(record: dict[str, Any]) -> None:
    origin = record["cache_before_origin"]
    assert (
        origin["boundary"] == "completed rollback recovery before this attempt snapshot"
    )
    body = Path(origin["path"]).read_bytes()
    assert hashlib.sha256(body).hexdigest() == origin["sha256"]
    retained = json.loads(body)
    assert retained["mode"] == "observe"
    assert retained["absence"]["stat"]["exists"] is False
    _same(record["cache_before"], retained["cache_before"])
    _observed(retained, "cache_before")
    before = _observed(record, "before")["protected"]
    after = _observed(retained, "after")["protected"]
    for field in (
        "registry",
        "python_executable",
        "network",
        "updates_policy",
        "updates_au_policy",
    ):
        _same(before[field], after[field])
    for protected in (before, after):
        services = {row["Name"]: row for row in protected["services"]}
        assert all(
            services[name]["State"] == "Stopped"
            for name in ("wuauserv", "BITS", "TrustedInstaller")
        )


def verify_capture(path: Path) -> dict[str, Any]:
    """Require successful whole public results and actual provider completion.

    :param path: Immutable raw capture from the maintained search fixture.
    :returns: One literal public pair, with byte recovery required separately.
    :raises AssertionError: Provider, public, process or resource evidence is invalid.
    :raises ValueError: Invalid JSON, Base64, UUID or nonfinite numeric evidence.
    """
    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["mode"] == "paired"
    _same(record["inputs"], INPUTS)
    native, original = _public(record["native"]), _public(record["original"])
    _same(native, original)
    before = _catalogue(_observed(record, "catalogue_before"))
    after = _catalogue(_observed(record, "catalogue_after"))
    # An online search may refresh the real catalogue. Preserve newly discovered
    # rows literally; existing EULA/download/install flags must remain unchanged.
    for identifier in before.keys() & after.keys():
        for field in ("eula_accepted", "downloaded", "installed"):
            _same(before[identifier][field], after[identifier][field])
    count = len(native["filtered_updates"])
    _logs(record, count)
    births = _backends(record)
    _same(_observed(record, "global_before"), _observed(record, "global_after"))
    # This is the historical completed rollback journal, not a new per-call
    # scan. The driver still requires one whole-byte comparison after rollback.
    _retained_baseline(record)
    return {
        "whole_typed_public_pairs": 1,
        "actual_backend_births_closed": births,
        "provider_catalogue_rows": count,
        "cache_recovery_required_separately": True,
    }


# pylint: enable=unidiomatic-typecheck


def main() -> None:
    """Verify a retained capture without contacting a Windows host."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    print(json.dumps(verify_capture(parser.parse_args().capture), sort_keys=True))


if __name__ == "__main__":
    main()
