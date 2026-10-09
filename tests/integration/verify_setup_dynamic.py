"""Validate complete Setup results with explicit independently measured bounds."""

# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import datetime
import json
import math
import sys
from decimal import Decimal
from typing import Any

_DATE_FIELDS = {
    "date",
    "day",
    "epoch_local",
    "epoch",
    "epoch_int",
    "hour",
    "iso8601",
    "iso8601_basic",
    "iso8601_basic_short",
    "iso8601_micro",
    "minute",
    "month",
    "second",
    "time",
    "tz",
    "tz_offset",
    "weekday",
    "weekday_number",
    "weeknumber",
    "year",
}
_FACT_FIELDS = {
    "gather_subset",
    "module_setup",
    "ansible_date_time",
    "ansible_lastboot",
    "ansible_uptime_seconds",
    "ansible_memtotal_mb",
    "ansible_memfree_mb",
    "ansible_swaptotal_mb",
    "ansible_pagefiletotal_mb",
    "ansible_pagefilefree_mb",
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _literal(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False)


def _integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _date(
    value: dict[str, Any], before: dict[str, Any], after: dict[str, Any]
) -> datetime.timedelta:
    _require(set(value) == _DATE_FIELDS, "The complete date fact schema differs.")
    _require(
        all(
            isinstance(item, str) for name, item in value.items() if name != "epoch_int"
        )
        and _integer(value["epoch_int"]),
        "Date fact JSON types differ.",
    )
    utc = datetime.datetime.strptime(value["iso8601_micro"], "%Y-%m-%dT%H:%M:%S.%fZ")
    epoch = utc.replace(tzinfo=datetime.timezone.utc).timestamp()
    _require(
        before["epoch"] <= epoch <= after["epoch"],
        "Date instant is outside its observed target window.",
    )
    offset = value["tz_offset"]
    _require(
        len(offset) == 6 and offset[0] in "+-" and offset[3] == ":",
        "Invalid timezone offset.",
    )
    delta = datetime.timedelta(hours=int(offset[1:3]), minutes=int(offset[4:6]))
    if offset[0] == "-":
        delta = -delta
    local = utc + delta
    zone = next(
        row["value"]
        for row in before["configuration"]["timezone"]
        if row["name"] == "TimeZoneKeyName"
    )
    expected = {
        "date": local.strftime("%Y-%m-%d"),
        "day": local.strftime("%d"),
        "hour": local.strftime("%H"),
        "minute": local.strftime("%M"),
        "month": local.strftime("%m"),
        "second": local.strftime("%S"),
        "time": local.strftime("%H:%M:%S"),
        "year": local.strftime("%Y"),
        "iso8601": utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "iso8601_basic": local.strftime("%Y%m%dT%H%M%S%f"),
        "iso8601_basic_short": local.strftime("%Y%m%dT%H%M%S"),
        "weekday": (
            "Monday",
            "Tuesday",
            "Wednesday",
            "Thursday",
            "Friday",
            "Saturday",
            "Sunday",
        )[local.weekday()],
        "weekday_number": str((local.weekday() + 1) % 7),
        "weeknumber": local.strftime("%W"),
        "tz": zone,
        "epoch_int": round(epoch),
    }
    for name, expected_value in expected.items():
        _require(value[name] == expected_value, "Inconsistent date field: " + name)
    # PowerShell's measured general-number formatting retains five decimal
    # places at this epoch magnitude; keep the complete string and its type.
    for name, instant in (("epoch", utc), ("epoch_local", local)):
        precise = Decimal(
            str(instant.replace(tzinfo=datetime.timezone.utc).timestamp())
        )
        _require(
            abs(Decimal(value[name]) - precise) <= Decimal("0.00001"),
            "Inconsistent epoch field: " + name,
        )
    return delta


def _memory(
    facts: dict[str, Any], before: dict[str, Any], after: dict[str, Any]
) -> None:
    total = math.ceil(before["physical_total_bytes"] / 1048576)
    _require(
        before["physical_total_bytes"] == after["physical_total_bytes"],
        "Physical capacity changed during sampling.",
    )
    _require(
        _integer(facts["ansible_memtotal_mb"])
        and facts["ansible_memtotal_mb"] == total,
        "Physical total differs from the native capacity.",
    )
    free = facts["ansible_memfree_mb"]
    _require(
        _integer(free) and 0 <= free <= total,
        "Free RAM exceeds the independently observed physical capacity.",
    )
    paging_total, paging_free = (
        facts["ansible_pagefiletotal_mb"],
        facts["ansible_pagefilefree_mb"],
    )
    _require(
        (paging_total is None and paging_free is None)
        or (
            _integer(paging_total)
            and _integer(paging_free)
            and 0 <= paging_free <= paging_total
        ),
        "Paging values exceed their public capacity.",
    )


def _public(record: dict[str, Any], name: str) -> dict[str, Any]:
    result: dict[str, Any] = copy.deepcopy(record[name])
    before = json.loads(record["before_" + name]["stdout"])
    after = json.loads(record["after_" + name]["stdout"])
    _require(
        not result.get("changed", False) and not result.get("failed", False),
        name + " failed or changed state.",
    )
    for field in ("protected", "configuration"):
        _require(
            _literal(before[field]) == _literal(after[field]),
            name + " changed " + field + ".",
        )
    facts = result["ansible_facts"]
    _require(set(facts) == _FACT_FIELDS, name + " fact keys differ.")
    offset = _date(facts["ansible_date_time"], before, after)
    uptime = facts["ansible_uptime_seconds"]
    _require(
        _integer(uptime)
        and before["tick_milliseconds"] / 1000 - 0.5
        <= uptime
        <= after["tick_milliseconds"] / 1000 + 0.5,
        name + " uptime is outside its native observation window.",
    )
    boot = (
        datetime.datetime.strptime(facts["ansible_lastboot"], "%Y-%m-%d %H:%M:%SZ")
        - offset
    )
    boot_epoch = boot.replace(tzinfo=datetime.timezone.utc).timestamp()
    inferred = [
        sample["epoch"] - sample["tick_milliseconds"] / 1000
        for sample in (before, after)
    ]
    _require(
        min(inferred) - 1 <= boot_epoch <= max(inferred) + 1,
        name + " lastboot is outside its native one-second bound.",
    )
    _memory(facts, before, after)
    # Every varying value has been validated above. Retain every public key
    # in the typed comparison; raw captures keep all original values intact.
    facts["ansible_date_time"] = dict.fromkeys(_DATE_FIELDS, 0)
    facts["ansible_uptime_seconds"] = 0
    facts["ansible_lastboot"] = "bounded"
    facts["ansible_memfree_mb"] = 0
    if facts["ansible_pagefilefree_mb"] is not None:
        facts["ansible_pagefilefree_mb"] = 0
    result.pop("invocation", None)
    result.pop("exception", None)
    return result


def validate(record: dict[str, Any]) -> dict[str, object]:
    """Validate complete public results without deleting dynamic fact keys.

    :param record: Raw case with complete results and independent observations.
    :returns: Exact qualifications for the compared results.
    :raises ValueError: A field, type, observation bound or literal result differs.
    """
    native = _public(record, "native")
    if record.get("original") is not None:
        original = _public(record, "original")
        _require(
            _literal(native) == _literal(original),
            "A nonvarying public field differs from the released source.",
        )
    return {
        "date_fields": sorted(_DATE_FIELDS),
        "clock": "Each complete date instant is inside its independent target window; "
        "derived fields and types are validated.",
        "uptime": "Independent GetTickCount64 window, rounded to a second; "
        "lastboot within one inferred second.",
        "free_ram": "Integer between zero and independently measured physical capacity; "
        "not contemporaneous free-RAM equality.",
        "free_paging": "Integer between zero and literal public paging capacity, "
        "or both paging values null.",
        "other_public_fields": "Literal typed JSON equality; "
        "only invocation and exception metadata excluded.",
    }


def main() -> None:
    """Validate the final dynamic case from a private raw capture.

    :raises ValueError: The capture or observed public behavior is inconsistent.
    :raises OSError: The capture cannot be read.
    """
    with open(sys.argv[1], encoding="utf-8") as stream:
        capture = json.load(stream)
    print(json.dumps(validate(capture["results"][-1]), sort_keys=True))


if __name__ == "__main__":
    main()
