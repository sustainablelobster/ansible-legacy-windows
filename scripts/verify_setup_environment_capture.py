"""Compare complete Setup results with independently witnessed SSH identities."""

# SPDX-License-Identifier: GPL-3.0-or-later
# The retained dynamic validator's private primitives preserve its existing bounds.
# pylint: disable=protected-access

import copy
import datetime
import json
import re
import sys
from pathlib import Path
from typing import Any

# Direct developer CLI invocation sets sys.path to scripts/, not the repository.
# Resolve the existing validator beside this script, independent of caller cwd.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
# pylint: disable-next=wrong-import-position
from tests.integration import verify_setup_dynamic as dynamic


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False)


def _bitvise(facts: dict[str, Any], witnesses: list[dict[str, Any]]) -> dict[str, Any]:
    environment = facts["ansible_env"]
    keys = [key for key in environment if key.lower() == "bitvisesfsdll"]
    _require(
        len(keys) == 1, "The complete Bitvise public field is missing or duplicated."
    )
    key = keys[0]
    token = environment[key]
    _require(
        isinstance(token, str)
        and re.fullmatch(r"[0-9A-F]{8}(?:-[0-9A-F]{8}){3}", token) is not None,
        "The opaque Bitvise token is not the measured native identity format.",
    )
    matching = [
        row
        for row in witnesses
        if row["token"] == token
        and _json(
            {name: value.rstrip("\\") for name, value in row["environment"].items()}
        )
        == _json(environment)
    ]
    _require(
        bool(matching),
        "No independently read complete environment matches the public token.",
    )
    owner = int(token[:8], 16)
    for row in matching:
        _require(
            dynamic._integer(row["created"]) and row["created"] > 0,
            "A matching environment witness has no native birth identity.",
        )
        chain = row["ancestry"]
        _require(
            chain[0]["pid"] == row["pid"]
            and chain[0]["parent_pid"] == row["parent_pid"],
            "The independently enumerated process identity differs.",
        )
        for child, parent in zip(chain, chain[1:]):
            _require(
                child["parent_pid"] == parent["pid"],
                "The literal ancestry chain is broken.",
            )
        owners = [
            item
            for item in chain
            if item["pid"] == owner and item["name"].lower() == "execs.exe"
        ]
        _require(
            len(owners) == 1,
            "The full token does not belong to its actual SSH ancestor.",
        )
        position = chain.index(owners[0])
        _require(
            position + 1 < len(chain)
            and chain[position + 1]["name"].lower() == "bvsshserver.exe",
            "The token's measured owner is not parented by the SSH server.",
        )
    exited = [row for row in matching if row.get("natural_exit") is True]
    _require(
        bool(exited), "No complete matching process was independently observed closed."
    )
    environment[key] = "<independently read whole per-SSH-exec token>"
    return {"token": token, "pid": exited[0]["pid"], "created": exited[0]["created"]}


def _bounded(
    facts: dict[str, Any], before: dict[str, Any], after: dict[str, Any]
) -> None:
    offset = dynamic._date(facts["ansible_date_time"], before, after)
    uptime = facts["ansible_uptime_seconds"]
    # This standalone verifier keeps its own literal result and cleanup gates.
    # pylint: disable=duplicate-code
    _require(
        dynamic._integer(uptime)
        and before["tick_milliseconds"] / 1000 - 0.5
        <= uptime
        <= after["tick_milliseconds"] / 1000 + 0.5,
        "Uptime is outside the independent native window.",
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
        "Lastboot exceeds the independently inferred one-second bound.",
    )
    # pylint: enable=duplicate-code
    dynamic._memory(facts, before, after)
    facts["ansible_date_time"] = {
        key: 0 if key == "epoch_int" else "<bounded>"
        for key in facts["ansible_date_time"]
    }
    facts["ansible_uptime_seconds"] = 0
    facts["ansible_lastboot"] = "<bounded>"
    facts["ansible_memfree_mb"] = 0
    if facts["ansible_pagefilefree_mb"] is not None:
        facts["ansible_pagefilefree_mb"] = 0


# The complete proof keeps result, independent bounds and recovery visible together.
def validate(
    capture: dict[str, Any], closure: dict[str, Any]
) -> dict[str, Any]:  # pylint: disable=too-many-locals
    """Validate every public key/type plus literal protection and process closure.

    :param capture: Untouched native/source public results and live observations.
    :param closure: Separate post-recovery workspace/staging observation.
    :returns: Qualified identities and compared case count.
    :raises ValueError: A result, bound, identity, protection or closure differs.
    """
    # The complete proof keeps independent bounds and recovery visible together.
    # pylint: disable=too-many-locals
    observations = {
        name: json.loads(capture[name]["stdout"])
        for name in ("preparation", "before_native", "between", "after_original")
    }
    recovery = json.loads(capture["recovery"]["stdout"])
    observations["recovery"] = recovery["observation"]
    for sample in observations.values():
        for field in ("configuration", "protected"):
            _require(
                _json(sample[field]) == _json(observations["preparation"][field]),
                "The literal protected " + field + " changed.",
            )
    witness = recovery["witness"]
    _require(
        recovery["restored"] is True and witness["failure"] is None,
        "The independent witness or owned recovery failed.",
    )
    _require(
        witness["identity"]["calibrated"] is True
        and witness["identity"]["closed"] is True,
        "The independent witness calibration or native process closure failed.",
    )
    _require(
        witness["python"].startswith("3.4.4 "),
        "The witness did not run on Python 3.4.4.",
    )
    completed = capture["completed"]
    _require(
        completed["finished"] is True
        and not completed.get("failed", False)
        and completed["rc"] == 0
        and json.loads(completed["stdout"])["witness_stopped"] is True,
        "The owned observer did not actually finish successfully.",
    )
    _require(
        completed["ansible_job_id"] == capture["launch"]["ansible_job_id"]
        and capture["cache_removed"]["erased"] == capture["launch"]["results_file"],
        "The completed owned observer cache differs from its launch.",
    )
    _require(
        closure["workspace_absent"] is True
        and json.loads(closure["staging_before"]["stdout"])
        == json.loads(closure["staging_after"]["stdout"])
        == json.loads(capture["staging_before"]["stdout"]),
        "Owned workspace or global staging remains.",
    )
    native, original = capture["native"]["results"], capture["original"]["results"]
    _require(
        len(native) == len(original) == 4,
        "Four complete public pairs were not retained.",
    )
    identities = []
    for index, (left, right) in enumerate(zip(native, original)):
        pair = []
        for result, before, after in (
            (left, observations["before_native"], observations["between"]),
            (right, observations["between"], observations["after_original"]),
        ):
            public = copy.deepcopy(result)
            _require(
                public.get("changed") is False and not public.get("failed", False),
                "A public Setup request failed or changed state.",
            )
            facts = public["ansible_facts"]
            item = public["item"]
            expected_subsets = ["all"] if index < 2 else ["!all", "!min", "env"]
            _require(
                item["subsets"] == facts["gather_subset"] == expected_subsets
                and item["check"] is bool(index % 2)
                and facts["module_setup"] is True,
                "The completed public request is not the intended normal/check subset.",
            )
            _require(
                (item["environment"] == {}) is (index < 2),
                "A default request had a task environment or an override request lacked it.",
            )
            identities.append(_bitvise(facts, witness["witnesses"]))
            if index < 2:
                _bounded(facts, before, after)
            for metadata in ("invocation", "exception"):
                public.pop(metadata, None)
            pair.append(public)
        _require(
            _json(pair[0]) == _json(pair[1]),
            "A complete typed public result differs in case " + str(index) + ".",
        )
    return {
        "pairs": 4,
        "bitvise_identities": identities,
        "dynamic_bounds": "Validated complete date schema, independent clocks/uptime "
        "and public memory capacity.",
        "other_fields": "Every remaining public key and JSON type/array order compares literally.",
    }


def main() -> None:
    """Validate a retained complete capture and its separate closure record.

    :raises OSError: An evidence file cannot be read.
    :raises ValueError: Its public comparison or recovery fails.
    """
    capture = Path(sys.argv[1])
    with capture.open(encoding="utf-8") as stream:
        record = json.load(stream)
    with Path(str(capture) + ".closure.json").open(encoding="utf-8") as stream:
        closure = json.load(stream)
    print(json.dumps(validate(record, closure), sort_keys=True))


if __name__ == "__main__":
    main()
