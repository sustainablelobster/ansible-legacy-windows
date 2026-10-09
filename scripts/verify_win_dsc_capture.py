"""Compare classic DSC results while independently bounding measured clocks."""

# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

# Only these released File-resource/LCM messages contain measured elapsed times.
# Retain their complete wording and spacing; replace only the numeric duration.
_DURATION = re.compile(
    r"^(?:\[[^\]\r\n]+\]: LCM:  \[ End    (?:Test     |Set      )\]  "
    r"(?:\[\[File\]DirectResourceAccess\] (?:False |True )?)? *in +"
    r"|Time taken for configuration job to complete is )"
    r"(?P<seconds>[0-9]+\.[0-9]+) seconds\.?$"
)


def _window(record: dict[str, Any], phase: str) -> float:
    start = datetime.strptime(record[f"before_{phase}"]["end"], "%Y-%m-%d %H:%M:%S.%f")
    end = datetime.strptime(record[f"after_{phase}"]["start"], "%Y-%m-%d %H:%M:%S.%f")
    seconds = (end - start).total_seconds()
    assert seconds > 0, (phase, start, end)
    return seconds


def _public(record: dict[str, Any], phase: str) -> tuple[dict[str, Any], int]:
    result = {
        key: value
        for key, value in record[phase].items()
        if key not in {"invocation", "exception"}
    }
    clocks = 0
    for field in ("verbose_test", "verbose_set"):
        if field not in result:
            continue
        stream = result[field]
        assert isinstance(stream, list), (phase, field, stream)
        checked = []
        for line in stream:
            assert isinstance(line, str), (phase, field, line)
            match = _DURATION.fullmatch(line)
            if match:
                assert 0 <= float(match["seconds"]) <= _window(record, phase), (
                    phase,
                    field,
                    line,
                )
                start, end = match.span("seconds")
                checked.append(line[:start] + "<elapsed>" + line[end:])
                clocks += 1
            else:
                # Unexpected duration wording must not acquire a broad exemption.
                assert not line.startswith("Time taken for configuration job"), line
                assert not (": LCM:  [ End" in line and "seconds" in line), line
                checked.append(line)
        result[field] = checked
    return result, clocks


def compare_record(record: dict[str, Any]) -> int:
    """Compare every public field, qualifying only the measured DSC clocks.

    :param record: Raw native/source result and surrounding target observations.
    :returns: Number of independently bounded duration values across both calls.
    :raises AssertionError: A public field differs or a duration exceeds its call.
    """
    native, native_clocks = _public(record, "native")
    original, original_clocks = _public(record, "original")
    # Each verifier keeps literal JSON equality next to its own clock exception.
    # A shared normalization layer would hide the evidence contract being checked.
    # pylint: disable=duplicate-code
    assert json.dumps(native, sort_keys=True) == json.dumps(original, sort_keys=True), (
        record["name"],
        native,
        original,
    )
    assert native_clocks == original_clocks
    return native_clocks + original_clocks


def verify_capture(path: Path, last_only: bool = False) -> dict[str, int]:
    """Verify paired records in a retained capture without changing raw evidence.

    :param path: UTF-8 JSON capture written by the maintained classic DSC fixture.
    :param last_only: Verify the last just-captured pair before marking it valid.
    :returns: Counts of compared pairs and independently bounded clock values.
    :raises AssertionError: A recorded pair does not match its source counterpart.
    """
    # Keep raw capture selection explicit in each standalone verifier; only its
    # module-specific comparison may qualify a recorded value.
    # pylint: disable=duplicate-code
    records = json.loads(path.read_text(encoding="utf-8"))["results"]
    assert records
    if last_only:
        records = records[-1:]
    clocks = sum(compare_record(record) for record in records)
    return {"pairs": len(records), "bounded_clocks": clocks}


def main() -> None:
    """Check a retained raw capture and print the verified counts."""
    # This standard CLI stays standalone for both direct execution and import.
    # pylint: disable=duplicate-code
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--last", action="store_true")
    args = parser.parse_args()
    print(json.dumps(verify_capture(args.capture, args.last), sort_keys=True))


if __name__ == "__main__":
    main()
