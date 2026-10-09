"""Verify six measured zero-timeout DNS/refused public failures and owned probes."""

# SPDX-License-Identifier: GPL-3.0-or-later

import argparse
import json
import math
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from scripts.verify_http_zero_capture import verify_capture


def verify_connect_capture(document: dict[str, Any]) -> int:
    """Require unchanged full results plus independently proven endpoint failures.

    :param document: Six paired observations from the maintained HTTP fixture.
    :returns: Number of verified source/native failure pairs.
    :raises AssertionError: If endpoint, result, file or recovery proof differs.
    """
    assert verify_capture(document) == 6
    cases = document["cases"]
    assert {(case["module"], case["connection_failure"]) for case in cases} == {
        (module, failure)
        for module in ("uri", "get_url", "package")
        for failure in ("dns", "refused")
    }
    setup = json.loads(document["setup"]["stdout"])
    process = setup["before"]["process"]
    assert json.loads(document["recovery"]["stdout"])["refused_port_closed"] is True
    for case, records in zip(
        cases, zip(document["results"][::2], document["results"][1::2])
    ):
        assert case.get("check", False) is (case["module"] == "package")
        for record in records:
            assert record["module"] == case["module"]
            assert record["result"]["failed"] is True
            assert record["result"]["changed"] is False
            assert isinstance(record["params"]["url_timeout"], int)
            assert not isinstance(record["params"]["url_timeout"], bool)
            assert record["params"]["url_timeout"] == 0
            assert record["params"]["use_proxy"] is False
            assert record["check"] is (case["module"] == "package")
            before = json.loads(record["before"]["stdout"])
            after = json.loads(record["after"]["stdout"])
            assert after["requests"] == []
            assert before["output"] == after["output"]
            for name in ("connection_before", "connection_after"):
                probe = record[name]
                assert probe["rc"] == 0
                value = json.loads(probe["stdout"])
                assert value["process"] == process
                assert value["dns_host"] == "legacy-windows-http-zero.invalid"
                assert isinstance(value["dns_error"], int)
                assert not isinstance(value["dns_error"], bool)
                assert value["dns_error"] == 11001
                assert value["refused_host"] == "127.0.0.1"
                assert isinstance(value["refused_error"], int)
                assert not isinstance(value["refused_error"], bool)
                assert value["refused_error"] == 10061
                assert isinstance(value["refused_port"], int)
                assert not isinstance(value["refused_port"], bool)
                assert value["refused_port"] == setup["server"]["refused_port"]
                assert isinstance(value["time"], float) and math.isfinite(value["time"])
                if name == "connection_before":
                    assert value["time"] <= before["time"]
                else:
                    assert value["time"] >= after["time"]
                uri = urlsplit(
                    record["params"]["path" if case["module"] == "package" else "url"]
                )
                assert uri.scheme == "http" and uri.path == "/fixture"
                assert uri.hostname == (
                    value["dns_host"]
                    if case["connection_failure"] == "dns"
                    else value["refused_host"]
                )
                assert uri.port == (
                    None
                    if case["connection_failure"] == "dns"
                    else value["refused_port"]
                )
    return 6


def main() -> None:
    """Verify a retained six-case capture without contacting Windows."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    arguments = parser.parse_args()
    count = verify_connect_capture(
        json.loads(arguments.capture.read_text(encoding="utf-8"))
    )
    print(
        f"PASS: {count} complete zero-timeout DNS/refused pairs, "
        "proven endpoints and owned recovery"
    )


if __name__ == "__main__":
    main()
