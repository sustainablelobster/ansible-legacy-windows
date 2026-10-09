# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later
"""Check public upload captures without contacting the Windows target."""

import base64
import json
import sys
from typing import Any


def _file_observation(row: dict[str, Any]) -> None:
    case, result = row["case"], row["result"]
    key = row["protocol"], case["name"]
    assert result.get("failed"), key
    expected = (
        b"baseline"
        if case.get("rejected") or case.get("read")
        else case["body"].encode("utf-8")
    )
    assert base64.b64decode(row["observation"]["content"]) == expected, key
    if case.get("rejected"):
        assert "Cannot send a content-body" in result["msg"], key
        return
    assert result["status_code"] == 200 and result["elapsed"] == 0, key
    assert result["content_length"] == str(
        len(expected) if case.get("read") else 0
    ), key
    assert result["content"] == ("baseline" if case.get("read") else ""), key
    assert "request '0'" in result["msg"], key


def _ftp_observation(row: dict[str, Any], protected: dict[str, Any]) -> None:
    case, result = row["case"], row["result"]
    key = row["protocol"], case["name"]
    independent = row["observation"]
    assert bool(result.get("failed")) == bool(case.get("failure")), key
    assert independent["protected"] == protected, key
    uploads = independent["uploads"]
    if case.get("no_file"):
        assert not uploads, key
    else:
        assert len(uploads) == 1, key
        if not case.get("unique"):
            assert list(uploads) == [case.get("filename", "upload.bin")], key
        written = bytes.fromhex(next(iter(uploads.values())))
        assert not row["readback"].get("failed"), key
        assert row["readback"]["content"].encode("utf-8") == written, key
        if case.get("partial"):
            supplied = case["body"].encode("utf-8")
            assert 0 < len(written) < len(supplied), key
            assert supplied.startswith(written), key
        else:
            assert written == case["expected"].encode("utf-8"), key
    if case.get("status") is not None:
        if case["name"] == "denied_store" or case.get("stream_failure"):
            assert result.get("status_code") is None, key
            assert str(case["status"]) in result["msg"], key
        else:
            assert result["status_code"] == case["status"], key
    if not case.get("failure"):
        assert result["status_code"] == 226, key
        assert result["content"] == "" and result["content_length"] == 0, key
    if case.get("stream_failure"):
        assert not any(
            event["kind"] == "command" and event["command"] == case["method"]
            for event in independent["wire"]
        ), key
    elif case.get("body") is not None and not case.get("partial"):
        assert any(
            event["kind"] == "command" and event["command"] == case["method"]
            for event in independent["wire"]
        ) == (case["method"] in ("STOR", "STOU", "APPE")), key


def verify(capture: dict[str, Any]) -> None:
    """Validate independent bytes, results, paired properties and cleanup.

    :param capture: Unmodified playbook evidence.
    :raises AssertionError: If behavior or resource recovery differs.
    """
    before = json.loads(capture["before"]["stdout"])
    after = json.loads(capture["after"]["stdout"])
    assert before["python"].startswith("3.4.4 ")
    assert before["staging"] == after["staging"] and after["workspace_absent"]
    assert json.loads(capture["guest_closed"]["stdout"])["guest_forward_ports_closed"]
    assert json.loads(capture["unforward"]["stdout"])["forwards_cancelled"]
    recovery = json.loads(capture["recovery"]["stdout"])
    assert recovery["restored"] and recovery["server_stopped"]
    assert recovery["uploads_removed"]
    assert json.loads(capture["finalize"]["stdout"])["finalized"]
    assert not capture["controller_absence"]["stat"]["exists"]
    assert capture["results"], "The fixture must exercise requests"
    pairs: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
    for observation in capture["results"]:
        case, result = observation["case"], observation["result"]
        key = observation["protocol"], case["name"]
        pairs.setdefault(key, {})[observation["engine"]] = result
        assert not result.get("changed"), key
        if observation["protocol"] == "file":
            _file_observation(observation)
        else:
            _ftp_observation(observation, recovery["protected"])
    for key, engines in pairs.items():
        if set(engines) != {"native", "upstream"}:
            continue
        native, upstream = engines["native"], engines["upstream"]
        assert bool(native.get("failed")) == bool(upstream.get("failed")), key
        # Network timeout and mid-stream failures can expose different native
        # error text; the assertions above independently check retained writes.
        if key[1] in ("final_timeout", "interrupted_transfer"):
            continue
        for name in (
            "status_code",
            "content",
            "content_length",
            "content_type",
            "status_description",
            "banner_message",
            "welcome_message",
            "exit_message",
            "response_uri",
            "headers",
            "supports_headers",
        ):
            assert native.get(name) == upstream.get(name), (key, name)


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as stream:
        verify(json.load(stream))
    print("Verified exact upload effects, response contracts and owned cleanup.")
