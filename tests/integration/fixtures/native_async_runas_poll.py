"""Observe self-completing Runas commands during core automatic polling."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import json
import os
import re
import sys
import time


def _namespace(source, name):
    namespace = {"__name__": name}
    for key in ("WMI_SOURCE", "ASYNC_SOURCE"):
        namespace[key] = globals()[key]
    # Embed only the exact maintained fixture/helper sources frozen by the play.
    exec(compile(source, name + ".py", "exec"), namespace)  # pylint: disable=exec-used
    return namespace


def _async_observer():
    return _namespace(globals()["ASYNC_SOURCE"], "owned_automatic_async_observer")


def _workspace(path):
    assert os.path.basename(path).startswith("legacy-windows-native-async-runas-poll-")


def _live_ancestors(observer, worker, payload):
    wmi = _namespace(globals()["WMI_SOURCE"], "owned_automatic_async_wmi")
    ancestors = []
    current = payload["pid"]
    with wmi["WmiConnection"]() as connection:
        for _ in range(8):
            identity = observer["_process"](current)
            assert identity and identity["alive"]
            ancestors.append(identity)
            if current == worker["pid"]:
                break
            rows = connection.query(
                "SELECT ParentProcessId FROM Win32_Process WHERE ProcessId={0}".format(
                    current
                ),
                ["ParentProcessId"],
            )
            assert len(rows) == 1
            current = rows[0]["ParentProcessId"]
        else:
            raise AssertionError("The owned watchdog is not a live payload ancestor")
    assert ancestors[-1] == worker and ancestors[0] == payload
    assert all(
        left["created"] >= right["created"]
        for left, right in zip(ancestors, ancestors[1:])
    )
    return ancestors


def _live_job(workspace, phase):
    observer = _async_observer()
    cache = os.path.join(workspace, "cache")
    names = os.listdir(cache)
    assert len(names) == 1 and re.match(r"^j[0-9]+\.[0-9]+$", names[0])
    launch = observer["_cache"](os.path.join(cache, names[0]))["json"]
    assert launch["ansible_job_id"] == names[0]
    assert launch["started"] is True and launch["finished"] is False
    worker_pid = launch["ansible_async_watchdog_pid"]
    assert (
        isinstance(worker_pid, int)
        and not isinstance(worker_pid, bool)
        and worker_pid > 0
    )
    worker, payload = observer["_process"](worker_pid), observer["_process"](
        os.getpid()
    )
    assert worker and payload and worker["alive"] and payload["alive"]
    ancestors = _live_ancestors(observer, worker, payload)
    record = {
        "phase": phase,
        "launch": launch,
        "worker": worker,
        "payload": payload,
        "ancestors": ancestors,
    }
    observer["_write"](os.path.join(workspace, "payload-" + names[0] + ".json"), record)
    # The accepted observer recovers only birth-journaled job identities. Include
    # both watchdog and payload so a failed play cannot lose its owned child.
    for suffix, identity in (("", worker), ("-payload", payload)):
        observer["_write"](
            os.path.join(workspace, "job-" + names[0] + suffix + ".json"),
            {"launch": launch, "worker": identity},
        )
    return record


def _payload(workspace, phase):
    _workspace(workspace)
    assert sys.version_info[:3] == (3, 4, 4) and phase in ("user", "system")
    body = sys.stdin.buffer.read()
    _live_job(workspace, phase)
    # Stay live for multiple positive polling intervals, then close naturally.
    # No controller task has to run while its automatic polling loop is blocked.
    time.sleep(3)
    observer = _namespace(globals()["RUNAS_SOURCE"], "owned_automatic_runas_identity")
    sys.argv = [sys.argv[0], base64.b64encode(body).decode("ascii")]
    observer["main"]()


def _records(workspace):
    observer = _async_observer()
    records = {}
    for name in os.listdir(workspace):
        if name.startswith("payload-") and name.endswith(".json"):
            value = observer["_read"](os.path.join(workspace, name))
            identifier = value["launch"]["ansible_job_id"]
            assert name == "payload-" + identifier + ".json"
            assert identifier not in records and value["phase"] in ("user", "system")
            records[identifier] = value
    return records


def _validate_result(result, record, expected):
    observer = _async_observer()
    actual = json.loads(result["stdout"])
    observer["_same"](actual, expected)
    assert result["rc"] == 0 and result["stderr"] == ""
    assert result["started"] is True and result["finished"] is True
    assert result["ansible_job_id"] == record["launch"]["ansible_job_id"]
    assert result["ansible_async_watchdog_pid"] == record["worker"]["pid"]
    assert result["results_file"] == record["launch"]["results_file"]
    assert record["worker"]["alive"] and record["payload"]["alive"]
    assert record["ancestors"][0] == record["payload"]
    assert record["ancestors"][-1] == record["worker"]
    assert record["worker"]["created"] <= record["payload"]["created"]


def _compare(workspace, pairs):
    _workspace(workspace)
    records = _records(workspace)
    assert len(pairs) == 2 and len(records) == 4
    assert {pair["phase"] for pair in pairs} == {"user", "system"}
    comparisons = []
    for pair in pairs:
        for key in ("native", "source"):
            result = pair[key]
            record = records[result["ansible_job_id"]]
            assert record["phase"] == pair["phase"]
            _validate_result(result, record, pair["expected"])
        comparisons.append(
            {"operation": "status", "native": pair["native"], "source": pair["source"]}
        )
    observer = _namespace(
        globals()["RUNAS_ASYNC_SOURCE"], "owned_automatic_public_compare"
    )
    return observer["_compare"](workspace, comparisons)


def _inspect(workspace):
    _workspace(workspace)
    observer = _async_observer()
    deadline = time.monotonic() + 30
    while True:
        actual = observer["_observe"](workspace)
        closed = all(
            not row["actual"]
            or row["actual"]["created"] != row["expected"]["created"]
            or not row["actual"]["alive"]
            for row in actual["processes"]
        )
        if closed and actual["cache"] == [] and actual["staging"] == []:
            return {
                "natural_exit": True,
                "automatic_cache_absence": True,
                "observation": actual,
                "payloads": _records(workspace),
            }
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "Owned automatic jobs did not naturally close their processes/cache/staging"
            )
        time.sleep(0.05)


def _recover(workspace):
    _workspace(workspace)
    observer = _namespace(
        globals()["RUNAS_ASYNC_SOURCE"], "owned_automatic_runas_recovery"
    )
    result = observer["_recover"](workspace)
    result["recorded_payloads"] = _records(workspace)
    return result


def _main():
    assert sys.version_info[:3] == (3, 4, 4)
    workspace, operation = sys.argv[1:3]
    if operation == "payload":
        _payload(workspace, sys.argv[3])
    elif operation == "compare":
        pairs = json.loads(base64.b64decode(sys.argv[3]).decode("utf-8"))
        print(json.dumps(_compare(workspace, pairs), sort_keys=True))
    else:
        assert operation in ("inspect", "recover")
        print(
            json.dumps(
                {"inspect": _inspect, "recover": _recover}[operation](workspace),
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    _main()
