"""Hold an owned background command until its live process is journaled."""

# SPDX-License-Identifier: GPL-3.0-or-later

import datetime
import json
import os
import re
import sys
import time


def _namespace(source, name):
    namespace = {"__name__": name}
    if "WMI_SOURCE" in globals():
        namespace["WMI_SOURCE"] = globals()["WMI_SOURCE"]
    # Only literal maintained observer bytes are embedded by the playbook.
    exec(compile(source, name + ".py", "exec"), namespace)  # pylint: disable=exec-used
    return namespace


def _recover(workspace):
    assert os.path.basename(workspace).startswith("legacy-windows-native-async-runas-")
    observer = _namespace(globals()["ASYNC_SOURCE"], "owned_async_recovery")
    # A launch can fail before its watchdog is journaled. Do not declare
    # recovery from an incomplete process journal while its staging is live.
    deadline = time.monotonic() + 120
    while os.listdir(os.path.join(workspace, "staging")):
        if time.monotonic() >= deadline:
            raise RuntimeError("Owned async staging did not close before recovery")
        time.sleep(0.05)
    result = observer["_cleanup"](workspace)
    payloads = []
    for phase in ("user", "system"):
        path = os.path.join(workspace, phase + "-live.json")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as stream:
                expected = json.load(stream)
            actual = observer["_process"](expected["pid"])
            payloads.append({"phase": phase, "expected": expected, "actual": actual})
            assert (
                not actual
                or actual["created"] != expected["created"]
                or not actual["alive"]
            )
    # Closed cache files may remain after an earlier failed status/cleanup task.
    # Preserve their complete observations before deleting the owned workspace.
    assert result["final"]["staging"] == []
    result["payloads"] = payloads
    return result


def _compare(workspace, pairs):
    observer = _namespace(globals()["ASYNC_SOURCE"], "owned_async_comparison")
    for pair in pairs:
        native = observer["_job_public"](pair["native"], pair["native"], workspace)
        source = observer["_job_public"](pair["source"], pair["source"], workspace)
        if pair["operation"] == "status":
            for result in (native, source):
                started = datetime.datetime.strptime(
                    result["start"], "%Y-%m-%d %H:%M:%S.%f"
                )
                ended = datetime.datetime.strptime(
                    result["end"], "%Y-%m-%d %H:%M:%S.%f"
                )
                assert ended >= started
                assert isinstance(result["delta"], str)
                match = re.match(
                    r"^(\d+):([0-5]\d):([0-5]\d)\.(\d{6})$", result["delta"]
                )
                assert match
                duration = datetime.timedelta(
                    hours=int(match.group(1)),
                    minutes=int(match.group(2)),
                    seconds=int(match.group(3)),
                    microseconds=int(match.group(4)),
                )
                # Released DateTime/TimeSpan truncate 100ns ticks independently
                # to six decimal places, allowing at most one microsecond.
                assert abs((ended - started) - duration) <= datetime.timedelta(
                    microseconds=1
                )
                # Separate executions necessarily have different wall clocks.
                # Validate their exact formats; compare every other public field.
                for field in ("start", "end", "delta"):
                    result[field] = "<validated-command-" + field + ">"
        observer["_same"](native, source)
    return {"complete_typed_public_equal": True, "pairs": len(pairs)}


def _main():
    assert sys.version_info[:3] == (3, 4, 4)
    workspace, phase, body = sys.argv[1:]
    assert os.path.basename(workspace).startswith("legacy-windows-native-async-runas-")
    assert phase in ("user", "system")
    processes = _namespace(globals()["PROCESS_SOURCE"], "owned_runas_process")
    identity = processes["_process"](os.getpid())
    assert identity and identity["alive"]
    with open(
        os.path.join(workspace, phase + "-live.json"), "x", encoding="utf-8"
    ) as stream:
        json.dump(identity, stream)
    deadline = time.monotonic() + 60
    while not os.path.exists(os.path.join(workspace, phase + "-release")):
        if time.monotonic() >= deadline:
            raise RuntimeError("Owned async runas release was not received")
        time.sleep(0.05)
    observer = _namespace(globals()["RUNAS_SOURCE"], "owned_runas_observer")
    # The existing observer accepts one base64 argument; retain that contract.
    sys.argv = [sys.argv[0], body]
    observer["main"]()


if __name__ == "__main__":
    _main()
