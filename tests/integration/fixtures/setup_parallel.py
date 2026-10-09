"""Observe owned parallel jobs and permit cleanup only after natural worker exit."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import os
import re
import sys
import time


def _observer(source, name):
    namespace = {"__name__": name, "WMI_SOURCE": globals()["WMI_SOURCE"]}
    # These are the exact maintained observers embedded by the private play.
    exec(compile(source, name + ".py", "exec"), namespace)  # pylint: disable=exec-used
    return namespace


_SETUP = _observer(globals()["SETUP_SOURCE"], "parallel_setup_observer")
_ASYNC = _observer(globals()["ASYNC_SOURCE"], "parallel_async_observer")


def _read(path):
    with open(path, encoding="utf-8-sig") as stream:
        return json.load(stream)


def _write(path, value):
    with open(path, "x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())


def _protected(root):
    return {
        "configuration": _ASYNC["_protected"](),
        "sentinel": _SETUP["_file"](os.path.join(root, "sentinel.bin")),
    }


def _persistent(protected):
    # Windows may start/stop idle services without any task changing them.
    # Keep every observed State in the evidence; protect service identities and
    # startup configuration rather than assert whole-machine runtime stasis.
    configuration = dict(protected["configuration"])
    configuration["services"] = [
        {"Name": service["Name"], "StartMode": service["StartMode"]}
        for service in configuration["services"]
    ]
    return dict(protected, configuration=configuration)


def _setup(root):
    assert os.listdir(root) == []
    for name in ("native-cache", "source-cache", "staging"):
        os.mkdir(os.path.join(root, name))
    with open(os.path.join(root, "sentinel.bin"), "xb") as stream:
        stream.write(b"parallel facts protected sentinel")
    record = {"workspace": root, "before": _protected(root)}
    _write(os.path.join(root, "parallel-journal.json"), record)
    return record


def _cache_identity(job):
    return (
        job["side"],
        job["name"],
        json.dumps(job["result"], sort_keys=True, separators=(",", ":")),
    )


def _jobs(root, exited=()):
    jobs = []
    for side in ("native-cache", "source-cache"):
        directory = os.path.join(root, side)
        for name in sorted(os.listdir(directory)):
            assert re.match(r"^j[0-9]+\.[0-9]+$", name), name
            record = _read(os.path.join(directory, name))
            assert record["ansible_job_id"] == name
            pid = record["ansible_async_watchdog_pid"]
            assert isinstance(pid, int) and not isinstance(pid, bool) and pid > 0
            job = {"side": side, "name": name, "result": record}
            # A recorded OpenProcess87 absence is final for that original
            # worker. Rechecking its number could observe an unrelated process.
            if _cache_identity(job) in exited:
                job.update(process=None, worker_exit_previously_confirmed=True)
            else:
                job["process"] = _ASYNC["_process"](pid)
            jobs.append(job)
    return jobs


def _observe(root, exited=()):
    journal = _read(os.path.join(root, "parallel-journal.json"))
    assert journal["workspace"] == root
    protected = _protected(root)
    assert _persistent(protected) == _persistent(
        journal["before"]
    ), "Persistent protected state changed"
    return {
        "workspace": root,
        "protected": protected,
        "jobs": _jobs(root, exited),
        "staging": sorted(os.listdir(os.path.join(root, "staging"))),
    }


def _cleanup(root, prior=None):
    # Never terminate a process identified only by a cache PID. Waiting until
    # that PID is absent/dead proves the original worker cannot still be alive.
    # Retain an earlier verified absence only for the exact unchanged cache,
    # rather than restart that proof against a potentially unrelated process.
    exited = set()
    if prior is not None:
        if prior["workspace"] != root:
            raise ValueError("Prior worker observation belongs to another workspace")
        exited = {
            _cache_identity(job)
            for job in prior["jobs"]
            if job["result"].get("finished") is True and job["process"] is None
        }
    deadline = time.monotonic() + 35
    while True:
        observed = _observe(root, exited)
        if not exited.issubset({_cache_identity(job) for job in observed["jobs"]}):
            raise ValueError("Previously observed job caches changed; retain workspace")
        if all(
            job["result"].get("finished")
            and (job["process"] is None or not job["process"]["alive"])
            for job in observed["jobs"]
        ):
            break
        if time.monotonic() >= deadline:
            raise ValueError("Parallel job workers are still alive; retain workspace")
        time.sleep(0.05)
    assert observed["staging"] == [], "Owned staging still exists"
    assert set(os.listdir(root)) == {
        "native-cache",
        "source-cache",
        "staging",
        "sentinel.bin",
        "parallel-journal.json",
    }
    for job in observed["jobs"]:
        os.remove(os.path.join(root, job["side"], job["name"]))
    observed["persistent_restored"] = True
    observed["before"] = _read(os.path.join(root, "parallel-journal.json"))["before"]
    return observed


def main():
    """Run only an explicitly owned parallel fixture operation on Windows3.4.4."""
    assert sys.version_info[:3] == (3, 4, 4)
    root = _SETUP["_root"](sys.argv[1])
    if sys.argv[2] == "cleanup":
        result = _cleanup(root, json.loads(globals().get("PRIOR_OBSERVATION", "null")))
    else:
        result = {"setup": _setup, "observe": _observe}[sys.argv[2]](root)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
