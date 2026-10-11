"""Exercise real fallback worker ownership without installing or removing updates."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# The controlled operation replaces only an owned generated bootstrap script;
# production native launch, token, journal, polling and cancellation stay intact.
# pylint: disable=protected-access

import json
import os
import subprocess
import sys
import time

import legacy_windows_updates_worker as worker  # pylint: disable=import-error

_CANCEL_PROGRAM = """
import os, sys, time
import legacy_windows_updates_worker as worker
def controlled_operation(options, emit, cancelled, log):
    assert sys.version_info[:3] == (3, 4, 4)
    emit('started', {'operation': 'controlled_lifecycle_not_WUA',
        'sid': worker._sid(os.getpid()), 'python': list(sys.version_info[:3])})
    deadline = time.monotonic() + 20
    while not cancelled():
        if time.monotonic() >= deadline:
            raise OSError('The finite controlled worker did not receive cancellation')
        time.sleep(0.05)
    emit('exit', {'changed': False, 'cancelled': True})
worker.updates.run = controlled_operation
worker.main()
"""

_OBSERVE_PROGRAM = """
import json, os, sys, time
import legacy_windows_updates_worker as worker
assert sys.version_info[:3] == (3, 4, 4)
output = sys.argv[1]
result = {'sid': worker._sid(os.getpid()), 'identity': worker._process(os.getpid()),
    'python': list(sys.version_info[:3])}
with open(output + '.next', 'x', encoding='utf-8') as stream:
    json.dump(result, stream)
os.replace(output + '.next', output)
deadline = time.monotonic() + 15
while not os.path.exists(output + '.release'):
    if time.monotonic() >= deadline:
        break
    time.sleep(0.05)
"""


def _closed(identity):
    actual = worker._process(identity["pid"])
    assert (
        actual is None
        or actual["created"] != identity["created"]
        or not actual["alive"]
    ), "The exact owned native child remains alive."
    return actual


def _cancel():
    native_launch = worker._launch
    calls, created = [], []
    options = None
    caller = worker._sid(os.getpid())

    def _controlled_launch(command, root, environment, dynamic_cloaking=False):
        calls.append(dynamic_cloaking)
        # start() owns this exact generated file and no process yet exists.
        with open(os.path.join(root, "worker.py"), "w", encoding="utf-8") as stream:
            stream.write(_CANCEL_PROGRAM)
        pid = native_launch(command, root, environment, dynamic_cloaking)
        created.append(pid)
        return pid

    worker._launch = _controlled_launch
    try:
        options = worker.start({"state": "searched", "check_mode": False})
        root, journal = worker._validate(options["poll_options"])
        request = worker._read(root, "request.json")
        packet = worker.poll(options["poll_options"])
        state = worker._read(root, "state.json")
        identity = state["worker"]
        assert journal["sid"] == caller and caller != "S-1-5-18"
        assert request["worker_sid"] == state["worker_sid"] == "S-1-5-18"
        assert calls == [False, True] and created == [identity["pid"]]
        assert worker._process(identity["pid"]) == identity and identity["alive"]
        assert not state["finished"]
        assert packet["output"] == [
            {
                "task": "started",
                "result": {
                    "operation": "controlled_lifecycle_not_WUA",
                    "sid": "S-1-5-18",
                    "python": [3, 4, 4],
                },
            }
        ]
        cancelled = worker.cancel(options["cancel_options"])
        actual = _closed(identity)
        assert not os.path.exists(root) and worker._sid(os.getpid()) == caller
        return {
            "operation": "controlled_lifecycle_not_WUA",
            "creator_sid": caller,
            "worker_sid": request["worker_sid"],
            "worker": identity,
            "progress": packet,
            "cancel": cancelled,
            "actual_after": actual,
            "directory_absent": True,
            "launch_calls": calls,
            "native_creations": created,
            "caller_identity_restored": True,
        }
    finally:
        worker._launch = native_launch
        if options and os.path.exists(options["cancel_options"]["root"]):
            worker.cancel(options["cancel_options"])


def _uncertain(root):
    native_launch = worker._launch
    calls, created, published = [], [], []
    caller = worker._sid(os.getpid())
    request = {"sid": caller, "environment": dict(os.environ)}
    output = os.path.join(root, "uncertain-observation.json")
    source = os.path.join(root, "uncertain-observe.py")
    with open(source, "x", encoding="utf-8") as stream:
        stream.write(_OBSERVE_PROGRAM)

    def _fail_after_creation(command, directory, environment, dynamic_cloaking=False):
        calls.append(dynamic_cloaking)
        pid = native_launch(command, directory, environment, dynamic_cloaking)
        created.append(pid)
        raise OSError("Controlled error after native process creation")

    worker._launch = _fail_after_creation
    try:
        try:
            worker._launch_owned(
                subprocess.list2cmdline([sys.executable, "-B", source, output]),
                root,
                request,
                lambda: published.append(request["worker_sid"]),
            )
        except OSError as error:
            assert str(error) == "Controlled error after native process creation"
        else:
            raise AssertionError("The uncertain creation result was hidden")
        assert calls == [False, True] and len(created) == 1
        assert published == ["S-1-5-18"] and request["worker_sid"] == "S-1-5-18"
        deadline = time.monotonic() + 10
        while not os.path.exists(output):
            assert time.monotonic() < deadline
            time.sleep(0.05)
        with open(output, encoding="utf-8") as stream:
            observed = json.load(stream)
        identity = worker._process(created[0])
        assert identity == observed["identity"] and identity["alive"]
        assert observed["sid"] == "S-1-5-18" and observed["python"] == [3, 4, 4]
    finally:
        worker._launch = native_launch
        # This release belongs only to the finite program created by this call.
        with open(output + ".release", "x", encoding="utf-8") as stream:
            stream.write("Release only this finite owned child\n")
    deadline = time.monotonic() + 20
    while worker._alive({"worker": identity}):
        assert time.monotonic() < deadline
        time.sleep(0.05)
    assert worker._sid(os.getpid()) == caller
    return {
        "creator_sid": caller,
        "worker": observed,
        "actual_after": _closed(identity),
        "launch_calls": calls,
        "native_creations": created,
        "uncertain_error_propagated": True,
        "caller_identity_restored": True,
    }


def main():
    """Run one bounded controlled operation through unchanged native worker code.

    :raises AssertionError: Identity, ownership, single-launch or cleanup fails.
    :raises OSError: Windows launch or cooperative cancellation fails.
    :raises ValueError: The requested controlled operation is unknown.
    """
    assert sys.version_info[:3] == (3, 4, 4)
    root, operation = sys.argv[1:]
    assert os.path.basename(root).startswith("legacy-windows-updates-runas-")
    assert os.path.abspath(os.path.dirname(worker.__file__)) == os.path.abspath(root)
    if operation == "cancel":
        result = _cancel()
    elif operation == "uncertain":
        result = _uncertain(root)
    else:
        raise ValueError("Unknown controlled lifecycle operation")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
