# SPDX-License-Identifier: GPL-3.0-or-later
"""Measure native Updates worker caller-loss supervision without WUA servicing."""

import ctypes
import hashlib
import json
import os
import subprocess
import sys
import time

namespace = {
    "__name__": "updates_async_protection",
    "WMI_SOURCE": globals()["HELPER_SOURCES"]["legacy_windows_wmi.py"],
}
# This fixture embeds frozen observations rather than installing global helpers.
# pylint: disable=exec-used
exec(
    compile(
        globals()["ASYNC_FIXTURE_SOURCE"], "frozen_native_async_fixture.py", "exec"
    ),
    namespace,
)
# pylint: enable=exec-used

_PROVIDER = r"""
import json,os,time

def run(options,emit,cancelled,log):
    workspace=options['fixture_workspace']
    before=cancelled()
    with open(os.path.join(workspace,'callback-before.json'),'x') as stream:
        json.dump({'cancelled':before,'worker_pid':os.getpid()},stream)
        stream.flush();os.fsync(stream.fileno())
    assert before is False
    emit('started',{})
    deadline=time.monotonic()+30
    while not cancelled():
        if time.monotonic()>=deadline:
            raise OSError('Fixture frontend did not exit within30 seconds')
        time.sleep(.01)
    with open(os.path.join(workspace,'callback-after.json'),'x') as stream:
        json.dump({'cancelled':True,'worker_pid':os.getpid(),'resource_closed':True},stream)
        stream.flush();os.fsync(stream.fileno())
    emit('exit',{'changed':False,'failed':False,'reboot_required':False,'exception':None})
"""

_FRONTEND = r"""
import json,os,sys,time
import legacy_windows_updates_worker as worker

workspace=sys.argv[1]
started=worker.start({'fixture_workspace':workspace},supervised=True)
root=started['poll_options']['root']
record={'frontend':worker._process(os.getpid()),'started':started,
        'worker':worker._read(root,'launch.json')['worker']}
with open(os.path.join(workspace,'frontend.json'),'x') as stream:
    json.dump(record,stream);stream.flush();os.fsync(stream.fileno())
deadline=time.monotonic()+30
while not os.path.isfile(os.path.join(workspace,'callback-before.json')):
    if time.monotonic()>=deadline:
        raise OSError('Fixture callback did not report its live frontend')
    time.sleep(.01)
# Natural frontend exit, not killing or assuming the backend has also exited.
"""

_STARTUP_OWNER = r"""
import json,os,sys,time
import legacy_windows_updates_worker as worker
with open(sys.argv[1]) as stream: bootstrap=json.load(stream)
frontend=bootstrap['request']['supervisor']
write=worker._write
def observe_journal(root,name,value):
    write(root,name,value)
    if name=='journal.json':
        marker=os.path.join(sys.argv[2],'startup-after-journal.json')
        with open(marker+'.tmp','x') as stream:
            json.dump({'frontend':frontend,'worker':value['worker'],
                       'root':root,'journal':value},stream)
            stream.flush();os.fsync(stream.fileno())
        os.replace(marker+'.tmp',marker)
        while worker._alive({'worker':frontend}): time.sleep(.01)
worker._write=observe_journal
worker._supervised_main()
"""

_STARTUP_FRONTEND = r"""
import json,os,subprocess,sys,time
import legacy_windows_updates_worker as worker
workspace,boundary=sys.argv[1:3]
launch=worker._launch
def observe_start(command,source,environment):
    for name in os.listdir(source):
        if name.startswith('.updates-start-') and name.endswith('.json'):
            with open(os.path.join(source,name)) as stream: bootstrap=json.load(stream)
            if bootstrap['request']['supervisor']['pid']==os.getpid():
                path=os.path.join(source,name);break
    if boundary=='before-launch':
        marker=os.path.join(workspace,'startup-before-launch.json')
        with open(marker+'.tmp','x') as stream:
            json.dump({'frontend':worker._process(os.getpid()),'worker':None,
                       'root':bootstrap['journal']['root'],'bootstrap':path},stream)
            stream.flush();os.fsync(stream.fileno())
        os.replace(marker+'.tmp',marker)
        while True: time.sleep(.01)
    with open(os.path.join(source,'startup-owner.py')) as stream: owner=stream.read()
    return launch(subprocess.list2cmdline([sys.executable,'-B','-c',owner,path,workspace]),
                  source,environment)
worker._launch=observe_start
worker.start({'fixture_workspace':workspace},supervised=True)
"""


def _read(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def _write_source(path, value):
    with open(path, "x", encoding="utf-8") as stream:
        stream.write(value)


def _prepare_sources(workspace):
    directory = os.path.join(workspace, "lifecycle-helpers")
    os.mkdir(directory)
    hashes = {}
    for name, source in sorted(globals()["HELPER_SOURCES"].items()):
        # Only this deterministic fixture provider differs. The production
        # worker, WMI, Win32 lifetime guard and cleanup are literal shipped bytes.
        source = _PROVIDER if name == "legacy_windows_updates.py" else source
        _write_source(os.path.join(directory, name), source)
        hashes[name] = hashlib.sha256(source.encode("utf-8")).hexdigest()
    frontend = os.path.join(directory, "frontend.py")
    _write_source(frontend, _FRONTEND)
    _write_source(os.path.join(directory, "startup-owner.py"), _STARTUP_OWNER)
    _write_source(os.path.join(directory, "startup-frontend.py"), _STARTUP_FRONTEND)
    return hashes


def _stop_frontend(identity):
    api = namespace["_kernel"]()
    handle = api.OpenProcess(0x100401, False, identity["pid"])
    assert handle
    try:
        clocks = [ctypes.c_uint64() for _ in range(4)]
        assert api.GetProcessTimes(handle, *[ctypes.byref(value) for value in clocks])
        assert clocks[0].value == identity["created"]
        assert api.TerminateProcess(handle, 1)
        assert api.WaitForSingleObject(handle, 5000) == 0
    finally:
        assert api.CloseHandle(handle)


def _startup_boundary(workspace, boundary):
    frontend = os.path.join(workspace, "lifecycle-helpers", "startup-frontend.py")
    marker = os.path.join(workspace, "startup-" + boundary + ".json")
    with open(marker + ".stdout", "xb") as stdout, open(
        marker + ".stderr", "xb"
    ) as stderr:
        with subprocess.Popen(
            [sys.executable, "-B", frontend, workspace, boundary],
            stdout=stdout,
            stderr=stderr,
        ) as process:
            deadline = time.monotonic() + 30
            while not os.path.isfile(marker):
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise OSError(
                        "Startup fixture did not reach its boundary: " + marker
                    )
                time.sleep(0.01)
            record = _read(marker)
            assert record["frontend"]["pid"] == process.pid
            record["root_before_frontend_death"] = os.path.exists(record["root"])
            assert record["root_before_frontend_death"] is (boundary == "after-journal")
            if record["worker"]:
                assert record["journal"]["worker"] == record["worker"]
                assert (
                    namespace["_process"](record["worker"]["pid"]) == record["worker"]
                )
            else:
                assert os.path.dirname(record["bootstrap"]) == os.path.dirname(frontend)
                assert os.path.isfile(record["bootstrap"])
            _stop_frontend(record["frontend"])
            process.wait(timeout=10)
    deadline = time.monotonic() + 35
    while True:
        actual = (
            namespace["_process"](record["worker"]["pid"]) if record["worker"] else None
        )
        alive = (
            actual
            and actual["created"] == record["worker"]["created"]
            and actual["alive"]
        )
        if not alive and not os.path.exists(record["root"]):
            break
        if time.monotonic() >= deadline:
            raise OSError("Startup cleanup owner has not recovered: " + record["root"])
        time.sleep(0.01)
    record["frontend_actual"] = namespace["_process"](record["frontend"]["pid"])
    record["worker_actual"] = actual
    record["owned_root_absent"] = not os.path.exists(record["root"])
    assert not os.path.exists(os.path.join(workspace, "callback-before.json"))
    return record


def _exit_frontend(workspace):
    frontend = os.path.join(workspace, "lifecycle-helpers", "frontend.py")
    with open(os.path.join(workspace, "frontend.stdout"), "xb") as stdout, open(
        os.path.join(workspace, "frontend.stderr"), "xb"
    ) as stderr:
        with subprocess.Popen(
            [sys.executable, "-B", frontend, workspace], stdout=stdout, stderr=stderr
        ) as process:
            returncode = process.wait(timeout=40)
    with open(os.path.join(workspace, "frontend.stderr"), "rb") as stderr:
        error = stderr.read().decode("utf-8", "replace")
    if returncode:
        raise OSError("Fixture frontend failed: " + error)
    return _read(os.path.join(workspace, "frontend.json"))


def _run(workspace):
    namespace["_journal"](workspace)
    hashes = _prepare_sources(workspace)
    startup = [
        _startup_boundary(workspace, boundary)
        for boundary in ("before-launch", "after-journal")
    ]
    record = _exit_frontend(workspace)
    owned_root = record["started"]["poll_options"]["root"]
    deadline = time.monotonic() + 35
    while os.path.exists(owned_root):
        if time.monotonic() >= deadline:
            raise OSError("Owned worker recovery incomplete; retained at " + owned_root)
        time.sleep(0.01)
    before = _read(os.path.join(workspace, "callback-before.json"))
    after = _read(os.path.join(workspace, "callback-after.json"))
    actual_worker = namespace["_process"](record["worker"]["pid"])
    actual_frontend = namespace["_process"](record["frontend"]["pid"])
    assert before["cancelled"] is False and after["cancelled"] is True
    assert before["worker_pid"] == after["worker_pid"] == record["worker"]["pid"]
    assert after["resource_closed"] is True
    for expected, actual in (
        (record["worker"], actual_worker),
        (record["frontend"], actual_frontend),
    ):
        assert (
            actual is None
            or actual["created"] != expected["created"]
            or not actual["alive"]
        )
    protected = namespace["_observe"](workspace)
    return {
        "python": list(sys.version_info[:3]),
        "fixture_provider_not_wua_servicing": True,
        "source_hashes": hashes,
        "startup_boundaries": startup,
        "frontend_record": record,
        "frontend_actual": actual_frontend,
        "worker_actual": actual_worker,
        "callback_before": before,
        "callback_after": after,
        "owned_root_absent": not os.path.exists(owned_root),
        "protected": protected,
    }


def _recover(workspace):
    for boundary in ("before-launch", "after-journal"):
        path = os.path.join(workspace, "startup-" + boundary + ".json")
        if os.path.isfile(path):
            record = _read(path)
            if os.path.exists(record["root"]):
                raise OSError(
                    "Owned startup recovery is still incomplete: " + record["root"]
                )
            for identity in (record["frontend"], record["worker"]):
                actual = namespace["_process"](identity["pid"]) if identity else None
                if (
                    actual
                    and actual["created"] == identity["created"]
                    and actual["alive"]
                ):
                    raise OSError(
                        "Owned startup process is still running; fixture retained"
                    )
    record_path = os.path.join(workspace, "frontend.json")
    if os.path.isfile(record_path):
        record = _read(record_path)
        for key in ("frontend", "worker"):
            actual = namespace["_process"](record[key]["pid"])
            if (
                actual
                and actual["created"] == record[key]["created"]
                and actual["alive"]
            ):
                raise OSError(
                    "Owned fixture " + key + " is still running; workspace retained"
                )
        if os.path.exists(record["started"]["poll_options"]["root"]):
            raise OSError("Owned Updates workspace remains; recovery retained")
    return namespace["_cleanup"](workspace)


if __name__ == "__main__":
    assert sys.version_info[:3] == (3, 4, 4)
    _WORKSPACE, _OPERATION = sys.argv[1:3]
    assert os.path.basename(_WORKSPACE).startswith(
        "legacy-windows-native-async-updates-"
    )
    _FUNCTIONS = {"setup": namespace["_setup"], "run": _run, "recover": _recover}
    print(json.dumps(_FUNCTIONS[_OPERATION](_WORKSPACE), sort_keys=True))
