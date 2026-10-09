"""Check the bounded Runas search matrix and its independent identity observer."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import json
import runpy
import sys
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE = _ROOT / "tests/integration/fixtures/win_updates_runas.py"


@pytest.fixture(name="observer")
def load_observer(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Load only pure observer decisions, not Windows APIs on the controller.

    :param monkeypatch: Scoped Windows-module substitute.
    :returns: The real fixture's pure decision functions.
    """
    monkeypatch.setitem(sys.modules, "winreg", ModuleType("winreg"))
    return runpy.run_path(
        str(_FIXTURE),
        init_globals={
            "WMI_SOURCE": "",
            "BASE_SOURCE": (_ROOT / "tests/integration/fixtures/native_async.py")
            .read_text()
            .split('if __name__ == "__main__":')[0],
            "MONITOR_SOURCE": "",
        },
    )


@pytest.mark.parametrize(
    "command,expected",
    [
        (None, None),
        ("powershell.exe -EncodedCommand plain-frontend", None),
        ("python.exe monitor.py C:\\Temp\\legacy-windows-updates-runas-test", None),
        ("powershell.exe Invoke-InProcessStub payload", None),
        ("powershell.exe ANSIBLE_BOOTSTRAP_ERROR: unrelated", None),
        (
            "powershell.exe Invoke-InProcessStub payload ANSIBLE_BOOTSTRAP_ERROR:",
            "original",
        ),
        (
            '"C:\\Python34\\python.exe" -B '
            '"C:\\Windows\\Temp\\legacy-windows-updates-abc\\worker.py"',
            "native",
        ),
        (
            'python.exe -B -c "import legacy_windows_updates_worker as worker;'
            'worker._supervised_main()" C:\\staging\\.updates-start-'
            + "a" * 32
            + ".json",
            "native",
        ),
        (
            'python.exe -c "import legacy_windows_updates_worker as worker;'
            'worker._supervised_main()" unrelated.json',
            None,
        ),
        (
            'python.exe -c "unrelated" C:\\staging\\.updates-start-'
            + "a" * 32
            + ".json",
            None,
        ),
    ],
)
def test_actual_backend_command_boundary(
    observer: dict[str, Any], command: str | None, expected: str | None
) -> None:
    assert observer["_backend"](command) == expected


def test_public_matrix_is_only_new_admin_system_searches_and_previews() -> None:
    variables = yaml.safe_load(
        (_ROOT / "tests/integration/vars/win_updates_runas.yml").read_text()
    )
    cases = variables["updates_runas_cases"]
    assert variables["updates_runas_system_account"] == "NT AUTHORITY\\SYSTEM"
    assert variables["updates_runas_source_cases"] == "{{ updates_runas_cases }}"
    assert cases == [
        {"actor": actor, "state": "installed" if check else "searched", "check": check}
        for actor in ("administrator", "system")
        for check in (False, True)
    ]
    play = yaml.safe_load(
        (_ROOT / "tests/integration/win_updates_runas.yml").read_text()
    )[0]
    block = next(task["block"] for task in play["tasks"] if "block" in task)
    requests = [
        task
        for task in block
        if any(
            name in task
            for name in (
                "sustainablelobster.legacy_windows.win_updates",
                "ansible.windows.win_updates",
            )
        )
    ]
    assert len(requests) == 2
    for task in requests:
        name = next(key for key in task if key.endswith(".win_updates"))
        assert task[name] == {
            "state": "{{ item.state }}",
            "server_selection": "managed_server",
            "category_names": ["*"],
            "reject_list": [".*"],
        }
        assert task["check_mode"] == "{{ item.check }}"
        assert (
            task["become"] is True and task["become_method"] == "ansible.builtin.runas"
        )
        assert "else updates_runas_system_account" in task["become_user"]
        assert task["loop"] == (
            "{{ updates_runas_source_cases }}"
            if name == "ansible.windows.win_updates"
            else "{{ updates_runas_cases }}"
        )
        assert "async" not in task and "reboot" not in task[name]


def test_monitor_is_closed_in_always_and_raw_evidence_precedes_reset() -> None:
    play = yaml.safe_load(
        (_ROOT / "tests/integration/win_updates_runas.yml").read_text()
    )[0]
    block = next(task for task in play["tasks"] if "block" in task)
    assert block["always"][0]["register"] == "updates_runas_monitor_closed"
    assert block["always"][0]["failed_when"] is False
    capture = next(
        index
        for index, task in enumerate(play["tasks"])
        if "ansible.builtin.copy" in task
    )
    reset = next(
        index
        for index, task in enumerate(play["tasks"])
        if task.get("ansible.builtin.meta") == "reset_connection"
    )
    assert capture < reset


@pytest.mark.parametrize("traceback_present", [True, False])
def test_failed_monitor_retains_original_traceback_and_partial_journals(
    observer: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    traceback_present: bool,
) -> None:
    identity = {"pid": 42, "created": 100, "alive": True}
    (tmp_path / "monitor-identity.json").write_text(json.dumps(identity))
    jobs = {"j1.42": {"startup": {"json": {"finished": False}}}}
    (tmp_path / "async-jobs.json").write_text(json.dumps(jobs))
    original_traceback = "Traceback (original observer)\nAssertionError: startup\n"
    if traceback_present:
        (tmp_path / "monitor-error.log").write_text(original_traceback)
    monkeypatch.setitem(
        observer["_stop"].__globals__["_BASE"], "_process", lambda _pid: None
    )
    with pytest.raises(
        OSError, match="Owned Updates identity monitor failed:"
    ) as error:
        observer["_stop"](str(tmp_path))
    diagnostics = json.loads(str(error.value).split(": ", 1)[1])
    assert diagnostics == {
        "monitor_identity": identity,
        "monitor_final": None,
        "monitor-error.log": original_traceback if traceback_present else None,
        "async-jobs.json": jobs,
        "backend-identities.json": None,
    }
    assert isinstance(error.value.__cause__, FileNotFoundError)
    assert not (tmp_path / "monitor-complete.json").exists()


@pytest.mark.parametrize("monitor_sid", ["S-1-5-18", "unexpected-account"])
def test_wmi_start_journals_birth_before_validating_actual_monitor_sid(
    observer: dict[str, Any], tmp_path: Path, monitor_sid: str
) -> None:
    workspace = tmp_path / "legacy-windows-updates-runas-controller-test"
    workspace.mkdir()
    identity = {"pid": 42, "created": 100, "alive": True}
    calls = []

    def _call(
        path: str, method: str, properties: list[str], inputs: Any = None
    ) -> dict[str, Any]:
        calls.append((path, method, properties, inputs))
        if method == "Create":
            (workspace / "monitor-ready.json").write_text(json.dumps(identity))
            return {"ReturnValue": 0, "ProcessId": 42}
        assert (workspace / "monitor-identity.json").exists()
        return {
            "ReturnValue": 0,
            "Sid": (monitor_sid if path == "Win32_Process.Handle='42'" else "S-1-5-18"),
        }

    @contextmanager
    def _connection() -> Any:
        yield SimpleNamespace(call_method=_call)

    observer["_WMI"]["WmiConnection"] = _connection
    observer["_BASE"]["_process"] = lambda _pid: identity
    observer["_start"].__globals__["MONITOR_SOURCE"] = "# owned pure test monitor\n"
    if monitor_sid == "S-1-5-18":
        result = observer["_start"](str(workspace))
        assert result["identity"] == identity
        assert [row["Sid"] for row in result["owners"]] == ["S-1-5-18"] * 2
    else:
        with pytest.raises(AssertionError):
            observer["_start"](str(workspace))
    assert json.loads((workspace / "monitor-identity.json").read_text()) == identity
    assert calls[0][:3] == ("Win32_Process", "Create", ["ReturnValue", "ProcessId"])
    assert calls[0][3]["CurrentDirectory"] == str(workspace)


def test_failed_observer_keeps_partial_evidence_and_does_not_delete_unknown_root() -> (
    None
):
    play = yaml.safe_load(
        (_ROOT / "tests/integration/win_updates_runas.yml").read_text()
    )[0]
    finalizers = next(task["always"] for task in play["tasks"] if "block" in task)
    retained = next(task for task in finalizers if "ansible.builtin.copy" in task)
    assert retained["ansible.builtin.copy"]["dest"].endswith(".partial.json")
    removal = next(
        task
        for task in finalizers
        if "sustainablelobster.legacy_windows.win_file" in task
    )
    assert removal["when"] == [
        "updates_runas_monitor_closed is defined",
        "updates_runas_monitor_closed.rc | default(-1) == 0",
    ]


@pytest.mark.parametrize(
    "fault", [None, "completed-first", "path", "bool-pid", "reused-birth", "owner"]
)
def test_poll_cache_requires_literal_startup_and_a_live_owned_watchdog(
    observer: dict[str, Any],
    tmp_path: Path,
    fault: str | None,
) -> None:
    workspace = tmp_path / "legacy-windows-updates-runas-owned"
    cache = workspace / "cache"
    cache.mkdir(parents=True)
    name = "j123.456"
    value = {
        "ansible_job_id": name,
        "results_file": str(cache / name),
        "ansible_async_watchdog_pid": 42,
        "started": True,
        "finished": False,
    }
    identity = {"pid": 42, "created": 100, "alive": True}
    if fault == "completed-first":
        value["finished"] = True
    elif fault == "path":
        value["results_file"] = str(workspace / name)
    elif fault == "bool-pid":
        value["ansible_async_watchdog_pid"] = True
    (cache / name).write_text(json.dumps(value))
    identities = iter(
        [identity, dict(identity, created=200) if fault == "reused-birth" else identity]
    )
    observer["_BASE"]["_process"] = lambda _pid: next(identities)
    connection = SimpleNamespace(
        call_method=lambda *_args: {
            "ReturnValue": 0,
            "Sid": None if fault == "owner" else "S-1-5-18",
        }
    )
    jobs: dict[str, Any] = {}
    races: list[Any] = []
    if fault:
        with pytest.raises(AssertionError):
            observer["_poll_cache"](str(workspace), connection, jobs, races)
        return
    assert observer["_poll_cache"](str(workspace), connection, jobs, races) == name
    assert jobs[name]["startup"]["json"] == value
    assert jobs[name]["worker"] == {"identity": identity, "sid": "S-1-5-18"}
    value.update(finished=True, failed=True, hresult=-2145107951)
    (cache / name).write_text(json.dumps(value))
    assert observer["_poll_cache"](str(workspace), connection, jobs, races) is None
    completed = jobs[name]["completed"]
    assert json.loads(base64.b64decode(completed["body_base64"])) == value
    assert completed["json"] == value
    (cache / name).unlink()
    assert observer["_poll_cache"](str(workspace), connection, jobs, races) is None
    assert json.loads((workspace / "async-jobs.json").read_text()) == jobs


def _poll_pairs(workspace: Path) -> tuple[dict[str, Any], dict[str, Any], list[Any]]:
    cases = [
        {"actor": actor, "state": "installed" if check else "searched", "check": check}
        for actor in ("administrator", "system")
        for check in (False, True)
    ]
    pairs: dict[str, Any] = {"cases": cases, "administrator_sid": "S-1-5-21-1-2-3-500"}
    jobs: dict[str, Any] = {}
    identities: list[Any] = []
    for offset, side in enumerate(("native", "original")):
        pairs[side] = []
        for index, case in enumerate(cases):
            identifier, pid = f"j123.{offset * 10 + index}", 100 + offset * 10 + index
            sid = (
                pairs["administrator_sid"]
                if case["actor"] == "administrator"
                else "S-1-5-18"
            )
            launch = {
                "ansible_job_id": identifier,
                "results_file": str(workspace / "cache" / identifier),
                "ansible_async_watchdog_pid": pid,
                "started": True,
                "finished": False,
            }
            body = dict(
                launch,
                finished=True,
                failed=True,
                hresult=-2145107951,
                changed=False,
                rebooted=False,
                updates={},
                filtered_updates={},
                msg="literal source error",
                found_update_count=0,
            )
            identity = {"pid": pid, "created": 1000 + pid, "alive": True}
            jobs[identifier] = {
                "startup": {"json": launch},
                "worker": {"identity": identity, "sid": sid},
                "completed": {
                    "json": body,
                    "body_base64": base64.b64encode(json.dumps(body).encode()).decode(),
                },
            }
            identities.append(
                {"job_id": identifier, "side": side, "sid": sid, "identity": identity}
            )
            pairs[side].append(dict(body, item=case, _ansible_no_log=True))
    return pairs, jobs, identities


@pytest.mark.parametrize(
    "fault",
    [None, "worker-sid", "backend-sid", "cache", "type", "message", "extra", "missing"],
)
@pytest.mark.parametrize("retained", [False, True])
def test_poll_comparison_keeps_whole_public_results_cache_and_identity_proof(
    observer: dict[str, Any],
    tmp_path: Path,
    fault: str | None,
    retained: bool,
) -> None:
    pairs, jobs, identities = _poll_pairs(tmp_path)
    identifier = pairs["native"][0]["ansible_job_id"]
    if fault == "worker-sid":
        jobs[identifier]["worker"]["sid"] = "unrequested"
    elif fault == "backend-sid":
        identities[0]["sid"] = "unrequested"
    elif fault == "cache":
        jobs[identifier]["completed"]["body_base64"] = base64.b64encode(b"{}").decode()
    elif fault == "type":
        pairs["original"][0]["found_update_count"] = False
    elif fault == "message":
        pairs["original"][0]["msg"] = "different"
    elif fault == "extra":
        pairs["original"][0]["extra_public_field"] = 1
    elif fault == "missing":
        identities.pop()
    if retained:
        source_jobs = {
            name: job
            for name, job in jobs.items()
            if name in {row["ansible_job_id"] for row in pairs["original"]}
        }
        source_records = [row for row in identities if row["side"] == "original"]
        source_workspace = tmp_path / "independently-restored-owned-source"
        for row in pairs["original"]:
            path = str(source_workspace / "cache" / row["ansible_job_id"])
            row["results_file"] = path
            job = source_jobs[row["ansible_job_id"]]
            job["startup"]["json"]["results_file"] = path
            job["completed"]["json"]["results_file"] = path
            job["completed"]["body_base64"] = base64.b64encode(
                json.dumps(job["completed"]["json"]).encode()
            ).decode()
        pairs["retained_original"] = {
            "workspace": str(source_workspace),
            "observation": {
                "jobs": source_jobs,
                "records": source_records,
                "cache_after": [],
                "workers_closed": [
                    {"expected": job["worker"]["identity"], "actual": None}
                    for job in source_jobs.values()
                ],
                "backends_closed": [
                    {"expected": row["identity"], "actual": None}
                    for row in source_records
                ],
            },
        }
        jobs = {name: job for name, job in jobs.items() if name not in source_jobs}
        identities = [row for row in identities if row["side"] == "native"]
    (tmp_path / "async-jobs.json").write_text(json.dumps(jobs))
    (tmp_path / "backend-identities.json").write_text(json.dumps(identities))
    original = json.dumps(pairs)
    if fault:
        with pytest.raises(AssertionError):
            observer["_compare_poll"](str(tmp_path), pairs)
    else:
        assert observer["_compare_poll"](str(tmp_path), pairs) == {
            "whole_typed_public_pairs": 4,
            "startup_and_completed_cache_pairs": 4,
            "watchdog_and_backend_sid_birth_observations": 16,
        }
    assert json.dumps(pairs) == original


def test_poll_public_tasks_use_the_existing_wrapper_and_protect_cache_capture() -> None:
    play = yaml.safe_load(
        (_ROOT / "tests/integration/win_updates_runas_poll.yml").read_text()
    )[0]
    block = next(task["block"] for task in play["tasks"] if "block" in task)
    requests = [
        task for task in block if any(key.endswith(".win_updates") for key in task)
    ]
    assert len(requests) == 2
    for task in requests:
        assert task["async"] == 300 and task["poll"] == 5
        assert (
            task["vars"]["ansible_async_dir"]
            == "{{ updates_runas_workspace.path }}\\cache"
        )
        assert task["become"] is True
        assert task["check_mode"] == "{{ item.check }}"
        assert task["ignore_errors"] is True
    assert block[-1]["register"] == "updates_runas_poll_comparison"
    cache = next(
        i
        for i, task in enumerate(block)
        if task.get("sustainablelobster.legacy_windows.win_file")
    )
    monitor = next(
        i
        for i, task in enumerate(block)
        if task.get("register") == "updates_runas_monitor"
    )
    assert cache < monitor
